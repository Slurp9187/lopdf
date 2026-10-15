//! The copy pass: every object of the input, in input order, decrypted and written to the output,
//! then new cross-reference data. Streams go through a chunk decipher a fixed buffer at a time.

use super::index::{Index, read_index};
use super::source::Source;
use super::{Caps, StripFallback, StripOptions, StripReport};
use crate::encryption::stream::{ChunkDecipher, MAX_EXPANSION};
use crate::encryption::{self, PasswordAlgorithm};
use crate::parser::{self, ObjectHead};
use crate::writer::{Writer, XRefStreamFilter};
use crate::xref::{Xref, XrefEntry, XrefType};
use crate::{DecompressError, Dictionary, Document, EncryptionState, Error, Object, ObjectId, Result, Stream};
use std::collections::HashSet;
use std::io::{self, Read, Seek, Write};
use zeroize::{Zeroize as _, Zeroizing};

/// How much stream data is read and decrypted at a time.
const CHUNK: usize = 64 * 1024;

/// The first window an object's head is read through. It doubles until the head fits, up to
/// [`Caps::max_head`].
const FIRST_HEAD_WINDOW: usize = 4 * 1024;

fn fallback(reason: StripFallback) -> Error {
    Error::NeedsWholeDocument(reason)
}

/// Strips `input` into `output`. See [`super::strip`].
pub(crate) fn strip<R: Read + Seek, W: Write>(
    input: R, output: W, options: &StripOptions, caps: &Caps,
) -> Result<StripReport> {
    let mut source = Source::new(input)?;
    let index = read_index(&mut source, caps)?;
    if index.older_trailer_has_encrypt {
        return Err(fallback(StripFallback::InconsistentEncrypt));
    }

    let version = read_version(&mut source, index.base)?;
    let (state, encrypt_id) = open_encryption(&mut source, &index, caps, options)?;

    let mut stripper = Stripper {
        source,
        out: Output {
            inner: output,
            position: 0,
        },
        index,
        state,
        caps: *caps,
        decoded: 0,
        container: None,
        input: Zeroizing::new(vec![0; CHUNK]),
        output: Zeroizing::new(vec![0; CHUNK + MAX_EXPANSION]),
        report: StripReport::default(),
    };
    stripper.copy(&version, encrypt_id)?;
    Ok(stripper.report)
}

/// The version in the `%PDF-` header at `base`.
fn read_version<R: Read + Seek>(source: &mut Source<R>, base: u64) -> Result<String> {
    let head = source.window(base, 32)?;
    parser::header(&head, false).ok_or(fallback(StripFallback::NoHeader))
}

/// Authenticates the password, as a whole-document load does, and builds the decryption state from
/// a stand-in document that holds only the trailer and the encryption dictionary. Returns the id
/// of the encryption dictionary, which is not copied.
fn open_encryption<R: Read + Seek>(
    source: &mut Source<R>, index: &Index, caps: &Caps, options: &StripOptions,
) -> Result<(EncryptionState, Option<ObjectId>)> {
    let encrypt = index.trailer.get(b"Encrypt").map_err(|_| Error::NotEncrypted)?;

    let mut stand_in = Document::new();
    stand_in.trailer = index.trailer.clone();
    let encrypt_id = match encrypt {
        Object::Reference(id) => {
            let dict = match index.get(id.0) {
                Some(&XrefEntry::Normal { offset, generation }) if generation == id.1 => {
                    let (head_id, head, _) = read_head(source, index.base + u64::from(offset), caps)?;
                    match head {
                        ObjectHead::Direct {
                            object: Object::Dictionary(dict),
                            ..
                        } if head_id == *id => dict,
                        _ => return Err(fallback(StripFallback::EncryptUnreadable)),
                    }
                }
                _ => return Err(fallback(StripFallback::EncryptUnreadable)),
            };
            stand_in.objects.insert(*id, Object::Dictionary(dict));
            Some(*id)
        }
        // A direct dictionary in the trailer: give it an id in the stand-in only.
        Object::Dictionary(dict) => {
            let id = (index.entries.last().map_or(0, |(number, _)| *number) + 1, 0);
            stand_in.objects.insert(id, Object::Dictionary(dict.clone()));
            stand_in.trailer.set("Encrypt", Object::Reference(id));
            None
        }
        _ => return Err(fallback(StripFallback::EncryptUnreadable)),
    };

    let password: &str = if stand_in.authenticate_password("").is_ok() {
        ""
    } else if stand_in.authenticate_password(&options.password).is_ok() {
        &options.password
    } else {
        return Err(Error::InvalidPassword);
    };

    // Derive the key from the same sanitized bytes `authenticate_password` checked.
    let password = Zeroizing::new(PasswordAlgorithm::try_from(&stand_in)?.sanitize_password(password)?);
    let state = EncryptionState::decode(&stand_in, &*password)?;
    Ok((state, encrypt_id))
}

/// Reads the head of the object at `at` through a window that doubles until the head fits.
fn read_head<R: Read + Seek>(
    source: &mut Source<R>, at: u64, caps: &Caps,
) -> Result<(ObjectId, ObjectHead, Zeroizing<Vec<u8>>)> {
    if at >= source.len() {
        return Err(fallback(StripFallback::ObjectUnreadable));
    }

    let mut size = FIRST_HEAD_WINDOW.min(caps.max_head);
    loop {
        let window = source.window(at, size)?;
        let at_eof = window.len() as u64 == source.len() - at;
        if let Some((id, head)) = parser::object_head(&window, at_eof) {
            return Ok((id, head, window));
        }
        if at_eof || size >= caps.max_head {
            return Err(fallback(StripFallback::ObjectUnreadable));
        }
        size = size.saturating_mul(2).min(caps.max_head);
    }
}

/// The output, counting the bytes written, so each object's offset is known.
struct Output<W> {
    inner: W,
    position: u64,
}

impl<W: Write> Write for Output<W> {
    fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
        let written = self.inner.write(buffer)?;
        self.position += written as u64;
        Ok(written)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }
}

/// One decrypted and decompressed object stream, kept while lengths are read from it.
struct Container {
    id: u32,
    /// Its decoded content, which is plaintext and wiped on drop.
    decoded: Zeroizing<Vec<u8>>,
    /// Where the objects start in `decoded` (`/First`).
    first: usize,
    /// Each member's object number and offset from `first`.
    members: Vec<(u32, usize)>,
}

struct Stripper<R, W> {
    source: Source<R>,
    out: Output<W>,
    index: Index,
    state: EncryptionState,
    caps: Caps,
    /// How much the object streams read so far decompressed to.
    decoded: usize,
    container: Option<Container>,
    /// The chunk read from a stream, and the chunk decrypted from it. Both are wiped on drop.
    input: Zeroizing<Vec<u8>>,
    output: Zeroizing<Vec<u8>>,
    report: StripReport,
}

impl<R: Read + Seek, W: Write> Stripper<R, W> {
    fn copy(&mut self, version: &str, encrypt_id: Option<ObjectId>) -> Result<()> {
        // Object streams are copied whole, so their members keep their entries.
        let containers: HashSet<u32> = self
            .index
            .entries
            .iter()
            .filter_map(|(_, entry)| match entry {
                XrefEntry::Compressed { container, .. } => Some(*container),
                _ => None,
            })
            .collect();
        for &container in &containers {
            if !matches!(self.index.get(container), Some(XrefEntry::Normal { generation: 0, .. })) {
                return Err(fallback(StripFallback::BadObjectStream));
            }
        }

        // Object streams need a cross-reference stream, which needs PDF 1.5.
        let compressed = !containers.is_empty();
        let version = if compressed && version < "1.5" { "1.5" } else { version };
        self.out
            .write_all(format!("%PDF-{version}\n%\u{e2}\u{e3}\u{cf}\u{d3}\n").as_bytes())?;

        let mut objects: Vec<(u64, u32, u16)> = self
            .index
            .entries
            .iter()
            .filter_map(|(id, entry)| match entry {
                XrefEntry::Normal { offset, generation } => Some((u64::from(*offset), *id, *generation)),
                _ => None,
            })
            .collect();
        objects.sort_unstable();

        let mut xref = Xref::new(
            0,
            if compressed {
                XrefType::CrossReferenceStream
            } else {
                XrefType::CrossReferenceTable
            },
        );
        for (offset, id, generation) in objects {
            let entry = if Some((id, generation)) == encrypt_id {
                XrefEntry::Free
            } else {
                match self.copy_object((id, generation), offset, &containers)? {
                    Some(at) => XrefEntry::Normal {
                        offset: u32::try_from(at)?,
                        generation,
                    },
                    None => XrefEntry::Free,
                }
            };
            xref.insert(id, entry);
        }
        for (id, entry) in &self.index.entries {
            // Object 0 is written by the table writer itself.
            if *id != 0 && !entry.is_normal() {
                xref.insert(*id, entry.clone());
            }
        }

        self.write_xref(xref, compressed)
    }

    /// Copies the object `id` at `offset`, decrypted, and returns where it starts in the output, or
    /// `None` for an object that is not copied: an old cross-reference stream.
    fn copy_object(&mut self, id: ObjectId, offset: u64, containers: &HashSet<u32>) -> Result<Option<u64>> {
        let at = self.index.base + offset;
        let (head_id, head, window) = read_head(&mut self.source, at, &self.caps)?;
        if head_id != id {
            return Err(fallback(StripFallback::ObjectIdMismatch));
        }
        let start = self.out.position;

        match head {
            ObjectHead::Direct { object, end } if !has_strings(&object) => {
                // Nothing to decrypt: copy the bytes as they are.
                let from = window.iter().take_while(|byte| byte.is_ascii_whitespace()).count();
                self.out.write_all(&window[from..end])?;
                if !window[..end].last().is_some_and(u8::is_ascii_whitespace) {
                    self.out.write_all(b"\n")?;
                }
            }
            ObjectHead::Direct { mut object, .. } => {
                let result = encryption::decrypt_object(&self.state, id, &mut object)
                    .map_err(Error::from)
                    .and_then(|()| self.write_direct(id, &object));
                wipe_object(&mut object);
                result?;
            }
            ObjectHead::Stream { dict, data_start } => {
                if dict.has_type(b"XRef") {
                    return Ok(None);
                }
                if containers.contains(&id.0) && !dict.has_type(b"ObjStm") {
                    return Err(fallback(StripFallback::BadObjectStream));
                }
                self.copy_stream(id, dict, at + data_start as u64)?;
            }
        }

        self.report.objects += 1;
        Ok(Some(start))
    }

    fn write_direct(&mut self, id: ObjectId, object: &Object) -> Result<()> {
        writeln!(self.out, "{} {} obj", id.0, id.1)?;
        Writer::write_object(&mut self.out, object)?;
        self.out.write_all(b"\nendobj\n")?;
        Ok(())
    }

    /// Copies a stream whose data starts at `data_at`: the dictionary with its strings decrypted and
    /// the plaintext `/Length`, then the data through a chunk decipher.
    fn copy_stream(&mut self, id: ObjectId, dict: Dictionary, data_at: u64) -> Result<()> {
        let length = self.resolve_length(dict.get(b"Length").ok())?;
        self.check_endstream(data_at, length)?;

        let mut decipher = encryption::stream_decipher(&self.state, id, &dict)?
            .ok_or(fallback(StripFallback::UnsupportedCryptFilter))?;
        let plaintext_len = {
            let tail_len = (decipher.tail_len() as u64).min(length);
            let tail = self.source.window(data_at + length - tail_len, tail_len as usize)?;
            decipher.plaintext_len(usize::try_from(length)?, &tail)?
        };

        let mut dict = Object::Dictionary(dict);
        let result = encryption::decrypt_object(&self.state, id, &mut dict)
            .map_err(Error::from)
            .and_then(|()| {
                if let Object::Dictionary(dict) = &mut dict {
                    dict.set("Length", plaintext_len as i64);
                }
                writeln!(self.out, "{} {} obj", id.0, id.1)?;
                Writer::write_object(&mut self.out, &dict)?;
                self.out.write_all(b"\nstream\n")?;
                Ok(())
            });
        wipe_object(&mut dict);
        result?;

        let written = self.copy_data(&mut *decipher, data_at, length)?;
        if written != plaintext_len {
            return Err(encryption::DecryptionError::InvalidCipherTextLength.into());
        }
        self.out.write_all(b"\nendstream\nendobj\n")?;

        self.report.streams += 1;
        self.report.stream_bytes += written as u64;
        Ok(())
    }

    /// Decrypts `length` bytes of stream data at `data_at` into the output, a chunk at a time, and
    /// returns how many plaintext bytes it wrote.
    fn copy_data(&mut self, decipher: &mut dyn ChunkDecipher, data_at: u64, length: u64) -> Result<usize> {
        let mut written = 0;
        let mut done = 0;
        while done < length {
            let n = (length - done).min(CHUNK as u64) as usize;
            self.source.read_into(data_at + done, &mut self.input[..n])?;
            let decrypted = decipher.update(&self.input[..n], &mut self.output)?;
            self.out.write_all(&self.output[..decrypted])?;
            written += decrypted;
            done += n as u64;
        }
        let decrypted = decipher.finish(&mut self.output)?;
        self.out.write_all(&self.output[..decrypted])?;
        Ok(written + decrypted)
    }

    /// Checks that `endstream` follows the data, after an optional end of line.
    fn check_endstream(&mut self, data_at: u64, length: u64) -> Result<()> {
        let after = self.source.window(data_at + length, 11)?;
        let rest = after
            .strip_prefix(b"\r\n")
            .or_else(|| after.strip_prefix(b"\n"))
            .or_else(|| after.strip_prefix(b"\r"))
            .unwrap_or(&after);
        if !rest.starts_with(b"endstream") {
            return Err(fallback(StripFallback::LengthMismatch));
        }
        Ok(())
    }

    fn resolve_length(&mut self, length: Option<&Object>) -> Result<u64> {
        let object = match length {
            Some(Object::Reference(id)) => self.length_object(*id)?,
            Some(object) => object.clone(),
            None => return Err(fallback(StripFallback::LengthUnresolvable)),
        };
        object
            .as_i64()
            .ok()
            .and_then(|length| u64::try_from(length).ok())
            .ok_or(fallback(StripFallback::LengthUnresolvable))
    }

    /// The object an indirect `/Length` names, from its own place or from an object stream.
    fn length_object(&mut self, id: ObjectId) -> Result<Object> {
        match self.index.get(id.0).cloned() {
            Some(XrefEntry::Normal { offset, generation }) if generation == id.1 => {
                let at = self.index.base + u64::from(offset);
                match read_head(&mut self.source, at, &self.caps)? {
                    (head_id, ObjectHead::Direct { object, .. }, _) if head_id == id => Ok(object),
                    _ => Err(fallback(StripFallback::LengthUnresolvable)),
                }
            }
            Some(XrefEntry::Compressed { container, .. }) if id.1 == 0 => self.member(container, id.0),
            _ => Err(fallback(StripFallback::LengthUnresolvable)),
        }
    }

    /// Object `number` from object stream `container`, which is read once and kept until another
    /// is needed.
    fn member(&mut self, container: u32, number: u32) -> Result<Object> {
        if self.container.as_ref().is_none_or(|kept| kept.id != container) {
            self.container = None;
            self.container = Some(self.read_container(container)?);
        }
        let kept = self.container.as_ref().expect("just read");

        let offset = kept
            .members
            .iter()
            .find(|(member, _)| *member == number)
            .map(|(_, offset)| *offset)
            .ok_or(fallback(StripFallback::LengthUnresolvable))?;
        kept.decoded
            .get(kept.first + offset..)
            .and_then(parser::direct_object)
            .ok_or(fallback(StripFallback::LengthUnresolvable))
    }

    /// Reads, decrypts and decompresses object stream `container` under the caps.
    fn read_container(&mut self, container: u32) -> Result<Container> {
        let Some(&XrefEntry::Normal { offset, generation: 0 }) = self.index.get(container) else {
            return Err(fallback(StripFallback::BadObjectStream));
        };
        let at = self.index.base + u64::from(offset);
        let (head_id, head, _) = read_head(&mut self.source, at, &self.caps)?;
        let ObjectHead::Stream { dict, data_start } = head else {
            return Err(fallback(StripFallback::BadObjectStream));
        };
        if head_id != (container, 0) || !dict.has_type(b"ObjStm") {
            return Err(fallback(StripFallback::BadObjectStream));
        }

        // An object stream's own /Length is direct (ISO 32000-1, 7.5.7).
        let length = dict
            .get(b"Length")
            .and_then(Object::as_i64)
            .ok()
            .and_then(|length| usize::try_from(length).ok())
            .ok_or(fallback(StripFallback::LengthUnresolvable))?;
        if length > self.caps.max_decoded {
            return Err(DecompressError::MemoryLimitExceeded {
                limit: self.caps.max_decoded,
            }
            .into());
        }
        let first = dict.get(b"First").and_then(Object::as_i64).ok();
        let count = dict.get(b"N").and_then(Object::as_i64).ok();
        let (Some(first), Some(count)) = (
            first.and_then(|first| usize::try_from(first).ok()),
            count.and_then(|count| usize::try_from(count).ok()),
        ) else {
            return Err(fallback(StripFallback::BadObjectStream));
        };

        let data_at = at + data_start as u64;
        self.check_endstream(data_at, length as u64)?;
        let ciphertext = self.source.window(data_at, length)?;
        let mut decipher = encryption::stream_decipher(&self.state, (container, 0), &dict)?
            .ok_or(fallback(StripFallback::UnsupportedCryptFilter))?;
        let mut plaintext = Zeroizing::new(vec![0; length + MAX_EXPANSION]);
        let n = decipher.update(&ciphertext, &mut plaintext)?;
        let m = decipher.finish(&mut plaintext[n..])?;
        plaintext.truncate(n + m);

        let limit = self
            .caps
            .max_decoded
            .min(self.caps.max_total_decoded.saturating_sub(self.decoded));
        let mut stream = Stream::new(dict, std::mem::take(&mut *plaintext));
        let decoded = stream.decompressed_content_with_limit(limit);
        stream.content.zeroize();
        let decoded = Zeroizing::new(decoded?);
        self.decoded += decoded.len();

        let members = std::str::from_utf8(decoded.get(..first).unwrap_or_default())
            .ok()
            .and_then(|header| {
                let numbers: Vec<usize> = header
                    .split_ascii_whitespace()
                    .map(str::parse)
                    .collect::<std::result::Result<_, _>>()
                    .ok()?;
                (numbers.len() == count * 2).then(|| {
                    numbers
                        .chunks(2)
                        .map(|pair| (pair[0] as u32, pair[1]))
                        .collect::<Vec<_>>()
                })
            })
            .ok_or(fallback(StripFallback::BadObjectStream))?;

        Ok(Container {
            id: container,
            decoded,
            first,
            members,
        })
    }

    /// Writes the new cross-reference data and trailer: a table, or a cross-reference stream when
    /// object streams were copied.
    fn write_xref(&mut self, mut xref: Xref, compressed: bool) -> Result<()> {
        let mut trailer = self.index.trailer.clone();
        for key in [
            &b"Encrypt"[..],
            b"Prev",
            b"XRefStm",
            b"Type",
            b"W",
            b"Index",
            b"Length",
            b"Filter",
            b"DecodeParms",
        ] {
            trailer.remove(key);
        }
        let max_id = xref.max_id().max(self.index.entries.last().map_or(0, |(id, _)| *id));
        let start = self.out.position;

        if compressed {
            let id = max_id + 1;
            xref.insert(
                id,
                XrefEntry::Normal {
                    offset: u32::try_from(start)?,
                    generation: 0,
                },
            );
            let (data, data_len, index) = Writer::create_xref_steam(&xref, XRefStreamFilter::None)?;
            trailer.set("Type", Object::Name(b"XRef".to_vec()));
            trailer.set("Size", i64::from(id) + 1);
            trailer.set("W", vec![Object::Integer(1), Object::Integer(4), Object::Integer(2)]);
            trailer.set("Index", index);
            trailer.set("Length", data_len as i64);
            writeln!(self.out, "{id} 0 obj")?;
            Writer::write_object(&mut self.out, &Object::Dictionary(trailer))?;
            self.out.write_all(b"\nstream\n")?;
            self.out.write_all(&data)?;
            self.out.write_all(b"\nendstream\nendobj\n")?;
        } else {
            Writer::write_xref(&mut self.out, &xref)?;
            trailer.set("Size", i64::from(max_id) + 1);
            self.out.write_all(b"trailer\n")?;
            Writer::write_object(&mut self.out, &Object::Dictionary(trailer))?;
            self.out.write_all(b"\n")?;
        }

        write!(self.out, "startxref\n{start}\n%%EOF\n")?;
        self.out.flush()?;
        Ok(())
    }
}

/// Whether `object` holds a string anywhere, which would need decrypting.
fn has_strings(object: &Object) -> bool {
    match object {
        Object::String(..) => true,
        Object::Array(items) => items.iter().any(has_strings),
        Object::Dictionary(dict) => dict.iter().any(|(_, value)| has_strings(value)),
        Object::Stream(stream) => stream.dict.iter().any(|(_, value)| has_strings(value)),
        _ => false,
    }
}

/// Wipes every string in `object`: once decrypted, they are plaintext.
fn wipe_object(object: &mut Object) {
    match object {
        Object::String(bytes, _) => bytes.zeroize(),
        Object::Array(items) => items.iter_mut().for_each(wipe_object),
        Object::Dictionary(dict) => dict.iter_mut().for_each(|(_, value)| wipe_object(value)),
        Object::Stream(stream) => {
            stream.dict.iter_mut().for_each(|(_, value)| wipe_object(value));
            stream.content.zeroize();
        }
        _ => {}
    }
}

#[cfg(test)]
mod tests {
    use super::strip;
    use crate::encryption::crypt_filters::{Aes256CryptFilter, CryptFilter};
    use crate::strip::{Caps, StripFallback, StripOptions};
    use crate::writer::{Writer, XRefStreamFilter};
    use crate::xref::{Xref, XrefEntry, XrefType};
    use crate::{
        DecompressError, Document, EncryptionState, EncryptionVersion, Error, LoadOptions, Object, Permissions, Stream,
        dictionary,
    };
    use std::collections::BTreeMap;
    use std::io::{Cursor, Write as _};
    use std::sync::Arc;

    const CONTENT: &[u8] = b"BT /F1 12 Tf (Inside a content stream) Tj ET";

    /// Writes object `id` at the end of `pdf` and records its offset in `xref`.
    fn write_object(pdf: &mut Vec<u8>, xref: &mut Xref, id: u32, object: &Object) {
        xref.insert(
            id,
            XrefEntry::Normal {
                offset: pdf.len() as u32,
                generation: 0,
            },
        );
        writeln!(pdf, "{id} 0 obj").unwrap();
        match object {
            Object::Stream(stream) => {
                Writer::write_object(pdf, &Object::Dictionary(stream.dict.clone())).unwrap();
                pdf.extend_from_slice(b"\nstream\n");
                pdf.extend_from_slice(&stream.content);
                pdf.extend_from_slice(b"\nendstream");
            }
            other => Writer::write_object(pdf, other).unwrap(),
        }
        pdf.extend_from_slice(b"\nendobj\n");
    }

    /// An AES-256 file whose catalog, page tree, `/Info` and the length of its content stream live
    /// in an object stream, indexed by a cross-reference stream:
    ///
    /// - 1 catalog, 2 page tree, 3 `/Info`, 7 the content stream's length, all in object stream 4;
    /// - 5 the encryption dictionary, 6 the content stream, whose `/Length` is `7 0 R`;
    /// - 8 the cross-reference stream.
    fn object_stream_file() -> Vec<u8> {
        let aes: Arc<dyn CryptFilter> = Arc::new(Aes256CryptFilter);
        let state = EncryptionState::try_from(EncryptionVersion::V5 {
            encrypt_metadata: true,
            crypt_filters: BTreeMap::from([(b"StdCF".to_vec(), aes)]),
            file_encryption_key: &[9; 32],
            stream_filter: b"StdCF".to_vec(),
            string_filter: b"StdCF".to_vec(),
            owner_password: "owner",
            user_password: "user",
            permissions: Permissions::all(),
        })
        .unwrap();

        let mut content = Object::Stream(Stream::new(dictionary! {}, CONTENT.to_vec()));
        crate::encryption::encrypt_object(&state, (6, 0), &mut content).unwrap();
        let Object::Stream(mut content) = content else {
            unreachable!("a stream stays a stream");
        };
        let ciphertext_len = content.content.len();
        content.dict.set("Length", Object::Reference((7, 0)));

        // Members are not encrypted one by one: the object stream is, as a whole.
        let members = [
            (1, "<< /Type /Catalog /Pages 2 0 R >>".to_string()),
            (2, "<< /Type /Pages /Kids [] /Count 0 >>".to_string()),
            (3, "<< /Title (In an object stream) >>".to_string()),
            (7, ciphertext_len.to_string()),
        ];
        let mut header = String::new();
        let mut bodies = String::new();
        for (number, body) in &members {
            header.push_str(&format!("{number} {} ", bodies.len()));
            bodies.push_str(body);
            bodies.push(' ');
        }
        let mut container = Stream::new(
            dictionary! { "Type" => "ObjStm", "N" => members.len() as i64, "First" => header.len() as i64 },
            format!("{header}{bodies}").into_bytes(),
        );
        container.compress().unwrap();
        let mut container = Object::Stream(container);
        crate::encryption::encrypt_object(&state, (4, 0), &mut container).unwrap();

        let mut pdf = b"%PDF-1.7\n".to_vec();
        let mut xref = Xref::new(9, XrefType::CrossReferenceStream);
        write_object(&mut pdf, &mut xref, 4, &container);
        write_object(&mut pdf, &mut xref, 5, &Object::Dictionary(state.encode().unwrap()));
        write_object(&mut pdf, &mut xref, 6, &Object::Stream(content));
        for (index, (number, _)) in members.iter().enumerate() {
            xref.insert(
                *number,
                XrefEntry::Compressed {
                    container: 4,
                    index: index as u16,
                },
            );
        }
        let xref_at = pdf.len();
        xref.insert(
            8,
            XrefEntry::Normal {
                offset: xref_at as u32,
                generation: 0,
            },
        );
        let (data, data_len, index) = Writer::create_xref_steam(&xref, XRefStreamFilter::None).unwrap();
        let dict = dictionary! {
            "Type" => "XRef",
            "Size" => 9,
            "W" => vec![1.into(), 4.into(), 2.into()],
            "Index" => index,
            "Length" => data_len as i64,
            "Root" => Object::Reference((1, 0)),
            "Info" => Object::Reference((3, 0)),
            "Encrypt" => Object::Reference((5, 0)),
        };
        pdf.extend_from_slice(b"8 0 obj\n");
        Writer::write_object(&mut pdf, &Object::Dictionary(dict)).unwrap();
        pdf.extend_from_slice(b"\nstream\n");
        pdf.extend_from_slice(&data);
        pdf.extend_from_slice(b"\nendstream\nendobj\nstartxref\n");
        pdf.extend_from_slice(format!("{xref_at}\n%%EOF\n").as_bytes());
        pdf
    }

    fn stripped(bytes: &[u8], caps: &Caps) -> crate::Result<Vec<u8>> {
        let mut output = Vec::new();
        strip(
            Cursor::new(bytes),
            &mut output,
            &StripOptions::with_password("user"),
            caps,
        )?;
        Ok(output)
    }

    /// Each object but cross-reference streams, as text, stream content included.
    fn objects(doc: &Document) -> BTreeMap<crate::ObjectId, String> {
        doc.objects
            .iter()
            .filter(|(_, object)| object.type_name().ok() != Some(b"XRef"))
            .map(|(id, object)| match object {
                Object::Stream(stream) => (*id, format!("{:?} {:?}", stream.dict, stream.content)),
                other => (*id, format!("{other:?}")),
            })
            .collect()
    }

    #[test]
    fn object_streams_are_copied_whole_and_an_indirect_length_is_read_from_one() {
        let bytes = object_stream_file();
        let expected = Document::load_mem_with_options(&bytes, LoadOptions::with_password("user")).unwrap();
        assert_eq!(
            expected.get_object((6, 0)).unwrap().as_stream().unwrap().content,
            CONTENT,
            "the oracle reads the file"
        );

        let output = stripped(&bytes, &Caps::default()).unwrap();
        let strict = LoadOptions {
            strict: true,
            ..Default::default()
        };
        let actual = Document::load_mem_with_options(&output, strict).unwrap();

        assert_eq!(objects(&actual), objects(&expected));
        assert_eq!(actual.get_object((6, 0)).unwrap().as_stream().unwrap().content, CONTENT);
        assert!(actual.reference_table.get(3).is_some_and(XrefEntry::is_compressed));
        assert!(output.starts_with(b"%PDF-1.7\n"));
        assert!(!actual.trailer.has(b"Encrypt"));
        assert_eq!(actual.trailer.get(b"Info").unwrap().as_reference().unwrap(), (3, 0));
    }

    #[test]
    fn an_object_stream_past_the_decompression_cap_is_refused() {
        let caps = Caps {
            max_decoded: 32,
            ..Caps::default()
        };
        let result = stripped(&object_stream_file(), &caps);
        assert!(
            matches!(
                result,
                Err(Error::Decompress(DecompressError::MemoryLimitExceeded { .. }))
            ),
            "{:?}",
            result.err()
        );
    }

    #[test]
    fn a_compressed_entry_whose_container_is_not_an_object_stream_needs_the_whole_document_path() {
        // Point the members at object 6, the content stream, by rewriting the container number in
        // the cross-reference stream's type 2 entries.
        let mut bytes = object_stream_file();
        let xref_at = bytes.windows(8).rposition(|window| window == b"8 0 obj\n").unwrap();
        let data_at = xref_at
            + bytes[xref_at..]
                .windows(7)
                .position(|window| window == b"stream\n")
                .unwrap()
            + 7;
        for entry in bytes[data_at..data_at + 9 * 7].chunks_mut(7) {
            if entry[0] == 2 {
                entry[1..5].copy_from_slice(&6u32.to_be_bytes());
            }
        }

        assert!(matches!(
            stripped(&bytes, &Caps::default()),
            Err(Error::NeedsWholeDocument(StripFallback::BadObjectStream))
        ));
    }
}
