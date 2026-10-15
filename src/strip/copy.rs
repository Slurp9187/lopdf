//! The copy pass: every object of the input, in input order, decrypted and written to the output,
//! then new cross-reference data. Streams go through a chunk decipher a fixed buffer at a time.

use super::index::{Index, read_index};
use super::source::Source;
use super::{Caps, Inspection, PasswordCheck, Signed, StripFallback, StripOptions, StripReport};
use crate::encryption::stream::{ChunkDecipher, IdentityDecipher, MAX_EXPANSION};
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
    let (stand_in, encrypt_id) = stand_in(&mut source, &index, caps)?;
    check_embedded_file_filter(&stand_in)?;

    let password: &str = if stand_in.authenticate_password("").is_ok() {
        ""
    } else if stand_in.authenticate_password(&options.password).is_ok() {
        &options.password
    } else {
        return Err(Error::InvalidPassword);
    };
    let state = decryption_state(&stand_in, password)?;

    let mut stripper = Stripper::new(source, output, index, Some(state), caps);
    stripper.copy(&version, encrypt_id)?;
    Ok(stripper.report)
}

/// Reports what [`super::inspect`] reports. Writes nothing and decrypts no stream data but, where
/// the signature fields live in an object stream, that one object stream.
pub(crate) fn inspect<R: Read + Seek>(input: R, password: Option<&str>, caps: &Caps) -> Result<Inspection> {
    let mut source = Source::new(input)?;
    let index = read_index(&mut source, caps)?;
    let encrypted = index.trailer.has(b"Encrypt");

    let mut needs_whole_document = None;
    if index.older_trailer_has_encrypt {
        needs_whole_document = Some(StripFallback::InconsistentEncrypt);
    }
    if let Err(reason) = check_containers(&index) {
        needs_whole_document.get_or_insert(reason);
    }

    let mut check = PasswordCheck::NotGiven;
    let mut state = None;
    if encrypted {
        match stand_in(&mut source, &index, caps) {
            Ok((stand_in, _)) => {
                if let Err(Error::NeedsWholeDocument(reason)) = check_embedded_file_filter(&stand_in) {
                    needs_whole_document.get_or_insert(reason);
                }
                if let Some(password) = password {
                    check = if stand_in.authenticate_user_password(password).is_ok() {
                        PasswordCheck::User
                    } else if stand_in.authenticate_owner_password(password).is_ok() {
                        PasswordCheck::Owner
                    } else {
                        PasswordCheck::Wrong
                    };
                }
                // The key, if one opens the file, to read signature fields in an object stream.
                let opening = match check {
                    PasswordCheck::User | PasswordCheck::Owner => password,
                    _ => stand_in.authenticate_password("").is_ok().then_some(""),
                };
                if let Some(opening) = opening {
                    state = Some(decryption_state(&stand_in, opening)?);
                }
            }
            Err(Error::NeedsWholeDocument(reason)) => {
                needs_whole_document.get_or_insert(reason);
            }
            Err(error) => return Err(error),
        }
    }

    let mut stripper = Stripper::new(source, io::sink(), index, state, caps);
    stripper.encrypted = encrypted;
    let signed = stripper.signed();
    let usage_rights = stripper.usage_rights();

    Ok(Inspection {
        encrypted,
        password: check,
        signed,
        usage_rights,
        needs_whole_document,
    })
}

/// Every container a compressed entry names must be a generation-0 object.
fn check_containers(index: &Index) -> std::result::Result<HashSet<u32>, StripFallback> {
    let containers: HashSet<u32> = index
        .entries
        .iter()
        .filter_map(|(_, entry)| match entry {
            XrefEntry::Compressed { container, .. } => Some(*container),
            _ => None,
        })
        .collect();
    for &container in &containers {
        if !matches!(index.get(container), Some(XrefEntry::Normal { generation: 0, .. })) {
            return Err(StripFallback::BadObjectStream);
        }
    }
    Ok(containers)
}

/// Embedded files are found only through every file specification, which takes the whole document,
/// so a file whose `/EFF` differs from `/StmF` goes to the whole-document path, which honors it.
/// An absent `/StmF` means `/Identity`; an absent `/EFF` means `/StmF`.
fn check_embedded_file_filter(stand_in: &Document) -> Result<()> {
    let encrypt = stand_in.get_encrypted()?;
    let name = |key: &[u8]| {
        encrypt
            .get(key)
            .and_then(Object::as_name)
            .map_or(b"Identity".to_vec(), <[u8]>::to_vec)
    };
    if encrypt.has(b"EFF") && name(b"EFF") != name(b"StmF") {
        return Err(fallback(StripFallback::EmbeddedFileFilter));
    }
    Ok(())
}

/// The version in the `%PDF-` header at `base`.
fn read_version<R: Read + Seek>(source: &mut Source<R>, base: u64) -> Result<String> {
    let head = source.window(base, 32)?;
    parser::header(&head, false).ok_or(fallback(StripFallback::NoHeader))
}

/// A stand-in document that holds only the trailer and the encryption dictionary, enough to check a
/// password and build the decryption state, and the id of the encryption dictionary, which is not
/// copied.
fn stand_in<R: Read + Seek>(
    source: &mut Source<R>, index: &Index, caps: &Caps,
) -> Result<(Document, Option<ObjectId>)> {
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
    Ok((stand_in, encrypt_id))
}

/// The decryption state for `password`, which must authenticate.
fn decryption_state(stand_in: &Document, password: &str) -> Result<EncryptionState> {
    // Derive the key from the same sanitized bytes `authenticate_password` checked.
    let password = Zeroizing::new(PasswordAlgorithm::try_from(stand_in)?.sanitize_password(password)?);
    EncryptionState::decode(stand_in, &*password)
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
    /// The decryption state; `inspect` may have none.
    state: Option<EncryptionState>,
    /// Whether the file is encrypted, so an object stream is never read as plaintext without the key.
    encrypted: bool,
    caps: Caps,
    /// How much the object streams read so far decompressed to.
    decoded: usize,
    container: Option<Container>,
    /// The offsets of the hint streams a linearization dictionary names, which are dropped with it.
    hint_streams: HashSet<u64>,
    /// The chunk read from a stream, and the chunk decrypted from it. Both are wiped on drop.
    input: Zeroizing<Vec<u8>>,
    output: Zeroizing<Vec<u8>>,
    report: StripReport,
}

impl<R: Read + Seek, W: Write> Stripper<R, W> {
    fn new(source: Source<R>, output: W, index: Index, state: Option<EncryptionState>, caps: &Caps) -> Self {
        Self {
            source,
            out: Output {
                inner: output,
                position: 0,
            },
            index,
            encrypted: state.is_some(),
            state,
            caps: *caps,
            decoded: 0,
            container: None,
            hint_streams: HashSet::new(),
            input: Zeroizing::new(vec![0; CHUNK]),
            output: Zeroizing::new(vec![0; CHUNK + MAX_EXPANSION]),
            report: StripReport::default(),
        }
    }

    fn state(&self) -> Result<&EncryptionState> {
        self.state.as_ref().ok_or(Error::InvalidPassword)
    }

    fn copy(&mut self, version: &str, encrypt_id: Option<ObjectId>) -> Result<()> {
        // Object streams are copied whole, so their members keep their entries.
        let containers = check_containers(&self.index).map_err(fallback)?;

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
        // Each object ends, at the latest, where the next one starts: the bound for recovering a
        // stream whose /Length is wrong.
        let bounds: Vec<u64> = objects
            .iter()
            .skip(1)
            .map(|(offset, ..)| self.index.base + offset)
            .chain(std::iter::once(self.source.len()))
            .collect();
        for ((offset, id, generation), bound) in objects.into_iter().zip(bounds) {
            let entry = if Some((id, generation)) == encrypt_id {
                XrefEntry::Free
            } else {
                match self.copy_object((id, generation), offset, bound, &containers)? {
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
    /// `None` for an object that is not copied: an old cross-reference stream, or the linearization
    /// dictionary and its hint streams, which describe a layout the output does not have.
    fn copy_object(&mut self, id: ObjectId, offset: u64, bound: u64, containers: &HashSet<u32>) -> Result<Option<u64>> {
        if self.hint_streams.contains(&offset) {
            return Ok(None);
        }
        let at = self.index.base + offset;
        let (head_id, head, window) = read_head(&mut self.source, at, &self.caps)?;
        if head_id != id {
            return Err(fallback(StripFallback::ObjectIdMismatch));
        }
        let start = self.out.position;

        match head {
            ObjectHead::Direct {
                object: Object::Dictionary(dict),
                ..
            } if dict.has(b"Linearized") => {
                // /H holds the offset and length of one or two hint streams.
                if let Ok(hints) = dict.get(b"H").and_then(Object::as_array) {
                    let offsets = hints.iter().step_by(2).filter_map(|offset| offset.as_i64().ok());
                    self.hint_streams
                        .extend(offsets.filter_map(|offset| u64::try_from(offset).ok()));
                }
                return Ok(None);
            }
            ObjectHead::Direct { object, end } if !has_strings(&object) => {
                // Nothing to decrypt: copy the bytes as they are.
                let from = window.iter().take_while(|byte| byte.is_ascii_whitespace()).count();
                self.out.write_all(&window[from..end])?;
                if !window[..end].last().is_some_and(u8::is_ascii_whitespace) {
                    self.out.write_all(b"\n")?;
                }
            }
            ObjectHead::Direct { mut object, .. } => {
                let result = self
                    .state()
                    .and_then(|state| Ok(encryption::decrypt_object(state, id, &mut object)?))
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
                self.copy_stream(id, dict, at + data_start as u64, bound)?;
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
    fn copy_stream(&mut self, id: ObjectId, dict: Dictionary, data_at: u64, bound: u64) -> Result<()> {
        let length = self.resolve_length(dict.get(b"Length").ok())?;
        // A wrong /Length is recovered as a lenient load recovers it.
        let length = if self.endstream_follows(data_at, length)? {
            length
        } else {
            self.recover_length(data_at, bound)?
        };

        let mut decipher = encryption::stream_decipher(self.state()?, id, &dict)?
            .ok_or(fallback(StripFallback::UnsupportedCryptFilter))?;
        let plaintext_len = {
            let tail_len = (decipher.tail_len() as u64).min(length);
            let tail = self.source.window(data_at + length - tail_len, tail_len as usize)?;
            decipher.plaintext_len(usize::try_from(length)?, &tail)?
        };

        let mut dict = Object::Dictionary(dict);
        let result = self
            .state()
            .and_then(|state| Ok(encryption::decrypt_object(state, id, &mut dict)?))
            .and_then(|()| {
                if let Object::Dictionary(dict) = &mut dict {
                    dict.set("Length", plaintext_len as i64);
                    remove_crypt_filter(dict);
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
        if !self.endstream_follows(data_at, length)? {
            return Err(fallback(StripFallback::LengthMismatch));
        }
        Ok(())
    }

    /// Whether `endstream` follows `length` bytes of data at `data_at`, after an optional end of
    /// line.
    fn endstream_follows(&mut self, data_at: u64, length: u64) -> Result<bool> {
        let after = self.source.window(data_at + length, 11)?;
        let rest = after
            .strip_prefix(b"\r\n")
            .or_else(|| after.strip_prefix(b"\n"))
            .or_else(|| after.strip_prefix(b"\r"))
            .unwrap_or(&after);
        Ok(rest.starts_with(b"endstream"))
    }

    /// The length of the stream data at `data_at` when its `/Length` is wrong, by the rule a
    /// lenient load uses: the data ends at the only `endstream` before `bound` that follows an end
    /// of line and is followed by `endobj`. The scan reads a chunk at a time, keeping a few bytes
    /// of the last one so that a marker across two chunks is still seen.
    fn recover_length(&mut self, data_at: u64, bound: u64) -> Result<u64> {
        const MARKER: &[u8] = b"endstream";
        // Two bytes of end of line before the marker.
        const CARRY: usize = MARKER.len() + 1;

        let mut found = None;
        let mut window_at = data_at;
        while window_at < bound {
            let size = ((bound - window_at) as usize).min(CHUNK);
            let window = self.source.window(window_at, size)?;
            for (at, candidate) in window.windows(MARKER.len()).enumerate() {
                if candidate != MARKER {
                    continue;
                }
                let marker_at = window_at + at as u64;
                let Some(data_end) = self.data_end_before(data_at, marker_at, bound)? else {
                    continue;
                };
                if found.is_some_and(|end| end != data_end) {
                    return Err(fallback(StripFallback::LengthMismatch));
                }
                found = Some(data_end);
            }
            if window_at + size as u64 >= bound {
                break;
            }
            // Step back over the bytes a marker split across this chunk and the next may need.
            window_at += (size - CARRY.min(size)).max(1) as u64;
        }

        let data_end = found.ok_or(fallback(StripFallback::LengthMismatch))?;
        Ok(data_end - data_at)
    }

    /// Where the data ends if the `endstream` at `marker_at` closes the stream: after an end of
    /// line, and followed by `endobj` and then white space or `bound`. `None` otherwise.
    fn data_end_before(&mut self, data_at: u64, marker_at: u64, bound: u64) -> Result<Option<u64>> {
        let before_at = marker_at.saturating_sub(2).max(data_at);
        let before = self.source.window(before_at, (marker_at - before_at) as usize)?;
        let data_end = if before.ends_with(b"\r\n") {
            marker_at - 2
        } else if before.ends_with(b"\n") || before.ends_with(b"\r") {
            marker_at - 1
        } else {
            return Ok(None);
        };

        let after_at = marker_at + 9;
        let after = self
            .source
            .window(after_at, (bound.saturating_sub(after_at) as usize).min(64))?;
        let rest = &after[after.iter().take_while(|byte| b" \t\r\n\x0C\0".contains(byte)).count()..];
        let ends_object = rest
            .strip_prefix(b"endobj")
            .is_some_and(|tail| tail.first().is_none_or(|byte| b" \t\r\n\x0C\0".contains(byte)));
        Ok(ends_object.then_some(data_end))
    }

    fn resolve_length(&mut self, length: Option<&Object>) -> Result<u64> {
        let object = match length {
            Some(Object::Reference(id)) => self.object(*id)?,
            Some(object) => object.clone(),
            None => return Err(fallback(StripFallback::LengthUnresolvable)),
        };
        object
            .as_i64()
            .ok()
            .and_then(|length| u64::try_from(length).ok())
            .ok_or(fallback(StripFallback::LengthUnresolvable))
    }

    /// The direct object `id` names, from its own place or from an object stream: an indirect
    /// `/Length`, or the catalog and form fields `inspect` walks. Its strings are not decrypted.
    fn object(&mut self, id: ObjectId) -> Result<Object> {
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
        let mut decipher: Box<dyn ChunkDecipher> = match &self.state {
            Some(state) => encryption::stream_decipher(state, (container, 0), &dict)?
                .ok_or(fallback(StripFallback::UnsupportedCryptFilter))?,
            // Never read an encrypted object stream as plaintext.
            None if self.encrypted => return Err(Error::InvalidPassword),
            None => Box::new(IdentityDecipher),
        };
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

/// The most form fields [`Stripper::signed`] looks at before answering [`Signed::Unknown`].
const MAX_FIELDS: usize = 10_000;

impl<R: Read + Seek, W: Write> Stripper<R, W> {
    /// Whether the file holds a signature: a `/FT /Sig` field with a `/V` under the catalog's
    /// `/AcroForm /Fields`, `/FT` inherited down `/Kids`. An unsigned signature field is not one.
    /// Any object that cannot be read, or more than [`MAX_FIELDS`] fields, gives `Unknown`.
    fn signed(&mut self) -> Signed {
        self.find_signature().unwrap_or(Signed::Unknown)
    }

    fn find_signature(&mut self) -> Result<Signed> {
        let root = self.index.trailer.get(b"Root")?.clone();
        let root = self.resolve(&root)?;
        let Ok(acro_form) = root.as_dict().and_then(|root| root.get(b"AcroForm")).cloned() else {
            return Ok(Signed::No);
        };
        let acro_form = self.resolve(&acro_form)?;
        let Ok(fields) = acro_form.as_dict().and_then(|form| form.get(b"Fields")).cloned() else {
            return Ok(Signed::No);
        };
        let fields = self.resolve(&fields)?;

        let mut pending: Vec<(Object, Option<Vec<u8>>)> =
            fields.as_array()?.iter().map(|field| (field.clone(), None)).collect();
        let mut seen = HashSet::new();
        let mut looked_at = 0;
        while let Some((field, inherited)) = pending.pop() {
            if let Object::Reference(id) = field
                && !seen.insert(id)
            {
                continue;
            }
            looked_at += 1;
            if looked_at > MAX_FIELDS {
                return Ok(Signed::Unknown);
            }

            let field = self.resolve(&field)?;
            let Ok(field) = field.as_dict() else {
                continue;
            };
            let field_type = field
                .get(b"FT")
                .and_then(Object::as_name)
                .map(<[u8]>::to_vec)
                .ok()
                .or(inherited);
            let has_value = field.get(b"V").is_ok_and(|value| !matches!(value, Object::Null));
            if field_type.as_deref() == Some(b"Sig") && has_value {
                return Ok(Signed::Yes);
            }
            if let Ok(kids) = field.get(b"Kids").and_then(Object::as_array) {
                pending.extend(kids.iter().map(|kid| (kid.clone(), field_type.clone())));
            }
        }
        Ok(Signed::No)
    }

    /// Whether the catalog's `/Perms` holds a usage-rights signature, `/UR3` or the older `/UR`.
    fn usage_rights(&mut self) -> bool {
        let perms = (|| {
            let root = self.index.trailer.get(b"Root")?.clone();
            let perms = self.resolve(&root)?.as_dict()?.get(b"Perms")?.clone();
            self.resolve(&perms)
        })();
        perms
            .ok()
            .and_then(|perms| perms.as_dict().ok().map(|perms| perms.has(b"UR3") || perms.has(b"UR")))
            .unwrap_or(false)
    }

    fn resolve(&mut self, object: &Object) -> Result<Object> {
        match object {
            Object::Reference(id) => self.object(*id),
            other => Ok(other.clone()),
        }
    }
}

/// Takes the `/Crypt` filter out of a decrypted stream's `/Filter`, with its entry in `/DecodeParms`:
/// the data is no longer encrypted, and the output has no crypt filters to name.
fn remove_crypt_filter(dict: &mut Dictionary) {
    let filters: Vec<Object> = match dict.get(b"Filter") {
        Ok(Object::Name(name)) => vec![Object::Name(name.clone())],
        Ok(Object::Array(names)) => names.clone(),
        _ => return,
    };
    let Some(position) = filters
        .iter()
        .position(|filter| filter.as_name().ok() == Some(b"Crypt"))
    else {
        return;
    };

    let mut filters = filters;
    filters.remove(position);
    let parameters = match dict.get(b"DecodeParms") {
        Ok(Object::Array(parameters)) => {
            let mut parameters = parameters.clone();
            if position < parameters.len() {
                parameters.remove(position);
            }
            Some(parameters)
        }
        // A single dictionary goes with a single filter, the /Crypt one.
        _ => None,
    };

    match filters.len() {
        0 => {
            dict.remove(b"Filter");
            dict.remove(b"DecodeParms");
        }
        _ => {
            dict.set("Filter", Object::Array(filters));
            match parameters {
                Some(parameters) => dict.set("DecodeParms", Object::Array(parameters)),
                None => {
                    dict.remove(b"DecodeParms");
                }
            }
        }
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

    #[test]
    fn inspect_reads_a_catalog_in_an_object_stream_only_with_the_key() {
        use crate::strip::{PasswordCheck, Signed};

        let bytes = object_stream_file();
        let opened = super::inspect(Cursor::new(&bytes), Some("user"), &Caps::default()).unwrap();
        assert_eq!(opened.password, PasswordCheck::User);
        assert_eq!(opened.signed, Signed::No, "the catalog has no /AcroForm");

        // Without the key the object stream is ciphertext, never read as plaintext.
        let locked = super::inspect(Cursor::new(&bytes), Some("wrong"), &Caps::default()).unwrap();
        assert_eq!(locked.password, PasswordCheck::Wrong);
        assert_eq!(locked.signed, Signed::Unknown);
    }
}
