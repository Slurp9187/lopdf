//! The index pass: the merged cross-reference data of a file, read from a `Read + Seek` source
//! section by section, without loading the file.

use super::source::Source;
use super::{Caps, StripFallback};
use crate::xref::{Xref, XrefEntry};
use crate::{DecompressError, Dictionary, Error, LoadOptions, Reader, Result, parser};
use std::collections::HashSet;
use std::io::{Read, Seek};

/// The first window a cross-reference section is read through. It doubles until the section
/// fits, up to [`Caps::max_section`].
const FIRST_SECTION_WINDOW: usize = 64 * 1024;

/// How far into the file the `%PDF-` header may start, as other readers allow.
const HEADER_SEARCH: usize = 1024;

/// How much of the end of the file is searched for `startxref`: the last 1024 bytes before
/// `%%EOF`, after any padding.
const TAIL: usize = 4096;

/// The merged cross-reference data of a file: for each object number, the newest revision's entry.
pub(crate) struct Index {
    /// Where the `%PDF-` header starts. Every offset the file records counts from here.
    pub(crate) base: u64,
    /// The newest revision's entry for each object, by object number.
    pub(crate) entries: Vec<(u32, XrefEntry)>,
    /// The newest trailer, without `/Prev` and `/XRefStm`.
    pub(crate) trailer: Dictionary,
    /// Whether an older revision's trailer has `/Encrypt` although the newest one does not.
    pub(crate) older_trailer_has_encrypt: bool,
}

impl Index {
    /// The entry for object number `id`.
    pub(crate) fn get(&self, id: u32) -> Option<&XrefEntry> {
        self.entries
            .binary_search_by_key(&id, |(number, _)| *number)
            .ok()
            .map(|at| &self.entries[at].1)
    }
}

fn fallback(reason: StripFallback) -> Error {
    Error::NeedsWholeDocument(reason)
}

/// Reads the merged cross-reference data of `source`: the header, `startxref`, then each section
/// back along `/Prev`, completing a hybrid section with its `/XRefStm` stream first.
pub(crate) fn read_index<R: Read + Seek>(source: &mut Source<R>, caps: &Caps) -> Result<Index> {
    let head = source.window(0, HEADER_SEARCH)?;
    let base = head
        .windows(5)
        .position(|window| window == b"%PDF-")
        .ok_or(fallback(StripFallback::NoHeader))? as u64;
    drop(head);

    let tail_len = source.len().min(TAIL as u64);
    let tail = source.window(source.len() - tail_len, TAIL)?;
    let start = Reader::get_xref_start(&tail).map_err(|_| fallback(StripFallback::XrefUnresolvable))? as u64;
    drop(tail);

    let mut decoded = 0;
    let (mut xref, mut trailer) = read_complete_section(source, base, start, caps, &mut decoded)?;
    let newest_has_encrypt = trailer.has(b"Encrypt");
    let mut older_trailer_has_encrypt = false;

    let mut seen = HashSet::from([start]);
    let mut prev = trailer.remove(b"Prev");
    while let Some(offset) = prev.and_then(|offset| offset.as_i64().ok()) {
        let offset = u64::try_from(offset).map_err(|_| fallback(StripFallback::XrefUnresolvable))?;
        if !seen.insert(offset) {
            break;
        }

        let (section, mut section_trailer) = read_complete_section(source, base, offset, caps, &mut decoded)?;
        older_trailer_has_encrypt |= section_trailer.has(b"Encrypt") && !newest_has_encrypt;
        xref.merge(section);
        check_count(&xref, caps)?;
        prev = section_trailer.remove(b"Prev");
    }

    Ok(Index {
        base,
        entries: xref.entries.into_iter().collect(),
        trailer,
        older_trailer_has_encrypt,
    })
}

/// One section, completed with the `/XRefStm` stream its trailer names, if any. Only within a
/// section may a stream entry replace a free table entry.
fn read_complete_section<R: Read + Seek>(
    source: &mut Source<R>, base: u64, offset: u64, caps: &Caps, decoded: &mut usize,
) -> Result<(Xref, Dictionary)> {
    let (mut xref, mut trailer) = read_section(source, base, offset, caps, decoded)?;

    if let Some(stream_offset) = trailer.remove(b"XRefStm") {
        let stream_offset = stream_offset
            .as_i64()
            .ok()
            .and_then(|offset| u64::try_from(offset).ok())
            .ok_or(fallback(StripFallback::XrefUnresolvable))?;
        let (stream_xref, _) = read_section(source, base, stream_offset, caps, decoded)?;
        xref.merge_hybrid(stream_xref);
    }

    check_count(&xref, caps)?;
    Ok((xref, trailer))
}

/// One cross-reference section at `offset`: a table and its trailer, or a cross-reference stream.
/// The window doubles until the section parses, the cap is reached or the file ends.
fn read_section<R: Read + Seek>(
    source: &mut Source<R>, base: u64, offset: u64, caps: &Caps, decoded: &mut usize,
) -> Result<(Xref, Dictionary)> {
    let at = base
        .checked_add(offset)
        .filter(|&at| at < source.len())
        .ok_or(fallback(StripFallback::XrefUnresolvable))?;

    let mut size = FIRST_SECTION_WINDOW.min(caps.max_section);
    loop {
        let window = source.window(at, size)?;
        let reaches_end = window.len() as u64 == source.len() - at;

        // The section's own reader, over just this window, applies the decompression caps to a
        // cross-reference stream; the total carries over from the sections before.
        let options = LoadOptions {
            max_decompressed_size: Some(caps.max_decoded),
            max_total_decompressed_size: Some(caps.max_total_decoded.saturating_sub(*decoded)),
            ..Default::default()
        };
        let reader = Reader::with_options(&window, options);

        match parser::xref_and_trailer(&window, &reader) {
            Ok(section) => {
                *decoded += reader.decompressed_total();
                return Ok(section);
            }
            Err(e @ Error::Decompress(DecompressError::MemoryLimitExceeded { .. })) => return Err(e),
            // The section may run past the window: try a longer one.
            Err(_) if !reaches_end && size < caps.max_section => size = size.saturating_mul(2).min(caps.max_section),
            Err(_) => return Err(fallback(StripFallback::XrefUnresolvable)),
        }
    }
}

fn check_count(xref: &Xref, caps: &Caps) -> Result<()> {
    if xref.entries.len() > caps.max_objects {
        return Err(fallback(StripFallback::TooManyObjects));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{Index, read_index};
    use crate::strip::source::Source;
    use crate::strip::{Caps, StripFallback};
    use crate::{Document, Error};
    use std::io::Cursor;

    fn index(bytes: &[u8], caps: &Caps) -> crate::Result<Index> {
        read_index(&mut Source::new(Cursor::new(bytes.to_vec())).unwrap(), caps)
    }

    /// The index as `Reader` builds it for the same bytes.
    fn reader_entries(bytes: &[u8]) -> String {
        let doc = Document::load_mem(bytes).unwrap();
        format!("{:?}", doc.reference_table.entries.iter().collect::<Vec<_>>())
    }

    fn index_entries(index: &Index) -> String {
        format!(
            "{:?}",
            index.entries.iter().map(|(id, entry)| (id, entry)).collect::<Vec<_>>()
        )
    }

    /// A file whose only cross-reference data is a Flate-compressed cross-reference stream of
    /// `entries` entries, most of them free, so it decompresses to 5 bytes an entry.
    fn compressed_xref_stream_file(entries: usize) -> Vec<u8> {
        use flate2::{Compression, write::ZlibEncoder};
        use std::io::Write as _;

        let mut pdf = b"%PDF-1.5
"
        .to_vec();
        let catalog = pdf.len();
        pdf.extend_from_slice(
            b"1 0 obj
<< /Type /Catalog >>
endobj
",
        );
        let xref = pdf.len();
        let mut body = Vec::new();
        for id in 0..entries {
            let (kind, offset) = match id {
                1 => (1u8, catalog as u32),
                2 => (1, xref as u32),
                _ => (0, 0),
            };
            body.push(kind);
            body.extend_from_slice(&offset.to_be_bytes()[1..]);
            body.push(0);
        }
        let mut encoder = ZlibEncoder::new(Vec::new(), Compression::default());
        encoder.write_all(&body).unwrap();
        let compressed = encoder.finish().unwrap();
        pdf.extend_from_slice(
            format!(
                "2 0 obj
<< /Type /XRef /Size {entries} /W [1 3 1] /Root 1 0 R /Filter /FlateDecode /Length {} >>
stream
",
                compressed.len()
            )
            .as_bytes(),
        );
        pdf.extend_from_slice(&compressed);
        pdf.extend_from_slice(
            format!(
                "
endstream
endobj
startxref
{xref}
%%EOF"
            )
            .as_bytes(),
        );
        pdf
    }

    #[test]
    fn the_index_matches_the_readers_table_on_every_fixture() {
        let mut checked = 0;
        for directory in ["assets", "tests/fixtures/crypt"] {
            for entry in std::fs::read_dir(directory).unwrap() {
                let path = entry.unwrap().path();
                if path.extension().is_none_or(|extension| extension != "pdf") {
                    continue;
                }
                let bytes = std::fs::read(&path).unwrap();
                let index = index(&bytes, &Caps::default()).unwrap_or_else(|e| panic!("{path:?}: {e}"));
                assert_eq!(index_entries(&index), reader_entries(&bytes), "{path:?}");
                checked += 1;
            }
        }
        assert!(checked >= 9, "only {checked} fixtures found");
    }

    #[test]
    fn a_compressed_cross_reference_stream_is_read() {
        let mut doc = Document::load_mem(&std::fs::read("assets/example.pdf").unwrap()).unwrap();
        let mut bytes = Vec::new();
        doc.save_modern(&mut bytes).unwrap();
        assert!(
            Document::load_mem(&bytes)
                .unwrap()
                .reference_table
                .entries
                .values()
                .any(|e| e.is_compressed())
        );

        let index = index(&bytes, &Caps::default()).unwrap();
        assert_eq!(index_entries(&index), reader_entries(&bytes));
        assert!(index.trailer.has(b"Root"));
        assert!(!index.trailer.has(b"Prev"));
    }

    #[test]
    fn offsets_count_from_the_header() {
        let mut bytes = b"junk before the header\n".to_vec();
        bytes.extend_from_slice(&std::fs::read("assets/example.pdf").unwrap());
        let index = index(&bytes, &Caps::default()).unwrap();
        assert_eq!(index.base, 23);
        assert_eq!(index_entries(&index), reader_entries(&bytes));
    }

    #[test]
    fn a_file_without_a_header_or_startxref_needs_the_whole_document_path() {
        assert!(matches!(
            index(b"not a pdf at all", &Caps::default()),
            Err(Error::NeedsWholeDocument(StripFallback::NoHeader))
        ));

        let mut bytes = std::fs::read("assets/example.pdf").unwrap();
        let at = bytes.windows(9).rposition(|window| window == b"startxref").unwrap();
        bytes.truncate(at);
        assert!(matches!(
            index(&bytes, &Caps::default()),
            Err(Error::NeedsWholeDocument(StripFallback::XrefUnresolvable))
        ));
    }

    #[test]
    fn a_section_longer_than_the_first_window_is_read() {
        // About 6,000 table entries: 120 KiB, past the first 64 KiB window.
        let mut doc = Document::with_version("1.4");
        let pages_id = doc
            .add_object(crate::dictionary! { "Type" => "Pages", "Kids" => Vec::<crate::Object>::new(), "Count" => 0 });
        let catalog_id = doc.add_object(crate::dictionary! { "Type" => "Catalog", "Pages" => pages_id });
        doc.trailer.set("Root", catalog_id);
        for number in 0..6000 {
            doc.add_object(crate::Object::Integer(number));
        }
        doc.reference_table.cross_reference_type = crate::xref::XrefType::CrossReferenceTable;
        let mut bytes = Vec::new();
        doc.save_to(&mut bytes).unwrap();

        let index = index(&bytes, &Caps::default()).unwrap();
        assert_eq!(index_entries(&index), reader_entries(&bytes));

        // A cap below the section's size sends the file to the whole-document path.
        let small = Caps {
            max_section: 64 * 1024,
            ..Caps::default()
        };
        assert!(matches!(
            super::read_index(&mut Source::new(Cursor::new(bytes.clone())).unwrap(), &small),
            Err(Error::NeedsWholeDocument(StripFallback::XrefUnresolvable))
        ));

        let few = Caps {
            max_objects: 100,
            ..Caps::default()
        };
        assert!(matches!(
            super::read_index(&mut Source::new(Cursor::new(bytes)).unwrap(), &few),
            Err(Error::NeedsWholeDocument(StripFallback::TooManyObjects))
        ));
    }

    #[test]
    fn a_cross_reference_stream_past_the_decompression_cap_is_refused() {
        let bytes = compressed_xref_stream_file(1000);
        let read = index(&bytes, &Caps::default()).unwrap();
        assert_eq!(index_entries(&read), reader_entries(&bytes));

        let tiny = Caps {
            max_decoded: 8,
            ..Caps::default()
        };
        let result = index(&bytes, &tiny);
        assert!(
            matches!(
                result,
                Err(Error::Decompress(crate::DecompressError::MemoryLimitExceeded { .. }))
            ),
            "{:?}",
            result.err()
        );
    }

    #[cfg(not(feature = "async"))]
    #[test]
    fn hybrid_sections_and_freed_objects_follow_the_reader() {
        let (hybrid, prev) = crate::reader::hybrid_reference_file();
        let index = index(&hybrid, &Caps::default()).unwrap();
        assert_eq!(index_entries(&index), reader_entries(&hybrid));
        assert!(index.get(3).is_some_and(|entry| entry.is_compressed()));

        let freed = crate::reader::free_object_3_with_table(hybrid, prev);
        let index = super::read_index(&mut Source::new(Cursor::new(freed.clone())).unwrap(), &Caps::default()).unwrap();
        assert_eq!(index_entries(&index), reader_entries(&freed));
        assert!(
            index
                .get(3)
                .is_some_and(|entry| !entry.is_normal() && !entry.is_compressed())
        );

        let (classic, prev) = crate::reader::classic_file_with_object_3();
        let freed = crate::reader::free_object_3_with_table(classic, prev);
        let index = super::read_index(&mut Source::new(Cursor::new(freed.clone())).unwrap(), &Caps::default()).unwrap();
        assert_eq!(index_entries(&index), reader_entries(&freed));
        assert!(index.get(3).is_some_and(|entry| !entry.is_normal()));
    }

    #[test]
    fn an_older_trailer_with_encrypt_is_noticed() {
        // An update whose trailer leaves out /Encrypt, on top of an encrypted file.
        let mut bytes = std::fs::read("tests/fixtures/crypt/identity-stmf.pdf").unwrap();
        let prev = crate::Reader::get_xref_start(&bytes).unwrap();
        let root = Document::load_mem(&bytes)
            .unwrap()
            .trailer
            .get(b"Root")
            .unwrap()
            .as_reference()
            .unwrap();
        let xref_pos = bytes.len();
        bytes.extend_from_slice(
            format!(
                "xref\n0 0\ntrailer\n<< /Size 1 /Root {} {} R /Prev {prev} >>\nstartxref\n{xref_pos}\n%%EOF\n",
                root.0, root.1
            )
            .as_bytes(),
        );

        let index = index(&bytes, &Caps::default()).unwrap();
        assert!(index.older_trailer_has_encrypt);
        assert!(!index.trailer.has(b"Encrypt"));
    }
}
