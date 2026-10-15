//! The streaming Strip against the whole-document path: for the same bytes, the stripped file holds
//! the objects a password load gives, and a failure is the same error.

use lopdf::encryption::crypt_filters::{Aes128CryptFilter, Aes256CryptFilter, CryptFilter};
use lopdf::strip::{StripFallback, StripOptions, strip};
use lopdf::{
    Document, EncryptionState, EncryptionVersion, Error, LoadOptions, Object, ObjectId, Permissions, Stream, dictionary,
};
use std::collections::BTreeMap;
use std::io::Cursor;
use std::sync::Arc;

fn stripped(bytes: &[u8], password: &str) -> lopdf::Result<Vec<u8>> {
    let mut output = Vec::new();
    strip(Cursor::new(bytes), &mut output, &StripOptions::with_password(password))?;
    Ok(output)
}

fn whole(bytes: &[u8], password: &str) -> lopdf::Result<Document> {
    Document::load_mem_with_options(bytes, LoadOptions::with_password(password))
}

/// The objects of a linearized `doc` that describe its layout, which a Strip drops: the
/// linearization dictionary and the hint streams at the offsets its `/H` gives.
fn layout_objects(doc: &Document) -> Vec<ObjectId> {
    let Some((&id, linearized)) = doc
        .objects
        .iter()
        .find(|(_, object)| object.as_dict().is_ok_and(|dict| dict.has(b"Linearized")))
    else {
        return Vec::new();
    };
    let hints: Vec<i64> = linearized
        .as_dict()
        .unwrap()
        .get(b"H")
        .and_then(Object::as_array)
        .map(|hints| {
            hints
                .iter()
                .step_by(2)
                .filter_map(|offset| offset.as_i64().ok())
                .collect()
        })
        .unwrap_or_default();
    let mut ids = vec![id];
    for (&number, entry) in &doc.reference_table.entries {
        if let lopdf::xref::XrefEntry::Normal { offset, generation } = entry
            && hints.contains(&i64::from(*offset))
        {
            ids.push((number, *generation));
        }
    }
    ids
}

/// Each object a Strip keeps, as text: a stream's content too, which `Debug` leaves out.
fn objects(doc: &Document) -> BTreeMap<ObjectId, String> {
    let layout = layout_objects(doc);
    doc.objects
        .iter()
        .filter(|(id, object)| object.type_name().ok() != Some(b"XRef") && !layout.contains(id))
        .map(|(id, object)| {
            let text = match object {
                Object::Stream(stream) => format!("{:?} {:?}", stream.dict, stream.content),
                other => format!("{other:?}"),
            };
            (*id, text)
        })
        .collect()
}

/// Strips `bytes` and checks the result against a password load of the same bytes.
fn assert_matches_whole(bytes: &[u8], password: &str) -> Vec<u8> {
    let expected = whole(bytes, password).unwrap();
    let output = stripped(bytes, password).unwrap();
    // Strictly: a lenient load would repair a wrong /Length on its own.
    let strict = LoadOptions {
        strict: true,
        ..Default::default()
    };
    let actual = Document::load_mem_with_options(&output, strict).unwrap();
    assert!(!objects(&actual).is_empty());

    assert!(!actual.trailer.has(b"Encrypt"), "the output still says it is encrypted");
    assert!(actual.encryption_state.is_none());
    assert_eq!(objects(&actual), objects(&expected));
    for key in [&b"Root"[..], b"Info", b"ID"] {
        assert_eq!(
            format!("{:?}", actual.trailer.get(key).ok()),
            format!("{:?}", expected.trailer.get(key).ok()),
            "trailer {}",
            String::from_utf8_lossy(key)
        );
    }
    output
}

const OWNER: &str = "owner";
const USER: &str = "user";

/// A document with one page whose content stream is `content_len` bytes, a second, compressed
/// stream, and an `/Info` string, with the trailer `/ID` the MD5-based revisions need.
fn document(content_len: usize) -> Document {
    let mut doc = Document::with_version("1.7");
    doc.trailer.set(
        "ID",
        Object::Array(vec![
            Object::string_literal(b"0123456789abcdef"),
            Object::string_literal(b"fedcba9876543210"),
        ]),
    );
    let pages_id = doc.new_object_id();
    let content: Vec<u8> = (0..content_len).map(|i| b"BT (stream) Tj ET\n"[i % 18]).collect();
    let contents_id = doc.add_object(Stream::new(dictionary! {}, content));
    let mut compressed = Stream::new(dictionary! {}, b"a compressible run, ".repeat(500));
    compressed.compress().unwrap();
    let compressed_id = doc.add_object(compressed);
    let page_id = doc.add_object(dictionary! {
        "Type" => "Page",
        "Parent" => pages_id,
        "MediaBox" => vec![0.into(), 0.into(), 612.into(), 792.into()],
        "Contents" => contents_id,
        "Thumb" => compressed_id,
    });
    doc.objects.insert(
        pages_id,
        Object::Dictionary(dictionary! { "Type" => "Pages", "Kids" => vec![page_id.into()], "Count" => 1 }),
    );
    let catalog_id = doc.add_object(dictionary! { "Type" => "Catalog", "Pages" => pages_id });
    let info_id = doc.add_object(dictionary! { "Title" => Object::string_literal("A title (with parentheses)") });
    doc.trailer.set("Root", catalog_id);
    doc.trailer.set("Info", info_id);
    doc
}

fn encrypted(doc: Document, version: &str) -> Vec<u8> {
    save(encrypted_document(doc, version))
}

fn save(mut doc: Document) -> Vec<u8> {
    let mut bytes = Vec::new();
    doc.save_to(&mut bytes).unwrap();
    bytes
}

/// `doc` encrypted in memory, before it is saved. A load without the password keeps only the
/// encryption dictionary, so a test that changes an encrypted file changes it here.
fn encrypted_document(mut doc: Document, version: &str) -> Document {
    let state = match version {
        "RC4" => EncryptionState::try_from(EncryptionVersion::V2 {
            document: &doc,
            owner_password: OWNER,
            user_password: USER,
            key_length: 128,
            permissions: Permissions::all(),
        }),
        "AES-128" => {
            let aes: Arc<dyn CryptFilter> = Arc::new(Aes128CryptFilter);
            EncryptionState::try_from(EncryptionVersion::V4 {
                document: &doc,
                encrypt_metadata: true,
                crypt_filters: BTreeMap::from([(b"StdCF".to_vec(), aes)]),
                stream_filter: b"StdCF".to_vec(),
                string_filter: b"StdCF".to_vec(),
                owner_password: OWNER,
                user_password: USER,
                permissions: Permissions::all(),
            })
        }
        _ => {
            let aes: Arc<dyn CryptFilter> = Arc::new(Aes256CryptFilter);
            EncryptionState::try_from(EncryptionVersion::V5 {
                encrypt_metadata: true,
                crypt_filters: BTreeMap::from([(b"StdCF".to_vec(), aes)]),
                file_encryption_key: &[7; 32],
                stream_filter: b"StdCF".to_vec(),
                string_filter: b"StdCF".to_vec(),
                owner_password: OWNER,
                user_password: USER,
                permissions: Permissions::all(),
            })
        }
    }
    .unwrap();
    doc.encrypt(&state).unwrap();
    doc
}

#[test]
fn every_revision_strips_to_what_a_password_load_gives() {
    // Larger than the 64 KiB chunk, and not a whole number of chunks or AES blocks.
    for version in ["RC4", "AES-128", "AES-256"] {
        let bytes = encrypted(document(150_001), version);
        for password in [USER, OWNER] {
            let output = assert_matches_whole(&bytes, password);
            assert!(!output.windows(9).any(|window| window == b"/Encrypt "), "{version}");
        }
    }
}

#[test]
fn the_committed_fixtures_strip_to_what_a_password_load_gives() {
    for name in ["identity-stmf.pdf", "stream-dict-string.pdf"] {
        let bytes = std::fs::read(format!("tests/fixtures/crypt/{name}")).unwrap();
        assert_matches_whole(&bytes, USER);
    }
}

#[test]
fn a_signed_real_world_form_strips_to_what_a_load_gives() {
    // Opens with the empty password, and holds a usage-rights signature whose /Contents is not
    // encrypted.
    let bytes = std::fs::read("assets/encrypted.pdf").unwrap();
    assert_matches_whole(&bytes, "");
}

/// The discriminant of a result's error, for comparing two failures.
fn error_kind(result: &lopdf::Result<impl Sized>) -> String {
    match result {
        Ok(_) => "Ok".to_string(),
        Err(Error::Decryption(inner)) => format!("Decryption({inner:?})"),
        Err(error) => format!("{:?}", std::mem::discriminant(error)),
    }
}

#[test]
fn failures_are_the_errors_a_whole_document_load_gives() {
    let undecryptable = std::fs::read("tests/fixtures/crypt/undecryptable-string.pdf").unwrap();
    let identity = std::fs::read("tests/fixtures/crypt/identity-stmf.pdf").unwrap();
    for (what, bytes, password) in [
        ("a string that fails to decrypt", &undecryptable, USER),
        ("a wrong password", &identity, "wrong"),
    ] {
        let expected = error_kind(&whole(bytes, password));
        assert_ne!(expected, "Ok", "{what}");
        assert_eq!(error_kind(&stripped(bytes, password)), expected, "{what}");
    }
    assert!(matches!(stripped(&identity, "wrong"), Err(Error::InvalidPassword)));
}

#[test]
fn an_unencrypted_file_is_refused() {
    let mut bytes = Vec::new();
    document(10).save_to(&mut bytes).unwrap();
    assert!(matches!(stripped(&bytes, ""), Err(Error::NotEncrypted)));
}

#[test]
fn a_wrong_stream_length_needs_the_whole_document_path() {
    let bytes = encrypted(document(1000), "RC4");
    // RC4 keeps the length, so the content stream's /Length is 1000; make it 999.
    let at = bytes.windows(13).position(|window| window == b"/Length 1000>").unwrap();
    let mut damaged = bytes.clone();
    damaged[at..at + 13].copy_from_slice(b"/Length  999>");

    assert!(matches!(
        stripped(&damaged, USER),
        Err(Error::NeedsWholeDocument(StripFallback::LengthMismatch))
    ));
}

#[test]
fn the_linearization_dictionary_and_its_hint_streams_are_dropped() {
    let bytes = std::fs::read("assets/encrypted.pdf").unwrap();
    let original = whole(&bytes, "").unwrap();
    let layout = layout_objects(&original);
    assert_eq!(layout.len(), 2, "the form is linearized with one hint stream");

    let output = stripped(&bytes, "").unwrap();
    let actual = Document::load_mem(&output).unwrap();
    for id in layout {
        assert!(!actual.objects.contains_key(&id), "{id:?} was copied");
    }
    assert!(!output.windows(11).any(|window| window == b"/Linearized"));
}

#[test]
fn a_streams_crypt_filter_is_taken_out_with_its_parameters() {
    let mut doc = document(10);
    let plaintext = b"compressed after its own crypt filter, ".repeat(50);
    let mut stream = Stream::new(dictionary! {}, plaintext.clone());
    stream.compress().unwrap();
    stream.dict.set(
        "Filter",
        vec![Object::Name(b"Crypt".to_vec()), Object::Name(b"FlateDecode".to_vec())],
    );
    stream.dict.set(
        "DecodeParms",
        vec![Object::Dictionary(dictionary! { "Name" => "StdCF" }), Object::Null],
    );
    let id = doc.add_object(stream);
    let bytes = encrypted(doc, "AES-128");

    let output = stripped(&bytes, USER).unwrap();
    let strict = LoadOptions {
        strict: true,
        ..Default::default()
    };
    let actual = Document::load_mem_with_options(&output, strict).unwrap();
    let stream = actual.get_object(id).unwrap().as_stream().unwrap();
    assert_eq!(format!("{:?}", stream.dict.get(b"Filter").unwrap()), "[/FlateDecode]");
    assert_eq!(format!("{:?}", stream.dict.get(b"DecodeParms").unwrap()), "[Null]");
    assert_eq!(stream.decompressed_content().unwrap(), plaintext);
}

#[test]
fn an_embedded_file_filter_other_than_the_stream_filter_needs_the_whole_document_path() {
    let mut doc = encrypted_document(document(10), "AES-128");
    let encrypt = doc.trailer.get(b"Encrypt").unwrap().as_reference().unwrap();
    doc.get_dictionary_mut(encrypt)
        .unwrap()
        .set("EFF", Object::Name(b"Identity".to_vec()));
    let bytes = save(doc);

    assert!(matches!(
        stripped(&bytes, USER),
        Err(Error::NeedsWholeDocument(StripFallback::EmbeddedFileFilter))
    ));
}

#[test]
fn a_direct_encryption_dictionary_in_the_trailer_is_read() {
    let doc = encrypted_document(document(1000), "RC4");
    let expected = whole(&save(doc.clone()), USER).unwrap();

    let mut doc = doc;
    let encrypt = doc.trailer.get(b"Encrypt").unwrap().as_reference().unwrap();
    let dict = doc.objects.remove(&encrypt).unwrap();
    doc.trailer.set("Encrypt", dict);
    let direct = save(doc);

    let output = stripped(&direct, USER).unwrap();
    let actual = Document::load_mem(&output).unwrap();
    assert!(!objects(&actual).is_empty());
    assert_eq!(objects(&actual), objects(&expected));
}

#[test]
fn an_update_that_drops_encrypt_needs_the_whole_document_path() {
    let mut bytes = std::fs::read("tests/fixtures/crypt/identity-stmf.pdf").unwrap();
    let tail = &bytes[bytes.len() - 64..];
    let at = tail.windows(9).rposition(|window| window == b"startxref").unwrap();
    let prev: usize = std::str::from_utf8(&tail[at + 9..])
        .unwrap()
        .split_whitespace()
        .next()
        .unwrap()
        .parse()
        .unwrap();
    let xref_pos = bytes.len();
    bytes.extend_from_slice(
        format!("xref\n0 0\ntrailer\n<< /Size 1 /Root 4 0 R /Prev {prev} >>\nstartxref\n{xref_pos}\n%%EOF\n")
            .as_bytes(),
    );

    assert!(matches!(
        stripped(&bytes, USER),
        Err(Error::NeedsWholeDocument(StripFallback::InconsistentEncrypt))
    ));
}
