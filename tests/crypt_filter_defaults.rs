//! Crypt filter selection (ISO 32000-1, 7.6.5 and 7.4.10): from `V4` on, `/Identity` is a
//! predefined filter that leaves data as is, and it is the default when `/StmF`, `/StrF` or a
//! stream's own `/Crypt` name is absent. Any other name must be an entry in `/CF`.
//!
//! Each test checks the saved bytes, not only a round trip: encryption and decryption share one
//! filter lookup, so a wrong filter round-trips cleanly and shows only in the file.

use lopdf::encryption::crypt_filters::{Aes128CryptFilter, CryptFilter};
use lopdf::{
    Document, EncryptionState, EncryptionVersion, LoadOptions, Object, ObjectId, Permissions, Stream, dictionary,
};
use std::collections::BTreeMap;
use std::sync::Arc;

const USER_PASSWORD: &str = "user";
const OWNER_PASSWORD: &str = "owner";
const PAGE_TEXT: &str = "Identity filtered page";

/// A one-page document with the trailer `/ID` that the MD5-based revisions need.
fn document() -> Document {
    let mut doc = Document::with_version("1.5");
    doc.trailer.set(
        "ID",
        Object::Array(vec![
            Object::string_literal(b"0123456789abcdef"),
            Object::string_literal(b"fedcba9876543210"),
        ]),
    );

    let pages_id = doc.new_object_id();
    let font_id = doc.add_object(dictionary! {
        "Type" => "Font",
        "Subtype" => "Type1",
        "BaseFont" => "Helvetica",
    });
    let content = format!("BT\n/F1 12 Tf\n100 700 Td\n({PAGE_TEXT}) Tj\nET\n");
    let contents_id = doc.add_object(Stream::new(dictionary! {}, content.into_bytes()));
    let page_id = doc.add_object(dictionary! {
        "Type" => "Page",
        "Parent" => pages_id,
        "MediaBox" => vec![0.into(), 0.into(), 612.into(), 792.into()],
        "Resources" => dictionary! { "Font" => dictionary! { "F1" => font_id } },
        "Contents" => contents_id,
    });
    doc.objects.insert(
        pages_id,
        Object::Dictionary(dictionary! {
            "Type" => "Pages",
            "Kids" => vec![page_id.into()],
            "Count" => 1,
        }),
    );
    let catalog_id = doc.add_object(dictionary! {
        "Type" => "Catalog",
        "Pages" => pages_id,
    });
    doc.trailer.set("Root", catalog_id);
    doc
}

/// A `V4` state whose `/CF` holds one AES-128 filter, `/StdCF`.
fn v4_state(doc: &Document, stream_filter: &[u8], string_filter: &[u8]) -> Result<EncryptionState, lopdf::Error> {
    let aes: Arc<dyn CryptFilter> = Arc::new(Aes128CryptFilter);
    EncryptionState::try_from(EncryptionVersion::V4 {
        document: doc,
        encrypt_metadata: true,
        crypt_filters: BTreeMap::from([(b"StdCF".to_vec(), aes)]),
        stream_filter: stream_filter.to_vec(),
        string_filter: string_filter.to_vec(),
        owner_password: OWNER_PASSWORD,
        user_password: USER_PASSWORD,
        permissions: Permissions::all(),
    })
}

fn save(doc: &mut Document) -> Vec<u8> {
    let mut buffer = Vec::new();
    doc.save_to(&mut buffer).unwrap();
    buffer
}

fn load(buffer: &[u8]) -> lopdf::Result<Document> {
    Document::load_mem_with_options(buffer, LoadOptions::with_password(USER_PASSWORD))
}

fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    haystack.windows(needle.len()).any(|window| window == needle)
}

fn page_text(doc: &Document) -> String {
    doc.extract_text(&[1]).unwrap()
}

/// The id of the `/Encrypt` dictionary of an encrypted `doc`.
fn encrypt_dictionary_id(doc: &Document) -> ObjectId {
    doc.trailer.get(b"Encrypt").unwrap().as_reference().unwrap()
}

/// A document whose streams use `/Identity` and whose strings use AES-128.
fn identity_streams_document() -> Vec<u8> {
    let mut doc = document();
    let state = v4_state(&doc, b"Identity", b"StdCF").unwrap();
    doc.encrypt(&state).unwrap();
    save(&mut doc)
}

#[test]
fn identity_stream_filter_leaves_streams_as_is() {
    let buffer = identity_streams_document();

    // The content stream is stored as is, not run through RC4.
    assert!(contains(&buffer, PAGE_TEXT.as_bytes()));
    assert!(page_text(&load(&buffer).unwrap()).contains(PAGE_TEXT));
}

#[test]
fn identity_stream_filter_fixture_decrypts() {
    // The same shape as `identity_streams_document`, committed so that other projects can test
    // against these exact bytes.
    let buffer = include_bytes!("fixtures/crypt/identity-stmf.pdf");

    assert!(contains(buffer, PAGE_TEXT.as_bytes()));
    assert!(page_text(&load(buffer).unwrap()).contains(PAGE_TEXT));
}

#[test]
fn absent_stream_filter_means_identity() {
    // Blank `/StmF /Identity` out of the fixture's bytes, which leaves every offset in place. The
    // streams in the file are stored as is, so they read back only if the absent name is Identity.
    let mut buffer = include_bytes!("fixtures/crypt/identity-stmf.pdf").to_vec();
    let entry = b"/StmF/Identity";
    let start = buffer.windows(entry.len()).position(|window| window == entry).unwrap();
    buffer[start..start + entry.len()].fill(b' ');

    assert!(page_text(&load(&buffer).unwrap()).contains(PAGE_TEXT));
}

#[test]
fn unknown_stream_filter_name_is_refused() {
    let mut doc = document();
    assert!(matches!(
        v4_state(&doc, b"NoSuchFilter", b"StdCF"),
        Err(lopdf::Error::Decryption(
            lopdf::encryption::DecryptionError::UnknownCryptFilter
        ))
    ));

    // A file that names one is refused rather than decrypted with RC4.
    let state = v4_state(&doc, b"StdCF", b"StdCF").unwrap();
    doc.encrypt(&state).unwrap();
    let encrypt_id = encrypt_dictionary_id(&doc);
    doc.get_dictionary_mut(encrypt_id)
        .unwrap()
        .set("StmF", Object::Name(b"NoSuchFilter".to_vec()));
    let buffer = save(&mut doc);

    let result = load(&buffer);
    assert!(
        matches!(
            result,
            Err(lopdf::Error::Decryption(
                lopdf::encryption::DecryptionError::UnknownCryptFilter
            ))
        ),
        "got {result:?}"
    );
}

/// Adds a stream whose own `/Crypt` filter is set by `dict`, encrypts the document with
/// `/StdCF` as the default, and returns the saved bytes and the stream's id.
fn document_with_crypt_stream(dict: lopdf::Dictionary, content: &[u8]) -> (Vec<u8>, ObjectId) {
    let mut doc = document();
    let stream_id = doc.add_object(Stream::new(dict, content.to_vec()));
    let state = v4_state(&doc, b"StdCF", b"StdCF").unwrap();
    doc.encrypt(&state).unwrap();
    (save(&mut doc), stream_id)
}

#[test]
fn crypt_filter_without_decode_parms_is_identity() {
    let content = b"crypt filter without parameters";
    let (buffer, stream_id) = document_with_crypt_stream(dictionary! { "Filter" => "Crypt" }, content);

    assert!(contains(&buffer, content));
    let doc = load(&buffer).unwrap();
    assert_eq!(doc.get_object(stream_id).unwrap().as_stream().unwrap().content, content);
}

#[test]
fn crypt_filter_parameters_in_an_array_are_found() {
    // `/StdCF` rather than `/Identity`, so that missing the array would show: the default for a
    // `/Crypt` filter without parameters is Identity.
    let content = b"crypt filter parameters in an array";
    let (buffer, stream_id) = document_with_crypt_stream(
        dictionary! {
            "Filter" => vec![Object::Name(b"Crypt".to_vec())],
            "DecodeParms" => vec![Object::Dictionary(dictionary! {
                "Type" => "CryptFilterDecodeParms",
                "Name" => "StdCF",
            })],
        },
        content,
    );

    assert!(!contains(&buffer, content), "a /StdCF stream is encrypted");
    let doc = load(&buffer).unwrap();
    assert_eq!(doc.get_object(stream_id).unwrap().as_stream().unwrap().content, content);
}

#[test]
fn crypt_filter_naming_a_cf_entry_uses_it() {
    let content = b"crypt filter naming StdCF";
    let (buffer, stream_id) = document_with_crypt_stream(
        dictionary! {
            "Filter" => "Crypt",
            "DecodeParms" => dictionary! { "Name" => "StdCF" },
        },
        content,
    );

    assert!(!contains(&buffer, content), "a /StdCF stream is encrypted");
    let doc = load(&buffer).unwrap();
    assert_eq!(doc.get_object(stream_id).unwrap().as_stream().unwrap().content, content);
}

/// Rewrites the committed fixtures: `cargo test --test crypt_filter_defaults -- --ignored`.
#[test]
#[ignore = "rewrites committed fixtures"]
fn regenerate_fixtures() {
    let directory = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/crypt");
    std::fs::create_dir_all(&directory).unwrap();
    std::fs::write(directory.join("identity-stmf.pdf"), identity_streams_document()).unwrap();
}
