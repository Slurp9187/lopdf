//! Strings in a stream's dictionary are encrypted like every other string in the file
//! (ISO 32000-1, 7.6.2). An embedded file's `/Params` is the common case: its `/CheckSum`
//! and `/ModDate` are strings.

use lopdf::encryption::crypt_filters::{Aes256CryptFilter, CryptFilter};
use lopdf::{
    Document, EncryptionState, EncryptionVersion, LoadOptions, Object, ObjectId, Permissions, Stream, dictionary,
};
use std::collections::BTreeMap;
use std::sync::Arc;

const USER_PASSWORD: &str = "user";
const OWNER_PASSWORD: &str = "owner";
const MOD_DATE: &[u8] = b"D:20261015120000Z";
const CHECKSUM: &[u8] = b"0123456789ABCDEF";
const FILE_CONTENT: &[u8] = b"embedded file content";

/// The embedded file's id in every document built here.
const EMBEDDED_FILE_ID: ObjectId = (3, 0);

/// An AES-256 (`V5`, `R6`) document holding one embedded file stream with string `/Params`.
fn encrypted_document() -> Vec<u8> {
    let mut doc = Document::with_version("2.0");
    let pages_id = doc.add_object(dictionary! {
        "Type" => "Pages",
        "Kids" => Vec::<Object>::new(),
        "Count" => 0,
    });
    let catalog_id = doc.add_object(dictionary! {
        "Type" => "Catalog",
        "Pages" => pages_id,
    });
    let embedded_file_id = doc.add_object(Stream::new(
        dictionary! {
            "Type" => "EmbeddedFile",
            "Params" => dictionary! {
                "ModDate" => Object::string_literal(MOD_DATE),
                "CheckSum" => Object::string_literal(CHECKSUM),
            },
        },
        FILE_CONTENT.to_vec(),
    ));
    assert_eq!(embedded_file_id, EMBEDDED_FILE_ID);
    doc.trailer.set("Root", catalog_id);

    let aes: Arc<dyn CryptFilter> = Arc::new(Aes256CryptFilter);
    let state = EncryptionState::try_from(EncryptionVersion::V5 {
        encrypt_metadata: true,
        crypt_filters: BTreeMap::from([(b"StdCF".to_vec(), aes)]),
        file_encryption_key: &[7u8; 32],
        stream_filter: b"StdCF".to_vec(),
        string_filter: b"StdCF".to_vec(),
        owner_password: OWNER_PASSWORD,
        user_password: USER_PASSWORD,
        permissions: Permissions::all(),
    })
    .unwrap();
    doc.encrypt(&state).unwrap();

    let mut buffer = Vec::new();
    doc.save_to(&mut buffer).unwrap();
    buffer
}

fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    haystack.windows(needle.len()).any(|window| window == needle)
}

/// The embedded file's `/Params` string `key`, after loading `buffer` with the user password.
fn param(buffer: &[u8], key: &[u8]) -> Vec<u8> {
    let doc = Document::load_mem_with_options(buffer, LoadOptions::with_password(USER_PASSWORD)).unwrap();
    let stream = doc.get_object(EMBEDDED_FILE_ID).unwrap().as_stream().unwrap();
    assert_eq!(stream.content, FILE_CONTENT);
    let params = stream.dict.get(b"Params").unwrap().as_dict().unwrap();
    params.get(key).unwrap().as_str().unwrap().to_vec()
}

#[test]
fn stream_dictionary_strings_are_encrypted() {
    let buffer = encrypted_document();

    assert!(!contains(&buffer, MOD_DATE), "/ModDate is stored in the clear");
    assert!(!contains(&buffer, CHECKSUM), "/CheckSum is stored in the clear");
    assert_eq!(param(&buffer, b"ModDate"), MOD_DATE);
    assert_eq!(param(&buffer, b"CheckSum"), CHECKSUM);
}

#[test]
fn stream_dictionary_strings_fixture_decrypts() {
    // The same shape as `encrypted_document`, committed so that other projects can test against
    // these exact bytes.
    let buffer = include_bytes!("fixtures/crypt/stream-dict-string.pdf");

    assert!(!contains(buffer, MOD_DATE));
    assert_eq!(param(buffer, b"ModDate"), MOD_DATE);
    assert_eq!(param(buffer, b"CheckSum"), CHECKSUM);
}

/// Rewrites the committed fixtures: `cargo test --test stream_dict_strings -- --ignored`.
#[test]
#[ignore = "rewrites committed fixtures"]
fn regenerate_fixtures() {
    let directory = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/crypt");
    std::fs::create_dir_all(&directory).unwrap();
    std::fs::write(directory.join("stream-dict-string.pdf"), encrypted_document()).unwrap();
}
