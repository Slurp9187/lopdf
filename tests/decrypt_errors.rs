//! An object that fails to decrypt fails the load, rather than leaving its ciphertext in a
//! document that no longer says it is encrypted.

use lopdf::encryption::DecryptionError;
use lopdf::encryption::crypt_filters::{Aes256CryptFilter, CryptFilter};
use lopdf::{
    Document, EncryptionState, EncryptionVersion, Error, LoadOptions, Object, ObjectId, Permissions, dictionary,
};
use std::collections::BTreeMap;
use std::sync::Arc;

const USER_PASSWORD: &str = "user";
const OWNER_PASSWORD: &str = "owner";

/// The id of the dictionary holding the string that `undecryptable_document` damages.
const INFO_ID: ObjectId = (3, 0);

/// An unencrypted document whose `/Info` dictionary, object 3, is `info`.
fn document_with_info(info: lopdf::Dictionary) -> Document {
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
    let info_id = doc.add_object(info);
    assert_eq!(info_id, INFO_ID);
    doc.trailer.set("Root", catalog_id);
    doc.trailer.set("Info", info_id);
    doc
}

/// Encrypts `doc` with AES-256 (`V5`, `R6`).
fn encrypt(doc: &mut Document) {
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
}

fn save(doc: &mut Document) -> Vec<u8> {
    let mut buffer = Vec::new();
    doc.save_to(&mut buffer).unwrap();
    buffer
}

fn load(buffer: &[u8]) -> lopdf::Result<Document> {
    Document::load_mem_with_options(buffer, LoadOptions::with_password(USER_PASSWORD))
}

/// An AES-256 (`V5`, `R6`) document whose `/Info /Title` is cut to 17 bytes after encryption, as
/// a truncated file would have it. AES ciphertext is always a multiple of 16 bytes.
fn undecryptable_document() -> Vec<u8> {
    let mut doc = document_with_info(dictionary! {
        "Title" => Object::string_literal("A title that is long enough to span blocks"),
    });
    encrypt(&mut doc);

    let Object::String(title, _) = doc.get_dictionary_mut(INFO_ID).unwrap().get_mut(b"Title").unwrap() else {
        unreachable!("the title is a string");
    };
    assert_eq!(title.len() % 16, 0);
    title.truncate(17);

    save(&mut doc)
}

fn assert_refused(buffer: &[u8]) {
    let result = load(buffer);
    assert!(
        matches!(result, Err(Error::Decryption(DecryptionError::InvalidCipherTextLength))),
        "got {result:?}"
    );
}

#[test]
fn an_object_that_fails_to_decrypt_fails_the_load() {
    assert_refused(&undecryptable_document());
}

#[test]
fn undecryptable_fixture_is_refused() {
    // The same shape as `undecryptable_document`, committed so that other projects can test
    // against these exact bytes.
    assert_refused(include_bytes!("fixtures/crypt/undecryptable-string.pdf"));
}

#[test]
fn a_signatures_contents_is_left_unencrypted() {
    // A signature's /Contents covers the file's bytes as written, so it is never encrypted; the
    // dictionary's other strings are. Here the dictionary stands in /Info for simplicity.
    let contents = b"\x30\x82\x01\x00 DER-encoded signature";
    let mod_date = b"D:20261015120000Z";
    let mut doc = document_with_info(dictionary! {
        "Type" => "Sig",
        "ByteRange" => vec![0.into(), 10.into(), 20.into(), 30.into()],
        "Contents" => Object::String(contents.to_vec(), lopdf::StringFormat::Hexadecimal),
        "M" => Object::string_literal(mod_date.to_vec()),
    });
    encrypt(&mut doc);
    let buffer = save(&mut doc);

    let hex: String = contents.iter().map(|byte| format!("{byte:02X}")).collect();
    let contains = |needle: &[u8]| buffer.windows(needle.len()).any(|window| window == needle);
    assert!(contains(hex.as_bytes()), "/Contents was encrypted");
    assert!(!contains(mod_date), "/M was left in the clear");

    let loaded = load(&buffer).unwrap();
    let info = loaded.get_dictionary(INFO_ID).unwrap();
    assert_eq!(info.get(b"Contents").unwrap().as_str().unwrap(), contents);
    assert_eq!(info.get(b"M").unwrap().as_str().unwrap(), mod_date);
}

#[test]
fn a_signed_real_world_file_still_loads() {
    // The catalog of this form holds a usage-rights signature (/Perms /UR3) whose /Contents is not
    // encrypted. Decrypting it anyway failed on its padding.
    let doc = Document::load_mem(&std::fs::read("assets/encrypted.pdf").unwrap()).unwrap();
    let catalog = doc.catalog().unwrap();
    let signature = catalog
        .get(b"Perms")
        .and_then(Object::as_dict)
        .and_then(|perms| perms.get(b"UR3"))
        .and_then(Object::as_dict)
        .unwrap();
    // A DER SEQUENCE, as written.
    assert!(
        signature
            .get(b"Contents")
            .unwrap()
            .as_str()
            .unwrap()
            .starts_with(&[0x30, 0x82])
    );
}

/// Rewrites the committed fixtures: `cargo test --test decrypt_errors -- --ignored`.
#[test]
#[ignore = "rewrites committed fixtures"]
fn regenerate_fixtures() {
    let directory = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/crypt");
    std::fs::create_dir_all(&directory).unwrap();
    std::fs::write(directory.join("undecryptable-string.pdf"), undecryptable_document()).unwrap();
}
