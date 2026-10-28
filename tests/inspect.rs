//! `strip::inspect`: what a file is before a Strip, or for keeping it encrypted as it is.

use lopdf::encryption::crypt_filters::{Aes256CryptFilter, CryptFilter};
use lopdf::strip::{PasswordCheck, SecurityHandler, Signed, StripFallback, UsageRights, inspect};
use lopdf::{Dictionary, Document, EncryptionState, EncryptionVersion, Error, Object, Permissions, dictionary};
use std::collections::BTreeMap;
use std::io::Cursor;
use std::sync::Arc;

fn inspect_bytes(bytes: &[u8], password: Option<&str>) -> lopdf::Result<lopdf::strip::Inspection> {
    inspect(Cursor::new(bytes), password)
}

#[test]
fn the_password_is_checked_against_each_entry() {
    let bytes = std::fs::read("tests/fixtures/crypt/identity-stmf.pdf").unwrap();
    for (password, check) in [
        (Some("user"), PasswordCheck::User),
        (Some("owner"), PasswordCheck::Owner),
        (Some("wrong"), PasswordCheck::Wrong),
        (None, PasswordCheck::NotGiven),
    ] {
        let found = inspect_bytes(&bytes, password).unwrap();
        assert!(found.encrypted);
        assert_eq!(found.password, check, "{password:?}");
        assert_eq!(found.signed, Signed::No);
        assert_eq!(found.needs_whole_document, None);
    }
}

#[test]
fn an_unencrypted_file_is_reported_as_such() {
    let mut bytes = Vec::new();
    with_fields(vec![]).save_to(&mut bytes).unwrap();
    let found = inspect_bytes(&bytes, Some("anything")).unwrap();
    assert!(!found.encrypted);
    assert_eq!(found.password, PasswordCheck::NotGiven);
    assert_eq!(found.signed, Signed::No);
}

/// A document whose `/AcroForm /Fields` holds `fields`, each added as its own object.
fn with_fields(fields: Vec<Dictionary>) -> Document {
    let mut doc = Document::with_version("1.7");
    doc.trailer.set(
        "ID",
        Object::Array(vec![Object::string_literal(b"0123456789abcdef"); 2]),
    );
    let pages_id = doc.add_object(dictionary! { "Type" => "Pages", "Kids" => Vec::<Object>::new(), "Count" => 0 });
    let fields: Vec<Object> = fields.into_iter().map(|field| doc.add_object(field).into()).collect();
    let form_id = doc.add_object(dictionary! { "Fields" => fields });
    let catalog_id = doc.add_object(dictionary! { "Type" => "Catalog", "Pages" => pages_id, "AcroForm" => form_id });
    doc.trailer.set("Root", catalog_id);
    doc
}

fn signed(doc: Document) -> Signed {
    let mut bytes = Vec::new();
    let mut doc = doc;
    doc.save_to(&mut bytes).unwrap();
    inspect_bytes(&bytes, None).unwrap().signed
}

fn signature_value() -> Object {
    Object::Dictionary(dictionary! {
        "Type" => "Sig",
        "ByteRange" => vec![0.into(), 1.into(), 2.into(), 3.into()],
        "Contents" => Object::string_literal(b"signature".to_vec()),
    })
}

#[test]
fn a_signature_field_with_a_value_is_a_signature() {
    let field = dictionary! { "FT" => "Sig", "T" => Object::string_literal("Signature1"), "V" => signature_value() };
    assert_eq!(signed(with_fields(vec![field])), Signed::Yes);
}

#[test]
fn an_unsigned_signature_field_is_not_one() {
    let field = dictionary! { "FT" => "Sig", "T" => Object::string_literal("Signature1") };
    let text = dictionary! { "FT" => "Tx", "V" => Object::string_literal("text value") };
    assert_eq!(signed(with_fields(vec![field, text])), Signed::No);
}

#[test]
fn a_kid_inherits_its_parents_field_type() {
    let mut doc = with_fields(vec![]);
    let kid_id = doc.add_object(dictionary! { "V" => signature_value() });
    let parent_id = doc.add_object(dictionary! { "FT" => "Sig", "Kids" => vec![kid_id.into()] });
    let form_id = doc.catalog().unwrap().get(b"AcroForm").unwrap().as_reference().unwrap();
    doc.get_dictionary_mut(form_id)
        .unwrap()
        .set("Fields", vec![parent_id.into()]);
    assert_eq!(signed(doc), Signed::Yes);
}

#[test]
fn too_many_fields_answer_unknown() {
    let fields = (0..10_001).map(|_| dictionary! { "FT" => "Tx" }).collect();
    assert_eq!(signed(with_fields(fields)), Signed::Unknown);
}

#[test]
fn an_encrypted_files_fields_are_read_without_a_password() {
    let field = dictionary! { "FT" => "Sig", "V" => signature_value() };
    let mut doc = with_fields(vec![field]);
    let aes: Arc<dyn CryptFilter> = Arc::new(Aes256CryptFilter);
    let state = EncryptionState::try_from(EncryptionVersion::V5 {
        encrypt_metadata: true,
        crypt_filters: BTreeMap::from([(b"StdCF".to_vec(), aes)]),
        file_encryption_key: &[3; 32],
        stream_filter: b"StdCF".to_vec(),
        string_filter: b"StdCF".to_vec(),
        owner_password: "owner",
        user_password: "user",
        permissions: Permissions::all(),
    })
    .unwrap();
    doc.encrypt(&state).unwrap();
    let mut bytes = Vec::new();
    doc.save_to(&mut bytes).unwrap();

    let found = inspect_bytes(&bytes, None).unwrap();
    assert!(found.encrypted);
    assert_eq!(found.signed, Signed::Yes);
}

#[test]
fn unreadable_cross_reference_data_needs_the_whole_document_path() {
    assert!(matches!(
        inspect_bytes(b"not a pdf", None),
        Err(Error::NeedsWholeDocument(StripFallback::NoHeader))
    ));
}

#[test]
fn an_update_that_drops_encrypt_is_reported_up_front() {
    let mut bytes = std::fs::read("tests/fixtures/crypt/identity-stmf.pdf").unwrap();
    append_update_without_encrypt(&mut bytes);
    let found = inspect_bytes(&bytes, Some("user")).unwrap();
    assert_eq!(found.needs_whole_document, Some(StripFallback::InconsistentEncrypt));
}

#[test]
fn an_embedded_file_filter_of_its_own_is_reported_up_front() {
    let mut doc = with_fields(vec![]);
    let aes: Arc<dyn CryptFilter> = Arc::new(Aes256CryptFilter);
    let state = EncryptionState::try_from(EncryptionVersion::V5 {
        encrypt_metadata: true,
        crypt_filters: BTreeMap::from([(b"StdCF".to_vec(), aes)]),
        file_encryption_key: &[3; 32],
        stream_filter: b"StdCF".to_vec(),
        string_filter: b"StdCF".to_vec(),
        owner_password: "owner",
        user_password: "user",
        permissions: Permissions::all(),
    })
    .unwrap();
    doc.encrypt(&state).unwrap();
    let encrypt = doc.trailer.get(b"Encrypt").unwrap().as_reference().unwrap();
    doc.get_dictionary_mut(encrypt)
        .unwrap()
        .set("EFF", Object::Name(b"Identity".to_vec()));
    let mut bytes = Vec::new();
    doc.save_to(&mut bytes).unwrap();

    let found = inspect_bytes(&bytes, Some("user")).unwrap();
    assert_eq!(found.needs_whole_document, Some(StripFallback::EmbeddedFileFilter));
}

#[test]
fn a_usage_rights_signature_is_reported_apart_from_signed_fields() {
    // The form's catalog holds /Perms /UR3, and no signed signature field.
    let bytes = std::fs::read("assets/encrypted.pdf").unwrap();
    let found = inspect_bytes(&bytes, None).unwrap();
    assert_eq!(found.usage_rights, UsageRights::Yes);
    assert_eq!(found.signed, Signed::No);

    for bytes in [
        std::fs::read("tests/fixtures/crypt/identity-stmf.pdf").unwrap(),
        std::fs::read("assets/example.pdf").unwrap(),
    ] {
        assert_eq!(
            inspect_bytes(&bytes, Some("user")).unwrap().usage_rights,
            UsageRights::No
        );
    }
}

#[test]
fn the_older_usage_rights_entry_counts_too() {
    let mut doc = with_fields(vec![]);
    let catalog = doc.trailer.get(b"Root").unwrap().as_reference().unwrap();
    doc.get_dictionary_mut(catalog)
        .unwrap()
        .set("Perms", dictionary! { "UR" => dictionary! { "Type" => "Sig" } });
    let mut bytes = Vec::new();
    doc.save_to(&mut bytes).unwrap();
    assert_eq!(inspect_bytes(&bytes, None).unwrap().usage_rights, UsageRights::Yes);
}

/// Appends an empty incremental update whose trailer leaves out `/Encrypt`.
pub fn append_update_without_encrypt(bytes: &mut Vec<u8>) {
    let tail = &bytes[bytes.len().saturating_sub(64)..];
    let at = tail.windows(9).rposition(|window| window == b"startxref").unwrap();
    let prev: usize = std::str::from_utf8(&tail[at + 9..])
        .unwrap()
        .split_whitespace()
        .next()
        .unwrap()
        .parse()
        .unwrap();
    let root = Document::load_mem(bytes)
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
}

/// A file whose trailer names `encrypt` as its encryption dictionary. Nothing in it is encrypted:
/// `inspect` reads only the dictionary to name its handler.
fn named_encryption(encrypt: Dictionary) -> Vec<u8> {
    let mut doc = with_fields(vec![]);
    let id = doc.add_object(encrypt);
    doc.trailer.set("Encrypt", Object::Reference(id));
    let mut bytes = Vec::new();
    doc.save_to(&mut bytes).unwrap();
    bytes
}

#[test]
fn the_security_handler_is_named() {
    let standard = std::fs::read("tests/fixtures/crypt/identity-stmf.pdf").unwrap();
    let found = inspect_bytes(&standard, None).unwrap();
    assert_eq!(found.security_handler, SecurityHandler::Standard);

    let mut plain = Vec::new();
    with_fields(vec![]).save_to(&mut plain).unwrap();
    let found = inspect_bytes(&plain, None).unwrap();
    assert_eq!(found.security_handler, SecurityHandler::NotEncrypted);

    for (encrypt, handler) in [
        (
            dictionary! { "Filter" => "Adobe.PubSec", "V" => 4, "SubFilter" => "adbe.pkcs7.s5" },
            SecurityHandler::PublicKey,
        ),
        // A revision the password check does not implement.
        (
            dictionary! { "Filter" => "Standard", "V" => 99, "R" => 99, "O" => Object::string_literal("o"), "U" => Object::string_literal("u"), "P" => -1 },
            SecurityHandler::StandardUnreadable,
        ),
        (
            dictionary! { "Filter" => "SomeoneElses", "V" => 2 },
            SecurityHandler::Other,
        ),
        (dictionary! { "V" => 2 }, SecurityHandler::Other),
    ] {
        let bytes = named_encryption(encrypt);
        let found = inspect_bytes(&bytes, Some("anything")).unwrap();
        assert!(found.encrypted, "{handler:?}");
        assert_eq!(found.security_handler, handler);
        // A password does not open any of them, which is why the handler is reported: the
        // check alone cannot tell these from a wrong password.
        assert_eq!(found.password, PasswordCheck::Wrong, "{handler:?}");
    }
}
