//! `Document::save_encrypted` encrypts as it writes, so an encrypted document keeps its object
//! streams: `Document::encrypt` followed by a save writes every object on its own.

#![cfg(not(feature = "async"))]

use lopdf::encryption::crypt_filters::{Aes256CryptFilter, CryptFilter};
use lopdf::xref::XrefEntry;
use lopdf::{
    Document, EncryptionState, EncryptionVersion, LoadOptions, Object, Permissions, SaveOptions, Stream, StringFormat,
    dictionary,
};
use std::collections::BTreeMap;
use std::sync::Arc;

/// Plaintext no other part of the file holds.
const MARKER: &[u8] = b"object stream marker 5e1d";

/// A one-page document with `MARKER` in its Info dictionary and a signature dictionary.
fn sample_document() -> Document {
    let mut doc = Document::with_version("1.7");
    let pages_id = doc.new_object_id();
    let content_id = doc.add_object(Stream::new(dictionary! {}, b"BT ET".to_vec()));
    let page_id = doc.add_object(dictionary! {
        "Type" => "Page",
        "Parent" => pages_id,
        "MediaBox" => vec![0.into(), 0.into(), 612.into(), 792.into()],
        "Contents" => content_id,
    });
    doc.objects.insert(
        pages_id,
        Object::Dictionary(dictionary! {
            "Type" => "Pages",
            "Kids" => vec![page_id.into()],
            "Count" => 1,
        }),
    );
    let catalog_id = doc.add_object(dictionary! { "Type" => "Catalog", "Pages" => pages_id });
    let info_id = doc.add_object(dictionary! {
        "Title" => Object::String(MARKER.to_vec(), StringFormat::Literal),
    });
    doc.add_object(dictionary! {
        "Type" => "Sig",
        "ByteRange" => vec![0.into(), 10.into(), 20.into(), 30.into()],
        "Contents" => Object::String(b"signature bytes".to_vec(), StringFormat::Hexadecimal),
    });
    doc.trailer.set("Root", catalog_id);
    doc.trailer.set("Info", info_id);
    doc
}

fn aes256_state() -> EncryptionState {
    let crypt_filter: Arc<dyn CryptFilter> = Arc::new(Aes256CryptFilter);
    EncryptionState::try_from(EncryptionVersion::V5 {
        encrypt_metadata: true,
        crypt_filters: BTreeMap::from([(b"StdCF".to_vec(), crypt_filter)]),
        file_encryption_key: &[3u8; 32],
        stream_filter: b"StdCF".to_vec(),
        string_filter: b"StdCF".to_vec(),
        owner_password: "owner",
        user_password: "user",
        permissions: Permissions::all(),
    })
    .unwrap()
}

fn object_streams() -> SaveOptions {
    SaveOptions::builder()
        .use_object_streams(true)
        .use_xref_streams(true)
        .build()
}

fn strict_load(pdf: &[u8]) -> Document {
    let options = LoadOptions {
        strict: true,
        ..LoadOptions::with_password("user")
    };
    Document::load_mem_with_options(pdf, options).unwrap()
}

fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    haystack.windows(needle.len()).any(|window| window == needle)
}

#[test]
fn an_encrypted_save_keeps_object_streams_and_encrypts_them() {
    let mut doc = sample_document();
    let mut pdf = Vec::new();
    doc.save_encrypted(&mut pdf, &aes256_state(), object_streams()).unwrap();

    assert!(contains(&pdf, b"/ObjStm"), "no object stream was written");
    assert!(!contains(&pdf, MARKER), "an object stream went out in the clear");

    let loaded = strict_load(&pdf);
    let compressed = loaded
        .reference_table
        .entries
        .values()
        .filter(|entry| matches!(entry, XrefEntry::Compressed { .. }))
        .count();
    assert!(compressed > 0, "the reloaded file has no objects in object streams");
    let info = loaded.trailer.get(b"Info").and_then(Object::as_reference).unwrap();
    let title = loaded.get_dictionary(info).unwrap().get(b"Title").unwrap();
    assert_eq!(title.as_str().unwrap(), MARKER);
    assert_eq!(loaded.get_pages().len(), 1);
}

#[test]
fn a_signature_stays_out_of_object_streams_when_encrypting() {
    let mut doc = sample_document();
    let signature = doc
        .objects
        .iter()
        .find(|(_, object)| object.type_name().ok() == Some(b"Sig"))
        .map(|(&id, _)| id)
        .unwrap();
    let mut pdf = Vec::new();
    doc.save_encrypted(&mut pdf, &aes256_state(), object_streams()).unwrap();

    let loaded = strict_load(&pdf);
    assert!(matches!(
        loaded.reference_table.get(signature.0),
        Some(XrefEntry::Normal { .. })
    ));
}

#[test]
fn the_document_is_left_unencrypted() {
    let mut doc = sample_document();
    let before = doc.objects.clone();
    let mut pdf = Vec::new();
    doc.save_encrypted(&mut pdf, &aes256_state(), object_streams()).unwrap();

    assert!(!doc.is_encrypted());
    assert!(!doc.trailer.has(b"Encrypt"));
    assert_eq!(doc.objects, before);

    // So it can be saved again, encrypted or not.
    let mut again = Vec::new();
    doc.save_encrypted(&mut again, &aes256_state(), SaveOptions::default())
        .unwrap();
    assert!(!contains(&again, MARKER));
    assert_eq!(strict_load(&again).get_pages().len(), 1);
    let mut plain = Vec::new();
    doc.save_to(&mut plain).unwrap();
    assert!(contains(&plain, MARKER));
}

#[test]
fn an_already_encrypted_document_is_refused() {
    let mut doc = sample_document();
    doc.encrypt(&aes256_state()).unwrap();
    let mut pdf = Vec::new();
    assert!(matches!(
        doc.save_encrypted(&mut pdf, &aes256_state(), object_streams()),
        Err(lopdf::Error::AlreadyEncrypted)
    ));
    assert!(pdf.is_empty());
}

/// An encrypted save leaves the document as it was, as a plain save does since upstream #633:
/// the `/Encrypt` dictionary is numbered after `max_id` for the save only, and the object
/// streams after it, so none of them shares a number.
#[test]
fn an_encrypted_save_leaves_max_id_and_the_trailer_as_they_were() {
    for options in [SaveOptions::default(), object_streams()] {
        let mut doc = sample_document();
        let max_id = doc.max_id;
        let trailer = doc.trailer.clone();

        let mut pdf = Vec::new();
        doc.save_encrypted(&mut pdf, &aes256_state(), options.clone()).unwrap();

        assert_eq!(doc.max_id, max_id, "{options:?}");
        assert_eq!(doc.trailer, trailer, "{options:?}");
        let loaded = strict_load(&pdf);
        assert!(loaded.trailer.get(b"Info").is_ok(), "{options:?}");
    }
}
