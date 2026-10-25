//! `/EFF` names the crypt filter for embedded file streams (ISO 32000-1, 7.6.5), which may differ
//! from `/StmF`, the one for every other stream. An embedded file is a stream a file specification's `/EF` names; `/Type
//! /EmbeddedFile` on the stream is optional. A stream's own `/Crypt` filter still wins.

use lopdf::encryption::crypt_filters::{Aes128CryptFilter, CryptFilter, Rc4CryptFilter};
use lopdf::{
    Document, EncryptionState, EncryptionVersion, LoadOptions, Object, ObjectId, Permissions, Stream, dictionary,
};
use std::collections::BTreeMap;
use std::sync::Arc;

const USER: &str = "user";
const OWNER: &str = "owner";
const ATTACHMENT: &[u8] = b"an attachment named only by /EF";
const TYPED: &[u8] = b"an attachment known by its /Type";
const OWN_FILTER: &[u8] = b"an attachment with its own /Crypt filter";
const CONTENT: &[u8] = b"BT (page content) Tj ET";

/// The ids of the streams in [`eff_document`]: the `/EF` attachment, the typed one, the one with
/// its own filter, and the page content.
const IDS: [ObjectId; 4] = [(2, 0), (3, 0), (4, 0), (5, 0)];

/// A `V4` file whose streams and strings use `/StdCF`, RC4, and whose embedded files use `/EFF
/// /EmbCF`, AES-128, so that decrypting an attachment with the wrong one gives garbage.
fn eff_document() -> Vec<u8> {
    let mut bytes = Vec::new();
    encrypted_eff_document().save_to(&mut bytes).unwrap();
    bytes
}

/// [`eff_document`], encrypted in memory and not yet saved.
fn encrypted_eff_document() -> Document {
    let mut doc = Document::with_version("1.6");
    doc.trailer.set(
        "ID",
        Object::Array(vec![
            Object::string_literal(b"0123456789abcdef"),
            Object::string_literal(b"fedcba9876543210"),
        ]),
    );
    let pages_id = doc.add_object(dictionary! { "Type" => "Pages", "Kids" => Vec::<Object>::new(), "Count" => 0 });
    let attachment = doc.add_object(Stream::new(dictionary! {}, ATTACHMENT.to_vec()));
    let typed = doc.add_object(Stream::new(dictionary! { "Type" => "EmbeddedFile" }, TYPED.to_vec()));
    let own_filter = doc.add_object(Stream::new(
        dictionary! { "Filter" => "Crypt", "DecodeParms" => dictionary! { "Name" => "Identity" } },
        OWN_FILTER.to_vec(),
    ));
    let content = doc.add_object(Stream::new(dictionary! {}, CONTENT.to_vec()));
    assert_eq!([attachment, typed, own_filter, content], IDS);

    let file_spec = |name: &str, file: ObjectId| {
        Object::Dictionary(dictionary! {
            "Type" => "Filespec",
            "F" => Object::string_literal(name),
            "EF" => dictionary! { "F" => file },
        })
    };
    let catalog_id = doc.add_object(dictionary! {
        "Type" => "Catalog",
        "Pages" => pages_id,
        "Names" => dictionary! {
            "EmbeddedFiles" => dictionary! {
                "Names" => vec![
                    Object::string_literal("attachment.txt"), file_spec("attachment.txt", attachment),
                    Object::string_literal("own.txt"), file_spec("own.txt", own_filter),
                ],
            },
        },
        "Thumb" => content,
        "Extra" => typed,
    });
    doc.trailer.set("Root", catalog_id);

    let rc4: Arc<dyn CryptFilter> = Arc::new(Rc4CryptFilter);
    let aes: Arc<dyn CryptFilter> = Arc::new(Aes128CryptFilter);
    let state = EncryptionState::try_from(EncryptionVersion::V4 {
        document: &doc,
        encrypt_metadata: true,
        crypt_filters: BTreeMap::from([(b"StdCF".to_vec(), rc4), (b"EmbCF".to_vec(), aes)]),
        stream_filter: b"StdCF".to_vec(),
        string_filter: b"StdCF".to_vec(),
        owner_password: OWNER,
        user_password: USER,
        permissions: Permissions::all(),
    })
    .unwrap();
    doc.encrypt(&state).unwrap();

    // lopdf writes no /EFF, so encrypt the two attachments the stream does not override with
    // /EmbCF by hand, and name it in /EFF.
    for (id, plaintext) in [(attachment, ATTACHMENT), (typed, TYPED)] {
        let key = Aes128CryptFilter.compute_key(state.file_encryption_key(), id).unwrap();
        let ciphertext = Aes128CryptFilter.encrypt(&key, plaintext).unwrap();
        doc.get_object_mut(id)
            .unwrap()
            .as_stream_mut()
            .unwrap()
            .set_content(ciphertext);
    }
    let encrypt = doc.trailer.get(b"Encrypt").unwrap().as_reference().unwrap();
    doc.get_dictionary_mut(encrypt)
        .unwrap()
        .set("EFF", Object::Name(b"EmbCF".to_vec()));
    doc
}

fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    haystack.windows(needle.len()).any(|window| window == needle)
}

fn assert_decrypted(doc: &Document) {
    for (id, plaintext) in IDS.into_iter().zip([ATTACHMENT, TYPED, OWN_FILTER, CONTENT]) {
        let stream = doc.get_object(id).unwrap().as_stream().unwrap();
        assert_eq!(stream.content, plaintext, "{id:?}");
    }
}

#[test]
fn embedded_files_are_decrypted_with_the_embedded_file_filter() {
    let bytes = eff_document();
    // The attachment with its own Identity filter is stored as is; the others are encrypted.
    assert!(!contains(&bytes, ATTACHMENT));
    assert!(!contains(&bytes, TYPED));
    assert!(contains(&bytes, OWN_FILTER));
    assert!(!contains(&bytes, CONTENT));

    let doc = Document::load_mem_with_options(&bytes, LoadOptions::with_password(USER)).unwrap();
    assert_decrypted(&doc);
}

#[test]
fn decrypting_a_document_uses_the_embedded_file_filter_too() {
    let mut doc = encrypted_eff_document();
    doc.decrypt(USER).unwrap();
    assert_decrypted(&doc);
}

#[test]
fn the_embedded_file_filter_fixture_decrypts() {
    // The same shape as `eff_document`, committed so that other projects can test against these
    // exact bytes.
    let bytes = include_bytes!("fixtures/crypt/eff-differs.pdf");
    let doc = Document::load_mem_with_options(bytes, LoadOptions::with_password(USER)).unwrap();
    assert_decrypted(&doc);
}

/// Rewrites the committed fixture: `cargo test --test embedded_file_filter -- --ignored`.
#[test]
#[ignore = "rewrites committed fixtures"]
fn regenerate_fixtures() {
    let directory = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/crypt");
    std::fs::create_dir_all(&directory).unwrap();
    std::fs::write(directory.join("eff-differs.pdf"), eff_document()).unwrap();
}
