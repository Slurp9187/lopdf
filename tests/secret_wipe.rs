//! Secret material is wiped before its memory goes back to the allocator.
//!
//! This binary installs a global allocator that can watch one allocation: when
//! the watched pointer is freed, it records whether every byte was zero.

use lopdf::encryption::crypt_filters::{Aes256CryptFilter, CryptFilter};
use lopdf::{Document, EncryptionState, EncryptionVersion, Object, Permissions, Stream, dictionary};
use std::alloc::{GlobalAlloc, Layout, System};
use std::collections::BTreeMap;
use std::sync::atomic::{AtomicBool, AtomicU8, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

struct WatchingAllocator;

/// The address of the allocation being watched, or 0.
static WATCHED: AtomicUsize = AtomicUsize::new(0);
/// What happened to it: `PENDING`, `WIPED` or `NOT_WIPED`.
static OUTCOME: AtomicU8 = AtomicU8::new(PENDING);
const PENDING: u8 = 0;
const WIPED: u8 = 1;
const NOT_WIPED: u8 = 2;

/// The watch is global, so the tests take turns.
static SERIAL: Mutex<()> = Mutex::new(());

/// While set, every freed allocation is searched for `MARKER`, for buffers a test cannot reach.
static SCANNING: AtomicBool = AtomicBool::new(false);
/// Whether a freed allocation still held `MARKER` while scanning.
static MARKER_FREED: AtomicBool = AtomicBool::new(false);
/// Plaintext no other allocation in the test binary holds.
const MARKER: &[u8; 32] = b"plaintext marker 7f3a9c1e5b2d804";

unsafe impl GlobalAlloc for WatchingAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        unsafe { System.alloc(layout) }
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        let addr = ptr as usize;
        // Disarm on the first match, so a later allocation that reuses the
        // address is never inspected.
        if addr != 0
            && WATCHED
                .compare_exchange(addr, 0, Ordering::SeqCst, Ordering::SeqCst)
                .is_ok()
        {
            let bytes = unsafe { std::slice::from_raw_parts(ptr, layout.size()) };
            let outcome = if bytes.iter().all(|&b| b == 0) {
                WIPED
            } else {
                NOT_WIPED
            };
            OUTCOME.store(outcome, Ordering::SeqCst);
        }
        if SCANNING.load(Ordering::SeqCst) {
            let bytes = unsafe { std::slice::from_raw_parts(ptr, layout.size()) };
            if bytes.windows(MARKER.len()).any(|window| window == MARKER) {
                MARKER_FREED.store(true, Ordering::SeqCst);
            }
        }
        unsafe { System.dealloc(ptr, layout) }
    }
}

#[global_allocator]
static ALLOCATOR: WatchingAllocator = WatchingAllocator;

/// Watches the heap buffer at `ptr`, runs `drop_it`, and asserts the buffer was
/// freed with every byte zero.
fn assert_wiped_when(ptr: *const u8, what: &str, drop_it: impl FnOnce()) {
    OUTCOME.store(PENDING, Ordering::SeqCst);
    WATCHED.store(ptr as usize, Ordering::SeqCst);
    drop_it();
    WATCHED.store(0, Ordering::SeqCst);
    match OUTCOME.load(Ordering::SeqCst) {
        WIPED => {}
        NOT_WIPED => panic!("{what} was freed without being wiped"),
        _ => panic!("{what} was not freed"),
    }
}

const FILE_KEY: [u8; 32] = [0xA5; 32];

fn v5_state() -> EncryptionState {
    let crypt_filter: Arc<dyn CryptFilter> = Arc::new(Aes256CryptFilter);
    EncryptionState::try_from(EncryptionVersion::V5 {
        encrypt_metadata: true,
        crypt_filters: BTreeMap::from([(b"StdCF".to_vec(), crypt_filter)]),
        file_encryption_key: &FILE_KEY,
        stream_filter: b"StdCF".to_vec(),
        string_filter: b"StdCF".to_vec(),
        owner_password: "owner-secret",
        user_password: "user-secret",
        permissions: Permissions::all(),
    })
    .unwrap()
}

/// A one-page document with the trailer `/ID` that encryption requires.
fn document() -> Document {
    let mut doc = Document::with_version("1.7");
    doc.trailer.set(
        "ID",
        Object::Array(vec![
            Object::string_literal(b"0123456789abcdef"),
            Object::string_literal(b"fedcba9876543210"),
        ]),
    );
    let pages_id = doc.new_object_id();
    let contents_id = doc.add_object(Stream::new(dictionary! {}, b"BT ET".to_vec()));
    let page_id = doc.add_object(dictionary! {
        "Type" => "Page",
        "Parent" => pages_id,
        "MediaBox" => vec![0.into(), 0.into(), 612.into(), 792.into()],
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
    let catalog_id = doc.add_object(dictionary! { "Type" => "Catalog", "Pages" => pages_id });
    doc.trailer.set("Root", catalog_id);
    doc
}

#[test]
fn the_file_encryption_key_is_wiped_when_the_state_drops() {
    let _serial = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
    let state = v5_state();
    assert_eq!(state.file_encryption_key(), FILE_KEY);
    assert_wiped_when(state.file_encryption_key().as_ptr(), "the state's key", || drop(state));
}

#[test]
fn a_clone_of_the_state_wipes_its_own_copy_of_the_key() {
    let _serial = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
    let state = v5_state();
    let clone = state.clone();
    assert_ne!(
        clone.file_encryption_key().as_ptr(),
        state.file_encryption_key().as_ptr()
    );
    assert_wiped_when(clone.file_encryption_key().as_ptr(), "the clone's key", || drop(clone));
    assert_wiped_when(state.file_encryption_key().as_ptr(), "the state's key", || drop(state));
}

#[test]
fn a_decrypted_document_wipes_its_key_when_it_drops() {
    let _serial = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
    let mut doc = document();
    doc.encrypt(&v5_state()).unwrap();
    doc.decrypt("user-secret").unwrap();

    let state = doc.encryption_state.as_ref().expect("decrypt keeps the state");
    assert_eq!(state.file_encryption_key(), FILE_KEY);
    let key = state.file_encryption_key().as_ptr();
    assert_wiped_when(key, "the document's key", || drop(doc));
}

/// Runs `f` and asserts that no allocation freed meanwhile still held `MARKER`.
fn assert_marker_never_freed(what: &str, f: impl FnOnce()) {
    MARKER_FREED.store(false, Ordering::SeqCst);
    SCANNING.store(true, Ordering::SeqCst);
    f();
    SCANNING.store(false, Ordering::SeqCst);
    assert!(
        !MARKER_FREED.load(Ordering::SeqCst),
        "{what} freed the plaintext without wiping it"
    );
}

#[test]
fn aes_decryption_leaves_no_unwiped_plaintext_behind() {
    let _serial = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
    let key = [0x5Au8; 32];
    let ciphertext = Aes256CryptFilter.encrypt(&key, MARKER).unwrap();

    // The caller wipes the plaintext it gets back; nothing else may hold a copy.
    assert_marker_never_freed("AES decryption", || {
        let plaintext = zeroize::Zeroizing::new(Aes256CryptFilter.decrypt(&key, &ciphertext).unwrap());
        assert_eq!(plaintext.as_slice(), MARKER);
    });
}

#[test]
fn the_password_algorithms_debug_hides_the_password_values() {
    let _serial = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
    let mut doc = document();
    doc.encrypt(&v5_state()).unwrap();

    let algorithm = lopdf::encryption::PasswordAlgorithm::try_from(&doc).unwrap();
    let debug = format!("{algorithm:?}");
    for key in [
        "owner_value",
        "owner_encrypted",
        "user_value",
        "user_encrypted",
        "permission_encrypted",
    ] {
        assert!(
            debug.contains(&format!("{key}: \"[REDACTED]\"")),
            "{key} is shown: {debug}"
        );
    }
}

/// The password handed to a loader is wiped once the reader is done with it,
/// whether it opened the document or not.
#[cfg(not(feature = "async"))]
#[test]
fn the_reader_wipes_the_password_it_was_given() {
    let _serial = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
    let mut doc = document();
    doc.encrypt(&v5_state()).unwrap();
    let mut pdf = Vec::new();
    doc.save_to(&mut pdf).unwrap();

    for (password, opens) in [("user-secret", true), ("wrong-secret", false)] {
        let options = lopdf::LoadOptions::with_password(password);
        let buffer = options.password.as_ref().unwrap().as_ptr();
        let mut result = None;
        assert_wiped_when(buffer, "the reader's password", || {
            result = Some(Document::load_mem_with_options(&pdf, options));
        });
        assert_eq!(result.unwrap().is_ok(), opens, "{password}");
    }
}
