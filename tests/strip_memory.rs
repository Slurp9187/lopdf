//! The streaming Strip's memory does not grow with the file.
//!
//! This is its own test binary because it installs a global allocator that counts every live byte
//! and the peak, which any other test running beside it would disturb. Each test takes `SERIAL`.
//!
//! Falsify: each guard below, removed, makes the 64 MiB rise grow with the payload:
//! - `copy_data` reading a stream through the fixed chunk (read the whole stream into a `Vec`);
//! - the chunk decipher writing into the lent buffer (collect its output into a `Vec`);
//! - `Source::window` reading only what is asked (read the whole file);
//! - `verify_stripped` reading stream data through its chunk (read the whole stream).

use lopdf::encryption::crypt_filters::{Aes128CryptFilter, Aes256CryptFilter, CryptFilter};
use lopdf::strip::{StripObserver, StripOptions, inspect, strip, verify_stripped};
use lopdf::{Document, EncryptionState, EncryptionVersion, Object, ObjectId, Permissions, Stream, dictionary};
use std::alloc::{GlobalAlloc, Layout, System};
use std::collections::BTreeMap;
use std::fs::File;
use std::io::{Seek, SeekFrom, Write};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

struct Counting;

/// Bytes allocated and not yet freed.
static LIVE: AtomicUsize = AtomicUsize::new(0);
/// The most `LIVE` has been since the last reset.
static PEAK: AtomicUsize = AtomicUsize::new(0);

unsafe impl GlobalAlloc for Counting {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let ptr = unsafe { System.alloc(layout) };
        if !ptr.is_null() {
            let now = LIVE.fetch_add(layout.size(), Ordering::SeqCst) + layout.size();
            PEAK.fetch_max(now, Ordering::SeqCst);
        }
        ptr
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        unsafe { System.dealloc(ptr, layout) };
        LIVE.fetch_sub(layout.size(), Ordering::SeqCst);
    }

    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        let new = unsafe { System.realloc(ptr, layout, new_size) };
        if !new.is_null() {
            if new_size > layout.size() {
                let now = LIVE.fetch_add(new_size - layout.size(), Ordering::SeqCst) + new_size - layout.size();
                PEAK.fetch_max(now, Ordering::SeqCst);
            } else {
                LIVE.fetch_sub(layout.size() - new_size, Ordering::SeqCst);
            }
        }
        new
    }
}

#[global_allocator]
static ALLOCATOR: Counting = Counting;

/// The tests take turns: the counters are global.
static SERIAL: Mutex<()> = Mutex::new(());

const MIB: usize = 1024 * 1024;
/// The most the peak may rise by while a 64 MiB stream is stripped.
const BOUND: usize = 16 * MIB;
/// The most the rise for 64 MiB may exceed the rise for 4 MiB: flat, not growing with the payload.
const FLAT: usize = MIB;

/// How far the peak rose above where it stood while `f` ran.
fn peak_rise(f: impl FnOnce()) -> usize {
    let start = LIVE.load(Ordering::SeqCst);
    PEAK.store(start, Ordering::SeqCst);
    f();
    PEAK.load(Ordering::SeqCst) - start
}

/// A file of `version`'s encryption holding one stream of `payload` bytes, written to a temporary
/// file. Built before anything is measured, so it may use what memory it likes.
fn encrypted_file(version: &str, payload: usize) -> File {
    let mut doc = Document::with_version("1.7");
    doc.trailer.set(
        "ID",
        Object::Array(vec![
            Object::string_literal(b"0123456789abcdef"),
            Object::string_literal(b"fedcba9876543210"),
        ]),
    );
    let pages_id = doc.add_object(dictionary! { "Type" => "Pages", "Kids" => Vec::<Object>::new(), "Count" => 0 });
    let data: Vec<u8> = (0..payload).map(|i| (i % 251) as u8).collect();
    let big_id = doc.add_object(Stream::new(dictionary! {}, data));
    let catalog_id = doc.add_object(dictionary! { "Type" => "Catalog", "Pages" => pages_id, "Big" => big_id });
    let info_id = doc.add_object(dictionary! { "Title" => Object::string_literal("A title") });
    doc.trailer.set("Root", catalog_id);
    doc.trailer.set("Info", info_id);

    let state = match version {
        "RC4" => EncryptionState::try_from(EncryptionVersion::V2 {
            document: &doc,
            owner_password: "owner",
            user_password: "user",
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
                owner_password: "owner",
                user_password: "user",
                permissions: Permissions::all(),
            })
        }
        _ => {
            let aes: Arc<dyn CryptFilter> = Arc::new(Aes256CryptFilter);
            EncryptionState::try_from(EncryptionVersion::V5 {
                encrypt_metadata: true,
                crypt_filters: BTreeMap::from([(b"StdCF".to_vec(), aes)]),
                file_encryption_key: &[5; 32],
                stream_filter: b"StdCF".to_vec(),
                string_filter: b"StdCF".to_vec(),
                owner_password: "owner",
                user_password: "user",
                permissions: Permissions::all(),
            })
        }
    }
    .unwrap();
    doc.encrypt(&state).unwrap();

    let mut file = tempfile::tempfile().unwrap();
    doc.save_to(&mut file).unwrap();
    file.flush().unwrap();
    file.seek(SeekFrom::Start(0)).unwrap();
    file
}

/// An observer that keeps nothing, as a hashing one would keep only its state.
struct Discard;

impl StripObserver for Discard {
    fn object(&mut self, _id: ObjectId) {}
    fn string(&mut self, _plaintext: &[u8]) {}
    fn stream(&mut self, _length: u64) {}
    fn stream_data(&mut self, _plaintext: &[u8]) {}
}

/// The peak rises of stripping, reading back and inspecting a file with `payload` bytes of stream.
fn rises(version: &str, payload: usize) -> [usize; 3] {
    let input = encrypted_file(version, payload);
    let mut output = tempfile::tempfile().unwrap();
    let options = StripOptions::with_password("user");

    let strip_rise = peak_rise(|| {
        let report = strip(input.try_clone().unwrap(), output.try_clone().unwrap(), &options).unwrap();
        assert!(
            report.stream_bytes >= payload as u64,
            "{version}: the stream was copied"
        );
    });
    output.seek(SeekFrom::Start(0)).unwrap();
    let verify_rise = peak_rise(|| verify_stripped(output.try_clone().unwrap(), &mut Discard).unwrap());
    let inspect_rise = peak_rise(|| {
        inspect(input.try_clone().unwrap(), Some("user")).unwrap();
    });
    [strip_rise, verify_rise, inspect_rise]
}

fn assert_flat(version: &str) {
    let _serial = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
    let small = rises(version, 4 * MIB);
    let large = rises(version, 64 * MIB);
    eprintln!("{version}: peak rise [strip, verify_stripped, inspect] at 4 MiB {small:?}, at 64 MiB {large:?}");
    for (what, (small, large)) in ["strip", "verify_stripped", "inspect"]
        .iter()
        .zip(small.into_iter().zip(large))
    {
        assert!(
            large < BOUND,
            "{version} {what}: the peak rose {large} bytes for a 64 MiB stream"
        );
        assert!(
            large.saturating_sub(small) < FLAT,
            "{version} {what}: the peak rose {small} bytes for 4 MiB and {large} for 64 MiB"
        );
    }
}

#[test]
fn stripping_rc4_does_not_grow_with_the_file() {
    assert_flat("RC4");
}

#[test]
fn stripping_aes_128_does_not_grow_with_the_file() {
    assert_flat("AES-128");
}

#[test]
fn stripping_aes_256_does_not_grow_with_the_file() {
    assert_flat("AES-256");
}

/// A quarter of a gigabyte, too slow for a debug build: `cargo test --release --test strip_memory
/// -- --ignored`.
#[test]
#[ignore = "slow outside a release build"]
fn stripping_256_mib_stays_under_the_bound() {
    let _serial = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
    let [strip_rise, verify_rise, _] = rises("AES-256", 256 * MIB);
    eprintln!("AES-256 at 256 MiB: strip rose {strip_rise}, verify_stripped {verify_rise}");
    assert!(strip_rise < BOUND, "strip rose {strip_rise} bytes");
    assert!(verify_rise < BOUND, "verify_stripped rose {verify_rise} bytes");
}
