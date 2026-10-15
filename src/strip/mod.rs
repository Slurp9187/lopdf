//! Removing a PDF's Standard-handler encryption in memory that does not grow with the file: the
//! streaming Strip. See `docs/plans/stream-strip.md`.
//!
//! The Strip reads a `Read + Seek` source through bounded windows, object by object. A file it
//! cannot handle that way fails with [`Error::NeedsWholeDocument`](crate::Error::NeedsWholeDocument)
//! and a [`StripFallback`] saying why; the caller then strips it through the whole-document path.

mod copy;
mod index;
mod source;

use crate::Result;
use std::fmt;
use std::io::{Read, Seek, Write};
use zeroize::Zeroizing;

/// Removes the Standard security handler's encryption from the PDF in `input`, writing the result
/// to `output`, in memory that does not grow with the file.
///
/// Every object is copied in input order and decrypted: strings, stream dictionaries' strings, and
/// stream data, which stays in its own filters (a content stream is never decoded). Object streams
/// are copied whole. The encryption dictionary and old cross-reference streams are dropped, and new
/// cross-reference data is written: one revision, the newest version of each object, ids and
/// generations kept.
///
/// Errors are those of a whole-document load for the same bytes: a wrong password is
/// [`Error::InvalidPassword`](crate::Error::InvalidPassword), data that fails to decrypt is
/// [`Error::Decryption`](crate::Error::Decryption), and a decompression cap is
/// [`Error::Decompress`](crate::Error::Decompress). A file the Strip cannot handle in bounded
/// memory is [`Error::NeedsWholeDocument`](crate::Error::NeedsWholeDocument); `output` may then
/// hold a partial file, which the caller discards. A file that is not encrypted is
/// [`Error::NotEncrypted`](crate::Error::NotEncrypted).
pub fn strip<R: Read + Seek, W: Write>(input: R, output: W, options: &StripOptions) -> Result<StripReport> {
    copy::strip(input, output, options, &Caps::default())
}

/// What [`strip`] needs besides the file.
pub struct StripOptions {
    /// The user or owner password. The empty password is tried first, as a load does.
    password: Zeroizing<String>,
}

impl StripOptions {
    /// Options with `password`, which is copied and wiped when the options drop.
    pub fn with_password(password: &str) -> Self {
        Self {
            password: Zeroizing::new(password.to_owned()),
        }
    }
}

impl fmt::Debug for StripOptions {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("StripOptions").field("password", &"[REDACTED]").finish()
    }
}

/// What [`strip`] copied.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct StripReport {
    /// Objects copied.
    pub objects: usize,
    /// Streams among them.
    pub streams: usize,
    /// Stream data written, in bytes.
    pub stream_bytes: u64,
}

/// Why a file needs the whole-document path rather than the streaming Strip. None of these is an
/// error in the file as such: the whole-document path, which can repair it, may still succeed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum StripFallback {
    /// No `%PDF-` header in the first 1024 bytes.
    NoHeader,
    /// The cross-reference chain cannot be followed from `startxref`, so the file would need its
    /// cross-reference data rebuilt.
    XrefUnresolvable,
    /// More objects than the streaming index holds.
    TooManyObjects,
    /// An older revision's trailer has `/Encrypt` but the newest one does not.
    InconsistentEncrypt,
    /// The encryption dictionary is not a plain object where the cross-reference data says.
    EncryptUnreadable,
    /// An object does not parse where the cross-reference data says, within the head window.
    ObjectUnreadable,
    /// An object's `N G obj` header does not match its cross-reference entry.
    ObjectIdMismatch,
    /// A compressed entry's container is not a generation-0 object stream, or the stream is
    /// malformed.
    BadObjectStream,
    /// A stream's `/Length` cannot be resolved.
    LengthUnresolvable,
    /// `endstream` does not follow a stream's data where its `/Length` says.
    LengthMismatch,
    /// A stream uses a crypt filter that cannot decrypt in chunks.
    UnsupportedCryptFilter,
}

impl fmt::Display for StripFallback {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            StripFallback::NoHeader => "no %PDF- header in the first 1024 bytes",
            StripFallback::XrefUnresolvable => "the cross-reference chain cannot be followed",
            StripFallback::TooManyObjects => "more objects than the streaming index holds",
            StripFallback::InconsistentEncrypt => "an older trailer has /Encrypt but the newest does not",
            StripFallback::EncryptUnreadable => "the encryption dictionary cannot be read",
            StripFallback::ObjectUnreadable => "an object does not parse where the cross-reference data says",
            StripFallback::ObjectIdMismatch => "an object's header does not match its cross-reference entry",
            StripFallback::BadObjectStream => "an object stream is missing or malformed",
            StripFallback::LengthUnresolvable => "a stream's /Length cannot be resolved",
            StripFallback::LengthMismatch => "endstream does not follow a stream's data",
            StripFallback::UnsupportedCryptFilter => "a crypt filter cannot decrypt in chunks",
        })
    }
}

/// The bounds that keep the Strip's memory independent of the file. Unlike `LoadOptions`, every
/// one is set: unbounded is not an option here.
#[derive(Clone, Copy, Debug)]
pub(crate) struct Caps {
    /// The most cross-reference entries the index holds.
    pub(crate) max_objects: usize,
    /// The largest window a cross-reference section (a table and its trailer, or a cross-reference
    /// stream object) may need.
    pub(crate) max_section: usize,
    /// The largest window an object's head (a direct object, or a stream's dictionary) may need.
    pub(crate) max_head: usize,
    /// The most any one cross-reference or object stream may decompress to, and the largest object
    /// stream read whole.
    pub(crate) max_decoded: usize,
    /// The most all of them together may decompress to.
    pub(crate) max_total_decoded: usize,
}

impl Default for Caps {
    fn default() -> Self {
        Self {
            max_objects: 1_000_000,
            // A classic table entry is 20 bytes, so this holds a section of every object the index
            // may hold, with room for its trailer.
            max_section: 21 * 1024 * 1024,
            max_head: 4 * 1024 * 1024,
            max_decoded: 64 * 1024 * 1024,
            max_total_decoded: 256 * 1024 * 1024,
        }
    }
}
