//! Reading a stripped file back, independently of the writer, for the round-trip check.

use super::index::read_index;
use super::source::Source;
use super::{Caps, StripFallback, StripObserver, observe_strings};
use crate::parser::{self, ObjectHead};
use crate::xref::XrefEntry;
use crate::{Error, Object, Result};
use std::io::{Read, Seek};
use zeroize::{Zeroize as _, Zeroizing};

/// How much stream data is read at a time.
const CHUNK: usize = 64 * 1024;

/// The first window an object's head is read through; it doubles up to [`Caps::max_head`].
const FIRST_HEAD_WINDOW: usize = 4 * 1024;

fn unreadable() -> Error {
    Error::NeedsWholeDocument(StripFallback::ObjectUnreadable)
}

/// Reports every object of the stripped file `written` to `observer`, in file order, as the Strip
/// reported it while writing: its strings, and a stream's length and data. The file's own
/// cross-reference stream, which the Strip writes after the objects, is not reported.
pub(crate) fn verify<R: Read + Seek>(written: R, observer: &mut dyn StripObserver, caps: &Caps) -> Result<()> {
    let mut source = Source::new(written)?;
    let index = read_index(&mut source, caps)?;
    if index.trailer.has(b"Encrypt") {
        return Err(Error::Syntax(
            "a stripped file still names an encryption dictionary".to_string(),
        ));
    }

    let mut objects: Vec<(u64, crate::ObjectId)> = index
        .entries
        .iter()
        .filter_map(|(number, entry)| match entry {
            XrefEntry::Normal { offset, generation } => Some((u64::from(*offset), (*number, *generation))),
            _ => None,
        })
        .collect();
    objects.sort_unstable();

    let mut chunk = Zeroizing::new(vec![0; CHUNK]);
    for (offset, id) in objects {
        let at = index.base + offset;
        let (head_id, head) = read_head(&mut source, at, caps)?;
        if head_id != id {
            return Err(unreadable());
        }

        match head {
            ObjectHead::Direct { mut object, .. } => {
                observer.object(id);
                observe_strings(observer, &object);
                wipe(&mut object);
            }
            ObjectHead::Stream { dict, data_start } => {
                if dict.has_type(b"XRef") {
                    continue;
                }
                // The Strip writes every /Length direct.
                let length = dict
                    .get(b"Length")
                    .and_then(Object::as_i64)
                    .ok()
                    .and_then(|length| u64::try_from(length).ok())
                    .ok_or_else(unreadable)?;
                let mut dict = Object::Dictionary(dict);
                observer.object(id);
                observe_strings(observer, &dict);
                wipe(&mut dict);
                observer.stream(length);

                let data_at = at + data_start as u64;
                if data_at + length > source.len() {
                    return Err(unreadable());
                }
                let mut done = 0;
                while done < length {
                    let n = (length - done).min(CHUNK as u64) as usize;
                    source.read_into(data_at + done, &mut chunk[..n])?;
                    observer.stream_data(&chunk[..n]);
                    done += n as u64;
                }
            }
        }
    }
    Ok(())
}

/// Reads the head of the object at `at` through a window that doubles until the head fits.
fn read_head<R: Read + Seek>(source: &mut Source<R>, at: u64, caps: &Caps) -> Result<(crate::ObjectId, ObjectHead)> {
    if at >= source.len() {
        return Err(unreadable());
    }
    let mut size = FIRST_HEAD_WINDOW.min(caps.max_head);
    loop {
        let window = source.window(at, size)?;
        let at_eof = window.len() as u64 == source.len() - at;
        if let Some(found) = parser::object_head(&window, at_eof) {
            return Ok(found);
        }
        if at_eof || size >= caps.max_head {
            return Err(unreadable());
        }
        size = size.saturating_mul(2).min(caps.max_head);
    }
}

/// Wipes every string in `object`: in a stripped file they are plaintext.
fn wipe(object: &mut Object) {
    match object {
        Object::String(bytes, _) => bytes.zeroize(),
        Object::Array(items) => items.iter_mut().for_each(wipe),
        Object::Dictionary(dict) => dict.iter_mut().for_each(|(_, value)| wipe(value)),
        Object::Stream(stream) => stream.dict.iter_mut().for_each(|(_, value)| wipe(value)),
        _ => {}
    }
}
