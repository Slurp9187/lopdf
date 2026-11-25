# Streaming Strip: remove a PDF's encryption in bounded memory

Fork-only work on `topic/stream-strip`, built in pull requests into that branch. It is the lopdf
part of
[encrypted-file-vault#1193](https://github.com/Slurp9187/encrypted-file-vault/issues/1193)
("Streaming for every encryption format"), adopted on EFV's side as slice A7.

## Why

lopdf reads a whole file into memory and builds a whole `Document` before it can decrypt anything,
and EFV's PDF protocol inherits that. #1193 requires that every format process a file in memory that
does not grow with the file.

EFV never writes PDF encryption. A PDF is either **Preserved** (kept encrypted as is, which needs a
password check that writes nothing) or **Stripped** (the Standard security handler's encryption is
removed). This engine covers both. Encrypting and re-encrypting are out of scope.

## Verdict

| Operation | Verdict | Memory |
|---|---|---|
| Strip | Feasible for well-formed files; broken ones take a named fallback | flat in the stream bytes |
| Preserve's password check | Feasible: tail, trailer chain, `/Encrypt`; decrypts no content | one xref section |

Why it works:

- `decrypt_object(state, id, &mut Object)` needs no `Document`.
- Decryption runs on the raw, still-filtered stream bytes, so content streams are never decoded.
- `EncryptionState::decode` needs only the trailer (`/Encrypt`, `/ID`) and the Encrypt dictionary.
- Members of an object stream are never encrypted one by one: the container is decrypted whole, as
  one stream, and copied without decoding it.

Memory is an index that grows with the object count (about 24 bytes an object, capped at 1,000,000
objects), 64 KiB wiped buffers, and capped decoding of cross-reference streams and, only to resolve
an indirect `/Length`, one object stream. Nothing grows with the payload.

### Fallback

`Error::NeedsWholeDocument(StripFallback)`: the caller discards the output and runs the capped
whole-document path instead. It is returned when:

- the cross-reference chain cannot be resolved (the file would need reconstruction);
- a stream's `/Length` cannot be resolved, or `endstream` is not where it says;
- an `N G obj` header does not match its cross-reference id and generation;
- an object's head is larger than the 4 MiB window;
- `/Encrypt` sits inside an object stream;
- an older trailer has `/Encrypt` but the newest does not;
- a compressed entry's container is not a generation-0 `/Type /ObjStm` object.

### Refused, as today

Input of 4 GiB or more, an unknown security handler, `/EFF` different from `/StmF`, a string or
stream that fails to decrypt, a wrong password, and a decompression cap exceeded.

### Output

One flattened revision: the newest version of each object, in input offset order, with ids and
generations kept. The linearization dictionary, hint streams, old cross-reference streams and
`/Encrypt` are dropped, `/Crypt` filters are stripped from streams, and a new cross-reference table
is written (a cross-reference stream, with the header raised to 1.5, when compressed entries exist).
Objects without strings are copied byte for byte.

## API

```rust
lopdf::strip::inspect<R: Read + Seek>(r, password: Option<&str>) -> lopdf::Result<Inspection>
lopdf::strip::strip<R: Read + Seek, W: Write>(r, w, &StripOptions, Option<&mut dyn StripObserver>)
    -> lopdf::Result<StripReport>
lopdf::strip::verify_stripped<R: Read + Seek>(written, &expected) -> lopdf::Result<()>
```

The whole-buffer APIs do not change.

### Errors

There is no separate error type; `strip` and `inspect` return `lopdf::Error`, so a caller maps both
paths the same way:

- a wrong password is `Error::InvalidPassword`, as for a whole-document load;
- a string or stream that fails to decrypt is `Error::Decryption(_)`, with the same inner variant the
  whole-document path returns for the same bytes;
- caps are `Error::Decompress(MemoryLimitExceeded)`, an unknown handler is
  `UnsupportedSecurityHandler`, and reader errors (a cancelling reader) are `Error::IO`;
- the one new variant is `Error::NeedsWholeDocument(StripFallback)`, a reason with no bytes.

`inspect` does not fail on a wrong password: `Inspection.password` is
`PasswordCheck::{NotGiven, User, Owner, Wrong}`.

### `inspect`

`Inspection { encrypted, password, signed: Signed::{Yes, No, Unknown}, needs_whole_document }`.

- `signed` is `Yes` only for a `/FT /Sig` field with a `/V`, found by walking Root, `/AcroForm`,
  `/Fields` and `/Kids`. An unsigned signature field is `No`. The walk stops at 10,000 fields and
  answers `Unknown`, which the caller should treat as signed.
- Reading Root or `/AcroForm` may need one object stream decrypted, so the password is needed when
  they are compressed.
- `needs_whole_document` covers what the index pass can see. `strip` can still return it later, for
  a stream whose `/Length` fails.

## Secret hygiene

The baseline is `topic/secret-hygiene`: every key, password and derived value is wiped and redacted,
and password hashes are compared in constant time. EFV's secure-gate rules, § Streaming, apply.

- The 64 KiB chunk buffers and the decipher state (the RC4 state, AES-CBC's held-back block) are
  wiped. A growable buffer is never grown past the capacity it reserved.
- Plaintext moves through a fixed chunk, never through `io::copy` or a std `BufReader`, whose
  buffers are not wiped.
- One decipher per object: its key schedule is dropped when the object is done.
- No key, password or plaintext in an error, a report or a log, and no `Debug` that shows them.
- Parsed objects holding plaintext strings are wiped before they are dropped.
- Residue lopdf cannot close is named: buffers that `nom` and `flate2` grow internally, and copies
  in callee stack frames. A zero-on-free allocator in the application is the backstop.

Each pull request says which of these it touched.

## Slices

Each slice is tested on its own, and every guard it adds is falsified: the line is removed and the
test is seen to fail.

1. **Streaming decipher** (`src/encryption/stream.rs`). RC4 keeping its state, AES-CBC block by
   block holding back the final block, and Identity. The plaintext length of an AES stream comes
   from decrypting its last 32 bytes first. `CryptFilter::chunked_decrypt()` defaults to `None`, so
   the trait stays compatible. Property test: every chunk split matches whole-buffer `decrypt`.
2. **`parser::object_head`**. Parses `N G obj` and a direct object or a stream dictionary without
   a `Reader`. A window is accepted only when `endobj`, or `stream` and its end of line, ends inside
   it or the window reaches the end of the file; otherwise the window doubles, up to the cap.
3. **Index pass**. `startxref` from a tail slice; classic tables parsed incrementally, keeping free
   entries; cross-reference streams decoded under non-optional caps; `/Prev` and `/XRefStm`. The
   oracle is `Reader`'s table on every fixture. A test for the object-count cap.
4. **`inspect`**, as above.
5. **Copy pass** for files without compressed entries, writing a classic table. A positioned source
   with its own wiped buffer, a 64-bit counting writer, `Writer::write_object`. The oracle is the
   objects of `Document::load` over the output against those of a password load of the input. The
   error parity test runs every `tests/fixtures/crypt/` fixture through both paths.
6. **Object streams, cross-reference stream output and indirect `/Length`**, through a minimal
   container reader: decrypt, inflate under the caps into a wiped buffer, read one integer, wipe.
7. **Drops and policy**: linearization and hint streams, `/Crypt` stripping, `/EFF` refusal,
   trailer `/Encrypt` consistency, a direct `/Encrypt` dictionary.
8. **Bounded `/Length` recovery**: a chunked scan for a unique `endstream` followed by `endobj`,
   bounded by the next object's offset. It shrinks the fallback set.
9. **Read-back verify**. `StripObserver` sees each object's plaintext strings and stream chunks from
   the input. `verify_stripped` re-reads the output, independently of the writer, and folds one
   ordered BLAKE3 digest, separated by (id, generation, kind, length). Falsified by flipping a byte,
   dropping an object and swapping two.
10. **Memory test** (`tests/strip_memory.rs`, its own test binary with a counting global allocator):
    the rise at 64 MiB minus the rise at 4 MiB stays under 1 MiB, and the rise stays under 16 MiB,
    for RC4, AES-128 and AES-256 inputs. A 256 MiB run is `#[ignore]`d for release builds. Each
    guard is named in a comment and falsified.

## Branch and merge

`main` stays a pure mirror of upstream's `main`. The fix topics branch from it, so each can go
upstream as a pull request. `topic/stream-strip` is fork-only: it branches from a `fork` build,
because it builds on every fix topic, and holds this plan and the engine. Each slice, or a few
closely related ones, is a pull request into `topic/stream-strip` from its own branch
(`strip/<slice>`); its issue is closed by hand, since nothing merges into the default branch.
`.git/rebuild-fork.sh` builds `fork` from `main` and the topics, `topic/stream-strip` last, and tags
it; EFV pins the tag's revision.
