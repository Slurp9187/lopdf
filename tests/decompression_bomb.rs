//! Bounded stream decompression (decompression-bomb handling). Covers the unbounded API and
//! the bounded one (`decompressed_content_with_limit`, `decompress_to_writer`,
//! `LoadOptions::max_decompressed_size`) for nested filters and `Document::load`.
//!
//! Bombs stream zeros through the compressor, so the process never allocates the plaintext.

use flate2::Compression;
use flate2::write::ZlibEncoder;
use std::io::Write;

use lopdf::{
    DEFAULT_MAX_DECOMPRESSED_SIZE, DecompressError, Dictionary, Document, Error, LoadOptions, Object, ObjectId,
    ObjectStream, Stream, dictionary,
};

const MIB: usize = 1024 * 1024;

/// A zlib stream that decodes to `target` zero-bytes, built without ever holding
/// `target` bytes in memory at once.
fn flate_bomb(target: usize) -> Vec<u8> {
    let mut encoder = ZlibEncoder::new(Vec::new(), Compression::best());
    let zeros = [0u8; 64 * 1024];
    let mut remaining = target;
    while remaining > 0 {
        let n = remaining.min(zeros.len());
        encoder.write_all(&zeros[..n]).unwrap();
        remaining -= n;
    }
    encoder.finish().unwrap()
}

/// Compress arbitrary bytes with zlib (always emits a valid stream).
fn zlib_compress(data: &[u8]) -> Vec<u8> {
    let mut encoder = ZlibEncoder::new(Vec::new(), Compression::best());
    encoder.write_all(data).unwrap();
    encoder.finish().unwrap()
}

fn flate_stream(content: Vec<u8>) -> Stream {
    let mut dict = Dictionary::new();
    dict.set("Filter", "FlateDecode");
    Stream::new(dict, content)
}

/// Assert a result is the memory-limit error for `expected_limit`, without ever
/// `Debug`-printing a multi-megabyte success value.
fn assert_limit_err(result: lopdf::Result<Vec<u8>>, expected_limit: usize) {
    match result.map(|v| v.len()) {
        Err(Error::Decompress(DecompressError::MemoryLimitExceeded { limit })) => {
            assert_eq!(limit, expected_limit, "error reported the wrong limit");
        }
        Ok(n) => panic!("expected MemoryLimitExceeded, but decompressed {n} bytes"),
        Err(other) => panic!("expected MemoryLimitExceeded, got {other:?}"),
    }
}

/// A single `FlateDecode` stream inflates ~32 KiB of input to 32 MiB of output
/// (~1000x) with no cap — the library materializes the whole thing.
#[test]
fn single_filter_bomb_expands_without_limit() {
    let bomb = flate_stream(flate_bomb(32 * MIB));
    assert!(
        bomb.content.len() < 128 * 1024,
        "input should be tiny: {} bytes",
        bomb.content.len()
    );

    let output = bomb.decompressed_content().expect("decodes");
    assert_eq!(output.len(), 32 * MIB, "the full output was materialized with no cap");
}

/// Chained filters multiply the amplification: under 8 KiB of input expands to
/// 32 MiB through `[FlateDecode FlateDecode]`. Additional layers reach petabyte
/// scale.
#[test]
fn chained_filter_bomb_expands_without_limit() {
    let inner = flate_bomb(32 * MIB); // layer 2 decodes this -> 32 MiB
    let outer = zlib_compress(&inner); // layer 1 decodes to `inner` (tiny)

    let mut dict = Dictionary::new();
    dict.set("Filter", vec![Object::from("FlateDecode"), Object::from("FlateDecode")]);
    let stream = Stream::new(dict, outer);

    assert!(
        stream.content.len() < 8 * 1024,
        "input should be under 8 KiB: {} bytes",
        stream.content.len()
    );

    let output = stream.decompressed_content().expect("decodes");
    assert_eq!(output.len(), 32 * MIB, "nested filters expanded fully, no cap");
}

/// With a limit supplied, the same bomb is rejected before the full 32 MiB is
/// allocated.
#[test]
fn flate_bomb_rejected_with_limit() {
    let bomb = flate_stream(flate_bomb(32 * MIB));
    assert_limit_err(bomb.decompressed_content_with_limit(4 * MIB), 4 * MIB);
}

/// A stream comfortably under the limit still decodes correctly.
#[test]
fn legit_stream_decompresses_under_limit() {
    let payload: Vec<u8> = (0..64 * 1024).map(|i| (i % 251) as u8).collect();
    let stream = flate_stream(zlib_compress(&payload));

    let output = stream
        .decompressed_content_with_limit(MIB)
        .expect("stream under the limit should decode");
    assert_eq!(output, payload);
}

/// The same stream passes or fails based on the chosen limit.
#[test]
fn custom_limit_is_enforced() {
    let stream = flate_stream(flate_bomb(2 * MIB));

    // Limit below the output size: rejected.
    assert_limit_err(stream.decompressed_content_with_limit(MIB), MIB);

    // Limit above the output size: decoded in full.
    let output = stream
        .decompressed_content_with_limit(4 * MIB)
        .expect("2 MiB output fits under a 4 MiB limit");
    assert_eq!(output.len(), 2 * MIB);
}

/// Nested filters (`/Filter [FlateDecode FlateDecode]`) amplify per layer. The
/// limit bounds each layer, so the bomb is rejected at the second layer instead
/// of expanding.
#[test]
fn chained_flate_filters_are_bounded() {
    let inner = flate_bomb(32 * MIB); // layer 2 decodes this -> 32 MiB
    let outer = zlib_compress(&inner); // layer 1 decodes to `inner` (tiny)

    let mut dict = Dictionary::new();
    dict.set("Filter", vec![Object::from("FlateDecode"), Object::from("FlateDecode")]);
    let stream = Stream::new(dict, outer);

    assert_limit_err(stream.decompressed_content_with_limit(4 * MIB), 4 * MIB);
}

/// `decompress_to_writer` enforces the same bound and leaves the caller's sink
/// untouched on rejection.
#[test]
fn decompress_to_writer_bounds_output() {
    let bomb = flate_stream(flate_bomb(32 * MIB));

    let mut sink: Vec<u8> = Vec::new();
    let result = bomb.decompress_to_writer(&mut sink, 4 * MIB);

    match result {
        Err(Error::Decompress(DecompressError::MemoryLimitExceeded { limit })) => {
            assert_eq!(limit, 4 * MIB);
        }
        other => panic!(
            "expected MemoryLimitExceeded, got {:?}",
            other.map(|n| format!("Ok({n})"))
        ),
    }
    assert!(
        sink.is_empty(),
        "sink should be untouched on rejection, got {} bytes",
        sink.len()
    );
}

// Object streams and cross-reference streams are decompressed while the document
// is loaded, so the limit is supplied through `LoadOptions` to reach them.

/// Build a PDF whose cross-reference stream (`/Type /XRef`) is a FlateDecode
/// bomb. The reference stream is decoded during `Document::load` to build the
/// xref table.
fn xref_stream_bomb_pdf(bomb: &[u8]) -> Vec<u8> {
    let mut pdf = Vec::new();
    pdf.extend_from_slice(b"%PDF-1.5\n");
    let obj_offset = pdf.len();
    pdf.extend_from_slice(b"1 0 obj\n");
    pdf.extend_from_slice(
        format!(
            "<< /Type /XRef /Size 1 /W [1 1 1] /Root 1 0 R /Filter /FlateDecode /Length {} >>\n",
            bomb.len()
        )
        .as_bytes(),
    );
    // Framing matches lopdf's parser: `stream<eol><exactly Length bytes><eol>endstream`.
    pdf.extend_from_slice(b"stream\n");
    pdf.extend_from_slice(bomb);
    pdf.extend_from_slice(b"\nendstream\nendobj\n");
    pdf.extend_from_slice(format!("startxref\n{obj_offset}\n%%EOF").as_bytes());
    pdf
}

/// A bomb in the cross-reference stream is rejected during load when
/// `max_decompressed_size` is set.
#[test]
fn load_time_xref_stream_bomb_is_rejected_with_limit() {
    let pdf = xref_stream_bomb_pdf(&flate_bomb(64 * MIB));

    let result = Document::load_mem_with_options(&pdf, LoadOptions::with_max_decompressed_size(4 * MIB));

    match result {
        Err(Error::Decompress(DecompressError::MemoryLimitExceeded { limit })) => {
            assert_eq!(limit, 4 * MIB);
        }
        Err(other) => panic!("expected MemoryLimitExceeded during load, got {other:?}"),
        Ok(_) => panic!("bomb PDF loaded without hitting the decompression limit"),
    }
}

/// `Document::load_mem` uses `LoadOptions::default()`, which bounds decompression, so
/// an xref-stream bomb just over the default limit is rejected without any opt-in.
#[test]
fn load_time_xref_stream_bomb_is_rejected_by_default() {
    let pdf = xref_stream_bomb_pdf(&flate_bomb(DEFAULT_MAX_DECOMPRESSED_SIZE + MIB));

    match Document::load_mem(&pdf) {
        Err(Error::Decompress(DecompressError::MemoryLimitExceeded { limit })) => {
            assert_eq!(limit, DEFAULT_MAX_DECOMPRESSED_SIZE);
        }
        Err(other) => panic!("expected MemoryLimitExceeded during default load, got {other:?}"),
        Ok(_) => panic!("bomb PDF loaded without hitting the default decompression limit"),
    }
}

/// The standalone `decode_xref_stream` helper applies the same default bound.
#[test]
fn decode_xref_stream_rejects_bomb_by_default() {
    let mut stream = flate_stream(flate_bomb(DEFAULT_MAX_DECOMPRESSED_SIZE + MIB));
    stream.dict.set("Type", "XRef");
    stream.dict.set("Size", 1i64);
    stream
        .dict
        .set("W", vec![Object::from(1i64), Object::from(1i64), Object::from(1i64)]);

    match lopdf::xref::decode_xref_stream(stream).map(|_| ()) {
        Err(Error::Decompress(DecompressError::MemoryLimitExceeded { limit })) => {
            assert_eq!(limit, DEFAULT_MAX_DECOMPRESSED_SIZE);
        }
        other => panic!("expected MemoryLimitExceeded, got {other:?}"),
    }
}

// `get_page_content_with_limit` bounds the whole concatenated page content, unlike
// the per-stream-unbounded `get_page_content`.

/// Build a single-page document whose `/Contents` is the given streams, and
/// return the document plus the page's object id. No page tree / fonts, so this
/// exercises `get_page_content_with_limit` directly (not the full extract path).
fn doc_with_page_streams(streams: Vec<Stream>) -> (Document, ObjectId) {
    let mut doc = Document::with_version("1.5");
    let content_refs: Vec<Object> = streams.into_iter().map(|s| doc.add_object(s).into()).collect();
    let mut page = Dictionary::new();
    page.set("Type", "Page");
    page.set("Contents", Object::Array(content_refs));
    let page_id = doc.add_object(page);
    (doc, page_id)
}

/// A bomb in a page's content stream is rejected by `get_page_content_with_limit`
/// before the full output is allocated.
#[test]
fn page_content_bomb_is_rejected_with_limit() {
    let (doc, page_id) = doc_with_page_streams(vec![flate_stream(flate_bomb(32 * MIB))]);
    assert_limit_err(doc.get_page_content_with_limit(page_id, 4 * MIB), 4 * MIB);
}

/// A page comfortably under the limit yields exactly the same bytes as the
/// unbounded `get_page_content` (including the inter-stream `\n` separators).
#[test]
fn page_content_under_limit_matches_unbounded() {
    let (doc, page_id) = doc_with_page_streams(vec![
        flate_stream(zlib_compress(b"1 0 0 1 50 100 cm")),
        flate_stream(zlib_compress(b"BT /F1 12 Tf (hi) Tj ET")),
    ]);

    let bounded = doc
        .get_page_content_with_limit(page_id, MIB)
        .expect("small page content should decode under the limit");
    assert_eq!(bounded, doc.get_page_content(page_id));
}

/// The limit is a *total-page* budget, not a per-stream one: two streams that are
/// each individually under the limit but together exceed it are rejected. (A
/// per-stream bound would have let this through.)
#[test]
fn page_content_limit_is_total_across_streams() {
    let (doc, page_id) = doc_with_page_streams(vec![
        flate_stream(flate_bomb(3 * MIB)),
        flate_stream(flate_bomb(3 * MIB)),
    ]);

    // Each stream (3 MiB) is under 4 MiB, but 3 + 3 > 4, so the page is rejected.
    assert_limit_err(doc.get_page_content_with_limit(page_id, 4 * MIB), 4 * MIB);
}

/// A large *uncompressed* (no `/Filter`) content stream is also bounded: the raw
/// bytes count against the budget, so it can't bypass the guard.
#[test]
fn page_content_uncompressed_over_limit_is_rejected() {
    let raw = Stream::new(Dictionary::new(), vec![b'x'; 2 * MIB]);
    let (doc, page_id) = doc_with_page_streams(vec![raw]);
    assert_limit_err(doc.get_page_content_with_limit(page_id, MIB), MIB);
}

/// When a stream can't be decoded for a reason *other* than the size limit (here
/// an unimplemented filter), the code falls back to the raw bytes — but that
/// fallback is still bounded, so oversized raw content is rejected rather than
/// silently appended.
#[test]
fn page_content_raw_fallback_stays_bounded() {
    let mut dict = Dictionary::new();
    dict.set("Filter", "DCTDecode"); // not implemented → decode fails with a non-limit error
    let undecodable = Stream::new(dict, vec![b'x'; 2 * MIB]);

    let (doc, page_id) = doc_with_page_streams(vec![undecodable]);
    assert_limit_err(doc.get_page_content_with_limit(page_id, MIB), MIB);
}

/// A zero limit rejects any non-empty page content without panicking (the
/// `remaining` budget uses `saturating_sub`).
#[test]
fn page_content_zero_limit_rejects_nonempty() {
    let (doc, page_id) = doc_with_page_streams(vec![flate_stream(zlib_compress(b"BT ET"))]);
    assert_limit_err(doc.get_page_content_with_limit(page_id, 0), 0);
}

/// An object stream (`/ObjStm`) is decompressed eagerly during load; the bounded
/// constructor rejects an oversized stream.
#[test]
fn object_stream_bomb_is_rejected_with_limit() {
    let mut dict = Dictionary::new();
    dict.set("Type", "ObjStm");
    dict.set("N", 1i64);
    dict.set("First", 0i64);
    dict.set("Filter", "FlateDecode");
    let stream = Stream::new(dict, flate_bomb(64 * MIB));

    match ObjectStream::new_with_limit(&stream, Some(4 * MIB)) {
        Err(Error::Decompress(DecompressError::MemoryLimitExceeded { limit })) => {
            assert_eq!(limit, 4 * MIB);
        }
        Err(other) => panic!("expected MemoryLimitExceeded, got {other:?}"),
        Ok(_) => panic!("object stream bomb was not caught"),
    }
}

/// A lenient load never skips an object stream the decompression limit stops: it
/// fails, so a capped stream's objects cannot vanish from a document the caller
/// then trusts. Measured before the fix: the load succeeded without them.
fn pdf_with_object_streams() -> Vec<u8> {
    let mut doc = Document::with_version("1.7");
    let pages_id = doc.new_object_id();
    let page_id = doc.add_object(dictionary! {
        "Type" => "Page",
        "Parent" => Object::Reference(pages_id),
    });
    for i in 0..200 {
        doc.add_object(dictionary! { "Note" => Object::Integer(i) });
    }
    doc.objects.insert(
        pages_id,
        Object::Dictionary(dictionary! {
            "Type" => "Pages",
            "Kids" => vec![Object::Reference(page_id)],
            "Count" => 1,
        }),
    );
    let catalog = doc.add_object(dictionary! {
        "Type" => "Catalog",
        "Pages" => Object::Reference(pages_id),
    });
    doc.trailer.set("Root", Object::Reference(catalog));
    let mut pdf = Vec::new();
    doc.save_modern(&mut pdf).expect("save with object streams");
    pdf
}

#[test]
fn lenient_load_fails_on_a_capped_object_stream() {
    let pdf = pdf_with_object_streams();
    assert!(Document::load_mem_with_options(&pdf, LoadOptions::default()).is_ok());
    match Document::load_mem_with_options(&pdf, LoadOptions::with_max_decompressed_size(256)) {
        Err(Error::Decompress(DecompressError::MemoryLimitExceeded { limit })) => assert_eq!(limit, 256),
        Err(other) => panic!("expected MemoryLimitExceeded, got {other:?}"),
        Ok(_) => panic!("the capped object stream was skipped, not refused"),
    }
}

/// The total across every stream a load decodes is bounded on its own: each
/// stream here is under the per-stream limit, and together they are over the
/// total.
#[test]
fn total_decompressed_size_is_bounded_across_streams() {
    let pdf = pdf_with_object_streams();
    let mut options = LoadOptions::with_max_decompressed_size(MIB);
    assert!(Document::load_mem_with_options(&pdf, options).is_ok());
    options = LoadOptions::with_max_decompressed_size(MIB);
    options.max_total_decompressed_size = Some(256);
    match Document::load_mem_with_options(&pdf, options) {
        Err(Error::Decompress(DecompressError::MemoryLimitExceeded { limit })) => assert_eq!(limit, 256),
        Err(other) => panic!("expected MemoryLimitExceeded, got {other:?}"),
        Ok(_) => panic!("the total was not bounded"),
    }
}

/// A classic table that lists the object stream (object 4) under a second number too, at the
/// same offset. Returns the file and the length of the object stream's content.
fn pdf_listing_an_object_stream_twice() -> (Vec<u8>, usize) {
    let pages = "<< /Type /Pages /Kids [] /Count 0 >>";
    let content = format!("2 0 {pages}");
    let objects = [
        "1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n".to_string(),
        format!(
            "4 0 obj\n<< /Type /ObjStm /N 1 /First 4 /Length {} >>\nstream\n{content}\nendstream\nendobj\n",
            content.len()
        ),
    ];
    let mut pdf = b"%PDF-1.5\n".to_vec();
    let mut offsets = Vec::new();
    for object in &objects {
        offsets.push(pdf.len());
        pdf.extend_from_slice(object.as_bytes());
    }
    let xref = pdf.len();
    // Object 2 lives in the object stream, which the table does not say; objects 4 and 5 both
    // point at the stream.
    pdf.extend_from_slice(
        format!(
            "xref\n0 2\n0000000000 65535 f \n{:010} 00000 n \n4 2\n{:010} 00000 n \n{:010} 00000 n \ntrailer\n<< /Size 6 /Root 1 0 R >>\nstartxref\n{xref}\n%%EOF\n",
            offsets[0], offsets[1], offsets[1]
        )
        .as_bytes(),
    );
    (pdf, content.len())
}

/// An object stream that two table entries point at is unpacked once, and counted toward the
/// total once.
#[test]
fn an_object_stream_listed_twice_counts_toward_the_total_once() {
    let (pdf, decoded) = pdf_listing_an_object_stream_twice();
    let options = LoadOptions {
        max_total_decompressed_size: Some(decoded + decoded / 2),
        ..LoadOptions::default()
    };
    let doc = Document::load_mem_with_options(&pdf, options).unwrap();
    assert!(doc.objects.contains_key(&(2, 0)));
}

/// A file written with a cross-reference stream and no object streams, whose `startxref` points
/// at nothing, so a load finds the stream by scanning.
fn xref_stream_pdf_needing_a_scan() -> Vec<u8> {
    let mut doc = Document::with_version("1.5");
    let pages = doc.add_object(dictionary! { "Type" => "Pages", "Kids" => vec![], "Count" => 0 });
    let catalog = doc.add_object(dictionary! { "Type" => "Catalog", "Pages" => Object::Reference(pages) });
    doc.trailer.set("Root", Object::Reference(catalog));
    let options = lopdf::SaveOptions::builder()
        .use_xref_streams(true)
        .use_object_streams(false)
        .build();
    let mut pdf = Vec::new();
    doc.save_with_options(&mut pdf, options).unwrap();
    assert!(!pdf.windows(7).any(|window| window == b"trailer"));
    let startxref = pdf.windows(9).rposition(|window| window == b"startxref").unwrap();
    pdf.truncate(startxref);
    pdf.extend_from_slice(b"startxref\n9\n%%EOF\n");
    pdf
}

/// The cross-reference stream that a rebuilt table is found in counts toward the total.
#[test]
fn a_scanned_cross_reference_stream_counts_toward_the_total() {
    let pdf = xref_stream_pdf_needing_a_scan();
    let doc = Document::load_mem(&pdf).unwrap();
    assert!(doc.xref_recovery.is_some());
    let options = LoadOptions {
        max_total_decompressed_size: Some(1),
        ..LoadOptions::default()
    };
    match Document::load_mem_with_options(&pdf, options) {
        Err(Error::Decompress(DecompressError::MemoryLimitExceeded { limit })) => assert_eq!(limit, 1),
        other => panic!("expected MemoryLimitExceeded, got {other:?}"),
    }
}

/// A file whose objects all sit after an inserted line: its table reads, nothing it points
/// at loads, and lenient loading rebuilds the table by scanning (upstream #636). The rebuilt
/// load decodes an object stream the first load never reached.
fn shifted_pdf_with_object_stream(padding: usize) -> Vec<u8> {
    let mut members = b"10 0 ".to_vec();
    let first = members.len();
    members.extend_from_slice(format!("<< /Pad ({}) >>", "a".repeat(padding)).as_bytes());
    let compressed = zlib_compress(&members);

    let mut pdf = b"%PDF-1.5\n".to_vec();
    let mut offsets = Vec::new();
    for (number, body) in [
        (1, "<< /Type /Catalog /Pages 2 0 R >>".to_string()),
        (2, "<< /Type /Pages /Kids [3 0 R] /Count 1 >>".to_string()),
        (3, "<< /Type /Page /Parent 2 0 R /MediaBox [0 0 200 200] >>".to_string()),
    ] {
        offsets.push(pdf.len());
        pdf.extend_from_slice(format!("{number} 0 obj\n{body}\nendobj\n").as_bytes());
    }
    offsets.push(pdf.len());
    pdf.extend_from_slice(
        format!(
            "4 0 obj\n<< /Type /ObjStm /N 1 /First {first} /Filter /FlateDecode /Length {} >>\nstream\n",
            compressed.len()
        )
        .as_bytes(),
    );
    pdf.extend_from_slice(&compressed);
    pdf.extend_from_slice(b"\nendstream\nendobj\n");

    let inserted = b"% a line added after the cross-reference table was written\n";
    pdf.splice(9..9, inserted.iter().copied());

    let startxref = pdf.len();
    pdf.extend_from_slice(format!("xref\n0 {}\n0000000000 65535 f \n", offsets.len() + 1).as_bytes());
    for offset in offsets {
        pdf.extend_from_slice(format!("{offset:010} 00000 n \n").as_bytes());
    }
    pdf.extend_from_slice(format!("trailer\n<< /Size 5 /Root 1 0 R >>\nstartxref\n{startxref}\n%%EOF\n").as_bytes());
    pdf
}

/// The total bounds the load that rebuilds the cross-reference table too: that load decodes
/// streams again, and a limit it reaches fails the load rather than falling back to the
/// table that missed its objects. Measured before the fix: the rebuild ran with no total and
/// the load succeeded.
#[test]
fn the_total_bounds_a_rebuilt_load() {
    let pdf = shifted_pdf_with_object_stream(4096);
    let document = Document::load_mem_with_options(&pdf, LoadOptions::default()).unwrap();
    assert_eq!(document.get_pages().len(), 1, "the rebuild should find the page tree");
    assert!(
        document.objects.contains_key(&(10, 0)),
        "the rebuild should decode the object stream"
    );

    let options = LoadOptions {
        max_total_decompressed_size: Some(1024),
        ..LoadOptions::default()
    };
    match Document::load_mem_with_options(&pdf, options) {
        Err(Error::Decompress(DecompressError::MemoryLimitExceeded { limit })) => assert_eq!(limit, 1024),
        Err(other) => panic!("expected MemoryLimitExceeded, got {other:?}"),
        Ok(_) => panic!("the rebuilt load was not bounded by the total"),
    }
}

/// A classic-table file whose trailer names, with `/XRefStm`, a cross-reference stream that is
/// a bomb: a hybrid-reference file.
fn hybrid_pdf_with_xref_stream_bomb(bomb: &[u8]) -> Vec<u8> {
    let mut pdf = b"%PDF-1.5\n".to_vec();
    let mut offsets = Vec::new();
    for (number, body) in [
        (1, "<< /Type /Catalog /Pages 2 0 R >>"),
        (2, "<< /Type /Pages /Kids [] /Count 0 >>"),
    ] {
        offsets.push(pdf.len());
        pdf.extend_from_slice(format!("{number} 0 obj\n{body}\nendobj\n").as_bytes());
    }
    let stream_start = pdf.len();
    offsets.push(stream_start);
    pdf.extend_from_slice(
        format!(
            "3 0 obj\n<< /Type /XRef /Size 4 /W [1 1 1] /Filter /FlateDecode /Length {} >>\nstream\n",
            bomb.len()
        )
        .as_bytes(),
    );
    pdf.extend_from_slice(bomb);
    pdf.extend_from_slice(b"\nendstream\nendobj\n");
    let startxref = pdf.len();
    pdf.extend_from_slice(b"xref\n0 4\n0000000000 65535 f \n");
    for offset in offsets {
        pdf.extend_from_slice(format!("{offset:010} 00000 n \n").as_bytes());
    }
    pdf.extend_from_slice(
        format!("trailer\n<< /Size 4 /Root 1 0 R /XRefStm {stream_start} >>\nstartxref\n{startxref}\n%%EOF\n")
            .as_bytes(),
    );
    pdf
}

/// The stream a hybrid-reference file names is decoded like any other, and a decompression
/// limit it reaches fails a lenient load rather than being ignored as an unreadable stream.
/// Measured before the fix: the load succeeded.
#[test]
fn a_hybrid_cross_reference_stream_over_the_limit_fails_the_load() {
    let pdf = hybrid_pdf_with_xref_stream_bomb(&flate_bomb(64 * MIB));
    match Document::load_mem_with_options(&pdf, LoadOptions::with_max_decompressed_size(4 * MIB)) {
        Err(Error::Decompress(DecompressError::MemoryLimitExceeded { limit })) => assert_eq!(limit, 4 * MIB),
        Err(other) => panic!("expected MemoryLimitExceeded, got {other:?}"),
        Ok(_) => panic!("the hybrid cross-reference stream bomb was ignored"),
    }
}

/// When the table is rebuilt by scanning, a cross-reference stream over the limit fails the
/// load even though another one decodes. Measured before the fix: the load succeeded.
#[test]
fn a_scanned_cross_reference_stream_over_the_limit_fails_the_load_beside_a_good_one() {
    let mut pdf = xref_stream_pdf_needing_a_scan();
    let startxref = pdf.windows(9).rposition(|window| window == b"startxref").unwrap();
    let bomb = flate_bomb(64 * MIB);
    let mut object = format!(
        "90 0 obj\n<< /Type /XRef /Size 91 /W [1 1 1] /Filter /FlateDecode /Length {} >>\nstream\n",
        bomb.len()
    )
    .into_bytes();
    object.extend_from_slice(&bomb);
    object.extend_from_slice(b"\nendstream\nendobj\n");
    pdf.splice(startxref..startxref, object);

    let options = LoadOptions::with_max_decompressed_size(4 * MIB);
    match Document::load_mem_with_options(&pdf, options) {
        Err(Error::Decompress(DecompressError::MemoryLimitExceeded { limit })) => assert_eq!(limit, 4 * MIB),
        Err(other) => panic!("expected MemoryLimitExceeded, got {other:?}"),
        Ok(_) => panic!("the scanned cross-reference stream bomb was ignored"),
    }
}
