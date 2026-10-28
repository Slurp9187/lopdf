//! Real numbers keep their precision from load to save: a real used to be held as an `f32`, which
//! rounded `595.303937007874` (an A4 width in points) to `595.30396`.

use lopdf::content::Content;
use lopdf::{Document, Object, dictionary};

/// A one-page document whose page box and a dictionary value carry `value`.
fn document_with(value: f64) -> Document {
    let mut doc = Document::with_version("1.7");
    let pages_id = doc.new_object_id();
    let page_id = doc.add_object(dictionary! {
        "Type" => "Page",
        "Parent" => pages_id,
        "MediaBox" => vec![0.into(), 0.into(), value.into(), 841.889763779528.into()],
        "UserUnit" => value,
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
fn a_real_survives_load_and_save_in_full() {
    let mut saved = Vec::new();
    document_with(595.303937007874).save_to(&mut saved).unwrap();
    let text = String::from_utf8_lossy(&saved);
    assert!(text.contains("595.303937007874"), "{text}");
    assert!(text.contains("841.889763779528"), "{text}");

    // Loaded and saved again, the bytes it was written as come back.
    let mut doc = Document::load_mem(&saved).unwrap();
    let page = doc.page_iter().next().unwrap();
    let dict = doc.get_dictionary(page).unwrap();
    let media_box = dict.get(b"MediaBox").and_then(Object::as_array).unwrap();
    assert_eq!(media_box[2].as_f64().unwrap(), 595.303937007874);
    assert_eq!(
        dict.get(b"UserUnit").and_then(Object::as_f64).unwrap(),
        595.303937007874
    );

    let mut resaved = Vec::new();
    doc.save_to(&mut resaved).unwrap();
    assert!(String::from_utf8_lossy(&resaved).contains("595.303937007874"));
}

#[test]
fn a_real_in_a_content_stream_survives_decode_and_encode() {
    let content = Content::decode(b"0.123456789012 0 0 1 72.000000001 720 cm").unwrap();
    let encoded = String::from_utf8(content.encode().unwrap()).unwrap();
    assert!(encoded.contains("0.123456789012"), "{encoded}");
    assert!(encoded.contains("72.000000001"), "{encoded}");
}

#[test]
fn an_f32_converts_to_the_decimal_it_stands_for() {
    // Widened bit for bit, 0.1f32 is 0.10000000149011612.
    assert_eq!(Object::from(0.1f32), Object::Real(0.1));
    assert_eq!(Object::from(0.1f32).as_f32().unwrap(), 0.1f32);
    assert_eq!(
        Object::Real(595.303937007874).as_float().unwrap(),
        595.303937007874f64 as f32
    );
}
