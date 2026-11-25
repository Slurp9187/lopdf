use criterion::{Criterion, Throughput, criterion_group, criterion_main};
use lopdf::encryption::crypt_filters::{Aes256CryptFilter, CryptFilter};
use lopdf::encryption::stream::MAX_EXPANSION;

/// Streams 64 MiB of AES-256 ciphertext through the chunk decipher 64 KiB at a time.
fn bench_aes_chunked_decrypt(c: &mut Criterion) {
    const CHUNK: usize = 64 * 1024;
    let key = [0x42u8; 32];
    let plaintext: Vec<u8> = (0..64 * 1024 * 1024).map(|i: usize| (i * 7 + 3) as u8).collect();
    let ciphertext = Aes256CryptFilter.encrypt(&key, &plaintext).unwrap();

    let mut group = c.benchmark_group("decrypt_stream");
    group.sample_size(10);
    group.throughput(Throughput::Bytes(ciphertext.len() as u64));
    group.bench_function("aes256_64k_chunks", |b| {
        let mut output = vec![0u8; CHUNK + MAX_EXPANSION];
        b.iter(|| {
            let mut decipher = Aes256CryptFilter.chunked_decrypt(&key).unwrap().unwrap();
            let mut total = 0;
            for piece in ciphertext.chunks(CHUNK) {
                total += decipher.update(piece, &mut output).unwrap();
            }
            total += decipher.finish(&mut output).unwrap();
            assert_eq!(total, plaintext.len());
        });
    });
    group.finish();
}

criterion_group!(benches, bench_aes_chunked_decrypt);
criterion_main!(benches);
