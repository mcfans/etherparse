use std::io::IoSlice;

use criterion::{black_box, criterion_group, criterion_main, Criterion};
use etherparse::TcpHeader;

fn criterion_benchmark(c: &mut Criterion) {
    let data = vec![23; 16 * 1024];
    let mut tcp_header = TcpHeader::default();
    tcp_header.ack = true;
    tcp_header.acknowledgment_number = 1233218904;
    tcp_header.sequence_number = 456231323;

    c.bench_function("Continuous", |b| {
        b.iter(|| tcp_header.calc_checksum_ipv4_raw([10, 0, 0, 1], [1, 2, 3, 4], black_box(&data)))
    });

    c.bench_function("Simd", |b| {
        b.iter(|| {
            tcp_header.calc_checksum_ipv4_raw_with_slices_simd(
                [10, 0, 0, 1],
                [1, 2, 3, 4],
                black_box(&[IoSlice::new(&data)]),
            )
        })
    });

    let data1 = vec![23; 2389];
    let data2 = vec![46; 16 * 1024 - 2389];
    let mut tcp_header = TcpHeader::default();
    tcp_header.ack = true;
    tcp_header.acknowledgment_number = 1233218904;
    tcp_header.sequence_number = 456231323;
    c.bench_function("Simd with splited checksum", |b| {
        b.iter(|| {
            tcp_header.calc_checksum_ipv4_raw_with_slices_simd(
                [10, 0, 0, 1],
                [1, 2, 3, 4],
                black_box(&[IoSlice::new(&data1), IoSlice::new(&data2)]),
            )
        })
    });
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);
