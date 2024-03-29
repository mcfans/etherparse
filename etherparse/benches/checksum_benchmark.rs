use std::io::IoSlice;

use criterion::{black_box, criterion_group, criterion_main, Criterion};
use etherparse::TcpHeader;


fn criterion_benchmark(c: &mut Criterion) {
    let data = vec![23; 807];
    let mut tcp_header = TcpHeader::default();
    tcp_header.ack = true;
    tcp_header.acknowledgment_number = 1233218904;
    tcp_header.sequence_number = 456231323;

    c.bench_function("Continuous", |b| 
        b.iter(|| 
            tcp_header.calc_checksum_ipv4_raw([10, 0, 0, 1], [1, 2, 3, 4], black_box(&data))
        )
    );

    c.bench_function("Sparse", |b| 
        b.iter(|| 
            tcp_header.calc_checksum_ipv4_raw_with_slices([10, 0, 0, 1], [1, 2, 3, 4], black_box(&[IoSlice::new(&data)]))
        )
    );
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);