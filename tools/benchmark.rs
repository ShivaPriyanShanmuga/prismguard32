#[allow(dead_code)]
#[path = "../src/lib.rs"]
mod prism;
use prism::{entropy::Entropy, Secret32};
use std::{hint::black_box, time::Instant};
fn output(name: &str, mut values: Vec<u128>) {
    values.sort();
    println!(
        "{{\"case\":\"{name}\",\"samples\":{},\"median_ns\":{},\"p95_ns\":{}}}",
        values.len(),
        values[values.len() / 2],
        values[values.len() * 95 / 100]
    );
}
fn main() {
    let mut seals = Vec::new();
    let mut opens = Vec::new();
    let mut full = Vec::new();
    for seed in 0..1000 {
        let mut e = Entropy::fixture(seed);
        let (s, mut r) = prism::provision([7; 16], &mut e).unwrap();
        let m = prism::ingest(Secret32::new([0x73; 32]), &mut e).unwrap();
        let mut open_e = Entropy::fixture(seed + 1000);
        let start = Instant::now();
        let c = prism::seal(s, black_box(&m), b"vault/benchmark", &mut e).unwrap();
        seals.push(start.elapsed().as_nanos());
        let start = Instant::now();
        let _ = black_box(r.attempt(&c, b"vault/benchmark", &mut open_e).unwrap());
        opens.push(start.elapsed().as_nanos());
    }
    for _ in 0..200 {
        let start = Instant::now();
        let mut e = Entropy::system().unwrap();
        let (s, mut r) = prism::provision(prism::entropy::fresh_id().unwrap(), &mut e).unwrap();
        let m = prism::ingest(Secret32::new([0x73; 32]), &mut e).unwrap();
        let c = prism::seal(s, &m, b"vault/benchmark", &mut e).unwrap();
        let _ = black_box(
            r.attempt(&c, b"vault/benchmark", &mut Entropy::system().unwrap())
                .unwrap(),
        );
        full.push(start.elapsed().as_nanos());
    }
    output("seal_rng_provisioning_excluded", seals);
    output("open_rng_provisioning_excluded", opens);
    output(
        "end_to_end_including_os_rng_pools_ingress_and_provisioning",
        full,
    );
}
