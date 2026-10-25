//! Audit-only executable. Never accepts real keys. Logs synthetic test data.
#[allow(dead_code)]
#[path = "../src/lib.rs"]
mod prism;
use prism::{
    entropy::Entropy,
    field::{Arithmetic, F61},
    Secret32,
};
use std::collections::BTreeMap;
fn hex(data: &[u8]) -> String {
    data.iter().map(|b| format!("{b:02x}")).collect()
}
fn vectors() {
    for seed in 0..512u64 {
        let mut setup = Entropy::fixture(seed);
        let id = std::array::from_fn(|i| seed.wrapping_add(i as u64 * 17) as u8);
        let (s, mut r) = prism::provision(id, &mut setup).unwrap();
        let bytes = std::array::from_fn(|i| seed.wrapping_add(i as u64 * 31) as u8);
        let m = prism::ingest(Secret32::new(bytes), &mut setup).unwrap();
        let context = if seed < 6 {
            vec![0xC3; [0, 1, 7, 8, 255, 256][seed as usize]]
        } else {
            format!("vector/{seed}/λ").into_bytes()
        };
        let mut seal_entropy = Entropy::fixture(seed + 10000);
        let c = prism::seal(s, &m, &context, &mut seal_entropy).unwrap();
        let mut open_entropy = Entropy::fixture(seed + 20000);
        assert_eq!(
            r.attempt(&c, &context, &mut open_entropy).unwrap().expose(),
            &bytes
        );
        println!("{{\"seed\":{seed},\"secret\":\"{}\",\"context\":\"{}\",\"capsule\":\"{}\",\"seal_words\":{},\"open_words\":{}}}",hex(&bytes),hex(&context),hex(&c),seal_entropy.used(),open_entropy.used());
    }
}
fn model() {
    let mut baseline: Option<Vec<[u64; 5]>> = None;
    let mut checked = 0;
    let mut wire_count = 0;
    let mut negative = BTreeMap::new();
    for a in 0..5u64 {
        for b in 0..5u64 {
            let mut hist: Vec<[u64; 5]> = Vec::new();
            let mut unsafe_hist = [0u64; 5];
            for u in 0..5u64 {
                for v in 0..5u64 {
                    for da in 0..5u64 {
                        for db in 0..5u64 {
                            for rho in 0..5u64 {
                                let (output, trace) = prism::toy_mul(a, b, u, v, da, db, rho);
                                assert_eq!(output, a * b % 5);
                                if hist.is_empty() {
                                    hist = vec![[0; 5]; trace.len()];
                                    wire_count = trace.len();
                                }
                                for (i, (_, value)) in trace.iter().enumerate() {
                                    hist[i][*value as usize] += 1;
                                }
                                // Deliberately unsafe: summing three cross terms without rho.
                                let x = (u + da) % 5;
                                let y = (v + db) % 5;
                                let unsafe_cross = (a * b + 5 - x * y % 5) % 5;
                                unsafe_hist[unsafe_cross as usize] += 1;
                                checked += 1;
                            }
                        }
                    }
                }
            }
            if let Some(expected) = &baseline {
                assert_eq!(&hist, expected, "single-wire dependence a={a},b={b}");
            } else {
                baseline = Some(hist);
            }
            negative.insert((a, b), unsafe_hist);
        }
    }
    let h0 = negative[&(0, 0)];
    let h1 = negative[&(1, 1)];
    let tv = h0
        .iter()
        .zip(h1)
        .map(|(&x, y)| (x as f64 - y as f64).abs())
        .sum::<f64>()
        / (2.0 * 3125.0);
    assert!(tv > 0.19);
    println!("{{\"field\":5,\"logical_input_pairs\":25,\"random_assignments_per_pair\":3125,\"executions\":{checked},\"observed_wires\":{wire_count},\"single_wire_distribution_checks\":{},\"single_wire_mismatches\":0,\"unsafe_cross_sum_total_variation\":{tv},\"two_output_shares_reconstruct_product\":true,\"scope\":\"exact same generic multiplier schedule, instantiated over F5; not an exhaustive whole-protocol or hardware proof\"}}",wire_count*25);
}
fn arithmetic() {
    let mut e = Entropy::fixture(0xA11CE);
    use prism::entropy::Coins;
    for _ in 0..20000 {
        let a = e.draw();
        let b = e.draw();
        println!(
            "{a},{b},{},{},{}",
            F61::add(a, b),
            F61::sub(a, b),
            F61::mul(a, b)
        );
        if e.remaining() < 2 {
            e = Entropy::fixture(a ^ b);
        }
    }
}
fn fuzz() {
    let mut e = Entropy::fixture(0xF022);
    use prism::entropy::Coins;
    let mut rejected = 0;
    for seed in 0..2000u64 {
        if e.remaining() < 8 {
            e = Entropy::fixture(seed + 0xF022);
        }
        let mut setup = Entropy::fixture(seed);
        let (s, mut r) = prism::provision([3; 16], &mut setup).unwrap();
        let m = prism::ingest(Secret32::new([71; 32]), &mut setup).unwrap();
        let c = prism::seal(s, &m, b"fuzz", &mut setup).unwrap();
        let mut changed = c;
        let mut positions = Vec::new();
        let count = (e.draw() % 6 + 1) as usize;
        for _ in 0..count {
            let mut bit = (e.draw() % (104 * 8)) as usize;
            while positions.contains(&bit) {
                bit = (bit + 1) % (104 * 8);
            }
            positions.push(bit);
            changed[bit / 8] ^= 1 << (bit % 8);
        }
        assert!(r
            .attempt(&changed, b"fuzz", &mut Entropy::fixture(seed + 3000))
            .is_err());
        rejected += 1;
        assert_eq!(
            r.attempt(&c, b"fuzz", &mut Entropy::fixture(seed + 5000))
                .unwrap()
                .expose(),
            &[71; 32]
        );
    }
    println!("{{\"mutated_capsules_rejected\":{rejected},\"valid_recoveries_after_rejection\":{rejected},\"generator\":\"reproducible synthetic mutations; not a coverage-guided fuzzer\"}}");
}
fn main() {
    match std::env::args().nth(1).as_deref() {
        Some("vectors") => vectors(),
        Some("model") => model(),
        Some("arithmetic") => arithmetic(),
        Some("fuzz") => fuzz(),
        _ => panic!("audit-only: vectors|model|arithmetic|fuzz"),
    }
}
