//! Dudect-inspired diagnostic, not dudect itself and not a leakage certificate.
//! All keys and data here are published deterministic fixtures.
#[allow(dead_code)]
#[path = "../src/lib.rs"]
mod prism;
use prism::{entropy::Entropy, Secret32};
use std::{hint::black_box, time::Instant};

fn next(s: &mut u64) -> u64 {
    *s = s.wrapping_add(0x9e3779b97f4a7c15);
    let mut z = *s;
    z = (z ^ (z >> 30)).wrapping_mul(0xbf58476d1ce4e5b9);
    z = (z ^ (z >> 27)).wrapping_mul(0x94d049bb133111eb);
    z ^ (z >> 31)
}
fn stats(v: &[f64]) -> (f64, f64) {
    let m = v.iter().sum::<f64>() / v.len() as f64;
    (
        m,
        v.iter().map(|&x| (x - m).powi(2)).sum::<f64>() / (v.len() - 1) as f64,
    )
}
fn welch(a: &[f64], b: &[f64]) -> f64 {
    let (m0, v0) = stats(a);
    let (m1, v1) = stats(b);
    let d = (v0 / a.len() as f64 + v1 / b.len() as f64).sqrt();
    if d == 0.0 {
        0.0
    } else {
        (m0 - m1) / d
    }
}
fn summary(name: &str, groups: [Vec<f64>; 2], separation: bool) {
    let mut pooled = groups[0].clone();
    pooled.extend(&groups[1]);
    pooled.sort_by(f64::total_cmp);
    let raw = welch(&groups[0], &groups[1]);
    let mut max_t = raw.abs();
    let mut cuts = Vec::new();
    for percentile in [20, 50, 95] {
        let cutoff = pooled[(pooled.len() - 1) * percentile / 100];
        let a: Vec<_> = groups[0].iter().copied().filter(|&x| x <= cutoff).collect();
        let b: Vec<_> = groups[1].iter().copied().filter(|&x| x <= cutoff).collect();
        if a.len() > 1 && b.len() > 1 {
            let t = welch(&a, &b);
            max_t = max_t.max(t.abs());
            cuts.push(format!(
                "{{\"pooled_percentile\":{percentile},\"t\":{t},\"n0\":{},\"n1\":{}}}",
                a.len(),
                b.len()
            ));
        }
    }
    let pooled_mean = pooled.iter().sum::<f64>() / pooled.len() as f64;
    let a2: Vec<_> = groups[0]
        .iter()
        .map(|&x| (x - pooled_mean).powi(2))
        .collect();
    let b2: Vec<_> = groups[1]
        .iter()
        .map(|&x| (x - pooled_mean).powi(2))
        .collect();
    let second = welch(&a2, &b2);
    let (m0, _) = stats(&groups[0]);
    let (m1, _) = stats(&groups[1]);
    println!("{{\"case\":\"{name}\",\"n_per_class\":{},\"fixed_mean_ns\":{m0},\"varied_mean_ns\":{m1},\"raw_t\":{raw},\"max_abs_t_with_cropping\":{max_t},\"centered_square_t\":{second},\"cropped\":[{}],\"negative_control\":{separation},\"interpretation\":\"diagnostic only; no pass/fail security certificate\"}}",groups[0].len(),cuts.join(","));
}
#[inline(never)]
fn deliberately_leaky(value: u8) {
    let count = if value == 0 { 1 } else { 4000 };
    let mut x = black_box(1u64);
    for _ in 0..count {
        x = black_box(x.wrapping_mul(3).wrapping_add(1));
    }
    black_box(x);
}

fn main() {
    let n = std::env::args()
        .nth(1)
        .and_then(|s| s.parse::<usize>().ok())
        .unwrap_or(10000)
        .clamp(100, 20000);
    let seed = std::env::args()
        .nth(2)
        .and_then(|s| s.parse::<u64>().ok())
        .unwrap_or(20261025);
    let retain_raw = std::env::args().nth(3).as_deref() == Some("raw");
    for case in ["seal", "open-valid", "open-rejected", "negative-control"] {
        let mut rng = seed;
        let mut labels: Vec<usize> = (0..2 * n).map(|i| i % 2).collect();
        for i in (1..labels.len()).rev() {
            let j = next(&mut rng) as usize % (i + 1);
            labels.swap(i, j);
        }
        let mut groups = [Vec::with_capacity(n), Vec::with_capacity(n)];
        let mut records = Vec::with_capacity(2 * n);
        for (i, class) in labels.into_iter().enumerate() {
            let bytes = if class == 0 {
                [0; 32]
            } else {
                std::array::from_fn(|_| (next(&mut rng) >> 32) as u8)
            };
            // All provisioning, fixture generation, allocations and input setup
            // happen outside the timer. Memory remains O(one entropy pool).
            let mut prep = Entropy::fixture(42);
            let (s, mut r) = prism::provision([9; 16], &mut prep).unwrap();
            let m = prism::ingest(Secret32::new(bytes), &mut prep).unwrap();
            let mut coins = Entropy::fixture(i as u64 + seed);
            if case.starts_with("open") {
                let mut capsule = prism::seal(s, &m, b"fixed-length-vault", &mut prep).unwrap();
                if case == "open-rejected" {
                    capsule[88] ^= 1;
                }
                let start = Instant::now();
                let _ =
                    black_box(r.attempt(black_box(&capsule), b"fixed-length-vault", &mut coins));
                let duration = start.elapsed().as_nanos() as f64;
                groups[class].push(duration);
                records.push((class, duration));
            } else if case == "seal" {
                let start = Instant::now();
                black_box(
                    prism::seal(s, black_box(&m), b"fixed-length-vault", &mut coins).unwrap(),
                );
                let duration = start.elapsed().as_nanos() as f64;
                groups[class].push(duration);
                records.push((class, duration));
            } else {
                let start = Instant::now();
                deliberately_leaky(if class == 0 { 0 } else { 1 });
                let duration = start.elapsed().as_nanos() as f64;
                groups[class].push(duration);
                records.push((class, duration));
            }
        }
        summary(case, groups, case == "negative-control");
        if retain_raw {
            let rows: Vec<_> = records
                .iter()
                .map(|(class, ns)| format!("[{class},{ns}]"))
                .collect();
            println!(
                "{{\"raw_samples_for\":\"{case}\",\"ordered_class_and_ns\":[{}]}}",
                rows.join(",")
            );
        }
    }
}
