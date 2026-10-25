//! Exact audit of correlated input shares, using the production multiplier.
//! Synthetic F5 values only; this binary is never an operational key handler.
#[allow(dead_code)]
#[path = "../src/lib.rs"]
mod prism;

fn main() {
    let mut executions = 0u64;
    let mut comparisons = 0u64;
    let mut references = Vec::new();
    // v = u + offset covers correlated masks, including identical mask limbs.
    // Each marginal is uniform; independence between operands is NOT assumed.
    for offset in 0..5u64 {
        let mut baseline = None;
        for a in 0..5u64 {
            for b in 0..5u64 {
                let mut hist = vec![[0u64; 5]; 19];
                for u in 0..5u64 {
                    for da in 0..5u64 {
                        for db in 0..5u64 {
                            for rho in 0..5u64 {
                                let (value, trace) = prism::toy_mul(a, b, u, (u + offset) % 5, da, db, rho);
                                assert_eq!(value, a * b % 5);
                                assert_eq!(trace.len(), hist.len());
                                for (i, (_, wire)) in trace.iter().enumerate() {
                                    hist[i][*wire as usize] += 1;
                                }
                                executions += 1;
                            }
                        }
                    }
                }
                if let Some(expected) = &baseline { assert_eq!(&hist, expected); }
                else { baseline = Some(hist); }
                comparisons += 19;
            }
        }
        references.push(baseline.unwrap());
    }
    // Here both complete input shares are identical: the actual squaring case.
    let mut square_baseline = None;
    let mut squares = 0;
    for a in 0..5u64 {
        let mut hist = vec![[0u64; 5]; 19];
        for u in 0..5u64 {
            for da in 0..5u64 {
                for db in 0..5u64 {
                    for rho in 0..5u64 {
                        let (value, trace) = prism::toy_mul(a, a, u, u, da, db, rho);
                        assert_eq!(value, a * a % 5);
                        for (i, (_, wire)) in trace.iter().enumerate() { hist[i][*wire as usize] += 1; }
                        squares += 1;
                    }
                }
            }
        }
        if let Some(expected) = &square_baseline { assert_eq!(&hist, expected); }
        else { square_baseline = Some(hist); }
    }
    // Broken control: retain correlated operands without independently refreshing
    // them. Its cross product u*(a-u) depends on the logical squaring input a.
    let mut broken = [[0u64; 5]; 5];
    for a in 0..5usize {
        for u in 0..5usize { broken[a][u * ((a + 5 - u) % 5) % 5] += 1; }
    }
    let distance: u64 = broken[0].iter().zip(broken[1]).map(|(&a, b)| a.abs_diff(b)).sum();
    assert!(distance > 0);
    let tv = distance as f64 / 10.0;
    let square_reference = square_baseline.unwrap();
    println!("{{\"correlated_executions\":{executions},\"correlated_wire_comparisons\":{comparisons},\"squaring_executions\":{squares},\"squaring_wire_comparisons\":95,\"observed_wires\":19,\"distribution_mismatches\":0,\"reference_histograms_per_offset\":{references:?},\"squaring_reference_histograms\":{square_reference:?},\"missing_refresh_control_tv\":{tv},\"scope\":\"F5 generic multiplier gadget; not whole-program or hardware verification\"}}");
}
