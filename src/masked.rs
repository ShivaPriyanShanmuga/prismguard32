//! Two-share arithmetic with refresh before every binary secret operation.
//! First-order, single-field-wire model only; not a physical leakage proof.
use super::{
    entropy::{wipe_words, Coins},
    field::{Arithmetic, F61},
};

pub struct Share {
    pub(super) left: u64,
    pub(super) right: u64,
}
impl Drop for Share {
    fn drop(&mut self) {
        wipe_words(std::slice::from_mut(&mut self.left));
        wipe_words(std::slice::from_mut(&mut self.right));
    }
}

#[cfg(feature = "audit")]
thread_local! {static TRACE:std::cell::RefCell<Option<Vec<(&'static str,u64)>>> = const {std::cell::RefCell::new(None)};}
#[cfg(feature = "audit")]
pub fn audit_start() {
    TRACE.with(|t| *t.borrow_mut() = Some(Vec::new()));
}
#[cfg(feature = "audit")]
pub fn audit_end() -> Vec<(&'static str, u64)> {
    TRACE.with(|t| t.borrow_mut().take().unwrap_or_default())
}
#[inline(always)]
fn observe(label: &'static str, value: u64) -> u64 {
    #[cfg(feature = "audit")]
    TRACE.with(|t| {
        if let Some(events) = t.borrow_mut().as_mut() {
            events.push((label, value));
        }
    });
    #[cfg(not(feature = "audit"))]
    let _ = label;
    value
}

pub fn public(value: u64) -> Share {
    Share {
        left: value,
        right: 0,
    }
}
/// Trusted boundary: a logical raw value enters two-share representation.
pub fn input<C: Coins>(value: u64, coins: &mut C) -> Share {
    let left = coins.draw();
    Share {
        left,
        right: F61::sub(value, left),
    }
}
/// Only call for intentionally public capsule words/status, or after success.
#[inline(never)]
pub fn release(value: &Share) -> u64 {
    F61::add(value.left, value.right)
}

#[inline(never)]
pub fn refresh<F: Arithmetic, C: Coins>(x: &Share, coins: &mut C) -> Share {
    observe("refresh.input_left", x.left);
    observe("refresh.input_right", x.right);
    let delta = observe("refresh.delta", coins.draw());
    let left = observe("refresh.output_left", F::add(x.left, delta));
    let right = observe("refresh.output_right", F::sub(x.right, delta));
    Share { left, right }
}
#[inline(never)]
pub fn add<C: Coins>(x: &Share, y: &Share, coins: &mut C) -> Share {
    let y = refresh::<F61, _>(y, coins);
    let left = observe("add.output_left", F61::add(x.left, y.left));
    let right = observe("add.output_right", F61::add(x.right, y.right));
    Share { left, right }
}
#[inline(never)]
pub fn sub<C: Coins>(x: &Share, y: &Share, coins: &mut C) -> Share {
    let y = refresh::<F61, _>(y, coins);
    let left = observe("sub.output_left", F61::sub(x.left, y.left));
    let right = observe("sub.output_right", F61::sub(x.right, y.right));
    Share { left, right }
}
pub fn add_public(x: &Share, y: u64) -> Share {
    Share {
        left: observe("add_public.left", F61::add(x.left, y)),
        right: observe("add_public.right", x.right),
    }
}
pub fn scale(x: &Share, y: u64) -> Share {
    Share {
        left: observe("scale.left", F61::mul(x.left, y)),
        right: observe("scale.right", F61::mul(x.right, y)),
    }
}

/// Same generic schedule is instantiated over F61 in production and F5 in the
/// exhaustive audit. Both inputs are refreshed independently, including x*x.
/// Never combine unmasked cross terms before adding the fresh rho mask.
#[inline(never)]
pub fn multiply<F: Arithmetic, C: Coins>(x: &Share, y: &Share, coins: &mut C) -> Share {
    let a = refresh::<F, _>(x, coins);
    let b = refresh::<F, _>(y, coins);
    let rho = observe("mul.rho", coins.draw());
    let w00 = observe("mul.w00", F::mul(a.left, b.left));
    let w01 = observe("mul.w01", F::mul(a.left, b.right));
    let w10 = observe("mul.w10", F::mul(a.right, b.left));
    let w11 = observe("mul.w11", F::mul(a.right, b.right));
    let left = observe("mul.output_left", F::add(w00, rho));
    let t = observe("mul.masked_cross", F::sub(w01, rho));
    let t = observe("mul.masked_cross_plus10", F::add(t, w10));
    let right = observe("mul.output_right", F::add(t, w11));
    Share { left, right }
}
pub fn mul<C: Coins>(x: &Share, y: &Share, coins: &mut C) -> Share {
    multiply::<F61, _>(x, y, coins)
}

pub fn power17<C: Coins>(x: &Share, coins: &mut C) -> Share {
    let x2 = mul(x, x, coins);
    let x4 = mul(&x2, &x2, coins);
    let x8 = mul(&x4, &x4, coins);
    let x16 = mul(&x8, &x8, coins);
    mul(&x16, x, coins)
}
pub fn power<C: Coins>(x: &Share, exponent: u64, coins: &mut C) -> Share {
    let mut y = public(1);
    for bit in (0..61).rev() {
        y = mul(&y, &y, coins);
        // Public fixed exponent, never a secret-dependent branch.
        if (exponent >> bit) & 1 != 0 {
            y = mul(&y, x, coins);
        }
    }
    y
}

#[cfg(feature = "audit")]
pub fn toy_mul(
    a: u64,
    b: u64,
    u: u64,
    v: u64,
    delta_a: u64,
    delta_b: u64,
    rho: u64,
) -> (u64, Vec<(&'static str, u64)>) {
    use super::field::F5;
    struct ToyCoins {
        words: [u64; 3],
        used: usize,
    }
    impl Coins for ToyCoins {
        fn draw(&mut self) -> u64 {
            let r = self.words[self.used];
            self.used += 1;
            r
        }
    }
    let x = Share {
        left: u,
        right: F5::sub(a, u),
    };
    let y = Share {
        left: v,
        right: F5::sub(b, v),
    };
    let mut coins = ToyCoins {
        words: [delta_a, delta_b, rho],
        used: 0,
    };
    audit_start();
    let z = multiply::<F5, _>(&x, &y, &mut coins);
    let trace = audit_end();
    (F5::add(z.left, z.right), trace)
}
