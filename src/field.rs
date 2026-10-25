//! Canonical F_(2^61-1) arithmetic. All operands must be below P.
pub const P: u64 = (1u64 << 61) - 1;
pub const INV9: u64 = 2049638230412172401;
pub const INV17: u64 = 1763291712928118903;

#[inline(always)]
fn reduce(t: u64) -> u64 {
    let d = t.wrapping_sub(P);
    d.wrapping_add(P & 0u64.wrapping_sub(d >> 63))
}
pub trait Arithmetic {
    fn add(a: u64, b: u64) -> u64;
    fn sub(a: u64, b: u64) -> u64;
    fn mul(a: u64, b: u64) -> u64;
}
pub struct F61;
impl Arithmetic for F61 {
    #[inline(always)]
    fn add(a: u64, b: u64) -> u64 {
        reduce(a.wrapping_add(b))
    }
    #[inline(always)]
    fn sub(a: u64, b: u64) -> u64 {
        reduce(a.wrapping_add(P).wrapping_sub(b))
    }
    #[inline(always)]
    fn mul(a: u64, b: u64) -> u64 {
        let z = (a as u128) * (b as u128);
        let t = (z & P as u128).wrapping_add(z >> 61);
        let u = (t & P as u128).wrapping_add(t >> 61);
        reduce(u as u64)
    }
}
#[cfg(any(test, feature = "audit"))]
pub struct F5;
#[cfg(any(test, feature = "audit"))]
impl Arithmetic for F5 {
    fn add(a: u64, b: u64) -> u64 {
        (a + b) % 5
    }
    fn sub(a: u64, b: u64) -> u64 {
        (a + 5 - b) % 5
    }
    fn mul(a: u64, b: u64) -> u64 {
        (a * b) % 5
    }
}
