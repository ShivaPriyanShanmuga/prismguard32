//! PrismGuard-32: experimental masked capsule protocol, not an audited cipher.
//! Trusted ingress -> masked computation -> explicit authorized release.
pub mod entropy;
pub mod field;
mod masked;
use entropy::{wipe_bytes, wipe_words, Coins, Entropy};
use field::{Arithmetic, F61, INV17, INV9, P};
use masked::Share;

pub const CAPSULE_LEN: usize = 104;
pub const MAX_CONTEXT: usize = 256;
pub const MAX_ATTEMPTS: u8 = 8;
const MAGIC: &[u8; 8] = b"PGUARD\x00\x02";
const SEAL_BUDGET: usize = 1024;
const OPEN_BUDGET: usize = 6144;

#[derive(Debug, PartialEq, Eq)]
pub enum Failure {
    Rejected,
    Unavailable,
    EntropyUnavailable,
    EntropyExhausted,
}
pub struct Secret32([u8; 32]);
impl Secret32 {
    pub fn new(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }
    pub fn expose(&self) -> &[u8; 32] {
        &self.0
    }
}
impl Drop for Secret32 {
    fn drop(&mut self) {
        wipe_bytes(&mut self.0);
    }
}
pub struct MaskedSecret([Share; 8]);
pub fn ingest(secret: Secret32, entropy: &mut Entropy) -> Result<MaskedSecret, Failure> {
    if entropy.remaining() < 8 {
        return Err(Failure::EntropyExhausted);
    }
    Ok(MaskedSecret(std::array::from_fn(|i| {
        let word = u32::from_le_bytes(secret.0[4 * i..4 * i + 4].try_into().unwrap()) as u64;
        masked::input(word, entropy)
    })))
}
struct Material {
    id: [u8; 16],
    words: [Share; 12],
}
pub struct Sealer(Material);
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum ReceiverState {
    Ready { attempts_left: u8 },
    Opened,
    Locked,
}
pub struct Receiver {
    material: Option<Material>,
    attempts: u8,
    state: ReceiverState,
}
impl Receiver {
    pub fn state(&self) -> ReceiverState {
        self.state
    }
    fn rejected(&mut self) -> Failure {
        if self.attempts == MAX_ATTEMPTS {
            self.state = ReceiverState::Locked;
            self.material.take();
        }
        Failure::Rejected
    }
    /// Fresh blinding entropy for every attempt; at most eight attempts total.
    /// Only the authentication bit is released on rejection. A success consumes
    /// the material; a ninth attempt, replay, or rollback is not supported.
    pub fn attempt(
        &mut self,
        capsule: &[u8],
        context: &[u8],
        entropy: &mut Entropy,
    ) -> Result<Secret32, Failure> {
        if self.material.is_none() {
            return Err(Failure::Unavailable);
        }
        if entropy.remaining() < OPEN_BUDGET {
            return Err(Failure::EntropyExhausted);
        }
        self.attempts += 1;
        self.state = ReceiverState::Ready {
            attempts_left: MAX_ATTEMPTS - self.attempts,
        };
        let parsed = match parse(capsule, context) {
            Some(x) => x,
            None => return Err(self.rejected()),
        };
        let material = self.material.as_ref().unwrap();
        let (id, c, tags) = parsed;
        let mut public_id_difference = 0;
        for (a, b) in id.iter().zip(material.id.iter()) {
            public_id_difference |= a ^ b;
        }
        if public_id_difference != 0 {
            return Err(self.rejected());
        }
        let mut nonzero = Vec::with_capacity(2);
        for lane in 0..2 {
            let h = hash(&material.words[8 + 2 * lane], &id, &c, context, entropy);
            let tag = masked::add(&h, &material.words[9 + 2 * lane], entropy);
            let difference = masked::add_public(&tag, F61::sub(0, tags[lane]));
            // Fermat x^(p-1) is 0 at zero and 1 elsewhere. Never reconstruct
            // the secret tag difference just to do a comparison.
            nonzero.push(masked::power(&difference, P - 1, entropy));
        }
        let sum = masked::add(&nonzero[0], &nonzero[1], entropy);
        let product = masked::mul(&nonzero[0], &nonzero[1], entropy);
        let either = masked::sub(&sum, &product, entropy);
        let invalid = masked::release(&either); // Explicit public one-bit boundary.
        if invalid != 0 {
            return Err(self.rejected());
        }
        let mut v: [Share; 8] = std::array::from_fn(|i| masked::public(c[i]));
        unmix(&mut v, entropy);
        for (i, word) in v.iter_mut().enumerate() {
            let z = masked::power(word, INV17, entropy);
            *word = masked::sub(&z, &material.words[i], entropy);
        }
        unmix(&mut v, entropy);
        let mut raw = [0u64; 8];
        for i in 0..8 {
            raw[i] = masked::release(&v[i]);
        } // Authorized plaintext boundary.
        let invalid_domain = raw.iter().fold(0, |acc, &w| acc | (w >> 32));
        let mut secret = Secret32([0; 32]);
        for (i, &word) in raw.iter().enumerate() {
            secret.0[4 * i..4 * i + 4].copy_from_slice(&(word as u32).to_le_bytes());
        }
        wipe_words(&mut raw);
        if invalid_domain != 0 {
            return Err(self.rejected());
        }
        self.material.take();
        self.state = ReceiverState::Opened;
        Ok(secret)
    }
}

/// Trusted provisioning. Raw pad generation occurs here, before the protected
/// computation boundary; sender/receiver shares use independent representations.
/// Secure delivery, distinct physical domains, and rollback resistance are external.
pub fn provision(id: [u8; 16], entropy: &mut Entropy) -> Result<(Sealer, Receiver), Failure> {
    if entropy.remaining() < 128 {
        return Err(Failure::EntropyExhausted);
    }
    let mut values = [0; 12];
    for i in 0..12 {
        values[i] = entropy.draw();
        let mut retries = 0;
        while (i == 8 || i == 10) && values[i] == 0 {
            if entropy.remaining() == 0 || retries == 128 {
                wipe_words(&mut values);
                return Err(Failure::EntropyUnavailable);
            }
            retries += 1;
            values[i] = entropy.draw();
        }
    }
    if entropy.remaining() < 24 {
        wipe_words(&mut values);
        return Err(Failure::EntropyUnavailable);
    }
    let sender = Material {
        id,
        words: std::array::from_fn(|i| masked::input(values[i], entropy)),
    };
    let receiver = Material {
        id,
        words: std::array::from_fn(|i| masked::input(values[i], entropy)),
    };
    wipe_words(&mut values);
    Ok((
        Sealer(sender),
        Receiver {
            material: Some(receiver),
            attempts: 0,
            state: ReceiverState::Ready {
                attempts_left: MAX_ATTEMPTS,
            },
        },
    ))
}

fn sum(v: &[Share; 8], entropy: &mut Entropy) -> Share {
    let mut total = masked::public(0);
    for word in v {
        total = masked::add(&total, word, entropy);
    }
    total
}
fn mix(v: &mut [Share; 8], entropy: &mut Entropy) {
    let total = sum(v, entropy);
    for word in v {
        *word = masked::add(word, &total, entropy);
    }
}
fn unmix(v: &mut [Share; 8], entropy: &mut Entropy) {
    let correction = masked::scale(&sum(v, entropy), INV9);
    for word in v {
        *word = masked::sub(word, &correction, entropy);
    }
}
fn chunk_word(chunk: &[u8]) -> u64 {
    chunk
        .iter()
        .enumerate()
        .fold(0, |word, (i, &b)| word | ((b as u64) << (8 * i)))
}
fn hash(
    alpha: &Share,
    id: &[u8; 16],
    c: &[u64; 8],
    context: &[u8],
    entropy: &mut Entropy,
) -> Share {
    let mut h = masked::public(1);
    let mut step = |word| {
        h = masked::add_public(&masked::mul(&h, alpha, entropy), word);
    };
    step(0x504755415244);
    step(2);
    for chunk in id.chunks(7) {
        step(chunk_word(chunk));
    }
    step(context.len() as u64);
    for chunk in context.chunks(7) {
        step(chunk_word(chunk));
    }
    for &word in c {
        step(word);
    }
    masked::mul(&h, alpha, entropy)
}

pub fn seal(
    key: Sealer,
    secret: &MaskedSecret,
    context: &[u8],
    entropy: &mut Entropy,
) -> Result<[u8; CAPSULE_LEN], Failure> {
    if context.len() > MAX_CONTEXT {
        return Err(Failure::Rejected);
    }
    if entropy.remaining() < SEAL_BUDGET {
        return Err(Failure::EntropyExhausted);
    }
    let mut v = std::array::from_fn(|i| masked::refresh::<F61, _>(&secret.0[i], entropy));
    mix(&mut v, entropy);
    for (i, word) in v.iter_mut().enumerate() {
        let z = masked::add(word, &key.0.words[i], entropy);
        *word = masked::power17(&z, entropy);
    }
    mix(&mut v, entropy);
    let c: [u64; 8] = std::array::from_fn(|i| masked::release(&v[i])); // Public ciphertext.
    let mut out = [0; CAPSULE_LEN];
    out[..8].copy_from_slice(MAGIC);
    out[8..24].copy_from_slice(&key.0.id);
    for (i, &word) in c.iter().enumerate() {
        out[24 + 8 * i..32 + 8 * i].copy_from_slice(&word.to_le_bytes());
    }
    for lane in 0..2 {
        let h = hash(&key.0.words[8 + 2 * lane], &key.0.id, &c, context, entropy);
        let tag = masked::add(&h, &key.0.words[9 + 2 * lane], entropy);
        let public_tag = masked::release(&tag); // Public authentication tag.
        out[88 + 8 * lane..96 + 8 * lane].copy_from_slice(&public_tag.to_le_bytes());
    }
    Ok(out)
}

type Parsed = ([u8; 16], [u64; 8], [u64; 2]);
fn parse(capsule: &[u8], context: &[u8]) -> Option<Parsed> {
    if capsule.len() != CAPSULE_LEN || context.len() > MAX_CONTEXT || &capsule[..8] != MAGIC {
        return None;
    }
    let id = capsule[8..24].try_into().ok()?;
    let mut c = [0; 8];
    let mut tags = [0; 2];
    for (i, word) in c.iter_mut().enumerate() {
        *word = u64::from_le_bytes(capsule[24 + 8 * i..32 + 8 * i].try_into().ok()?);
        if *word >= P {
            return None;
        }
    }
    for (i, word) in tags.iter_mut().enumerate() {
        *word = u64::from_le_bytes(capsule[88 + 8 * i..96 + 8 * i].try_into().ok()?);
        if *word >= P {
            return None;
        }
    }
    Some((id, c, tags))
}

#[cfg(feature = "audit")]
#[allow(unused_imports)]
pub use masked::{audit_end, audit_start, toy_mul};

#[cfg(test)]
mod tests {
    use super::*;
    fn setup(seed: u64, bytes: [u8; 32], context: &[u8]) -> (Receiver, [u8; 104]) {
        let mut e = Entropy::fixture(seed);
        let (s, r) = provision([seed as u8; 16], &mut e).unwrap();
        let m = ingest(Secret32::new(bytes), &mut e).unwrap();
        let c = seal(s, &m, context, &mut e).unwrap();
        (r, c)
    }
    #[test]
    fn field_boundaries() {
        for a in [0, 1, P / 2, P - 2, P - 1] {
            for b in [0, 1, P / 2, P - 2, P - 1] {
                assert_eq!(F61::add(a, b), ((a as u128 + b as u128) % P as u128) as u64);
                assert_eq!(
                    F61::sub(a, b),
                    ((a as u128 + P as u128 - b as u128) % P as u128) as u64
                );
                assert_eq!(F61::mul(a, b), ((a as u128 * b as u128) % P as u128) as u64);
            }
        }
    }
    #[test]
    fn masked_correlated_operations() {
        let mut e = Entropy::fixture(7);
        for x in [0, 1, 3, P / 2, P - 1] {
            let a = masked::input(x, &mut e);
            assert_eq!(
                masked::release(&masked::mul(&a, &a, &mut e)),
                F61::mul(x, x)
            );
            assert_eq!(masked::release(&masked::sub(&a, &a, &mut e)), 0);
            assert_eq!(masked::release(&masked::power17(&a, &mut e)), {
                let mut p = 1;
                for _ in 0..17 {
                    p = F61::mul(p, x);
                }
                p
            });
        }
    }
    #[test]
    fn all_byte_values_roundtrip() {
        for b in 0..=255u8 {
            let (mut r, c) = setup(b as u64, [b; 32], "vault/λ".as_bytes());
            let mut e = Entropy::fixture(900 + b as u64);
            let m = r.attempt(&c, "vault/λ".as_bytes(), &mut e).unwrap();
            assert_eq!(m.expose(), &[b; 32]);
            assert_eq!(r.state(), ReceiverState::Opened);
        }
    }
    #[test]
    fn context_boundaries_and_entropy_budget() {
        for len in [0, 1, 7, 8, 255, 256] {
            let context = vec![0xC3; len];
            let (mut r, c) = setup(len as u64, [42; 32], &context);
            let mut e = Entropy::fixture(77);
            assert!(r.attempt(&c, &context, &mut e).is_ok());
            assert!(e.used() < OPEN_BUDGET);
        }
        let mut e = Entropy::fixture(1);
        let (s, _) = provision([0; 16], &mut e).unwrap();
        let m = ingest(Secret32::new([0; 32]), &mut e).unwrap();
        assert!(matches!(
            seal(s, &m, &[0; 257], &mut e),
            Err(Failure::Rejected)
        ));
    }
    #[test]
    fn every_bit_mutation_rejected() {
        for bit in 0..CAPSULE_LEN * 8 {
            let (mut r, mut c) = setup(21, [0x37; 32], b"vault");
            c[bit / 8] ^= 1 << (bit % 8);
            let mut e = Entropy::fixture(777);
            assert!(
                matches!(r.attempt(&c, b"vault", &mut e), Err(Failure::Rejected)),
                "bit {bit}"
            );
        }
    }
    #[test]
    fn seven_bad_packets_then_recovery() {
        let (mut r, c) = setup(22, [73; 32], b"recovery");
        let mut altered = c;
        altered[44] ^= 1;
        for i in 0..7 {
            assert!(matches!(
                r.attempt(&altered, b"recovery", &mut Entropy::fixture(i)),
                Err(Failure::Rejected)
            ));
        }
        let m = r
            .attempt(&c, b"recovery", &mut Entropy::fixture(8))
            .unwrap();
        assert_eq!(m.expose(), &[73; 32]);
        assert!(matches!(
            r.attempt(&c, b"recovery", &mut Entropy::fixture(9)),
            Err(Failure::Unavailable)
        ));
    }
    #[test]
    fn eighth_failure_locks_and_wipes() {
        let (mut r, c) = setup(8, [12; 32], b"x");
        for _ in 0..8 {
            assert!(r.attempt(&c, b"wrong", &mut Entropy::fixture(2)).is_err());
        }
        assert_eq!(r.state(), ReceiverState::Locked);
        assert!(r.material.is_none());
        assert!(matches!(
            r.attempt(&c, b"x", &mut Entropy::fixture(4)),
            Err(Failure::Unavailable)
        ));
    }
    #[test]
    fn malformed_input_and_noncanonical_tags() {
        let (_, c) = setup(5, [0; 32], b"");
        for len in 0..CAPSULE_LEN {
            let (mut r, _) = setup(5, [0; 32], b"");
            assert!(r.attempt(&c[..len], b"", &mut Entropy::fixture(6)).is_err());
        }
        for start in [24, 88, 96] {
            let (mut r, mut c) = setup(5, [0; 32], b"");
            c[start..start + 8].copy_from_slice(&P.to_le_bytes());
            assert!(r.attempt(&c, b"", &mut Entropy::fixture(6)).is_err());
        }
        let (mut r, c) = setup(5, [0; 32], b"");
        let mut ext = c.to_vec();
        ext.push(0);
        assert!(r.attempt(&ext, b"", &mut Entropy::fixture(6)).is_err());
    }
    #[test]
    fn blinding_randomness_does_not_change_wire_format() {
        let mut e1 = Entropy::fixture(9);
        let (s1, _) = provision([1; 16], &mut e1).unwrap();
        let m1 = ingest(Secret32::new([71; 32]), &mut e1).unwrap();
        let mut e2 = Entropy::fixture(9);
        let (s2, _) = provision([1; 16], &mut e2).unwrap();
        let m2 = ingest(Secret32::new([71; 32]), &mut e2).unwrap();
        let c1 = seal(s1, &m1, b"x", &mut Entropy::fixture(100)).unwrap();
        let c2 = seal(s2, &m2, b"x", &mut Entropy::fixture(999)).unwrap();
        assert_eq!(c1, c2);
    }
    #[test]
    fn wrong_receiver_and_context_are_rejected() {
        let (mut r, _) = setup(1, [0; 32], b"x");
        let (_, c) = setup(2, [0; 32], b"x");
        assert!(r.attempt(&c, b"x", &mut Entropy::fixture(3)).is_err());
        let (mut r, c) = setup(1, [0; 32], b"x");
        assert!(r.attempt(&c, b"x\0", &mut Entropy::fixture(3)).is_err());
    }
    #[test]
    fn entropy_shortage_does_not_consume_attempt() {
        let (mut r, c) = setup(2, [0; 32], b"x");
        let mut e = Entropy::fixture(7);
        for _ in 0..4096 {
            e.draw();
        }
        assert!(matches!(
            r.attempt(&c, b"x", &mut e),
            Err(Failure::EntropyExhausted)
        ));
        assert_eq!(r.state(), ReceiverState::Ready { attempts_left: 8 });
    }
    #[test]
    fn real_os_entropy_roundtrip() {
        let mut e = Entropy::system().unwrap();
        let (s, mut r) = provision(entropy::fresh_id().unwrap(), &mut e).unwrap();
        let m = ingest(Secret32::new([0x4C; 32]), &mut e).unwrap();
        let c = seal(s, &m, b"OS-rng", &mut e).unwrap();
        assert_eq!(
            r.attempt(&c, b"OS-rng", &mut Entropy::system().unwrap())
                .unwrap()
                .expose(),
            &[0x4C; 32]
        );
    }
    #[test]
    fn final_coefficient_additive_forgery_rejected() {
        let (mut r, mut c) = setup(13, [0; 32], b"x");
        for start in [80, 88, 96] {
            let value = u64::from_le_bytes(c[start..start + 8].try_into().unwrap());
            c[start..start + 8].copy_from_slice(&F61::add(value, 1).to_le_bytes());
        }
        assert!(matches!(
            r.attempt(&c, b"x", &mut Entropy::fixture(99)),
            Err(Failure::Rejected)
        ));
    }
    #[test]
    fn authenticated_out_of_domain_plaintext_rejected() {
        let mut e = Entropy::fixture(71);
        let (s, mut r) = provision([3; 16], &mut e).unwrap();
        let bad = MaskedSecret(std::array::from_fn(|i| {
            masked::input(if i == 0 { 1 << 32 } else { 0 }, &mut e)
        }));
        let c = seal(s, &bad, b"bad-domain", &mut Entropy::fixture(72)).unwrap();
        assert!(matches!(
            r.attempt(&c, b"bad-domain", &mut Entropy::fixture(73)),
            Err(Failure::Rejected)
        ));
    }
}
