use super::{field::P, Failure};
use std::sync::atomic::{compiler_fence, Ordering};

pub const POOL_WORDS: usize = 8192;
pub fn wipe_words(words: &mut [u64]) {
    for w in words {
        unsafe { std::ptr::write_volatile(w, 0) }
    }
    compiler_fence(Ordering::SeqCst);
}
pub fn wipe_bytes(bytes: &mut [u8]) {
    for b in bytes {
        unsafe { std::ptr::write_volatile(b, 0) }
    }
    compiler_fence(Ordering::SeqCst);
}
#[cfg(windows)]
fn os_bytes(out: &mut [u8]) -> Result<(), Failure> {
    #[link(name = "bcrypt")]
    extern "system" {
        fn BCryptGenRandom(h: *mut std::ffi::c_void, b: *mut u8, n: u32, flags: u32) -> i32;
    }
    let status =
        unsafe { BCryptGenRandom(std::ptr::null_mut(), out.as_mut_ptr(), out.len() as u32, 2) };
    if status < 0 {
        Err(Failure::EntropyUnavailable)
    } else {
        Ok(())
    }
}
#[cfg(unix)]
fn os_bytes(out: &mut [u8]) -> Result<(), Failure> {
    use std::io::Read;
    std::fs::File::open("/dev/urandom")
        .and_then(|mut f| f.read_exact(out))
        .map_err(|_| Failure::EntropyUnavailable)
}
#[cfg(not(any(windows, unix)))]
compile_error!("No reviewed OS entropy implementation for this target");

pub trait Coins {
    fn draw(&mut self) -> u64;
}
/// A pool of fresh field elements. Consumed words are wiped immediately.
/// Never Clone, Copy, serializable, or Debug. No deterministic fallback.
pub struct Entropy {
    words: Vec<u64>,
    used: usize,
}
impl Entropy {
    pub fn system() -> Result<Self, Failure> {
        let mut pool = Self {
            words: vec![0; POOL_WORDS],
            used: 0,
        };
        let bytes = unsafe {
            std::slice::from_raw_parts_mut(pool.words.as_mut_ptr() as *mut u8, POOL_WORDS * 8)
        };
        os_bytes(bytes)?;
        for word in &mut pool.words {
            *word &= P;
            let mut retries = 0;
            while *word == P {
                if retries == 4 {
                    return Err(Failure::EntropyUnavailable);
                }
                retries += 1;
                let mut b = [0; 8];
                os_bytes(&mut b)?;
                *word = u64::from_le_bytes(b) & P;
                wipe_bytes(&mut b);
            }
        }
        Ok(pool)
    }
    pub fn used(&self) -> usize {
        self.used
    }
    pub fn remaining(&self) -> usize {
        self.words.len() - self.used
    }
    /// Only test binaries have this public deterministic source.
    #[cfg(any(test, feature = "fixtures", feature = "audit"))]
    pub fn fixture(seed: u64) -> Self {
        let mut state = seed;
        let words = (0..POOL_WORDS)
            .map(|_| {
                state = state.wrapping_add(0x9e3779b97f4a7c15);
                let mut z = state;
                z = (z ^ (z >> 30)).wrapping_mul(0xbf58476d1ce4e5b9);
                z = (z ^ (z >> 27)).wrapping_mul(0x94d049bb133111eb);
                let word = (z ^ (z >> 31)) & P;
                if word == P {
                    0
                } else {
                    word
                }
            })
            .collect();
        Self { words, used: 0 }
    }
}
impl Coins for Entropy {
    #[inline(never)]
    fn draw(&mut self) -> u64 {
        // Every entry point checks a conservative public budget before work.
        let w = self.words[self.used];
        unsafe { std::ptr::write_volatile(&mut self.words[self.used], 0) };
        self.used += 1;
        w
    }
}
impl Drop for Entropy {
    fn drop(&mut self) {
        wipe_words(&mut self.words);
    }
}
pub fn fresh_id() -> Result<[u8; 16], Failure> {
    let mut id = [0; 16];
    os_bytes(&mut id)?;
    Ok(id)
}
