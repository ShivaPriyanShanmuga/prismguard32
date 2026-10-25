//! Windows CNG signatures for the application AFTER authorized key release.
//! This is an established signature consumer, not PrismGuard encryption or a
//! claim that the provider is covered by the capsule's probing argument.
use super::prism::{entropy::wipe_bytes, Secret32};
use std::{ffi::c_void, ptr};

#[cfg(not(windows))]
compile_error!("Recovery Desk currently requires Windows CNG; no fallback provider.");

type Handle = *mut c_void;
#[derive(Debug, PartialEq, Eq)]
pub enum Error {
    Provider(i32),
    InvalidBlob,
    Oversize,
}
pub type Result<T> = std::result::Result<T, Error>;

#[link(name = "bcrypt")]
extern "system" {
    fn BCryptOpenAlgorithmProvider(
        out: *mut Handle,
        algorithm: *const u16,
        implementation: *const u16,
        flags: u32,
    ) -> i32;
    fn BCryptCloseAlgorithmProvider(handle: Handle, flags: u32) -> i32;
    fn BCryptGenerateKeyPair(algorithm: Handle, key: *mut Handle, bits: u32, flags: u32) -> i32;
    fn BCryptFinalizeKeyPair(key: Handle, flags: u32) -> i32;
    fn BCryptDestroyKey(key: Handle) -> i32;
    fn BCryptExportKey(
        key: Handle,
        export_key: Handle,
        kind: *const u16,
        output: *mut u8,
        capacity: u32,
        written: *mut u32,
        flags: u32,
    ) -> i32;
    fn BCryptImportKeyPair(
        algorithm: Handle,
        import_key: Handle,
        kind: *const u16,
        key: *mut Handle,
        input: *const u8,
        length: u32,
        flags: u32,
    ) -> i32;
    fn BCryptHash(
        algorithm: Handle,
        secret: *const u8,
        secret_length: u32,
        input: *const u8,
        input_length: u32,
        output: *mut u8,
        output_length: u32,
    ) -> i32;
    fn BCryptSignHash(
        key: Handle,
        padding: *const c_void,
        digest: *const u8,
        digest_length: u32,
        signature: *mut u8,
        capacity: u32,
        written: *mut u32,
        flags: u32,
    ) -> i32;
    fn BCryptVerifySignature(
        key: Handle,
        padding: *const c_void,
        digest: *const u8,
        digest_length: u32,
        signature: *const u8,
        length: u32,
        flags: u32,
    ) -> i32;
}
fn checked(status: i32) -> Result<()> {
    if status < 0 {
        Err(Error::Provider(status))
    } else {
        Ok(())
    }
}
fn wide(text: &str) -> Vec<u16> {
    text.encode_utf16().chain(Some(0)).collect()
}
struct Algorithm(Handle);
impl Algorithm {
    fn open(name: &str) -> Result<Self> {
        let mut algorithm = Self(ptr::null_mut());
        // SAFETY: out handle is initialized, strings are nul-terminated and
        // alive throughout the call; flags 0 use the installed default provider.
        checked(unsafe {
            BCryptOpenAlgorithmProvider(&mut algorithm.0, wide(name).as_ptr(), ptr::null(), 0)
        })?;
        Ok(algorithm)
    }
}
impl Drop for Algorithm {
    fn drop(&mut self) {
        if !self.0.is_null() {
            unsafe {
                BCryptCloseAlgorithmProvider(self.0, 0);
            }
        }
    }
}
struct Key(Handle);
impl Drop for Key {
    fn drop(&mut self) {
        if !self.0.is_null() {
            unsafe {
                BCryptDestroyKey(self.0);
            }
        }
    }
}
struct PrivateBlob([u8; 104]);
impl Drop for PrivateBlob {
    fn drop(&mut self) {
        wipe_bytes(&mut self.0);
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub struct PublicKey([u8; 72]);
impl PublicKey {
    pub fn bytes(&self) -> &[u8; 72] {
        &self.0
    }
    pub fn from_bytes(bytes: [u8; 72]) -> Result<Self> {
        if u32::from_le_bytes(bytes[..4].try_into().unwrap()) != 0x31534345
            || u32::from_le_bytes(bytes[4..8].try_into().unwrap()) != 32
        {
            return Err(Error::InvalidBlob);
        }
        Ok(Self(bytes))
    }
}

/// Trusted enrollment. The original provider private handle and exported blob
/// are destroyed before return. The scalar is handed directly to PrismGuard.
pub fn generate_identity() -> Result<(Secret32, PublicKey)> {
    let algorithm = Algorithm::open("ECDSA_P256")?;
    let mut key = Key(ptr::null_mut());
    checked(unsafe { BCryptGenerateKeyPair(algorithm.0, &mut key.0, 256, 0) })?;
    checked(unsafe { BCryptFinalizeKeyPair(key.0, 0) })?;
    let mut length = 0;
    checked(unsafe {
        BCryptExportKey(
            key.0,
            ptr::null_mut(),
            wide("ECCPRIVATEBLOB").as_ptr(),
            ptr::null_mut(),
            0,
            &mut length,
            0,
        )
    })?;
    if length != 104 {
        return Err(Error::InvalidBlob);
    }
    let mut blob = PrivateBlob([0; 104]);
    checked(unsafe {
        BCryptExportKey(
            key.0,
            ptr::null_mut(),
            wide("ECCPRIVATEBLOB").as_ptr(),
            blob.0.as_mut_ptr(),
            104,
            &mut length,
            0,
        )
    })?;
    if length != 104
        || u32::from_le_bytes(blob.0[..4].try_into().unwrap()) != 0x32534345
        || u32::from_le_bytes(blob.0[4..8].try_into().unwrap()) != 32
    {
        return Err(Error::InvalidBlob);
    }
    let mut public = [0; 72];
    public.copy_from_slice(&blob.0[..72]);
    public[..4].copy_from_slice(&0x31534345u32.to_le_bytes());
    let secret = Secret32::new(blob.0[72..104].try_into().unwrap());
    Ok((secret, PublicKey::from_bytes(public)?))
}

pub fn sha256(input: &[u8]) -> Result<[u8; 32]> {
    let length = u32::try_from(input.len()).map_err(|_| Error::Oversize)?;
    let algorithm = Algorithm::open("SHA256")?;
    let mut output = [0; 32];
    checked(unsafe {
        BCryptHash(
            algorithm.0,
            ptr::null(),
            0,
            input.as_ptr(),
            length,
            output.as_mut_ptr(),
            32,
        )
    })?;
    Ok(output)
}

/// Consumes the recovered scalar; the temporary import blob and native key
/// handle have deterministic cleanup paths. OS spills/copies are not certified.
pub fn sign_recovered(secret: Secret32, public: &PublicKey, digest: &[u8; 32]) -> Result<[u8; 64]> {
    let algorithm = Algorithm::open("ECDSA_P256")?;
    let mut blob = PrivateBlob([0; 104]);
    blob.0[..72].copy_from_slice(public.bytes());
    blob.0[..4].copy_from_slice(&0x32534345u32.to_le_bytes());
    blob.0[72..].copy_from_slice(secret.expose());
    let mut key = Key(ptr::null_mut());
    checked(unsafe {
        BCryptImportKeyPair(
            algorithm.0,
            ptr::null_mut(),
            wide("ECCPRIVATEBLOB").as_ptr(),
            &mut key.0,
            blob.0.as_ptr(),
            104,
            0,
        )
    })?;
    let mut signature = [0; 64];
    let mut written = 0;
    checked(unsafe {
        BCryptSignHash(
            key.0,
            ptr::null(),
            digest.as_ptr(),
            32,
            signature.as_mut_ptr(),
            64,
            &mut written,
            0,
        )
    })?;
    if written != 64 {
        return Err(Error::InvalidBlob);
    }
    Ok(signature)
}

pub fn verify(public: &PublicKey, digest: &[u8; 32], signature: &[u8; 64]) -> Result<bool> {
    let algorithm = Algorithm::open("ECDSA_P256")?;
    let mut key = Key(ptr::null_mut());
    checked(unsafe {
        BCryptImportKeyPair(
            algorithm.0,
            ptr::null_mut(),
            wide("ECCPUBLICBLOB").as_ptr(),
            &mut key.0,
            public.0.as_ptr(),
            72,
            0,
        )
    })?;
    let status = unsafe {
        BCryptVerifySignature(
            key.0,
            ptr::null(),
            digest.as_ptr(),
            32,
            signature.as_ptr(),
            64,
            0,
        )
    };
    match status {
        0 => Ok(true),
        s if s == 0xC000A000u32 as i32 => Ok(false),
        s => Err(Error::Provider(s)),
    }
}
