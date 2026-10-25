//! In-memory signing-key recovery and public-key authorization application.
//! No filesystem, networking, registry, account or device-access operations.
use super::{cng, prism};
use prism::{
    entropy::{fresh_id, Entropy},
    Receiver, ReceiverState, Secret32, CAPSULE_LEN,
};

pub fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
#[derive(Debug, PartialEq, Eq)]
pub enum Error {
    Capsule(prism::Failure),
    Crypto(cng::Error),
    NotRecovered,
    AlreadySpent,
    WrongRequest,
    NoPendingChallenge,
    InvalidSignature,
}
impl From<prism::Failure> for Error {
    fn from(e: prism::Failure) -> Self {
        Self::Capsule(e)
    }
}
impl From<cng::Error> for Error {
    fn from(e: cng::Error) -> Self {
        Self::Crypto(e)
    }
}
pub type Result<T> = std::result::Result<T, Error>;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Request {
    pub nonce: [u8; 16],
    pub resource: u32,
    pub action: u8,
}
impl Request {
    pub fn encode(&self) -> Vec<u8> {
        let mut bytes = b"PRISMGUARD/DESK/REQUEST/v1\0".to_vec();
        bytes.extend_from_slice(&self.nonce);
        bytes.extend_from_slice(&self.resource.to_le_bytes());
        bytes.push(self.action);
        bytes
    }
    pub fn digest(&self) -> Result<[u8; 32]> {
        Ok(cng::sha256(&self.encode())?)
    }
}
#[derive(Clone, Copy)]
pub struct Receipt {
    pub request: Request,
    pub signature: [u8; 64],
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DeskState {
    AwaitingRecovery(ReceiverState),
    ReadyToIssue,
    Spent,
}
pub struct RecoveryDesk {
    receiver: Receiver,
    public: cng::PublicKey,
    context: Vec<u8>,
    expected_request: Request,
    recovered: Option<Secret32>,
    spent: bool,
}
impl RecoveryDesk {
    pub fn state(&self) -> DeskState {
        if self.spent {
            DeskState::Spent
        } else if self.recovered.is_some() {
            DeskState::ReadyToIssue
        } else {
            DeskState::AwaitingRecovery(self.receiver.state())
        }
    }
    pub fn context(&self) -> &[u8] {
        &self.context
    }
    pub fn recover(&mut self, capsule: &[u8]) -> Result<()> {
        self.recover_with_entropy(capsule, &mut Entropy::system()?)
    }
    pub fn recover_with_entropy(&mut self, capsule: &[u8], entropy: &mut Entropy) -> Result<()> {
        if self.spent {
            return Err(Error::AlreadySpent);
        }
        if self.recovered.is_some() {
            return Err(Error::AlreadySpent);
        }
        self.recovered = Some(self.receiver.attempt(capsule, &self.context, entropy)?);
        Ok(())
    }
    pub fn issue(&mut self, request: Request) -> Result<Receipt> {
        if self.spent {
            return Err(Error::AlreadySpent);
        }
        if self.recovered.is_none() {
            return Err(Error::NotRecovered);
        }
        // Public policy is checked before consuming the recovered secret.
        if request != self.expected_request {
            return Err(Error::WrongRequest);
        }
        let digest = request.digest()?;
        let secret = self.recovered.take().unwrap();
        self.spent = true; // Fail closed even if the provider subsequently fails.
        Ok(Receipt {
            request,
            signature: cng::sign_recovered(secret, &self.public, &digest)?,
        })
    }
}

/// The controller holds ONLY a public verification key and a pending public
/// request. It never receives the scalar, capsule pad, or recovery material.
pub struct AccessController {
    public: cng::PublicKey,
    pending: Option<Request>,
    grants: u32,
}
impl AccessController {
    pub fn grants(&self) -> u32 {
        self.grants
    }
    pub fn verify_and_grant(&mut self, receipt: &Receipt) -> Result<&'static str> {
        let pending = self.pending.ok_or(Error::NoPendingChallenge)?;
        if receipt.request != pending {
            return Err(Error::WrongRequest);
        }
        if !cng::verify(&self.public, &receipt.request.digest()?, &receipt.signature)? {
            return Err(Error::InvalidSignature);
        }
        self.pending.take();
        self.grants += 1;
        Ok("TRAINING PASS GRANTED: synthetic bench 7")
    }
}

pub struct Enrollment {
    pub capsule: [u8; CAPSULE_LEN],
    pub public: cng::PublicKey,
    pub request: Request,
    pub desk: RecoveryDesk,
    pub controller: AccessController,
}
pub fn enroll() -> Result<Enrollment> {
    let (secret, public) = cng::generate_identity()?;
    let fingerprint = cng::sha256(public.bytes())?;
    let context = format!(
        "prismguard/recovery-desk/v1|site=synthetic-lab-A|pk={}",
        hex(&fingerprint)
    )
    .into_bytes();
    let request = Request {
        nonce: fresh_id()?,
        resource: 7,
        action: 1,
    };
    let mut setup = Entropy::system()?;
    let (sender, receiver) = prism::provision(fresh_id()?, &mut setup)?;
    let shared = prism::ingest(secret, &mut setup)?; // Consumes the original scalar.
    let capsule = prism::seal(sender, &shared, &context, &mut Entropy::system()?)?;
    drop(shared); // The enrollment sharing is not retained by the application.
    Ok(Enrollment {
        capsule,
        public,
        request,
        desk: RecoveryDesk {
            receiver,
            public,
            context,
            expected_request: request,
            recovered: None,
            spent: false,
        },
        controller: AccessController {
            public,
            pending: Some(request),
            grants: 0,
        },
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    fn unlocked() -> Enrollment {
        let mut e = enroll().unwrap();
        e.desk.recover(&e.capsule).unwrap();
        e
    }
    #[test]
    fn signature_operation_requires_successful_recovery() {
        let mut e = enroll().unwrap();
        assert!(matches!(e.desk.issue(e.request), Err(Error::NotRecovered)));
        let fake = Receipt {
            request: e.request,
            signature: [0; 64],
        };
        assert_eq!(
            e.controller.verify_and_grant(&fake),
            Err(Error::InvalidSignature)
        );
        assert_eq!(e.controller.grants(), 0);
    }
    #[test]
    fn real_recovered_key_signs_and_public_controller_grants() {
        let mut e = unlocked();
        let receipt = e.desk.issue(e.request).unwrap();
        assert!(cng::verify(&e.public, &e.request.digest().unwrap(), &receipt.signature).unwrap());
        assert!(e.controller.verify_and_grant(&receipt).is_ok());
        assert_eq!(e.controller.grants(), 1);
        assert_eq!(e.desk.state(), DeskState::Spent);
    }
    #[test]
    fn tampered_capsule_cannot_unlock_application() {
        let mut e = enroll().unwrap();
        let mut bad = e.capsule;
        bad[44] ^= 1;
        assert!(e.desk.recover(&bad).is_err());
        assert!(matches!(e.desk.issue(e.request), Err(Error::NotRecovered)));
        e.desk.recover(&e.capsule).unwrap();
        assert!(e.desk.issue(e.request).is_ok());
    }
    #[test]
    fn wrong_public_key_context_prevents_recovery() {
        let mut e = enroll().unwrap();
        e.desk.context[60] ^= 1;
        assert!(e.desk.recover(&e.capsule).is_err());
        assert!(matches!(e.desk.issue(e.request), Err(Error::NotRecovered)));
    }
    #[test]
    fn altered_signature_does_not_consume_pending_challenge() {
        let mut e = unlocked();
        let receipt = e.desk.issue(e.request).unwrap();
        let mut bad = receipt;
        bad.signature[9] ^= 1;
        assert_eq!(
            e.controller.verify_and_grant(&bad),
            Err(Error::InvalidSignature)
        );
        assert_eq!(e.controller.grants(), 0);
        assert!(e.controller.verify_and_grant(&receipt).is_ok());
    }
    #[test]
    fn wrong_request_does_not_consume_recovered_key_or_pending_challenge() {
        let mut e = unlocked();
        let mut wrong = e.request;
        wrong.resource += 1;
        assert!(matches!(e.desk.issue(wrong), Err(Error::WrongRequest)));
        assert_eq!(e.desk.state(), DeskState::ReadyToIssue);
        let receipt = e.desk.issue(e.request).unwrap();
        let mut bad = receipt;
        bad.request = wrong;
        assert_eq!(
            e.controller.verify_and_grant(&bad),
            Err(Error::WrongRequest)
        );
        assert!(e.controller.verify_and_grant(&receipt).is_ok());
    }
    #[test]
    fn wrong_nonce_or_action_is_rejected() {
        let mut e = unlocked();
        let receipt = e.desk.issue(e.request).unwrap();
        for which in 0..2 {
            let mut bad = receipt;
            if which == 0 {
                bad.request.nonce[0] ^= 1
            } else {
                bad.request.action ^= 1
            }
            assert_eq!(
                e.controller.verify_and_grant(&bad),
                Err(Error::WrongRequest)
            );
        }
        assert!(e.controller.verify_and_grant(&receipt).is_ok());
    }
    #[test]
    fn controller_with_different_public_key_does_not_grant() {
        let mut e = unlocked();
        let other = enroll().unwrap();
        let receipt = e.desk.issue(e.request).unwrap();
        let mut controller = AccessController {
            public: other.public,
            pending: Some(e.request),
            grants: 0,
        };
        assert_eq!(
            controller.verify_and_grant(&receipt),
            Err(Error::InvalidSignature)
        );
    }
    #[test]
    fn receipts_and_issuance_are_one_shot() {
        let mut e = unlocked();
        let receipt = e.desk.issue(e.request).unwrap();
        e.controller.verify_and_grant(&receipt).unwrap();
        assert_eq!(
            e.controller.verify_and_grant(&receipt),
            Err(Error::NoPendingChallenge)
        );
        assert!(matches!(e.desk.issue(e.request), Err(Error::AlreadySpent)));
        assert_eq!(e.desk.recover(&e.capsule), Err(Error::AlreadySpent));
        assert_eq!(e.controller.grants(), 1);
    }
    #[test]
    fn eight_bad_capsules_lock_the_application() {
        let mut e = enroll().unwrap();
        let mut bad = e.capsule;
        bad[44] ^= 1;
        for _ in 0..8 {
            assert!(e.desk.recover(&bad).is_err());
        }
        assert_eq!(
            e.desk.state(),
            DeskState::AwaitingRecovery(ReceiverState::Locked)
        );
        assert!(e.desk.recover(&e.capsule).is_err());
        assert!(matches!(e.desk.issue(e.request), Err(Error::NotRecovered)));
    }
    #[test]
    fn entropy_shortage_never_unlocks_or_consumes_a_capsule_attempt() {
        use prism::entropy::Coins;
        let mut e = enroll().unwrap();
        let mut entropy = Entropy::fixture(12);
        for _ in 0..3000 {
            entropy.draw();
        }
        let before = e.desk.state();
        assert_eq!(
            e.desk.recover_with_entropy(&e.capsule, &mut entropy),
            Err(Error::Capsule(prism::Failure::EntropyExhausted))
        );
        assert_eq!(e.desk.state(), before);
        e.desk.recover(&e.capsule).unwrap();
    }
    #[test]
    fn standard_sha256_and_public_blob_format_are_checked() {
        assert_eq!(
            hex(&cng::sha256(b"abc").unwrap()),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
        assert!(cng::PublicKey::from_bytes([0; 72]).is_err());
    }
}
