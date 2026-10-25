//! Safe synthetic application: no files, sockets, system settings or real passes.
mod app;
mod cng;
#[allow(dead_code)]
#[path = "../../src/lib.rs"]
mod prism;
use app::{enroll, hex, Enrollment, Error, Receipt};
use std::io::{self, Write};

// Public signature arithmetic for an adversarial evidence case only. ECDSA
// admits (r,n-s) as an alternate valid encoding; replay state must use the
// challenge, never a hash of the signature bytes.
fn alternate_signature(signature: &[u8; 64]) -> [u8; 64] {
    let order = [
        0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xbc, 0xe6, 0xfa, 0xad, 0xa7, 0x17, 0x9e, 0x84, 0xf3, 0xb9, 0xca, 0xc2, 0xfc, 0x63,
        0x25, 0x51,
    ];
    let mut result = *signature;
    let mut borrow = 0i16;
    for i in (0..32).rev() {
        let value = order[i] as i16 - signature[32 + i] as i16 - borrow;
        result[32 + i] = value as u8;
        borrow = i16::from(value < 0);
    }
    assert_eq!(borrow, 0);
    result
}

fn demo() -> app::Result<()> {
    let mut e = enroll()?;
    println!("PRISMGUARD RECOVERY DESK | OFFLINE APPLICATION\nSynthetic training passes; no real credentials, devices or files.\n");
    println!("[1] Enrolled a CNG P-256 signing key; protected its 32-byte scalar in a PrismGuard capsule.");
    println!(
        "    Public identity: {}",
        hex(&cng::sha256(e.public.bytes())?[..8])
    );
    println!(
        "    Original private provider handle, export blob and enrollment shares are dropped."
    );
    assert!(matches!(e.desk.issue(e.request), Err(Error::NotRecovered)));
    println!("[2] Issue training pass before recovery: DENIED");
    let mut tampered = e.capsule;
    tampered[44] ^= 1;
    for i in 1..=3 {
        assert!(e.desk.recover(&tampered).is_err());
        println!("[3.{i}] Altered capsule: REJECTED; signing remains locked");
    }
    e.desk.recover(&e.capsule)?;
    println!("[4] Authenticated recovery: READY TO ISSUE");
    let receipt = e.desk.issue(e.request)?;
    println!(
        "[5] Recovered scalar used by CNG to sign a nonce-bound bench-7 request: 64-byte signature"
    );
    let mut bad = receipt;
    bad.signature[9] ^= 1;
    assert_eq!(
        e.controller.verify_and_grant(&bad),
        Err(Error::InvalidSignature)
    );
    println!("[6] Altered signed pass: REJECTED; challenge remains pending");
    let mut wrong = receipt;
    wrong.request.resource = 8;
    assert_eq!(
        e.controller.verify_and_grant(&wrong),
        Err(Error::WrongRequest)
    );
    println!("[7] Wrong-resource pass: REJECTED");
    let grant = e.controller.verify_and_grant(&receipt)?;
    println!("[8] Controller verifies with PUBLIC KEY ONLY -> {grant}");
    assert_eq!(
        e.controller.verify_and_grant(&receipt),
        Err(Error::NoPendingChallenge)
    );
    assert!(matches!(e.desk.issue(e.request), Err(Error::AlreadySpent)));
    println!(
        "[9] Pass replay and second issuance: BLOCKED; total grants = {}",
        e.controller.grants()
    );
    println!("\nProtected action is a real signature and verified state change, not a recovered-byte equality test.");
    println!("CNG signatures run after authorized release; the capsule probing model does not certify CNG.");
    println!("All roles are simulated in one process. Provisioning and restart/rollback protection remain external.");
    Ok(())
}
fn evidence() -> app::Result<()> {
    for index in 0..32 {
        let mut e = enroll()?;
        e.desk.recover(&e.capsule)?;
        let receipt = e.desk.issue(e.request)?;
        let mut bad = receipt;
        bad.signature[9] ^= 1;
        let altered_rejected = e.controller.verify_and_grant(&bad) == Err(Error::InvalidSignature);
        let granted = e.controller.verify_and_grant(&receipt).is_ok();
        let replay_rejected =
            e.controller.verify_and_grant(&receipt) == Err(Error::NoPendingChallenge);
        let alternate = alternate_signature(&receipt.signature);
        let alternate_valid = cng::verify(&e.public, &e.request.digest()?, &alternate)?;
        let alternate_replay_rejected = e.controller.verify_and_grant(&Receipt {
            request: e.request,
            signature: alternate,
        }) == Err(Error::NoPendingChallenge);
        println!("{{\"index\":{index},\"public_blob\":\"{}\",\"request\":\"{}\",\"sha256\":\"{}\",\"signature\":\"{}\",\"alternate_signature\":\"{}\",\"alternate_signature_valid\":{alternate_valid},\"alternate_replay_rejected\":{alternate_replay_rejected},\"context\":\"{}\",\"capsule\":\"{}\",\"altered_signature_rejected\":{altered_rejected},\"granted\":{granted},\"replay_rejected\":{replay_rejected},\"grants\":{}}}",hex(e.public.bytes()),hex(&e.request.encode()),hex(&e.request.digest()?),hex(&receipt.signature),hex(&alternate),hex(e.desk.context()),hex(&e.capsule),e.controller.grants());
    }
    Ok(())
}
fn show(e: &Enrollment, receipt: &Option<Receipt>) {
    println!(
        "\nDesk: {:?} | controller grants: {} | pass issued: {}",
        e.desk.state(),
        e.controller.grants(),
        receipt.is_some()
    );
    println!(
        "Synthetic resource: bench 7 | challenge {}",
        hex(&e.request.nonce)
    );
    println!("[1] altered capsule  [2] recover genuine capsule  [3] issue pass");
    println!("[4] submit pass  [5] alter signature and submit  [n] new enrollment  [q] quit");
}
fn desk() -> app::Result<()> {
    let mut e = enroll()?;
    let mut receipt = None;
    println!("PRISMGUARD RECOVERY DESK | Interactive synthetic workflow");
    println!("No real lab, OS permission, file or account is affected.");
    loop {
        show(&e, &receipt);
        print!("> ");
        io::stdout().flush().unwrap();
        let mut input = String::new();
        if io::stdin().read_line(&mut input).unwrap() == 0 {
            break;
        }
        match input.trim() {
            "1" => {
                let mut bad = e.capsule;
                bad[44] ^= 1;
                println!("Recovery result: {:?}", e.desk.recover(&bad));
            }
            "2" => println!("Recovery result: {:?}", e.desk.recover(&e.capsule)),
            "3" => match e.desk.issue(e.request) {
                Ok(pass) => {
                    println!("Signed pass: {}", hex(&pass.signature));
                    receipt = Some(pass)
                }
                Err(err) => println!("Issuance denied: {err:?}"),
            },
            "4" | "5" => {
                if let Some(pass) = receipt {
                    let mut pass = pass;
                    if input.trim() == "5" {
                        pass.signature[9] ^= 1
                    }
                    println!("Controller: {:?}", e.controller.verify_and_grant(&pass));
                } else {
                    println!("No signed pass exists.")
                }
            }
            "n" => {
                e = enroll()?;
                receipt = None;
                println!("Fresh independent enrollment created.");
            }
            "q" | "quit" => break,
            _ => println!("Choose a displayed command."),
        }
    }
    Ok(())
}
fn main() {
    let result = match std::env::args().nth(1).as_deref() {
        None | Some("demo") => demo(),
        Some("desk") => desk(),
        Some("evidence") => evidence(),
        _ => {
            eprintln!("Usage: recovery-desk [demo|desk|evidence]");
            std::process::exit(2)
        }
    };
    if let Err(err) = result {
        eprintln!("Recovery Desk failed closed: {err:?}");
        std::process::exit(1)
    }
}
