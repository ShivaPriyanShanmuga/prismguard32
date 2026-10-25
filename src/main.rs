#[path = "lib.rs"]
mod prism;
use prism::{
    entropy::{fresh_id, Entropy},
    ReceiverState, Secret32,
};
use std::io::{self, Write};
fn hex(data: &[u8]) -> String {
    data.iter().map(|b| format!("{b:02x}")).collect()
}
fn demo() {
    println!("PRISMGUARD-32 | Masked key capsule + adversarial recovery lab\nResearch prototype; synthetic data only\n");
    let mut setup = Entropy::system().expect("OS entropy required");
    let (sender, mut receiver) = prism::provision(fresh_id().unwrap(), &mut setup).unwrap();
    let secret =
        prism::ingest(Secret32::new(std::array::from_fn(|i| i as u8)), &mut setup).unwrap();
    let context = "vault/student-lab/λ".as_bytes();
    let mut sealing = Entropy::system().unwrap();
    let capsule = prism::seal(sender, &secret, context, &mut sealing).unwrap();
    println!("[1] Masked synthetic master key; protected computation uses two shares");
    println!("[2] Public 104-byte capsule: {}", hex(&capsule));
    println!("    Fresh blinding words used by seal: {}", sealing.used());
    let mut tampered = capsule;
    tampered[44] ^= 1;
    for packet in 1..=3 {
        assert!(receiver
            .attempt(&tampered, context, &mut Entropy::system().unwrap())
            .is_err());
        println!(
            "[3.{packet}] Modified ciphertext: REJECTED; state {:?}",
            receiver.state()
        );
    }
    let mut opening = Entropy::system().unwrap();
    let recovered = receiver.attempt(&capsule, context, &mut opening).unwrap();
    assert_eq!(
        recovered.expose(),
        &std::array::from_fn::<_, 32, _>(|i| i as u8)
    );
    println!("[4] Valid recovery after three bad packets: PASS");
    println!("    Fresh blinding words used by open: {}", opening.used());
    assert_eq!(receiver.state(), ReceiverState::Opened);
    assert!(receiver
        .attempt(&capsule, context, &mut Entropy::system().unwrap())
        .is_err());
    println!("[5] Replay after success: BLOCKED");
    println!("[6] Owned shares/material wiped on drop (copies/spills are not guaranteed erased)");
    println!("\nWindows demo: stdout + OS randomness only; no files, sockets, subprocesses or real credentials.");
    println!("Formal boundary: single field-wire probing model. Not hardware side-channel certification.");
}
fn lab() {
    loop {
        println!("\nPrismGuard lab: [1] recovery/tamper demo  [2] threat boundary  [q] quit");
        print!("> ");
        io::stdout().flush().unwrap();
        let mut line = String::new();
        if io::stdin().read_line(&mut line).unwrap() == 0 {
            break;
        }
        match line.trim(){
            "1"=>demo(),
            "2"=>println!("Never reuse provisioning material. Trusted ingress/authorized release are outside probing protection.\nTwo probes, physical transitions, a compromised OS, snapshots and rollback are outside the model.\nEight rejected packets exhaust the budget. Material must be delivered confidentially.\nEstablished masking/authentication techniques are credited; no global novelty or audit is claimed."),
            "q"|"quit"=>break,_=>println!("Choose 1, 2, or q.")
        }
    }
}
fn main() {
    match std::env::args().nth(1).as_deref() {
        None | Some("demo") => demo(),
        Some("lab") => lab(),
        _ => {
            eprintln!("Usage: prismguard32 [demo|lab]");
            std::process::exit(2);
        }
    }
}
