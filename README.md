# PrismGuard-32

**A masked master-key capsule with an executable attack laboratory.**

Cryptographer track only. Research prototype, version 0.2.0.

PrismGuard-32 asks a concrete question: can a short key-capsule protocol keep
its private arithmetic in randomized shares, authenticate without exposing a
raw tag difference, and tolerate several hostile packets before recovery?
It includes code, a mathematical argument, exact small-field experiments,
negative controls that deliberately fail, and an in-memory recovery application.

The project improves on the preserved `PrismLock-32` baseline. The confidentiality
foundation remains full-entropy one-use masking; the contribution is the protected
computation, explicit release policy, bounded-retry contract, and reproducible
evidence. Public matrix/power layers do not create additional secrecy.

## Start here

```powershell
.\build\prismguard32.exe demo
.\build\prismguard32.exe lab
```

The demo generates a synthetic master key, seals it in a 104-byte capsule,
rejects three modified packets, recovers from the genuine packet, and blocks
replay after success. `lab` adds a small terminal menu and explains the limits.
No actual user key or file is accepted as input.

Build with the installed Rust toolchain and no downloads:

```powershell
New-Item -ItemType Directory -Path build -Force | Out-Null
rustc --edition=2021 -C opt-level=3 -C overflow-checks=yes src/main.rs -o build/prismguard32.exe
python tools/verify.py
```

The verification script uses plain `rustc`; it installs nothing and confines
compiler outputs, diagnostic sources, and evidence to this new project.
The default application has no file/network/process-spawning code on Windows.
Its external runtime dependency is Windows BCryptGenRandom. The Unix branch
reads `/dev/urandom` and has not been tested in this Windows run.

## What changed

| Baseline | PrismGuard-32 |
| --- | --- |
| Raw secret arithmetic | Two-share arithmetic, including the nonlinear map |
| Raw tag-difference comparison | Shared Fermat zero tests; one public status bit |
| One invalid packet consumes recovery | Up to seven rejections, then valid recovery on attempt eight |
| Basic positive tests | Exact gadget distributions plus deliberately leaky negative controls |
| Seal-only timing smoke test | Seal, valid open, rejected open, and timing negative control |
| 256 oracle vectors | 512 vectors including context-size boundaries |
| Limited performance accounting | Separate operation timing and full OS-RNG workflow timing |

## Protocol in brief

Work over p = 2^61 - 1. Encode 32 bytes as eight 32-bit field words m. Let
A = I + 11^T in dimension eight. With a new uniform mask vector r per capsule:

    c = A ((A m + r)^[17])

The power is coordinatewise. A is invertible and 17 is coprime to p - 1.
Two independent masked polynomial tags bind the version, public identifier,
context length, context bytes, and all ciphertext words. Each message
coefficient depends on the hidden evaluation point.

Every private value x is represented as xL + xR mod p. Binary private
operations refresh shares before using them, including both inputs of x*x.
The multiplier masks its cross-term accumulation before adding secret terms.
Verification computes x^(p-1) in shares to test whether each tag difference
is zero. It reveals the combined rejection bit, not either raw difference.
Only an authenticated result crosses the plaintext-release boundary.

## Claims and boundaries

- **Ideal one-use confidentiality:** uniform field masks make the complete
  public capsule message-independent. OS-CSPRNG output is a computational
  instantiation, not truly random entropy.
- **Bounded substitution:** at most eight verification attempts per material
  pair give the conservative ideal bound 8(52/(p-1))^2, about 2^-107.6.
- **Arithmetic-circuit leakage argument:** individual private field wires have
  input-independent distributions with fresh masks. The shared multiplication
  schedule is exhaustively checked over F5 in Rust and independently in Python.
  This is not exhaustive verification of the entire protocol or generated code.
- **No hardware certificate:** multiple probes, register transitions, glitches,
  power/EM leakage, speculation, faults, compromised OS, and continual leakage
  across executions are outside the established result.
- **Trusted boundaries:** raw-key ingestion, provisioning, and authorized
  plaintext release are explicitly outside protected arithmetic. Both share
  components reside in one process; there is no claim of physical isolation.
- **Never reuse logical material:** a published attack recovers a second
  plaintext if a pad is reused and one plaintext is known.
- **Availability is bounded:** the eighth rejection locks the receiver.
  Snapshots/rollback can bypass in-memory state. No durable replay ledger exists.

See `docs/SECURITY.md` and the compiled LaTeX project in `docs/paper/`.

## Evidence from this build

- 14 Rust test groups; all 832 single-bit capsule modifications rejected.
- 512 independent Python/Rust wire-format matches and 60,000 arithmetic checks.
- 2,000 reproducibly mutated capsules rejected, with valid recovery afterward.
- 78,125 exact gadget executions in each of Rust and Python; 475 per-input
  wire-distribution comparisons in the Rust model, with zero mismatches.
- An unsafe unmasked cross-term sum has exact total-variation distance 0.20.
  Two output shares reconstruct the product: the second-order boundary is visible.
- A supplemental correlated-share audit checks 78,125 executions plus 3,125
  explicit squaring executions in Rust and independently in Python. All 19
  observed-wire distributions agree; omitting independent operand refresh
  exposes a cross-product with exact total-variation distance 0.60.
- Three timing runs with 10,000 samples per class per case retain all reported
  measurements and cropping summaries. Deliberately leaky controls are detected.
- This recorded run has no exploratory timing signal above 4.5 in the protected
  cases. This does not certify constant-time behavior or define a p-value.
- Optimized Windows x64 library assembly has no integer division instruction.
  The protected refresh/add/subtract/multiply function bodies have no conditional
  jump in the inspected build; their entropy-provider calls have public bounds checks.

Measured medians on this machine: seal 1.7 us, valid open 18.8 us (random
provisioning excluded); full provisioning/ingress/seal/open including OS entropy
pools 88.5 us. The raw JSON, sample counts, compiler version and source hashes
are included. These are observations from one run, not promises of throughput.

## Review guide

- `docs/DECISIONS.md`: why the project pivoted, comparison, and remaining gaps.
- `docs/SECURITY.md`: threat model, proof scope, prior work, and attack findings.
- `docs/paper/main.tex`: precise construction, masking schedule, and proofs.
- `docs/DEVPOST.md`: submission narrative with rendered-math syntax.
- `docs/DEVPOST-PUBLISHED.md`: the saved Devpost body with reviewer links and platform-specific inline-math escaping.
- `evidence/verification.json`: complete aggregate results.
- `tools/reference.py`: independent oracle and explicit reuse attack.
- `tools/audit.rs`: exact generic-gadget audit and synthetic mutation campaign.
- `tools/timing.rs`: diagnostic timing harness with negative control.
- `tools/verify.py`: single-command reproduction without package downloads.
- `tools/correlation_audit.py`: independently checked correlated-share and squaring experiment.
- `docs/ORIGINALITY-REVIEW.md`: contribution map and why a secret-matrix pivot was rejected.

The `audit` and `fixtures` features deliberately reveal synthetic diagnostics
and use deterministic test randomness. They are absent from the normal demo
binary and must never be used to provision operational keys.

## Originality and review status

This exact implementation and protocol composition were developed for this
hackathon. Finite-field masking, two-share gadgets, polynomial authentication,
and probing models are established techniques, explicitly credited. There is
no claim of inventing those techniques, proving worldwide novelty, or obtaining
a new multi-use encryption primitive. The organizer must interpret the rule
against pre-existing encryption algorithms; implementing mathematical components
ourselves does not automatically settle that interpretation.

No independent human cryptographic audit or physical measurement campaign has
been performed. This is a documented research experiment, not production software.

## Primary references

- [Hackathon requirements](https://mathematics-systems-security.devpost.com/)
- [Private Circuits, Ishai-Sahai-Wagner](https://iacr.org/archive/crypto2003/27290462/27290462.pdf)
- [Robust probing and composability, Faust et al.](https://eprint.iacr.org/2017/711)
- [Wegman-Carter authentication foundations](https://research.ibm.com/publications/new-classes-and-applications-of-hash-functions)
- [dudect and its limits](https://github.com/oreparaz/dudect)
- [Intel timing guidance](https://www.intel.com/content/www/us/en/developer/articles/technical/software-security-guidance/secure-coding/mitigate-timing-side-channel-crypto-implementation.html)
- [Microsoft BCryptGenRandom](https://learn.microsoft.com/en-us/windows/win32/api/bcrypt/nf-bcrypt-bcryptgenrandom)
