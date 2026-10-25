# Design decisions and competitive review

## The pivot

The original PrismLock-32 was a clear one-use field capsule with good basic
tests. Its public matrix and power layers did not improve secrecy beyond
full-entropy masking. Adding more public layers, a homemade small-key cipher,
or cosmetic complexity would not fix that weakness responsibly.

PrismGuard-32 keeps the inspectable confidentiality foundation and moves the
contribution to a concrete security boundary: protected computation on shares,
masked verification, and a bounded receiver state machine with executable
evidence. This is an implementation/protocol contribution, not an assertion
that a new hard cryptographic problem has been discovered.

## Alternatives considered

| Direction | Decision |
| --- | --- |
| More public matrix/power rounds | Reject: no new secrecy; misleading complexity |
| Invent a fast small-key block/stream cipher | Reject: no responsible way to establish competitive security in this session |
| Implement an existing AES/ChaCha encryption library | Reject: conflicts with the track's explicit plaintext-encryption restriction |
| Present existing leakage-resilient storage as novel | Reject: existing literature already covers it |
| Add measured masking, safe release, retry analysis, and negative controls | Choose: concrete, inspectable improvement with a limited mathematical argument |

## Criteria mapping

| Criterion | Evidence | Remaining limitation |
| --- | --- | --- |
| Cryptanalysis | Exact definitions/proofs; oracle; reuse attack; forgery regression; negative controls | Not an independent professional audit or general multi-query CCA result |
| Originality | Exact capsule composition, protected implementation, release/retry contract, shared-schedule test harness | Components are established; organizer interpretation remains material |
| Attack surface | Shared nonlinear arithmetic; masked tag comparison; canonical parser; ownership; bounded retries | Trusted endpoints, hardware leakage, rollback, and multi-probe attacks remain outside claims |
| LaTeX | Compiled full technical paper and mathematical Devpost narrative | Judges must be able to access the paper/source |
| Low-level code | Dependency-free Rust | One compiler/target tested |
| Application | In-memory vault recovery after adversarial packets; replay rejection; terminal lab | Synthetic application, no deployed vault or actual user secrets |
| Video | Generated captioned local walkthrough and project gallery | Hosting/publication is a separate external action |

## Reuse and availability

Randomized internal shares can be refreshed repeatedly; logical pad and tag
material cannot be used for a second encryption. The receiver's eight-attempt
policy changes the authentication contract: a union bound loses at most three
bits relative to one attempt. Seven bad packets need not prevent the eighth
valid recovery. Eight bad packets still deny service. A durable anti-rollback
ledger and a sound provisioning system are not implemented.

The leakage argument permits one sensitive field-wire observation in the
protected computation being analyzed. It is not a continual-leakage theorem
allowing an adversary to collect complementary shares over separate runs.

## Readiness

This version materially improves the security work and reviewer experience.
It remains inappropriate to call it guaranteed to win, globally novel, audited,
or physically side-channel resistant. Organizer clarification is unavailable.
The entry therefore states its contribution precisely and preserves the
originality uncertainty instead of assuming an exception to the published rule.

A further secret-matrix alternative was analyzed and rejected: a new appearance
did not establish a new cryptographic foundation and increased material costs.
See `ORIGINALITY-REVIEW.md` and the executable small-field experiment.
The chosen improvement is a correlated-share and squaring audit of the actual
generic multiplier, with an independently checked missing-refresh control.

## Machine-safety record

All new work lives in PrismGuard-32. PrismLock-32 is retained unchanged and its
files are hashed before/after verification. There are no delete operations,
system-setting changes, real credentials, malware samples, network targets,
exploits against software on the machine, or arbitrary file encryption.
The attacks are mathematical counterexamples and timing measurements of this
project's own synthetic functions. Core cryptographic verification installs
no dependencies. Subsequent optional neural narration used a PyPI client in
the project's own build folder and sent only the public explanation text.
