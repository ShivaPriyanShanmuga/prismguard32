# Contribution and pivot review

The Cryptographer rubric awards three points for cryptanalysis, two for
uniqueness, three for attack-surface reduction, and two for LaTeX. The
[overview](https://mathematics-systems-security.devpost.com/) also prohibits
pre-existing plaintext-encryption algorithms. No organizer clarification is
available. This note distinguishes the project's contribution from its
foundations without claiming that the ambiguity has been resolved.

| Item | Classification | What can be claimed |
| --- | --- | --- |
| Fresh field translation | Established perfect-secrecy principle | A specific one-use construction and proof, not a new secrecy principle |
| Public matrix and power maps | Established algebraic operations | Exact invertibility and encoding; no extra hardness |
| Two-share operations | Established masking family | An explicit refreshed schedule and reproducible experiments |
| Polynomial authentication | Established universal-hashing family | Specific transcript, final keyed coefficient, and bounded-attempt analysis |
| Capsule/recovery composition | Developed for this project | Concrete Rust API, wire format, release boundaries, and receiver policy |
| Adversarial laboratory | Developed for this project | Independent oracle, retained attacks, correlated-share audit, and negative controls |

No existing plaintext-cipher library is called. That fact alone is insufficient
to prove originality or eligibility: an independently written implementation
can still instantiate a familiar algorithm. The entry makes no worldwide
novelty, professional-audit, or production-resistance assertion.

## A rejected secret-matrix pivot

One alternative replaced public transforms plus a pad with a secret uniformly
random invertible 2-by-2 matrix M over Fp and ciphertext C=M(m,1)^T. The lifted
input avoids the zero vector. GL(2,p) acts transitively on nonzero vectors, so
one-use ciphertext distributions are equal for every m. Specifically, each
of the p^2-1 outputs has p^2-p preimages among the matrices.

This is not evidence of a new primitive. Secret linear transformations have
long-standing prior art, including [Hill's original paper](https://doi.org/10.1080/00029890.1929.11986963).
The proposed one-use variant also needs four field elements per scalar input
and doubles that scalar's ciphertext representation.

If the matrix is reused for two known distinct inputs m0 and m1, write their
outputs as (u0,v0) and (u1,v1). Then

    a = (u1-u0)/(m1-m0),  c = (v1-v0)/(m1-m0),
    b = u0-a*m0,         d = v0-c*m0.

All four matrix coefficients are recovered. The exact F5 experiment enumerates
all 480 invertible matrices, checks equal one-use distributions over 24
outputs, and demonstrates 9,600 two-known-input matrix recoveries. See
`tools/pivot_review.py` and `evidence/pivot-review.json`.

Decision: retain PrismGuard-32 rather than claim a superficial originality
improvement. A fresh small-key nonlinear cipher would require substantially
more independent cryptanalysis than this entry can substantiate.

## Improvement chosen

The new correlated-share experiment addresses a real gap in the original
evidence: independent input masks do not directly test repeated squaring.
It checks correlated limbs and identical operands through the exact generic
multiplier used by the Rust implementation. The negative control exposes a
missing-refresh leak. This strengthens a narrow, reproducible security result;
it does not turn established components into a new encryption primitive.

## Presentation and accuracy

No explicit mandatory AI-disclosure clause was found in the published overview,
rules, resources, or displayed track fields when checked on October 25, 2026.
An optional presentation banner is not treated as a hackathon requirement.
The [Devpost community guidelines](https://info.devpost.com/legal/community-guidelines)
still require accurate representation and proper credit. No assertion of
sole-human authorship or absence of AI use is made. Direct questions about
tools or authorship must be answered accurately. Existing publication history
is preserved rather than rewritten.
