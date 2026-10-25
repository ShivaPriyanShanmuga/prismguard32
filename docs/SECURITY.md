# Security argument and adversarial findings

## Exact scope

An experimental one-use master-key capsule with eight receiver attempts.
Its protection begins after trusted ingestion/provisioning has converted raw
values to shares. Authorized plaintext release ends that boundary. One process
contains both shares; they are not separate OS/hardware security domains.

The public adversary knows the algorithm, sees one capsule, and may submit at
most eight candidate packets to the corresponding receiver. The ideal circuit
leakage analysis additionally considers one sensitive field-wire observation,
including a full field word, with fresh independent gadget randomness.
It does not permit a second probe or complementary probes collected across
executions. Endpoint compromise, memory snapshots/rollback, power/EM,
register transitions, glitches, speculation, and active fault injection are
not covered. No compiler or physical implementation proof is claimed.

## Capsule and mathematical foundation

p = 2^61 - 1; m consists of eight 32-bit words; A = I + 11^T; c = A((Am+r)^[17]).
A^-1 = I - 9^-1 11^T, and gcd(17,p-1)=1. Fresh uniform r makes Am+r uniform;
public bijections preserve it. Independent beta masks hide both polynomial
tags. The complete ideal public distribution is independent of m.

This is equivalent in confidentiality to full-entropy additive masking through
public bijections. Public layers do not add hardness or entropy. Every logical
pad is one-use. Reusing it permits the reference attack to recover another
plaintext from one known plaintext. This is an explicit limitation, not an
attack claimed to be prevented by the new internal masking.

The stored key material has twelve logical field values (96 storage bytes).
Two-share storage uses 192 bytes per endpoint, plus a public 16-byte identifier.
The 32-byte master key occupies 128 bytes as eight two-share field values.
Each entropy pool is 8,192 field words / 64 KiB. Maximum observed seal/open
blinding consumption at the context bound is 482 / 3,317 field words.

## Two-share multiplication

Write a = aL+aR, b = bL+bR. Refresh each input with independent deltas.
The refreshed first shares U,V are independent uniform values, including
when the logical operands are identical or correlated. Compute:

    w00 = U V                 w01 = U (b-V)
    w10 = (a-U) V             w11 = (a-U)(b-V)
    outL = w00 + rho
    t0 = w01 - rho
    t1 = t0 + w10
    outR = t1 + w11

All arithmetic is in the field. The outputs sum to ab. Each w term is a product
of two independent uniform variables, whose distribution is independent of a,b.
Each accumulated value containing independent rho is uniform. Previous input
shares and refresh deltas individually have input-independent distributions.
Binary addition/subtraction also refresh one operand first, preventing
correlated-mask cancellation. Public scaling/addition is handled separately.

This gives a single-wire argument for the ideal arithmetic schedule. The same
generic multiplier is instantiated over F61 for production and F5 for exact
enumeration. The audit observes 19 wires and checks all 25 logical input pairs
and 3,125 random assignments per pair. Python independently repeats the model.
The result is not a whole-program verification or a robust/composable
higher-order masking theorem. It does not establish properties of Rust
register allocation or physical leakage.

## Why the negative control matters

If the cross terms are combined without rho, the unsafe value is ab - UV.
The product UV has a larger mass at zero; its shifted distribution reveals
information about ab. The exact toy model finds total-variation distance 0.20
between the selected logical cases. Both output shares together reveal ab
completely. These experiments demonstrate both the protection target and its
second-order boundary. No claim of protection against those excluded cases is made.

## Verification without a raw tag-difference release

Each transcript has at most 51 field coefficients. Its hash starts with a
leading 1 and finishes with multiplication by alpha, so different encodings
give nonconstant polynomial differences of degree at most 52 and zero constant
term. Independent beta masks leave alpha hidden after observing a valid tag.
Each substitution attempt has probability at most epsilon = (52/(p-1))^2.

Tag differences remain shared. Fermat's map delta^(p-1) yields 0 at zero and
1 elsewhere. The two nonzero bits are combined as b0+b1-b0*b1 in shares, and
only the resulting public rejection bit is released. Valid and invalid paths
may have different duration after this deliberate status release; no claim
of timing-equalized outcomes is made.

## Bounded adaptive attempts

Before the first acceptance, the adversary sees only rejections. For any
fixed external randomness and observed public capsule, the sequence along
that all-rejection path is fixed. Each candidate's acceptance event obeys
the original substitution bound. The union bound therefore gives Q*epsilon
for any Q <= 8 attempts, without incorrectly treating alpha as freshly
uniform after each rejection. Canonical parsing failures consume the same
public attempt budget. For an unchanged genuine packet, accepting it is not
a forgery. The eighth failure locks the receiver; success consumes the
material and prevents further attempts in that object.

The bound is about public substitution attempts in the ideal randomness model.
It is not an unrestricted chosen-ciphertext theorem with arbitrary leakage,
multiple encryptions under the pad, or rollback. One arithmetic-wire probe is
analyzed separately; the project does not claim the same numerical forgery
bound against additional key-dependent leakage without a joint security proof.

## Evidence versus claims

| Evidence | Supports | Does not establish |
| --- | --- | --- |
| 14 Rust groups | Specified correctness/state/parser behavior | General cryptographic security |
| 512 independent vectors | Agreement on encoding and arithmetic | A new hard primitive |
| 60,000 arithmetic checks | Additional arithmetic correctness evidence | Exhaustive F61 arithmetic verification |
| Exact F5 gadget model | Input-independent single-wire distributions in that model | All machine instructions or whole protocol |
| Unsafe gadget/reuse attacks | Tests detect declared failures | Independent human cryptanalysis |
| Timing with negative controls | Detection pipeline sees an intentional large timing leak | Absence of smaller or different leakage |
| Target assembly inspection | Specific instruction/branch observations | Compiler/CPU-independent constant-time proof |

## Memory lifetime and entropy

Owned shares, raw ingress buffers, and entropy pools have volatile wipe paths.
Consumed pool words are wiped immediately. Compiler moves, registers, spills,
caller copies, paging and crash dumps may retain data. Provisioning necessarily
duplicates logical material for sender/receiver. Raw ingestion/provisioning
temporaries belong to the trusted boundary. RNG failures return an error;
there is no deterministic fallback. Rare rejection loops are bounded.

## Prior work

The masked multiplication is a two-share arithmetic construction in the family
of established ISW-style masking techniques, with independent input refreshes
and an explicit schedule. No invention of masking or universal hashing is
claimed. The exact application, transcript, state policy, implementation,
release boundary and accompanying harness were developed for this entry.

- [Ishai, Sahai, Wagner: Private Circuits](https://iacr.org/archive/crypto2003/27290462/27290462.pdf)
- [Faust et al.: Robust probing and composability](https://eprint.iacr.org/2017/711)
- [Wegman and Carter](https://research.ibm.com/publications/new-classes-and-applications-of-hash-functions)
- [dudect documentation, including limitations](https://github.com/oreparaz/dudect)
- [Intel timing guidance](https://www.intel.com/content/www/us/en/developer/articles/technical/software-security-guidance/secure-coding/mitigate-timing-side-channel-crypto-implementation.html)

No independent human audit has occurred.

## Correlated operands and squaring

Independent input sharing is not a sufficient test for the implementation's
repeated squaring operations. The supplemental `correlation_audit` runs the
same generic Rust multiplier with input left limbs u and u+k for every k in
F5, every logical input pair, and all fresh randomness. That is 78,125
executions and 2,375 per-input wire comparisons. Another 3,125 executions and
95 comparisons explicitly use the identical complete input share twice.
All 19 single-wire histograms agree across logical inputs in each experiment.
Python checks the distributions independently and matches Rust's retained
reference histograms exactly. Source hashes accompany the evidence.

The missing-refresh control exposes u(a-u) when squaring. For logical inputs
0 and 1, its F5 count histograms are [1,2,0,0,2] and [2,0,0,2,1], giving exact
total-variation distance 0.60. This makes the reason for independent operand
refresh observable. The control is a mathematical counterexample, not a
modification to the production implementation. These tests remain local
gadget evidence; they do not establish arbitrary composition, a joint
leakage-and-forgery theorem, machine-code noninterference, or physical safety.
