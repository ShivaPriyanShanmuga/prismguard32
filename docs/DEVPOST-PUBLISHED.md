![PrismGuard-32: masked key capsules](https://raw.githubusercontent.com/ShivaPriyanShanmuga/prismguard32/main/media/cover-3x2.png)

**Reviewer resources:** [Source and reproduction instructions](https://github.com/ShivaPriyanShanmuga/prismguard32) · [Technical paper in LaTeX](https://github.com/ShivaPriyanShanmuga/prismguard32/blob/main/docs/paper/main.tex) · [135-second captioned walkthrough](https://github.com/ShivaPriyanShanmuga/prismguard32/blob/main/media/PrismGuard-32-walkthrough.mp4)

## Inspiration

A key wrapper should explain what its security depends on and show what
happens when those assumptions fail. PrismGuard-32 began as a simple one-use
capsule and developed into a protected-computation and recovery experiment.
The focus is measurable security behavior: secret arithmetic stays in randomized
shares, authentication reveals only its decision, and hostile packets need not
destroy the first opportunity for legitimate recovery.

## What it does

The Rust application wraps a synthetic 32-byte master key in a 104-byte
authenticated capsule. A UTF-8 vault context is bound to it. The terminal lab
rejects modified packets, then recovers from the genuine packet and rejects
replay after success. Up to seven failed attempts may precede valid recovery
on attempt eight. An eighth failure locks the receiver.

The default demo uses memory and OS randomness only. It does not encrypt user
files, scan the machine, access real credentials, contact a server, or change
system settings.

## Mathematical construction

Let \(p=2^{61}-1\), encode the key as eight 32-bit words
\(m\in\mathbb F_p^8\), and let \(A=I+\mathbf1\mathbf1^T\). With a new
uniform mask \(r\leftarrow\mathbb F_p^8\), compute

$$c=A\left((Am+r)^{[17]}\right).$$

The exponent is coordinatewise. The matrix is invertible, with
\(A^{-1}=I-9^{-1}\mathbf1\mathbf1^T\), and \(17\) is coprime to \(p-1\).
Fresh full-entropy masking supplies the confidentiality argument; the public
matrix and power maps do not add entropy or cryptographic hardness.

Two independently keyed and masked polynomial tags authenticate an injective
encoding of the version, identifier, context byte length, context bytes, and
ciphertext. For \(T=(t_1,\ldots,t_N)\), \(N\le51\),

$$H_\alpha(T)=\alpha^{N+1}+\sum_{j=1}^N t_j\alpha^{N+1-j},\qquad
\tau_\ell=H_{\alpha_\ell}(T)+\beta_\ell\pmod p.$$

The final multiplication by \(\alpha\) is essential: no message coefficient
is an unkeyed constant term. Under ideal independent one-use material, the
public capsule distribution is independent of the key. For at most eight
public substitution attempts, the conservative union bound is

$$\Pr[\text{any altered-transcript acceptance}]
\le8\left(\frac{52}{p-1}\right)^2\approx2^{-107.6}.$$

This is an explicitly bounded public-adversary model, not an unrestricted
chosen-ciphertext or joint leakage-security theorem. The OS CSPRNG instantiates
the ideal randomness assumption computationally.

## The protected computation

Each private field value is represented as \(x=x_L+x_R\pmod p\). Binary
operations refresh shares before use, including independently refreshing both
inputs to squaring. A shared multiplication computes

$$\begin{aligned}
w_{00}&=UV,&w_{01}&=U(b-V),\\
w_{10}&=(a-U)V,&w_{11}&=(a-U)(b-V),\\
z_L&=w_{00}+\rho,&z_R&=((w_{01}-\rho)+w_{10})+w_{11}.
\end{aligned}$$

Here \(U,V,\rho\) are fresh independent uniform values. The explicit schedule
avoids accumulating unmasked cross terms. Each observed individual field wire
has an input-independent distribution in the stated arithmetic model. The
same generic multiplier schedule runs over the production field and the exact
small-field audit.

Tag differences also stay shared. Fermat's map \(\Delta^{p-1}\) produces a
nonzero bit; two such bits are combined in shares. Only the final rejection
bit is released. Authenticated plaintext crosses a separate, explicit release
boundary. This is more specific than claiming that branch-free-looking source
alone prevents side channels.

## Attacks and validation

![Protected single-wire model](https://raw.githubusercontent.com/ShivaPriyanShanmuga/prismguard32/main/media/model-safe.png)

![Deliberately unsafe negative control](https://raw.githubusercontent.com/ShivaPriyanShanmuga/prismguard32/main/media/model-unsafe.png)

- **14 passing Rust test groups**, including every byte value, parser and context
  boundaries, state transitions, correlated operations, and authenticated
  out-of-domain plaintext.
- **832 individual capsule-bit changes rejected.**
- **512 complete wire vectors** matched by independent Python big-integer code;
  **60,000 arithmetic results** checked.
- **2,000 reproducible multi-bit mutations** rejected, with valid recovery
  afterward. This is a synthetic mutation campaign, not coverage-guided fuzzing.
- **78,125 exact multiplier executions in each of Rust and Python.** The Rust
  model compares 19 wires across all 25 input pairs over \(\mathbb F_5\),
  with zero distribution mismatches.
- A deliberately unsafe cross-term sum is distinguishable with **exact
  total-variation distance 0.20**. Two output shares reconstruct the product,
  demonstrating the second-order boundary.
- A known-plaintext attack succeeds when logical pad material is deliberately
  reused. The failure is retained, not concealed.
- Rust rejects sender reuse and receiver cloning. Successful opening prevents
  further attempts in that receiver object.
- Three timing runs cover sealing, valid opening, rejected opening, and an
  intentionally leaky control, with **10,000 samples per class per case**.
  Ordered raw samples and all reported statistics are included.
- The inspected optimized library has no integer division instruction. The
  refresh/add/subtract/multiply bodies have no conditional jump; entropy access
  has public bounds checks. This is instruction-shape evidence, not a binary proof.

Recorded median times were approximately **1.7 microseconds to seal** and
**18.8 microseconds to open**, excluding pool provisioning. A separate full
workflow including OS randomness measured **88.5 microseconds median** on the
tested Windows x64 machine. Exact results, source hashes and limits accompany
the code; no portable throughput promise is made.

## What is new, and what is established

The contribution is this specific masked capsule/recovery protocol, its
explicit release contract, bounded-attempt state machine, implementation, and
shared-schedule adversarial harness. No existing plaintext-cipher implementation
is invoked. Finite-field masking, matrix/power maps, polynomial authentication,
and ISW-style share techniques are established foundations and are credited.
No global novelty claim or invention of universal hashing/masking is made.
The organizer determines how the track's pre-existing-algorithm restriction
applies to this composition.

## What the results do not claim

The exact small-field audit is a gadget experiment, not a whole-program formal
verification or hardware certificate. The protected circuit model considers an
individual field-wire observation. Multiple probes, continual leakage across
executions, register transitions, physical power/EM, glitches, speculation,
active faults, a compromised OS, and rollback are outside the established result.

Trusted ingestion/provisioning initially handles raw values. Authorized release
returns plaintext. Both shares occupy one process, and physical isolation is
not claimed. Logical material must never be reused or stored beside a capsule.
It costs 96 logical-material bytes, or 192 bytes as two shares, per endpoint.
Eight hostile packets can still deny recovery. Volatile wipes do not erase all
possible moves, spills, caller copies or crash dumps.

## What I learned

A useful security project must show what its tests can detect and where its
argument stops. The unsafe gadget control, reuse attack, and second-order
boundary are as important as passing tests. The improvement over the baseline
is protected computation and an explicit operational contract, rather than
extra public mathematical layers.

## Disclosure and references

AI assistance contributed to design, code, tests and writing. No independent
human cryptographic audit or physical measurement campaign has occurred.

- [Ishai, Sahai, Wagner: Private Circuits](https://iacr.org/archive/crypto2003/27290462/27290462.pdf)
- [Faust et al.: Robust probing and composability](https://eprint.iacr.org/2017/711)
- [Wegman and Carter](https://research.ibm.com/publications/new-classes-and-applications-of-hash-functions)
- [dudect, including testing limitations](https://github.com/oreparaz/dudect)
- [Intel timing guidance](https://www.intel.com/content/www/us/en/developer/articles/technical/software-security-guidance/secure-coding/mitigate-timing-side-channel-crypto-implementation.html)
