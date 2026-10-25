![PrismGuard-32: masked key capsules](https://raw.githubusercontent.com/ShivaPriyanShanmuga/prismguard32/main/media/cover-3x2.png)

**Cryptographer track Â· Rust research prototype Â· version 0.2.0**

**Reviewer resources:** [Application demo â€” 1:36, narrated](https://github.com/ShivaPriyanShanmuga/prismguard32#watch-the-recovery-desk-application) Â· [Construction demo on YouTube â€” 3:08, English captions](https://youtu.be/nHYJd-8BGlc) Â· [Source and reproduction instructions](https://github.com/ShivaPriyanShanmuga/prismguard32) Â· [Technical paper in LaTeX](https://github.com/ShivaPriyanShanmuga/prismguard32/blob/main/docs/paper/main.tex)

## Inspiration

A key wrapper should explain what its security depends on and show what
happens when those assumptions fail. PrismGuard-32 began as a simple one-use
capsule and developed into a protected-computation and recovery experiment.
The focus is measurable security behavior: secret arithmetic stays in randomized
shares, authentication reveals only its decision, and hostile packets need not
destroy the first opportunity for legitimate recovery.

## What it does

PrismGuard-32 encrypts a 32-byte master key in a 104-byte authenticated capsule.
It keeps private arithmetic in randomized shares and checks authentication
before releasing the recovered key. The Recovery Desk uses that recovered key
to sign a fresh access request; a public-key-only controller verifies the
signature before granting one synthetic training pass.

The core terminal lab uses a generated synthetic key and binds a UTF-8 vault
context to its capsule. The lab
rejects modified packets, then recovers from the genuine packet and rejects
replay after success. Up to seven failed attempts may precede valid recovery
on attempt eight. An eighth failure locks the receiver.

The default demo uses memory and OS randomness only. It does not encrypt user
files, scan the machine, access real credentials, contact a server, or change
system settings.

## Applicable environment: Recovery Desk

[Watch the narrated application demo â€” 1:36](https://github.com/ShivaPriyanShanmuga/prismguard32#watch-the-recovery-desk-application).

The capsule is also integrated into an offline Rust signing-key recovery
application on Windows. Windows CNG enrolls a P-256 signing identity; PrismGuard encrypts
its 32-byte private scalar. Original enrollment handles and shares are dropped.
After successful capsule recovery, the scalar signs a fresh, resource-bound
synthetic training-access pass. A controller holding **only the public key**
verifies that signature before granting one request. This is an actual
signature operation and application state change.

The interactive desk denies issuance before recovery, rejects altered capsules,
rejects modified or wrong-resource passes, grants the genuine request, and
blocks replay and second issuance. Its context binds the site and public-key
fingerprint. Replay state tracks the challenge, so alternate valid ECDSA
signature encodings cannot create a second grant.

There are **26 combined Rust test groups: 14 core and 12 application groups**.
An independent Python verifier checks **32 public passes and 32 alternate
valid encodings**, including altered-message and altered-signature controls.
The actual interactive workflow is also exercised.
[Application source, instructions, and scope](https://github.com/ShivaPriyanShanmuga/prismguard32/tree/main/apps/recovery-desk)
and [retained application evidence](https://github.com/ShivaPriyanShanmuga/prismguard32/tree/main/evidence/recovery-desk)
are included. CNG provides established signatures after authorized release;
the capsule's probing argument does not certify the provider. All requests
and grants are synthetic, all roles share one process, and durable rollback
protection and confidential provisioning remain outside this prototype.

## Build and review it

The implementation uses Rust with no third-party crates. Python supplies an
independent arithmetic oracle and public-signature verifier. The application
uses the installed Windows CNG provider for signatures after recovery. The
five capsule-core source files are unchanged by the application integration.

With Rust and Python installed, run from the repository root on Windows:

```powershell
python tools/recovery_desk_verify.py
.\build\recovery-desk.exe desk
```

The first command builds the application, runs the 26 combined test groups,
checks 32 fresh public passes with independent Python arithmetic, and exercises
the interactive workflow. In the desk, try issuing before recovery, an altered
capsule, valid recovery, an altered pass, a valid pass, and replay. The genuine
pass grants once; the altered pass does not consume the pending challenge.

[Full core reproduction guide](https://github.com/ShivaPriyanShanmuga/prismguard32/blob/main/docs/REPRODUCE.md) Â·
[Core results](https://github.com/ShivaPriyanShanmuga/prismguard32/blob/main/evidence/verification.json) Â·
[Application results](https://github.com/ShivaPriyanShanmuga/prismguard32/blob/main/evidence/recovery-desk/verification.json).
All demonstration keys and grants are generated for the experiment; no real
files, credentials, accounts, doors, or network targets are accepted.

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

- **14 passing core Rust test groups**, including every byte value, parser and context
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
- A supplemental audit uses correlated share masks and identical operands:
  **78,125 correlated-mask executions plus 3,125 squaring executions** in Rust
  and independently in Python. All 19 wire distributions agree across logical
  inputs. A deliberately broken missing-refresh control has exact
  **total-variation distance 0.60**, showing why both operands are refreshed.
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
The [contribution map and rejected-pivot analysis](https://github.com/ShivaPriyanShanmuga/prismguard32/blob/main/docs/ORIGINALITY-REVIEW.md)
separate the developed protocol and test harness from those foundations.
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

## Design lessons

The main implementation challenge was preserving the masked computation at
the operations that are easiest to overlook: correlated operands, squaring,
cross-term accumulation, and the authentication decision. The multiplier and
Fermat zero test use an explicit share schedule. Negative controls retain the
leaks caused by unsafe accumulation and missing operand refresh. The recovery
state machine separately handles failed attempts, authenticated release, and
one-use consumption. Recovery Desk then makes that release boundary observable
as a real signature and a verified application decision.

A useful security project must show what its tests can detect and where its
argument stops. The unsafe gadget control, reuse attack, and second-order
boundary are as important as passing tests. The improvement over the baseline
is protected computation and an explicit operational contract, rather than
extra public mathematical layers.

## Review status and references

No independent human cryptographic audit or physical measurement campaign has occurred.

- [Ishai, Sahai, Wagner: Private Circuits](https://iacr.org/archive/crypto2003/27290462/27290462.pdf)
- [Faust et al.: Robust probing and composability](https://eprint.iacr.org/2017/711)
- [Wegman and Carter](https://research.ibm.com/publications/new-classes-and-applications-of-hash-functions)
- [dudect, including testing limitations](https://github.com/oreparaz/dudect)
- [Intel timing guidance](https://www.intel.com/content/www/us/en/developer/articles/technical/software-security-guidance/secure-coding/mitigate-timing-side-channel-crypto-implementation.html)
- [Microsoft CNG signature operation](https://learn.microsoft.com/en-us/windows/win32/api/bcrypt/nf-bcrypt-bcryptsignhash)
- [NIST FIPS 186-5: digital signatures](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.186-5.pdf)
