# PrismGuard-32 narrated demonstration

## 1. A masked master-key capsule

Prism Guard thirty two is a master key capsule and recovery laboratory. It wraps a synthetic thirty two byte key in an authenticated capsule. This demonstration uses no real credentials or user files.

## 2. Bounded recovery

The receiver can reject seven hostile packets and still recover from a genuine eighth packet. An eighth failure locks the receiver. After successful recovery, the receiver refuses further attempts. This makes both the recovery policy and its availability limit explicit.

## 3. Number theory and linear algebra

The construction uses a prime equal to two to the power of sixty one, minus one. An invertible matrix and a coordinate power transform the masked key. Fresh, independent, one use secret material supplies confidentiality. The public transformations do not add cryptographic hardness.

## 4. Protected computation

Private field values stay in two randomized shares. Both operands are independently refreshed before multiplication, including when a value is squared. Authentication differences also stay shared. Verification releases only its final decision, and plaintext is released only after authentication succeeds.

## 5. Exact small-field experiment

The exact small field experiment observes nineteen wires in the multiplier. Every logical input pair and every random assignment is checked. The protected wire distributions match across secret inputs. The same generic Rust schedule is used in production, and Python independently checks the experiment.

## 6. A control that deliberately leaks

The deliberately unsafe control combines cross terms without their random mask. Its distributions differ by total variation zero point two, so this experiment detects the intended leak. Observing both output shares also reconstructs the product. That attack lies outside the single wire protection model.

## 7. Actual captured demonstration output

This is an excerpt of actual captured Rust output. Three altered packets are rejected. The genuine capsule then recovers exactly the synthetic key. A replay after successful recovery is blocked. This is captured output presented as a walkthrough, rather than a continuous screen recording.

## 8. Additional adversarial evidence

The suite includes fourteen Rust test groups and an independent capsule oracle. An additional eighty one thousand two hundred and fifty executions test correlated shares and squaring. Those distributions match, while omitting independent refresh exposes a measurable leak. Timing diagnostics retain raw measurements and deliberately leaky controls.

## 9. Security boundaries

The limits matter. Never reuse logical pad material, and keep provisioning confidential. These arithmetic experiments are not a physical side channel certificate or an independent cryptographic audit. Multiple probes, power measurements, a compromised operating system, and rollback remain outside the established result. The source, mathematical paper, and reproducible evidence are available for review.
