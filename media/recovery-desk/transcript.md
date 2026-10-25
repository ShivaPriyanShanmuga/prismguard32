# PrismGuard Recovery Desk application demonstration

## 1. A recovered key that does something

The recovery desk gives the protected key a real application job. A fresh signing key is wrapped in a Prism Guard capsule. After authenticated recovery, it signs a synthetic training access pass. A separate controller verifies that pass using only the public key.

## 2. Recovery gates the signing operation

This is actual captured output from the application. Issuing a pass before recovery is denied. Three altered capsules are rejected, and signing stays locked. The genuine capsule then restores the signing key and makes the desk ready to issue one pass.

## 3. The controller makes a verified decision

The recovered key now performs a real signature operation through Windows. An altered signature and a wrong resource are rejected. The genuine signed pass grants one synthetic request. Replaying the pass, or asking the desk for another signature, is blocked.

## 4. Independent application evidence

Twenty six combined Rust test groups pass. Python independently verifies thirty two fresh public signatures and their alternate valid encodings. The controller tracks the challenge rather than signature bytes, so changing the signature encoding cannot produce another grant. The interactive application is tested as well.

## 5. The application boundary is explicit

Prism Guard encrypts the key. Windows provides the established signature operation after authorized recovery. That provider is outside the capsule leakage proof. All data and grants are synthetic, and all roles currently share one process. No real file, credential, device permission, or account is affected.
