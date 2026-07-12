# How to Justify & Validate that the Crypto is Genuinely Post-Quantum

> If an evaluator asks *"How do I know this is really post-quantum and not just a claim?"*,
> answer with these **five levels of evidence**, from "it is by construction" to a live proof
> you can run on the spot. Each level is independently convincing; together they're airtight.

---

## The one-line answer

**"It's post-quantum because the key exchange uses ML-KEM (NIST FIPS 203) via liboqs — the
official post-quantum standard — and I can prove it's really running: the key/ciphertext sizes
match the standard exactly, the two sides derive an identical secret (so decryption succeeds),
and tampering breaks it. Here, let me run the self-test."**

Then run:
```bash
cd gateway && make pqc_selftest && ./pqc_selftest
```

---

## Level 1 — By construction (it *is* post-quantum)

The definition of "post-quantum" is: it uses an algorithm believed secure against quantum
computers. We use **ML-KEM (formerly Kyber)** — the algorithm **NIST standardized as FIPS 203**
after a multi-year global cryptanalysis competition — via **liboqs (Open Quantum Safe)**, the
reference open-source PQC library.

Show the code in `gateway/pqc_handshake.c`:
```c
#include <oqs/oqs.h>                         // Open Quantum Safe
OQS_KEM *kem = OQS_KEM_new(OQS_KEM_alg_kyber_768);  // ML-KEM-768
OQS_KEM_keypair(kem, pk, sk);               // generate PQC keypair
OQS_KEM_encaps(kem, ct, ss, pk);            // encapsulate (responder)
OQS_KEM_decaps(kem, ss, ct, sk);            // decapsulate (initiator)
```
> Say: *"I'm not inventing crypto — I'm calling the NIST post-quantum standard from the
> reference library. That's what makes it post-quantum by definition."*

Also show it's **hybrid**: `pqc_handshake.c` combines the classical **X25519** secret and the
**ML-KEM** secret with `HKDF-SHA256`, so an attacker must break **both**.

---

## Level 2 — The standard's fingerprint on the wire

A real ML-KEM-768 implementation produces keys and ciphertexts of **exact, standardized sizes**.
If you observe those exact byte counts, the real algorithm is running.

| ML-KEM-768 (FIPS 203) | Size |
|---|---|
| Public key | **1184 bytes** |
| Secret key | 2400 bytes |
| Ciphertext | **1088 bytes** |
| Shared secret | 32 bytes |

Two ways to show it:
1. **The gateway logs it** — in `.demo_logs/gateway.log` / receiver output:
   ```
   [PQC] → Sent X25519 pubkey (32 B) + Kyber pubkey (1184 B)
   [PQC] ← Received X25519 pubkey (32 B) + Kyber ciphertext (1088 B)
   ```
2. **The self-test prints and checks it** (see Level 4).

> Say: *"32 bytes is the classical X25519 key; the 1184-byte public key and 1088-byte
> ciphertext are the ML-KEM-768 fingerprints from FIPS 203 — you can't get those sizes from
> classical crypto."*

---

## Level 3 — Functional proof (it actually works end-to-end)

The receiver **successfully decrypts** the messages (you see the real plaintext, e.g.
`[Receiver] msg 1 (68 B): POST /log HTTP/1.1`). This is a *proof*, not a demo nicety:

- The AES-256-GCM key = `HKDF(X25519_secret ‖ ML-KEM_secret)`.
- AES-GCM has an **authentication tag**; if the two sides' keys differ **by even one bit**,
  `EVP_DecryptFinal_ex` fails and you'd see `Authentication tag verification FAILED`.
- Decryption **succeeding** therefore proves the initiator's `OQS_KEM_decaps` and the
  responder's `OQS_KEM_encaps` produced the **identical** shared secret — i.e. real, correct
  ML-KEM. If the KEM were fake or broken, decryption would fail.

**Reinforce it (no hardcoded key):** `crypto_layer.c` now **refuses to encrypt/decrypt without
the PQC-derived key** (a NULL key is a hard error — there is no fallback key). So the encryption
*cannot* silently run on anything other than the handshake output.

> Say: *"The fact that it decrypts at all proves both ends agreed on the same key, which can
> only happen if the ML-KEM encapsulation and decapsulation are genuinely correct. And I
> removed any fallback key, so it's impossible for the crypto to run on a placeholder."*

---

## Level 4 — Standards conformance (the gold standard) — RUNNABLE LIVE

Run the self-test — it exercises **real ML-KEM-768** and checks everything:
```bash
cd gateway && make pqc_selftest && ./pqc_selftest
```
Output (verified):
```
Algorithm      : Kyber768  (NIST ML-KEM-768 / FIPS 203)
public key len : 1184  (expected 1184)
secret key len : 2400  (expected 2400)
ciphertext len : 1088  (expected 1088)
shared secret  : 32  (expected 32)
OK  : encapsulated and decapsulated secrets MATCH (KEM is correct)
OK  : tampered ciphertext yields a DIFFERENT secret (KEM is load-bearing)

SELF-TEST PASSED — real ML-KEM-768 in use.
```
This proves, live: the standardized sizes, that encaps/decaps agree (correctness), and that the
security **depends** on the KEM (tampering changes the secret).

**Even stronger (optional):** liboqs ships **Known-Answer Tests** against the **official NIST
test vectors** — the ultimate conformance check that the implementation matches FIPS 203 bit for
bit. If liboqs is built with tests:
```bash
cd liboqs/build && ./tests/test_kem ML-KEM-768     # or: kat_kem, runs NIST vectors
```
> Say: *"liboqs is validated against the NIST known-answer vectors, so the ML-KEM
> implementation isn't just 'a lattice thing' — it's bit-for-bit the standard."*

---

## Level 5 — Why it's quantum-*resistant* (the theory)

You can't run a quantum computer to "prove" resistance — nobody can. The justification is:

- **Classical crypto (RSA, ECDH) is broken by Shor's algorithm** on a large quantum computer.
  That's *why* today's traffic is vulnerable to "harvest now, decrypt later."
- **ML-KEM's security rests on Module Learning-With-Errors (MLWE)** — a lattice problem with
  **no known efficient quantum algorithm**, vetted through NIST's multi-year competition.
- **Hybrid** means even if ML-KEM were later weakened, the classical X25519 still protects the
  session (and vice-versa) — you'd have to break both.
- **The concrete guarantee**: because the KEM is quantum-safe, traffic recorded today stays
  confidential against a *future* quantum attacker — defeating harvest-now-decrypt-later.

> Say: *"Quantum resistance is a property of the math NIST selected, not something I can
> demonstrate with hardware. What I *can* demonstrate is that I'm genuinely running that
> standardized algorithm correctly — which is what the self-test shows."*

---

## Quick reference — what to run and what it proves

| Command / artifact | Proves |
|---|---|
| `./gateway/pqc_selftest` | real ML-KEM-768, standard sizes, correct encaps/decaps, tamper-sensitive |
| `[PQC]` lines in the gateway/receiver log | standardized 1184 B key / 1088 B ciphertext on the wire |
| `[Receiver] msg … : <plaintext>` | both ends derived the same key → KEM is functionally correct |
| `grep OQS_KEM gateway/pqc_handshake.c` | it calls the NIST standard via liboqs (not homemade) |
| `liboqs/build/tests/test_kem ML-KEM-768` | conformance to the official NIST test vectors |

---

## Honesty boundary (state this proactively)

- ✅ **Confidentiality is post-quantum** (the KEM is quantum-safe; harvest-now-decrypt-later is
  defended). This is what you can prove.
- ⚠️ **The handshake is not yet *authenticated*** — so do **not** claim man-in-the-middle
  resistance. Authentication (ML-DSA / DTLS) is the next phase. Keeping this line honest is
  what makes the rest of your PQC claims credible.
