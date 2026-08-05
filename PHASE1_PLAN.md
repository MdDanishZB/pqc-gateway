# Phase 1 — Coherence

> Goal: make the system **internally logically consistent** before touching data,
> testbed, or authentication. After Phase 1, no network-anomaly signal can change
> cryptographic strength, the crypto strength has an enforced floor, and the detector
> feeds in-distribution features into a transport-only decision path.
>
> **Still on synthetic data and loopback in Phase 1** — that is fine. Real data is Phase 2,
> the two-laptop testbed is Phase 3, DTLS/auth is Phase 4. Do **not** pull that work
> forward; Phase 1 is pure restructuring of logic you already have.

---

## The one design decision this phase encodes

```
            BEFORE (incoherent)                      AFTER (Phase 1)

  RF verdict ──► Kyber level (512/768/1024)   RF verdict ──► TransportAction
       │              │                              │         (failover / rate-limit /
       │         pqc_handshake                       │          rekey-cadence / alert)
       └──► failover                                 │
                                              crypto level ◄── crypto_policy
                                                              (floor = ML-KEM-768,
                                                               battery can't lower,
                                                               only explicit high-
                                                               assurance raises)
```

Two independent policies, two independent inputs. The detector never touches crypto.
Crypto has a hard floor.

---

## Task 1A — Crypto policy + enforced floor (both ends)

**Files:** new `gateway/crypto_policy.h/.c`; edit `gateway/sctp_gateway.c`,
`gateway/pqc_handshake.c`, `gateway/pqc_handshake.h`, `gateway/Makefile`.

1. New module `crypto_policy.h`:
   ```c
   #include "pqc_handshake.h"   /* KyberLevel enum */

   #define CRYPTO_FLOOR  KYBER_768   /* hybrid X25519 + ML-KEM-768 is the minimum, always */

   typedef struct {
       int high_assurance;     /* explicit, operator/policy-set — NOT from traffic stats */
       int battery_pressure;   /* 0..100 request to reduce cost (simulated for now) */
   } SecurityPosture;

   /* Returns the KEM level to use. NEVER returns below CRYPTO_FLOOR,
    * regardless of battery_pressure. high_assurance may raise to KYBER_1024. */
   KyberLevel select_kem(const SecurityPosture *p);
   ```
   ```c
   KyberLevel select_kem(const SecurityPosture *p) {
       KyberLevel lvl = p->high_assurance ? KYBER_1024 : CRYPTO_FLOOR;
       if (lvl < CRYPTO_FLOOR) lvl = CRYPTO_FLOOR;   /* invariant — battery can't breach */
       return lvl;
   }
   ```
2. `sctp_gateway.c:100` — **delete** `KyberLevel level = ai_response_to_level(ai_response);`
   Replace with:
   ```c
   SecurityPosture posture = { .high_assurance = 0, .battery_pressure = 0 };
   KyberLevel level = select_kem(&posture);
   ```
   The `ai_response` string still flows onward, but only to transport (Task 1B) and metrics.
3. **Enforce the floor on the responder too.** In `pqc_responder_handshake()`
   (`pqc_handshake.c`), after reading the 1-byte level, reject anything `< CRYPTO_FLOOR`
   and abort the handshake. This means even on-wire tampering of the level byte cannot
   downgrade below the floor — a real, testable win *without* full authentication.
   > Scope note: this stops *downgrade-below-floor*. Protecting the exact negotiated value
   > against an active MitM still needs the authenticated transcript from Phase 4. Don't
   > claim full on-wire downgrade resistance yet.
4. **Deprecate** `ai_response_to_level()` — remove it, or keep it only behind a clearly
   commented `#ifdef LEGACY` and ensure nothing in the build calls it.
5. Add `crypto_policy.c` to the `gateway:` target in the `Makefile`.

## Task 1B — Re-target detector output to transport actions

**Files:** new `gateway/transport_policy.h/.c`; edit `gateway/path_monitor.c`,
`gateway/sctp_gateway.c`, `gateway/Makefile`.

1. New `transport_policy.h`:
   ```c
   typedef enum {
       TA_NORMAL,
       TA_RATE_LIMIT,   /* flood-like: shed/throttle, don't touch crypto */
       TA_FAILOVER,     /* path degraded/down: move association to the other path */
       TA_REKEY_NOW,    /* hygiene: trigger a rekey (cadence lever) */
       TA_ALERT
   } TransportAction;

   TransportAction decide_transport(const char *verdict,   /* LOW/MEDIUM/HIGH */
                                    int primary_down,
                                    int secondary_available,
                                    int currently_secondary);
   ```
   Mapping (replace the inline logic in `path_monitor.c:108-142`):
   - `primary_down && secondary_available` → `TA_FAILOVER` (availability — unconditional).
   - `verdict == HIGH` && path healthy → `TA_RATE_LIMIT` + `TA_ALERT` (a flood is an
     availability attack; failover doesn't help volumetric floods — throttle instead).
     Only failover on HIGH if the path is *also* degraded.
   - `currently_secondary && verdict == LOW && primary healthy` → restore primary.
   - **Crucially: no branch in this function or its callers touches `KyberLevel`.**
2. `path_monitor.c` calls `decide_transport(...)` and acts on the returned action. Keep the
   failover plumbing (`switch_primary_path`) you already have.
3. `sctp_gateway.c:183-185` — the dashboard `kyber_str` currently derives from
   `ai_response` (the threat verdict). **Fix it to report the *actual* level** from
   `select_kem`:
   ```c
   const char *kyber_str =
       (level == KYBER_1024) ? "ML-KEM-1024" :
       (level == KYBER_768)  ? "ML-KEM-768"  : "ML-KEM-512";
   ```
   Now the dashboard shows real crypto state, decoupled from threat.

## Task 1C — Shared feature schema + kill train/serve skew

**Files:** new `ai_module/features.py`; edit `ai_module/model_server.py`,
`ai_module/train_model.py`, `ai_module/generate_dataset.py`, `gateway/path_monitor.c`.

1. New `ai_module/features.py` — single source of truth:
   ```python
   FEATURES = ["latency", "jitter", "packet_loss",
               "throughput", "inter_arrival", "bandwidth_util"]
   # units + plausible ranges, documented so the C side computes the SAME thing
   RANGES = {"latency": (0, 1000), "jitter": (0, 500), "packet_loss": (0, 100),
             "throughput": (0, 1e7), "inter_arrival": (0, 60000), "bandwidth_util": (0, 100)}

   def validate(vec: dict) -> list[str]:
       """Return list of out-of-range / skew warnings (empty == clean)."""
       ...
   ```
2. `model_server.py` — import `FEATURES` + `validate`; **log/clip out-of-range inputs**
   instead of silently predicting on garbage. This surfaces skew the moment it happens.
3. `train_model.py` and `generate_dataset.py` — import `FEATURES` from `features.py` so the
   column order can never drift between training and serving.
4. **Fix the skew bug at `path_monitor.c:69-78`.** Stop sending `primary_ps.cwnd` as
   "throughput" and the path-RTT *difference* as "jitter." Send the **same semantics the
   model trained on**: `throughput` = observed bytes/sec, `jitter` = `|Δlatency|` via
   `update_jitter()`. If a metric isn't meaningfully available in the monitor context,
   send the gateway-computed value rather than a different quantity. Document this C↔Python
   contract in the `features.py` docstring.
   > The synthetic model is still weak (that's Phase 2), but after this it at least
   > receives **in-distribution** inputs, so its verdicts stop being arbitrary.

## Task 1D — Tests (this is where the contribution becomes tangible)

**Files:** new `gateway/tests/` (a tiny C harness or asserts in a `make test` target) and
`ai_module/tests/test_features.py`.

1. `test_floor_invariant` — for every `SecurityPosture` including
   `{high_assurance:0, battery_pressure:100}` **and** a spoofed-LOW verdict path,
   assert `select_kem(...) >= CRYPTO_FLOOR`. This test *is* your headline claim, executable.
2. `test_responder_rejects_downgrade` — feed the responder a level byte `< CRYPTO_FLOOR`;
   assert the handshake aborts.
3. `test_no_crypto_from_verdict` — a grep/CI check (or code review gate) asserting no
   call path lets a LOW/MEDIUM/HIGH verdict reach `select_kem`/`pqc_*_handshake`.
4. `test_feature_parity` — `validate()` rejects out-of-range vectors; a fixed raw input
   produces the documented feature vector. Add `make test` to the Makefile.

---

## Sequencing (suggested order, ~1–2 weeks)

1. **1C first** (features module + skew fix) — small, self-contained, unblocks honest
   behavior and sets up Phase 2.
2. **1A** (crypto_policy + floor + responder check) — the core decoupling.
3. **1B** (transport_policy) — moves the verdict to its new home.
4. **1D** (tests) — lock the invariants so a later refactor can't silently re-couple them.

## Acceptance criteria (Phase 1 is "done" when all hold)

- [ ] `grep -rn "ai_response_to_level\|verdict" gateway/` shows **no** path from a network
      verdict to a KEM level. (decoupled)
- [ ] Every session uses KEM level **≥ ML-KEM-768**; `test_floor_invariant` passes.
- [ ] Responder rejects a sub-floor level byte; `test_responder_rejects_downgrade` passes.
- [ ] `path_monitor.c` feeds features matching training semantics; `model_server.py` logs
      **zero** out-of-range warnings under normal operation.
- [ ] Dashboard "kyber_level" reflects the **actual** negotiated level, not the threat.
- [ ] `make && make test` is green.

## Explicitly OUT of scope for Phase 1 (don't scope-creep)

- Real IDS dataset / retraining → **Phase 2**.
- Two-laptop testbed / real failover measurement → **Phase 3**.
- DTLS-1.3-over-SCTP, ML-DSA authentication, full on-wire downgrade resistance → **Phase 4**.
- Formal Tamarin/ProVerif proof of the floor invariant → **Phase 5**.
- LLM repositioning → can be done anytime, but not required for Phase 1 coherence.
