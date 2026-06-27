#ifndef CRYPTO_POLICY_H
#define CRYPTO_POLICY_H

#include "pqc_handshake.h"   /* KyberLevel */

/*
 * crypto_policy — chooses the hybrid KEM parameter set for a session.
 *
 * CORE INVARIANT (Phase 1 contribution):
 *   The cryptographic strength is decoupled from the network-threat detector.
 *   A network anomaly (DDoS, congestion, loss) NEVER selects the KEM level — that
 *   was a category error (a bigger KEM does not stop a flood, and a flood does not
 *   make a smaller KEM breakable).
 *
 *   Instead a fixed FLOOR is always enforced. A battery/load-pressure signal may
 *   REQUEST a cheaper configuration, but it can never push strength below the floor.
 *   Only an explicit high-assurance signal may RAISE strength above the floor.
 *   This asymmetry is what defeats the battery-drain / downgrade adversary.
 *
 *       battery_pressure ──► may lower cost, but NEVER below CRYPTO_FLOOR
 *       high_assurance   ──► may raise strength to ML-KEM-1024
 *       network threat   ──► does NOT touch this axis at all (see transport_policy.h)
 */

/* Minimum acceptable KEM: hybrid X25519 + ML-KEM-768. ML-KEM-512 is never used. */
#define CRYPTO_FLOOR  KYBER_768

typedef struct {
    int high_assurance;    /* explicit policy/operator signal — NOT from traffic stats */
    int battery_pressure;  /* 0..100, a request to reduce cost (simulated in Phase 1)   */
} SecurityPosture;

/*
 * select_kem — return the KEM level to negotiate for this session.
 * Guarantees the return value is always >= CRYPTO_FLOOR, for every possible
 * posture (including maximal battery_pressure).
 */
KyberLevel select_kem(const SecurityPosture *posture);

#endif /* CRYPTO_POLICY_H */
