#ifndef CRYPTO_POLICY_H
#define CRYPTO_POLICY_H

#include "pqc_handshake.h"   /* MlKemLevel */

/*
 * crypto_policy — chooses the hybrid ML-KEM parameter set for a session.
 *
 * SEPARATION-OF-CONCERNS INVARIANT (the project's core contribution):
 *   The cryptographic strength is determined SOLELY by the session's DATA
 *   CLASSIFICATION — a policy attribute of the channel. It is decoupled from every
 *   operational signal. Network conditions (latency, jitter, packet loss, throughput),
 *   the ML network-state classifier, the ML threat detector, and battery/power state
 *   MUST NEVER lower or directly determine the KEM level. (A bigger KEM does not stop a
 *   flood; a flood does not make a smaller KEM breakable — coupling them was a category
 *   error, now removed.)
 *
 *     data classification ──► the ONLY input to crypto strength
 *     ML-KEM-768          ──► IMMUTABLE minimum floor for every session
 *     ML-KEM-1024         ──► ONLY for data explicitly classified CRITICAL
 *     everything else      ──► does NOT touch this axis (see transport_policy.h)
 *
 *   select_kem() takes ONLY a DataClassification: by its type signature it is
 *   impossible for a network metric or an ML verdict to reach it. The invariant is
 *   therefore enforced at compile time, not merely by convention.
 */

/* Minimum acceptable KEM: hybrid X25519 + ML-KEM-768. ML-KEM-512 is never used. */
#define CRYPTO_FLOOR  ML_KEM_768

/*
 * Data sensitivity of the session — a POLICY input, set per device/port/config by an
 * operator. It is never derived from traffic statistics or any ML model.
 */
typedef enum {
    CLASS_ROUTINE   = 0,   /* ordinary telemetry            -> floor (ML-KEM-768) */
    CLASS_SENSITIVE = 1,   /* sensitive but not critical    -> floor (ML-KEM-768) */
    CLASS_CRITICAL  = 2    /* high-sensitivity / critical   -> ML-KEM-1024         */
} DataClassification;

/*
 * select_kem — return the ML-KEM level to negotiate for a session of this classification.
 * Guarantees: the result is ALWAYS >= CRYPTO_FLOOR; only CLASS_CRITICAL raises it to 1024.
 */
MlKemLevel select_kem(DataClassification cls);

/* Name <-> string helpers for config parsing and logging. Unknown -> CLASS_ROUTINE. */
DataClassification data_class_from_str(const char *s);
const char        *data_class_name(DataClassification cls);
const char        *ml_kem_name(MlKemLevel level);

#endif /* CRYPTO_POLICY_H */
