#ifndef PQC_HANDSHAKE_H
#define PQC_HANDSHAKE_H

#include <stdint.h>

/* Maps to OQS_KEM_alg_kyber_512/768/1024 */
typedef enum {
    KYBER_512  = 0,
    KYBER_768  = 1,
    KYBER_1024 = 2
} KyberLevel;

/*
 * FIPS 203 standardized names (ML-KEM) — aliases of the enum above, preferred in new
 * code. "Kyber" is the pre-standardization name kept only for the liboqs API symbols.
 */
typedef KyberLevel MlKemLevel;
#define ML_KEM_512  KYBER_512
#define ML_KEM_768  KYBER_768
#define ML_KEM_1024 KYBER_1024

/*
 * Final AES-256-GCM session key length (bytes).
 * Derived via HKDF-SHA256 over both classical and PQC secrets.
 */
#define PQC_SHARED_SECRET_LEN 32

/*
 * Hybrid handshake wire format
 * ─────────────────────────────
 * Initiator → Responder:
 *   [1 byte : KyberLevel]
 *   [32 bytes: X25519 public key]
 *   [N bytes : Kyber public key]   (N = 800 / 1184 / 1568 for 512/768/1024)
 *
 * Responder → Initiator:
 *   [32 bytes: X25519 public key]
 *   [M bytes : Kyber ciphertext]   (M = 768 / 1088 / 1568 for 512/768/1024)
 *
 * Authentication (ML-DSA-65 / FIPS 204) — appended to each flight:
 *   [4 bytes : big-endian signature length L][L bytes : ML-DSA signature]
 *   Initiator signs T_i  = level ‖ X25519_pub ‖ Kyber_pub.
 *   Responder signs T_r  = T_i ‖ resp_X25519_pub ‖ Kyber_ct.
 *   Each side verifies the peer's signature against its PINNED public key; a
 *   verification failure (or a missing signature when auth is required) ABORTS the
 *   handshake — this is what defeats a man-in-the-middle. L = 0 means unauthenticated.
 *
 * Key derivation (both sides):
 *   ikm      = ecdh_shared_secret (32 B) ‖ kyber_shared_secret (32 B)
 *   aes_key  = HKDF-SHA256(ikm, salt="pqc-gw", info="session-key", len=32)
 *
 * Security property: breaking RSA/ECDH (future quantum) leaves Kyber intact;
 * breaking Kyber (classical side-channel) leaves X25519 intact.
 */

/*
 * NOTE: the network-threat verdict no longer selects the KEM level. KEM selection
 * lives in crypto_policy.h (select_kem) behind a fixed security floor. The responder
 * additionally rejects any negotiated level below CRYPTO_FLOOR.
 */

/*
 * Handshake sub-phase timings (Phase 3 / Workstream D — latency decomposition).
 * All values in milliseconds. Lets the gateway show that ML-KEM compute is a small
 * fraction of the session, refuting the old "32% crypto-time reduction" claim.
 */
typedef struct {
    double x25519_keygen_ms;   /* classical keypair generation        */
    double kem_keygen_ms;      /* ML-KEM object + keypair             */
    double kem_decaps_ms;      /* ML-KEM decapsulation                */
    double auth_ms;            /* ML-DSA sign + verify                */
    double net_ms;             /* send pubkeys + wait for peer reply  */
    double total_ms;           /* whole handshake                     */
} PqcTiming;

/*
 * Initiator side — call after sctp_connectx() succeeds.
 * Writes 32-byte AES key into shared_secret.
 * Returns 0 on success, -1 on failure.
 */
int pqc_initiator_handshake(int fd, KyberLevel level,
                             uint8_t shared_secret[PQC_SHARED_SECRET_LEN]);

/* Same as above but fills *timing (may be NULL) with sub-phase durations. */
int pqc_initiator_handshake_timed(int fd, KyberLevel level,
                                   uint8_t shared_secret[PQC_SHARED_SECRET_LEN],
                                   PqcTiming *timing);

/*
 * Responder side — call after accept() succeeds.
 * Writes 32-byte AES key into shared_secret.
 * Returns 0 on success, -1 on failure.
 */
int pqc_responder_handshake(int fd,
                             uint8_t shared_secret[PQC_SHARED_SECRET_LEN]);

#endif /* PQC_HANDSHAKE_H */
