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
 * Initiator side — call after sctp_connectx() succeeds.
 * Writes 32-byte AES key into shared_secret.
 * Returns 0 on success, -1 on failure.
 */
int pqc_initiator_handshake(int fd, KyberLevel level,
                             uint8_t shared_secret[PQC_SHARED_SECRET_LEN]);

/*
 * Responder side — call after accept() succeeds.
 * Writes 32-byte AES key into shared_secret.
 * Returns 0 on success, -1 on failure.
 */
int pqc_responder_handshake(int fd,
                             uint8_t shared_secret[PQC_SHARED_SECRET_LEN]);

#endif /* PQC_HANDSHAKE_H */
