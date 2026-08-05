#ifndef PQC_AUTH_H
#define PQC_AUTH_H

#include <stdint.h>
#include <stddef.h>

/*
 * Post-quantum handshake authentication with ML-DSA-65 (FIPS 204 / Dilithium).
 *
 * Each side holds a long-term ML-DSA signing key (its identity) and the PINNED public
 * key of the peer. During the handshake each side signs the transcript (the exchanged
 * public keys) and verifies the peer's signature. This turns the hybrid KEM handshake
 * into a full post-quantum *authenticated* key exchange and defeats man-in-the-middle:
 * a MITM cannot substitute keys without producing a valid signature it can't forge.
 */
typedef struct {
    void    *sig;       /* OQS_SIG *            */
    uint8_t *my_sk;     /* my signing secret key */
    uint8_t *peer_pk;   /* pinned peer verify key */
    int      enabled;   /* 1 if both keys loaded correctly */
} PqcAuth;

/*
 * Load my signing secret key and the pinned peer public key from disk.
 * Returns 0 if authentication is enabled (both keys valid), -1 otherwise
 * (a->enabled == 0; the caller decides whether to proceed unauthenticated).
 */
int    pqc_auth_init(PqcAuth *a, const char *my_sk_path, const char *peer_pk_path);

size_t pqc_auth_sig_maxlen(const PqcAuth *a);
int    pqc_auth_sign(const PqcAuth *a, const uint8_t *msg, size_t len,
                     uint8_t *sig, size_t *sig_len);
int    pqc_auth_verify(const PqcAuth *a, const uint8_t *msg, size_t len,
                       const uint8_t *sig, size_t sig_len);   /* 0 = valid */
void   pqc_auth_free(PqcAuth *a);

const char *pqc_auth_alg(void);   /* algorithm name for logging */

#endif /* PQC_AUTH_H */
