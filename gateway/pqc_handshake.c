#include "pqc_handshake.h"

#include <oqs/oqs.h>
#include <openssl/evp.h>
#include <openssl/kdf.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

/* ── constants ──────────────────────────────────────────────────────────── */

#define ECDH_KEY_LEN   32   /* X25519 public key / shared secret length */
#define HKDF_SALT      "pqc-gw"
#define HKDF_INFO      "session-key"

/* ── I/O helpers ────────────────────────────────────────────────────────── */

static int read_exact(int fd, uint8_t *buf, size_t n)
{
    size_t got = 0;
    while (got < n) {
        ssize_t r = read(fd, buf + got, n - got);
        if (r <= 0) return -1;
        got += (size_t)r;
    }
    return 0;
}

static int write_exact(int fd, const uint8_t *buf, size_t n)
{
    size_t sent = 0;
    while (sent < n) {
        ssize_t w = write(fd, buf + sent, n - sent);
        if (w <= 0) return -1;
        sent += (size_t)w;
    }
    return 0;
}

/* ── Kyber helpers ──────────────────────────────────────────────────────── */

static const char *level_to_alg(KyberLevel level)
{
    switch (level) {
        case KYBER_512:  return OQS_KEM_alg_kyber_512;
        case KYBER_768:  return OQS_KEM_alg_kyber_768;
        case KYBER_1024: return OQS_KEM_alg_kyber_1024;
        default:         return OQS_KEM_alg_kyber_512;
    }
}

static const char *level_to_name(KyberLevel level)
{
    switch (level) {
        case KYBER_512:  return "Kyber-512  (LOW)";
        case KYBER_768:  return "Kyber-768  (MEDIUM)";
        case KYBER_1024: return "Kyber-1024 (HIGH)";
        default:         return "Kyber-512";
    }
}

/* ── X25519 ECDH helpers ────────────────────────────────────────────────── */

/* Generate an X25519 keypair. Caller must EVP_PKEY_free() the result. */
static EVP_PKEY *ecdh_keygen(void)
{
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_X25519, NULL);
    if (!ctx) return NULL;

    EVP_PKEY *key = NULL;
    if (EVP_PKEY_keygen_init(ctx) <= 0 ||
        EVP_PKEY_keygen(ctx, &key) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        return NULL;
    }
    EVP_PKEY_CTX_free(ctx);
    return key;
}

/* Extract raw 32-byte public key from an X25519 EVP_PKEY. */
static int ecdh_pub_bytes(EVP_PKEY *key, uint8_t out[ECDH_KEY_LEN])
{
    size_t len = ECDH_KEY_LEN;
    return EVP_PKEY_get_raw_public_key(key, out, &len) <= 0 ? -1 : 0;
}

/*
 * Derive X25519 shared secret.
 * local_priv  — our EVP_PKEY with private key
 * peer_pub    — 32-byte raw public key from peer
 * out         — 32-byte shared secret output
 */
static int ecdh_shared_secret(EVP_PKEY *local_priv,
                               const uint8_t peer_pub[ECDH_KEY_LEN],
                               uint8_t out[ECDH_KEY_LEN])
{
    EVP_PKEY *peer = EVP_PKEY_new_raw_public_key(EVP_PKEY_X25519, NULL,
                                                  peer_pub, ECDH_KEY_LEN);
    if (!peer) return -1;

    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(local_priv, NULL);
    int ret = -1;

    if (!ctx) goto cleanup;
    if (EVP_PKEY_derive_init(ctx)          <= 0) goto cleanup;
    if (EVP_PKEY_derive_set_peer(ctx, peer) <= 0) goto cleanup;

    size_t secret_len = ECDH_KEY_LEN;
    if (EVP_PKEY_derive(ctx, out, &secret_len) <= 0) goto cleanup;
    ret = 0;

cleanup:
    EVP_PKEY_CTX_free(ctx);
    EVP_PKEY_free(peer);
    return ret;
}

/* ── HKDF key derivation ────────────────────────────────────────────────── */

/*
 * Combine classical and PQC secrets into one AES-256-GCM session key.
 *
 * ikm = ecdh_secret (32 B) ‖ kyber_secret (32 B)   [64 bytes total]
 * out = HKDF-SHA256(ikm, salt=HKDF_SALT, info=HKDF_INFO, len=32)
 *
 * Security: both contributions must be broken simultaneously for the key
 * to be recoverable — the core "harvest now, decrypt later" defence.
 */
static int hkdf_derive(const uint8_t ecdh_secret[ECDH_KEY_LEN],
                        const uint8_t kyber_secret[PQC_SHARED_SECRET_LEN],
                        uint8_t       out[PQC_SHARED_SECRET_LEN])
{
    uint8_t ikm[ECDH_KEY_LEN + PQC_SHARED_SECRET_LEN];
    memcpy(ikm,                 ecdh_secret,   ECDH_KEY_LEN);
    memcpy(ikm + ECDH_KEY_LEN,  kyber_secret, PQC_SHARED_SECRET_LEN);

    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, NULL);
    if (!ctx) return -1;

    int ret = -1;
    size_t outlen = PQC_SHARED_SECRET_LEN;

    if (EVP_PKEY_derive_init(ctx) <= 0) goto cleanup;
    if (EVP_PKEY_CTX_set_hkdf_md(ctx, EVP_sha256()) <= 0) goto cleanup;
    if (EVP_PKEY_CTX_set1_hkdf_salt(ctx,
            (unsigned char *)HKDF_SALT,
            (int)strlen(HKDF_SALT)) <= 0) goto cleanup;
    if (EVP_PKEY_CTX_set1_hkdf_key(ctx, ikm, (int)sizeof(ikm)) <= 0) goto cleanup;
    if (EVP_PKEY_CTX_add1_hkdf_info(ctx,
            (unsigned char *)HKDF_INFO,
            (int)strlen(HKDF_INFO)) <= 0) goto cleanup;
    if (EVP_PKEY_derive(ctx, out, &outlen) <= 0) goto cleanup;

    ret = 0;

cleanup:
    /* Wipe IKM from stack before freeing */
    memset(ikm, 0, sizeof(ikm));
    EVP_PKEY_CTX_free(ctx);
    return ret;
}

/* ── public API ─────────────────────────────────────────────────────────── */

KyberLevel ai_response_to_level(const char *ai_response)
{
    if (strcmp(ai_response, "HIGH")   == 0) return KYBER_1024;
    if (strcmp(ai_response, "MEDIUM") == 0) return KYBER_768;
    return KYBER_512;
}

/* ── initiator ──────────────────────────────────────────────────────────── */

int pqc_initiator_handshake(int fd, KyberLevel level,
                             uint8_t shared_secret[PQC_SHARED_SECRET_LEN])
{
    printf("[PQC] Hybrid handshake — initiator — %s\n", level_to_name(level));

    /* ── X25519 keygen ─────────────────────────────────────────────────── */
    EVP_PKEY *ecdh_key = ecdh_keygen();
    if (!ecdh_key) { fprintf(stderr, "[PQC] X25519 keygen failed\n"); return -1; }

    uint8_t ecdh_pub[ECDH_KEY_LEN];
    if (ecdh_pub_bytes(ecdh_key, ecdh_pub) != 0) {
        EVP_PKEY_free(ecdh_key);
        return -1;
    }

    /* ── Kyber keygen ──────────────────────────────────────────────────── */
    const char *alg = level_to_alg(level);
    OQS_KEM *kem = OQS_KEM_new(alg);
    if (!kem) { EVP_PKEY_free(ecdh_key); return -1; }

    uint8_t *kyber_pub = malloc(kem->length_public_key);
    uint8_t *kyber_sec = malloc(kem->length_secret_key);
    uint8_t *kyber_ct  = malloc(kem->length_ciphertext);
    int ret = -1;

    if (!kyber_pub || !kyber_sec || !kyber_ct) goto cleanup;

    if (OQS_KEM_keypair(kem, kyber_pub, kyber_sec) != OQS_SUCCESS) {
        fprintf(stderr, "[PQC] Kyber keypair failed\n");
        goto cleanup;
    }

    /* ── Send: [1-byte level][X25519 pub][Kyber pub] ───────────────────── */
    uint8_t hdr = (uint8_t)level;
    if (write_exact(fd, &hdr,      1)                      != 0) goto cleanup;
    if (write_exact(fd, ecdh_pub,  ECDH_KEY_LEN)           != 0) goto cleanup;
    if (write_exact(fd, kyber_pub, kem->length_public_key) != 0) goto cleanup;

    printf("[PQC] → Sent X25519 pubkey (32 B) + Kyber pubkey (%zu B)\n",
           kem->length_public_key);

    /* ── Recv: [X25519 pub][Kyber ciphertext] ──────────────────────────── */
    uint8_t peer_ecdh_pub[ECDH_KEY_LEN];
    if (read_exact(fd, peer_ecdh_pub, ECDH_KEY_LEN)        != 0) goto cleanup;
    if (read_exact(fd, kyber_ct, kem->length_ciphertext)   != 0) goto cleanup;

    printf("[PQC] ← Received X25519 pubkey (32 B) + Kyber ciphertext (%zu B)\n",
           kem->length_ciphertext);

    /* ── Derive both secrets ────────────────────────────────────────────── */
    uint8_t ecdh_secret[ECDH_KEY_LEN];
    if (ecdh_shared_secret(ecdh_key, peer_ecdh_pub, ecdh_secret) != 0) {
        fprintf(stderr, "[PQC] X25519 ECDH failed\n");
        goto cleanup;
    }

    uint8_t kyber_secret[PQC_SHARED_SECRET_LEN];
    if (OQS_KEM_decaps(kem, kyber_secret, kyber_ct, kyber_sec) != OQS_SUCCESS) {
        fprintf(stderr, "[PQC] Kyber decapsulation failed\n");
        memset(ecdh_secret, 0, sizeof(ecdh_secret));
        goto cleanup;
    }

    /* ── HKDF: combine both secrets → session key ──────────────────────── */
    if (hkdf_derive(ecdh_secret, kyber_secret, shared_secret) != 0) {
        fprintf(stderr, "[PQC] HKDF derivation failed\n");
        memset(ecdh_secret,   0, sizeof(ecdh_secret));
        memset(kyber_secret,  0, sizeof(kyber_secret));
        goto cleanup;
    }

    memset(ecdh_secret,  0, sizeof(ecdh_secret));
    memset(kyber_secret, 0, sizeof(kyber_secret));

    printf("[PQC] Hybrid session key ready (X25519 + %s → HKDF-SHA256)\n",
           alg);
    ret = 0;

cleanup:
    if (kyber_sec) OQS_MEM_secure_free(kyber_sec, kem->length_secret_key);
    free(kyber_pub);
    free(kyber_ct);
    OQS_KEM_free(kem);
    EVP_PKEY_free(ecdh_key);
    return ret;
}

/* ── responder ──────────────────────────────────────────────────────────── */

int pqc_responder_handshake(int fd,
                             uint8_t shared_secret[PQC_SHARED_SECRET_LEN])
{
    /* ── Recv: [1-byte level][X25519 pub][Kyber pub] ───────────────────── */
    uint8_t hdr;
    if (read_exact(fd, &hdr, 1) != 0) return -1;

    KyberLevel level  = (KyberLevel)hdr;
    const char *alg   = level_to_alg(level);
    printf("[PQC] Hybrid handshake — responder — %s\n", level_to_name(level));

    uint8_t peer_ecdh_pub[ECDH_KEY_LEN];
    if (read_exact(fd, peer_ecdh_pub, ECDH_KEY_LEN) != 0) return -1;

    OQS_KEM *kem = OQS_KEM_new(alg);
    if (!kem) return -1;

    uint8_t *kyber_peer_pub = malloc(kem->length_public_key);
    uint8_t *kyber_ct       = malloc(kem->length_ciphertext);
    int ret = -1;

    if (!kyber_peer_pub || !kyber_ct) goto cleanup;

    if (read_exact(fd, kyber_peer_pub, kem->length_public_key) != 0) goto cleanup;

    printf("[PQC] ← Received X25519 pubkey (32 B) + Kyber pubkey (%zu B)\n",
           kem->length_public_key);

    /* ── X25519 keygen + ECDH ──────────────────────────────────────────── */
    EVP_PKEY *ecdh_key = ecdh_keygen();
    if (!ecdh_key) goto cleanup;

    uint8_t ecdh_pub[ECDH_KEY_LEN];
    if (ecdh_pub_bytes(ecdh_key, ecdh_pub) != 0) {
        EVP_PKEY_free(ecdh_key);
        goto cleanup;
    }

    uint8_t ecdh_secret[ECDH_KEY_LEN];
    if (ecdh_shared_secret(ecdh_key, peer_ecdh_pub, ecdh_secret) != 0) {
        fprintf(stderr, "[PQC] X25519 ECDH failed\n");
        EVP_PKEY_free(ecdh_key);
        goto cleanup;
    }
    EVP_PKEY_free(ecdh_key);

    /* ── Kyber encapsulate ──────────────────────────────────────────────── */
    uint8_t kyber_secret[PQC_SHARED_SECRET_LEN];
    if (OQS_KEM_encaps(kem, kyber_ct, kyber_secret, kyber_peer_pub) != OQS_SUCCESS) {
        fprintf(stderr, "[PQC] Kyber encapsulation failed\n");
        memset(ecdh_secret, 0, sizeof(ecdh_secret));
        goto cleanup;
    }

    /* ── Send: [X25519 pub][Kyber ciphertext] ──────────────────────────── */
    if (write_exact(fd, ecdh_pub, ECDH_KEY_LEN)           != 0) goto cleanup;
    if (write_exact(fd, kyber_ct, kem->length_ciphertext) != 0) goto cleanup;

    printf("[PQC] → Sent X25519 pubkey (32 B) + Kyber ciphertext (%zu B)\n",
           kem->length_ciphertext);

    /* ── HKDF: combine both secrets → session key ──────────────────────── */
    if (hkdf_derive(ecdh_secret, kyber_secret, shared_secret) != 0) {
        fprintf(stderr, "[PQC] HKDF derivation failed\n");
        memset(ecdh_secret,  0, sizeof(ecdh_secret));
        memset(kyber_secret, 0, sizeof(kyber_secret));
        goto cleanup;
    }

    memset(ecdh_secret,  0, sizeof(ecdh_secret));
    memset(kyber_secret, 0, sizeof(kyber_secret));

    printf("[PQC] Hybrid session key ready (X25519 + %s → HKDF-SHA256)\n", alg);
    ret = 0;

cleanup:
    free(kyber_peer_pub);
    OQS_MEM_secure_free(kyber_ct, kem->length_ciphertext);
    OQS_KEM_free(kem);
    return ret;
}
