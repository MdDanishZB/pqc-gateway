#include "pqc_handshake.h"
#include "crypto_policy.h"   /* CRYPTO_FLOOR — responder-side downgrade floor */
#include "pqc_auth.h"        /* ML-DSA handshake authentication */

#include <oqs/oqs.h>
#include <openssl/evp.h>
#include <openssl/kdf.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include <arpa/inet.h>

static double mono_ms(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return ts.tv_sec * 1000.0 + ts.tv_nsec / 1e6;
}

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

/* ── ML-DSA authentication helpers ──────────────────────────────────────── */

/* Wire signature block: [4-byte big-endian length][signature bytes]. len=0 = unauthenticated. */
static int send_sig_block(int fd, const uint8_t *sig, uint32_t len)
{
    uint32_t n = htonl(len);
    if (write_exact(fd, (uint8_t *)&n, 4) != 0) return -1;
    if (len && write_exact(fd, sig, len) != 0)   return -1;
    return 0;
}

static int recv_sig_block(int fd, uint8_t *buf, uint32_t cap, uint32_t *len)
{
    uint32_t n;
    if (read_exact(fd, (uint8_t *)&n, 4) != 0) return -1;
    *len = ntohl(n);
    if (*len > cap) return -1;
    if (*len && read_exact(fd, buf, *len) != 0) return -1;
    return 0;
}

/* Load the ML-DSA identity for one side of the handshake (env-overridable paths). */
static void load_auth(PqcAuth *auth, int initiator)
{
    const char *my_sk, *peer_pk;
    if (initiator) {
        my_sk   = getenv("GW_INIT_SK"); if (!my_sk)   my_sk   = "keys/gateway_sk.bin";
        peer_pk = getenv("GW_RESP_PK"); if (!peer_pk) peer_pk = "keys/receiver_pk.bin";
    } else {
        my_sk   = getenv("GW_RESP_SK"); if (!my_sk)   my_sk   = "keys/receiver_sk.bin";
        peer_pk = getenv("GW_INIT_PK"); if (!peer_pk) peer_pk = "keys/gateway_pk.bin";
    }
    if (pqc_auth_init(auth, my_sk, peer_pk) != 0)
        fprintf(stderr, "[PQC] WARNING: ML-DSA keys not loaded — handshake is UNAUTHENTICATED "
                        "(run ./pqc_keygen)\n");
    else
        printf("[PQC] Authentication: %s (identity pinned)\n", pqc_auth_alg());
}

/*
 * Sign the transcript with our long-term key and send the signature block.
 * When auth is disabled (no keys), sends an empty block (L=0) so the peer can
 * detect the unauthenticated case. Returns 0 on success.
 */
static int sign_and_send(const PqcAuth *auth, int fd,
                         const uint8_t *transcript, size_t tlen)
{
    if (!auth->enabled)
        return send_sig_block(fd, NULL, 0);

    size_t cap = pqc_auth_sig_maxlen(auth);
    uint8_t *sig = malloc(cap ? cap : 1);
    if (!sig) return -1;

    size_t slen = cap;
    int rc = -1;
    if (pqc_auth_sign(auth, transcript, tlen, sig, &slen) == 0)
        rc = send_sig_block(fd, sig, (uint32_t)slen);

    free(sig);
    return rc;
}

/*
 * Receive the peer's signature block and verify it against the pinned key.
 * Policy:
 *   - auth disabled (no pinned key): accept (we already warned) — nothing to verify.
 *   - auth enabled + empty block:    REJECT (peer refused to authenticate = downgrade).
 *   - auth enabled + bad signature:  REJECT (forged / MitM).
 * Returns 0 to proceed, -1 to abort the handshake.
 */
static int recv_and_verify(const PqcAuth *auth, int fd,
                           const uint8_t *transcript, size_t tlen, const char *who)
{
    uint32_t cap = (uint32_t)pqc_auth_sig_maxlen(auth);
    if (!cap) cap = 8192;                      /* safe upper bound if sig obj absent */

    uint8_t *sig = malloc(cap);
    if (!sig) return -1;

    uint32_t slen = 0;
    int rc = -1;
    if (recv_sig_block(fd, sig, cap, &slen) != 0) {
        fprintf(stderr, "[PQC] auth: failed to read %s signature block\n", who);
        goto out;
    }

    if (!auth->enabled) {          /* we cannot verify — proceed unauthenticated */
        rc = 0;
        goto out;
    }
    if (slen == 0) {
        fprintf(stderr, "[PQC] auth: %s sent NO signature but auth is required "
                        "→ ABORT (downgrade blocked)\n", who);
        goto out;
    }
    if (pqc_auth_verify(auth, transcript, tlen, sig, slen) != 0) {
        fprintf(stderr, "[PQC] auth: %s signature INVALID → handshake ABORTED "
                        "(MitM/tamper blocked)\n", who);
        goto out;
    }
    printf("[PQC] auth: %s — %s signature VERIFIED (identity pinned)\n",
           who, pqc_auth_alg());
    rc = 0;

out:
    free(sig);
    return rc;
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
        case KYBER_512:  return "ML-KEM-512";
        case KYBER_768:  return "ML-KEM-768";
        case KYBER_1024: return "ML-KEM-1024";
        default:         return "ML-KEM-768";
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

/* ── initiator ──────────────────────────────────────────────────────────── */

int pqc_initiator_handshake_timed(int fd, KyberLevel level,
                                   uint8_t shared_secret[PQC_SHARED_SECRET_LEN],
                                   PqcTiming *timing)
{
    double t_x25519 = 0.0, t_kemkg = 0.0, t_net = 0.0, t_decaps = 0.0, t_auth = 0.0;
    double t_start = mono_ms(), a;

    /* Long-term ML-DSA identity (initiator: my sk = gateway, pinned peer = receiver). */
    PqcAuth  auth;
    uint8_t *transcript = NULL;   /* T_i, then extended to T_r */
    load_auth(&auth, 1);

    printf("[PQC] Hybrid handshake — initiator — %s\n", level_to_name(level));

    /* ── X25519 keygen ─────────────────────────────────────────────────── */
    a = mono_ms();
    EVP_PKEY *ecdh_key = ecdh_keygen();
    if (!ecdh_key) { fprintf(stderr, "[PQC] X25519 keygen failed\n"); return -1; }

    uint8_t ecdh_pub[ECDH_KEY_LEN];
    if (ecdh_pub_bytes(ecdh_key, ecdh_pub) != 0) {
        EVP_PKEY_free(ecdh_key);
        return -1;
    }
    t_x25519 = mono_ms() - a;

    /* ── Kyber keygen ──────────────────────────────────────────────────── */
    const char *alg = level_to_alg(level);
    a = mono_ms();
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
    t_kemkg = mono_ms() - a;

    /* ── Build transcript T_i = level ‖ X25519_pub ‖ Kyber_pub ──────────── */
    size_t ti_len = 1 + ECDH_KEY_LEN + kem->length_public_key;
    transcript = malloc(ti_len);
    if (!transcript) goto cleanup;
    transcript[0] = (uint8_t)level;
    memcpy(transcript + 1,                ecdh_pub,  ECDH_KEY_LEN);
    memcpy(transcript + 1 + ECDH_KEY_LEN, kyber_pub, kem->length_public_key);

    /* ── Send T_i, then our ML-DSA signature over it ────────────────────── */
    a = mono_ms();
    if (write_exact(fd, transcript, ti_len) != 0) goto cleanup;
    printf("[PQC] → Sent X25519 pubkey (32 B) + Kyber pubkey (%zu B)\n",
           kem->length_public_key);
    {
        double s = mono_ms();
        if (sign_and_send(&auth, fd, transcript, ti_len) != 0) {
            fprintf(stderr, "[PQC] auth: failed to sign/send initiator transcript\n");
            goto cleanup;
        }
        t_auth += mono_ms() - s;
    }

    /* ── Recv: [X25519 pub][Kyber ciphertext] ──────────────────────────── */
    uint8_t peer_ecdh_pub[ECDH_KEY_LEN];
    if (read_exact(fd, peer_ecdh_pub, ECDH_KEY_LEN)        != 0) goto cleanup;
    if (read_exact(fd, kyber_ct, kem->length_ciphertext)   != 0) goto cleanup;

    printf("[PQC] ← Received X25519 pubkey (32 B) + Kyber ciphertext (%zu B)\n",
           kem->length_ciphertext);

    /* ── Extend to T_r = T_i ‖ resp_X25519_pub ‖ Kyber_ct, verify responder ─ */
    {
        size_t tr_len = ti_len + ECDH_KEY_LEN + kem->length_ciphertext;
        uint8_t *tr = realloc(transcript, tr_len);
        if (!tr) goto cleanup;
        transcript = tr;
        memcpy(transcript + ti_len,                peer_ecdh_pub, ECDH_KEY_LEN);
        memcpy(transcript + ti_len + ECDH_KEY_LEN, kyber_ct,      kem->length_ciphertext);

        double s = mono_ms();
        if (recv_and_verify(&auth, fd, transcript, tr_len, "responder") != 0)
            goto cleanup;   /* forged / downgraded / MitM → abort the session */
        t_auth += mono_ms() - s;
    }
    t_net = (mono_ms() - a) - t_auth;   /* pure network wait, auth compute excluded */

    /* ── Derive both secrets ────────────────────────────────────────────── */
    uint8_t ecdh_secret[ECDH_KEY_LEN];
    if (ecdh_shared_secret(ecdh_key, peer_ecdh_pub, ecdh_secret) != 0) {
        fprintf(stderr, "[PQC] X25519 ECDH failed\n");
        goto cleanup;
    }

    a = mono_ms();
    uint8_t kyber_secret[PQC_SHARED_SECRET_LEN];
    if (OQS_KEM_decaps(kem, kyber_secret, kyber_ct, kyber_sec) != OQS_SUCCESS) {
        fprintf(stderr, "[PQC] Kyber decapsulation failed\n");
        memset(ecdh_secret, 0, sizeof(ecdh_secret));
        goto cleanup;
    }
    t_decaps = mono_ms() - a;

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
    free(transcript);
    pqc_auth_free(&auth);
    OQS_KEM_free(kem);
    EVP_PKEY_free(ecdh_key);
    if (timing) {
        timing->x25519_keygen_ms = t_x25519;
        timing->kem_keygen_ms    = t_kemkg;
        timing->kem_decaps_ms    = t_decaps;
        timing->auth_ms          = t_auth;
        timing->net_ms           = t_net;
        timing->total_ms         = mono_ms() - t_start;
    }
    return ret;
}

int pqc_initiator_handshake(int fd, KyberLevel level,
                             uint8_t shared_secret[PQC_SHARED_SECRET_LEN])
{
    return pqc_initiator_handshake_timed(fd, level, shared_secret, NULL);
}

/* ── responder ──────────────────────────────────────────────────────────── */

int pqc_responder_handshake(int fd,
                             uint8_t shared_secret[PQC_SHARED_SECRET_LEN])
{
    /* Long-term ML-DSA identity (responder: my sk = receiver, pinned peer = gateway). */
    PqcAuth  auth = {0};
    uint8_t *transcript = NULL;   /* T_i, then extended to T_r */

    /* ── Recv: [1-byte level][X25519 pub][Kyber pub] ───────────────────── */
    uint8_t hdr;
    if (read_exact(fd, &hdr, 1) != 0) return -1;

    KyberLevel level  = (KyberLevel)hdr;

    /*
     * Floor enforcement: reject any negotiated level below CRYPTO_FLOOR. Even
     * without an authenticated transcript (Phase 4), this stops an on-wire
     * tampered level byte from downgrading the session below the security floor.
     */
    if (level < CRYPTO_FLOOR) {
        fprintf(stderr,
                "[PQC] Rejected downgrade: requested level %d is below floor %d\n",
                (int)level, (int)CRYPTO_FLOOR);
        return -1;
    }

    const char *alg   = level_to_alg(level);
    printf("[PQC] Hybrid handshake — responder — %s\n", level_to_name(level));

    uint8_t peer_ecdh_pub[ECDH_KEY_LEN];
    if (read_exact(fd, peer_ecdh_pub, ECDH_KEY_LEN) != 0) {
        fprintf(stderr, "[PQC] Failed to read peer ECDH pubkey\n");
        return -1;
    }

    OQS_KEM *kem = OQS_KEM_new(alg);
    if (!kem) {
        fprintf(stderr, "[PQC] Failed to create KEM object for %s\n", alg);
        return -1;
    }

    uint8_t *kyber_peer_pub = malloc(kem->length_public_key);
    uint8_t *kyber_ct       = malloc(kem->length_ciphertext);
    int ret = -1;

    if (!kyber_peer_pub || !kyber_ct) goto cleanup;

    if (read_exact(fd, kyber_peer_pub, kem->length_public_key) != 0) {
        fprintf(stderr, "[PQC] Failed to read peer Kyber pubkey\n");
        goto cleanup;
    }

    printf("[PQC] ← Received X25519 pubkey (32 B) + Kyber pubkey (%zu B)\n",
           kem->length_public_key);

    /* ── Verify initiator's signature over T_i = level ‖ X25519_pub ‖ Kyber_pub ─ */
    load_auth(&auth, 0);
    {
        size_t ti_len = 1 + ECDH_KEY_LEN + kem->length_public_key;
        transcript = malloc(ti_len);
        if (!transcript) goto cleanup;
        transcript[0] = (uint8_t)level;
        memcpy(transcript + 1,                peer_ecdh_pub,  ECDH_KEY_LEN);
        memcpy(transcript + 1 + ECDH_KEY_LEN, kyber_peer_pub, kem->length_public_key);
        if (recv_and_verify(&auth, fd, transcript, ti_len, "initiator") != 0)
            goto cleanup;   /* forged / downgraded / MitM → abort the session */
    }

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

    /* ── Sign T_r = T_i ‖ resp_X25519_pub ‖ Kyber_ct and send it ────────── */
    {
        size_t ti_len = 1 + ECDH_KEY_LEN + kem->length_public_key;
        size_t tr_len = ti_len + ECDH_KEY_LEN + kem->length_ciphertext;
        uint8_t *tr = realloc(transcript, tr_len);
        if (!tr) { memset(ecdh_secret, 0, sizeof(ecdh_secret)); goto cleanup; }
        transcript = tr;
        memcpy(transcript + ti_len,                ecdh_pub, ECDH_KEY_LEN);
        memcpy(transcript + ti_len + ECDH_KEY_LEN, kyber_ct, kem->length_ciphertext);
        if (sign_and_send(&auth, fd, transcript, tr_len) != 0) {
            fprintf(stderr, "[PQC] auth: failed to sign/send responder transcript\n");
            memset(ecdh_secret, 0, sizeof(ecdh_secret));
            goto cleanup;
        }
    }

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
    free(transcript);
    pqc_auth_free(&auth);
    free(kyber_peer_pub);
    OQS_MEM_secure_free(kyber_ct, kem->length_ciphertext);
    OQS_KEM_free(kem);
    return ret;
}
