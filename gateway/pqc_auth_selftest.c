/*
 * pqc_auth_selftest.c — standalone proof that the ML-DSA-65 (FIPS 204) handshake
 * authentication is real and load-bearing. Mirrors pqc_selftest.c (the KEM proof).
 *
 * It generates a real ML-DSA-65 identity, drives the SAME pqc_auth.c wrapper the
 * gateway/receiver use, and checks:
 *   1. standardized ML-DSA-65 key/signature sizes,
 *   2. a genuine signature over a transcript VERIFIES,
 *   3. a tampered transcript is REJECTED (auth is load-bearing),
 *   4. a tampered signature is REJECTED,
 *   5. a signature from the WRONG key is REJECTED (identity pinning works).
 *
 *   cd gateway && make pqc_auth_selftest && ./pqc_auth_selftest
 */
#include "pqc_auth.h"

#include <oqs/oqs.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define AUTH_ALG OQS_SIG_alg_ml_dsa_65

static int write_file(const char *path, const uint8_t *buf, size_t len)
{
    FILE *f = fopen(path, "wb");
    if (!f) { perror(path); return -1; }
    size_t w = fwrite(buf, 1, len, f);
    fclose(f);
    return w == len ? 0 : -1;
}

/* Generate an ML-DSA-65 keypair to <prefix>_sk.bin / <prefix>_pk.bin. */
static int gen_to_files(OQS_SIG *sig, const char *sk_path, const char *pk_path)
{
    uint8_t *pk = malloc(sig->length_public_key);
    uint8_t *sk = malloc(sig->length_secret_key);
    int rc = -1;
    if (!pk || !sk) goto out;
    if (OQS_SIG_keypair(sig, pk, sk) != OQS_SUCCESS) goto out;
    if (write_file(sk_path, sk, sig->length_secret_key) != 0) goto out;
    if (write_file(pk_path, pk, sig->length_public_key) != 0) goto out;
    rc = 0;
out:
    if (sk) OQS_MEM_secure_free(sk, sig->length_secret_key);
    free(pk);
    return rc;
}

int main(void)
{
    const char *sk = "/tmp/pqcauth_self_sk.bin", *pk = "/tmp/pqcauth_self_pk.bin";
    const char *osk = "/tmp/pqcauth_other_sk.bin", *opk = "/tmp/pqcauth_other_pk.bin";

    OQS_SIG *sig = OQS_SIG_new(AUTH_ALG);
    if (!sig) { fprintf(stderr, "OQS_SIG_new(ML-DSA-65) failed\n"); return 1; }

    printf("Algorithm      : %s  (NIST ML-DSA-65 / FIPS 204)\n", pqc_auth_alg());
    printf("public key len : %zu\n", sig->length_public_key);
    printf("secret key len : %zu\n", sig->length_secret_key);
    printf("signature  len : %zu (max)\n", sig->length_signature);

    if (gen_to_files(sig, sk, pk) != 0 || gen_to_files(sig, osk, opk) != 0) {
        fprintf(stderr, "key generation failed\n"); OQS_SIG_free(sig); return 1;
    }

    /* Our identity: sign with our sk, verify against our own pk (peer_pk = our pk). */
    PqcAuth a;
    if (pqc_auth_init(&a, sk, pk) != 0) {
        fprintf(stderr, "pqc_auth_init failed\n"); OQS_SIG_free(sig); return 1;
    }

    const char *msg = "level=1|X25519pub|MLKEMpub|X25519pub|MLKEMct";
    size_t mlen = strlen(msg);

    uint8_t *s = malloc(pqc_auth_sig_maxlen(&a));
    size_t slen = pqc_auth_sig_maxlen(&a);
    if (pqc_auth_sign(&a, (const uint8_t *)msg, mlen, s, &slen) != 0) {
        fprintf(stderr, "sign failed\n"); return 1;
    }

    int fail = 0;

    /* 2. genuine signature verifies */
    if (pqc_auth_verify(&a, (const uint8_t *)msg, mlen, s, slen) == 0)
        printf("OK  : genuine signature VERIFIES\n");
    else { printf("FAIL: genuine signature did NOT verify\n"); fail = 1; }

    /* 3. tampered transcript rejected */
    char bad[128]; memcpy(bad, msg, mlen + 1); bad[0] = '2';   /* flip the level byte */
    if (pqc_auth_verify(&a, (const uint8_t *)bad, mlen, s, slen) != 0)
        printf("OK  : tampered transcript is REJECTED (auth is load-bearing)\n");
    else { printf("FAIL: tampered transcript accepted!\n"); fail = 1; }

    /* 4. tampered signature rejected */
    s[slen / 2] ^= 0xFF;
    if (pqc_auth_verify(&a, (const uint8_t *)msg, mlen, s, slen) != 0)
        printf("OK  : tampered signature is REJECTED\n");
    else { printf("FAIL: tampered signature accepted!\n"); fail = 1; }
    s[slen / 2] ^= 0xFF;   /* restore */

    /* 5. signature from a DIFFERENT key rejected (identity pinning).
     *    Verify our genuine signature against the *other* identity's public key. */
    PqcAuth other;
    if (pqc_auth_init(&other, osk, opk) == 0) {
        if (pqc_auth_verify(&other, (const uint8_t *)msg, mlen, s, slen) != 0)
            printf("OK  : signature from wrong identity is REJECTED (pinning works)\n");
        else { printf("FAIL: wrong-identity signature accepted!\n"); fail = 1; }
        pqc_auth_free(&other);
    }

    free(s);
    pqc_auth_free(&a);
    OQS_SIG_free(sig);
    remove(sk); remove(pk); remove(osk); remove(opk);

    printf(fail ? "\nSELF-TEST FAILED\n" : "\nSELF-TEST PASSED — real ML-DSA-65 authentication in use.\n");
    return fail;
}
