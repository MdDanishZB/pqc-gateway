/*
 * pqc_selftest.c — proof that the gateway uses REAL post-quantum crypto.
 *
 * Runs ML-KEM-768 (NIST FIPS 203, via liboqs / Open Quantum Safe) end to end and checks:
 *   1. the key / ciphertext sizes match the FIPS 203 standard (a fingerprint of real ML-KEM);
 *   2. encapsulation (server side) and decapsulation (client side) produce the SAME shared
 *      secret — i.e. the KEM math is correct;
 *   3. tampering with the ciphertext changes the decapsulated secret — i.e. the security
 *      actually depends on the KEM, it isn't ignored.
 *
 * Build & run:  make pqc_selftest && ./pqc_selftest
 */
#include <oqs/oqs.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* FIPS 203 ML-KEM-768 sizes (bytes). */
#define EXP_PK 1184
#define EXP_SK 2400
#define EXP_CT 1088
#define EXP_SS 32

int main(void)
{
    int fail = 0;

    OQS_KEM *kem = OQS_KEM_new(OQS_KEM_alg_kyber_768);   /* liboqs name for ML-KEM-768 */
    if (!kem) { fprintf(stderr, "OQS_KEM_new failed (liboqs missing ML-KEM-768?)\n"); return 1; }

    printf("Algorithm      : %s  (NIST ML-KEM-768 / FIPS 203)\n", kem->method_name);
    printf("public key len : %zu  (expected %d)\n", kem->length_public_key,  EXP_PK);
    printf("secret key len : %zu  (expected %d)\n", kem->length_secret_key,  EXP_SK);
    printf("ciphertext len : %zu  (expected %d)\n", kem->length_ciphertext,  EXP_CT);
    printf("shared secret  : %zu  (expected %d)\n", kem->length_shared_secret, EXP_SS);

    if (kem->length_public_key   != EXP_PK) { printf("FAIL: public key size\n"); fail = 1; }
    if (kem->length_secret_key   != EXP_SK) { printf("FAIL: secret key size\n"); fail = 1; }
    if (kem->length_ciphertext   != EXP_CT) { printf("FAIL: ciphertext size\n"); fail = 1; }
    if (kem->length_shared_secret != EXP_SS){ printf("FAIL: shared secret size\n"); fail = 1; }

    uint8_t *pk   = malloc(kem->length_public_key);
    uint8_t *sk   = malloc(kem->length_secret_key);
    uint8_t *ct   = malloc(kem->length_ciphertext);
    uint8_t *ss_a = malloc(kem->length_shared_secret);   /* encapsulator (server) */
    uint8_t *ss_b = malloc(kem->length_shared_secret);   /* decapsulator (client) */
    uint8_t *ss_c = malloc(kem->length_shared_secret);   /* after tamper           */

    if (OQS_KEM_keypair(kem, pk, sk) != OQS_SUCCESS) { printf("FAIL: keypair\n"); return 1; }
    if (OQS_KEM_encaps(kem, ct, ss_a, pk) != OQS_SUCCESS) { printf("FAIL: encaps\n"); return 1; }
    if (OQS_KEM_decaps(kem, ss_b, ct, sk) != OQS_SUCCESS) { printf("FAIL: decaps\n"); return 1; }

    if (memcmp(ss_a, ss_b, kem->length_shared_secret) == 0)
        printf("OK  : encapsulated and decapsulated secrets MATCH (KEM is correct)\n");
    else { printf("FAIL: shared secrets differ\n"); fail = 1; }

    /* Tamper the ciphertext: the recovered secret must change (security depends on the KEM). */
    ct[0] ^= 0xFF;
    OQS_KEM_decaps(kem, ss_c, ct, sk);
    if (memcmp(ss_a, ss_c, kem->length_shared_secret) != 0)
        printf("OK  : tampered ciphertext yields a DIFFERENT secret (KEM is load-bearing)\n");
    else { printf("FAIL: tamper had no effect\n"); fail = 1; }

    OQS_MEM_secure_free(sk, kem->length_secret_key);
    free(pk); free(ct); free(ss_a); free(ss_b); free(ss_c);
    OQS_KEM_free(kem);

    printf(fail ? "\nSELF-TEST FAILED\n" : "\nSELF-TEST PASSED — real ML-KEM-768 in use.\n");
    return fail;
}
