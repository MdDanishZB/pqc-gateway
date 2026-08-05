/*
 * pqc_keygen.c — generate the two long-term ML-DSA-65 identities used to authenticate
 * the handshake. Run once:  make pqc_keygen && ./pqc_keygen
 *
 * Writes into ./keys/ :
 *   gateway_sk.bin  gateway_pk.bin   (the gateway / initiator identity)
 *   receiver_sk.bin receiver_pk.bin  (the receiver / responder identity)
 *
 * Pinning: the gateway loads gateway_sk.bin + receiver_pk.bin; the receiver loads
 * receiver_sk.bin + gateway_pk.bin. Each side thus knows exactly who the other must be.
 */
#include <oqs/oqs.h>

#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>

#define AUTH_ALG OQS_SIG_alg_ml_dsa_65

static int write_file(const char *path, const uint8_t *buf, size_t len)
{
    FILE *f = fopen(path, "wb");
    if (!f) { perror(path); return -1; }
    size_t w = fwrite(buf, 1, len, f);
    fclose(f);
    return (w == len) ? 0 : -1;
}

static int gen_identity(OQS_SIG *sig, const char *name,
                        const char *sk_path, const char *pk_path)
{
    uint8_t *pk = malloc(sig->length_public_key);
    uint8_t *sk = malloc(sig->length_secret_key);
    int rc = -1;
    if (!pk || !sk) goto out;
    if (OQS_SIG_keypair(sig, pk, sk) != OQS_SUCCESS) { fprintf(stderr, "keypair failed\n"); goto out; }
    if (write_file(sk_path, sk, sig->length_secret_key) != 0) goto out;
    if (write_file(pk_path, pk, sig->length_public_key) != 0) goto out;
    printf("  %-9s identity: %s (%zu B sk), %s (%zu B pk)\n",
           name, sk_path, sig->length_secret_key, pk_path, sig->length_public_key);
    rc = 0;
out:
    if (sk) OQS_MEM_secure_free(sk, sig->length_secret_key);
    free(pk);
    return rc;
}

int main(void)
{
    mkdir("keys", 0700);
    OQS_SIG *sig = OQS_SIG_new(AUTH_ALG);
    if (!sig) { fprintf(stderr, "OQS_SIG_new(ML-DSA-65) failed\n"); return 1; }

    printf("Generating ML-DSA-65 identities:\n");
    int rc = gen_identity(sig, "gateway",  "keys/gateway_sk.bin",  "keys/gateway_pk.bin")
           | gen_identity(sig, "receiver", "keys/receiver_sk.bin", "keys/receiver_pk.bin");

    OQS_SIG_free(sig);
    if (rc == 0) printf("Done. Keep the *_sk.bin files secret.\n");
    return rc ? 1 : 0;
}
