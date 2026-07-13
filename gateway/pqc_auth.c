#include "pqc_auth.h"

#include <oqs/oqs.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define AUTH_ALG OQS_SIG_alg_ml_dsa_65   /* ML-DSA-65, NIST Level 3 (matches ML-KEM-768) */

const char *pqc_auth_alg(void) { return "ML-DSA-65"; }

static uint8_t *read_file(const char *path, size_t *len_out)
{
    FILE *f = fopen(path, "rb");
    if (!f) return NULL;
    fseek(f, 0, SEEK_END);
    long n = ftell(f);
    fseek(f, 0, SEEK_SET);
    if (n <= 0) { fclose(f); return NULL; }
    uint8_t *buf = malloc((size_t)n);
    if (!buf || fread(buf, 1, (size_t)n, f) != (size_t)n) { free(buf); fclose(f); return NULL; }
    fclose(f);
    *len_out = (size_t)n;
    return buf;
}

int pqc_auth_init(PqcAuth *a, const char *my_sk_path, const char *peer_pk_path)
{
    memset(a, 0, sizeof(*a));
    OQS_SIG *sig = OQS_SIG_new(AUTH_ALG);
    if (!sig) return -1;
    a->sig = sig;

    size_t sk_len = 0, pk_len = 0;
    a->my_sk   = read_file(my_sk_path,   &sk_len);
    a->peer_pk = read_file(peer_pk_path, &pk_len);

    if (!a->my_sk || !a->peer_pk ||
        sk_len != sig->length_secret_key || pk_len != sig->length_public_key) {
        free(a->my_sk);   a->my_sk = NULL;
        free(a->peer_pk); a->peer_pk = NULL;
        a->enabled = 0;
        return -1;   /* keys missing or wrong size -> auth disabled */
    }
    a->enabled = 1;
    return 0;
}

size_t pqc_auth_sig_maxlen(const PqcAuth *a)
{
    return a->sig ? ((OQS_SIG *)a->sig)->length_signature : 0;
}

int pqc_auth_sign(const PqcAuth *a, const uint8_t *msg, size_t len,
                  uint8_t *sig, size_t *sig_len)
{
    if (!a->enabled) return -1;
    return (OQS_SIG_sign((OQS_SIG *)a->sig, sig, sig_len, msg, len, a->my_sk)
            == OQS_SUCCESS) ? 0 : -1;
}

int pqc_auth_verify(const PqcAuth *a, const uint8_t *msg, size_t len,
                    const uint8_t *sig, size_t sig_len)
{
    if (!a->enabled) return -1;
    return (OQS_SIG_verify((OQS_SIG *)a->sig, msg, len, sig, sig_len, a->peer_pk)
            == OQS_SUCCESS) ? 0 : -1;
}

void pqc_auth_free(PqcAuth *a)
{
    if (!a) return;
    if (a->sig) {
        if (a->my_sk) OQS_MEM_secure_free(a->my_sk, ((OQS_SIG *)a->sig)->length_secret_key);
        OQS_SIG_free((OQS_SIG *)a->sig);
    } else {
        free(a->my_sk);
    }
    free(a->peer_pk);
    memset(a, 0, sizeof(*a));
}
