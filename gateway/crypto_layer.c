#include <openssl/evp.h>
#include <openssl/rand.h>
#include <string.h>
#include <stdio.h>

#define GCM_IV_LEN  12
#define GCM_TAG_LEN 16

/*
 * Placeholder session key — will be replaced by OQS-derived key in Step 2.
 * Output layout: [ 12-byte IV | ciphertext | 16-byte TAG ]
 */
static unsigned char default_key[32] =
    "12345678901234567890123456789012";

/*
 * encrypt_data_gcm:
 *   key        - 32-byte AES-256 key (pass NULL to use placeholder)
 *   plaintext  - input bytes
 *   plain_len  - length of plaintext
 *   output     - caller-allocated buffer (plain_len + GCM_IV_LEN + GCM_TAG_LEN)
 *   output_len - bytes written to output
 * Returns 0 on success, -1 on failure.
 */
int encrypt_data_gcm(unsigned char *key,
                     unsigned char *plaintext,
                     int            plain_len,
                     unsigned char *output,
                     int           *output_len)
{
    if (!key) key = default_key;

    unsigned char iv[GCM_IV_LEN];
    if (RAND_bytes(iv, GCM_IV_LEN) != 1) {
        fprintf(stderr, "[Crypto] RAND_bytes failed\n");
        return -1;
    }

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return -1;

    int ret = -1;
    int len = 0;
    *output_len = 0;

    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL) != 1)
        goto cleanup;

    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, GCM_IV_LEN, NULL) != 1)
        goto cleanup;

    if (EVP_EncryptInit_ex(ctx, NULL, NULL, key, iv) != 1)
        goto cleanup;

    /* Prepend IV to output */
    memcpy(output, iv, GCM_IV_LEN);
    unsigned char *ciphertext_start = output + GCM_IV_LEN;

    if (EVP_EncryptUpdate(ctx, ciphertext_start, &len, plaintext, plain_len) != 1)
        goto cleanup;
    *output_len = len;

    if (EVP_EncryptFinal_ex(ctx, ciphertext_start + len, &len) != 1)
        goto cleanup;
    *output_len += len;

    /* Append authentication tag */
    unsigned char *tag_start = ciphertext_start + *output_len;
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, GCM_TAG_LEN, tag_start) != 1)
        goto cleanup;

    *output_len += GCM_IV_LEN + GCM_TAG_LEN;
    ret = 0;

cleanup:
    EVP_CIPHER_CTX_free(ctx);
    return ret;
}

/*
 * decrypt_data_gcm:
 *   key        - 32-byte AES-256 key (pass NULL to use placeholder)
 *   input      - [ 12-byte IV | ciphertext | 16-byte TAG ]
 *   input_len  - total bytes in input
 *   plaintext  - caller-allocated output buffer
 *   plain_len  - bytes written
 * Returns 0 on success, -1 on failure (including auth tag mismatch).
 */
int decrypt_data_gcm(unsigned char *key,
                     unsigned char *input,
                     int            input_len,
                     unsigned char *plaintext,
                     int           *plain_len)
{
    if (!key) key = default_key;

    if (input_len < GCM_IV_LEN + GCM_TAG_LEN) {
        fprintf(stderr, "[Crypto] Input too short\n");
        return -1;
    }

    unsigned char *iv          = input;
    unsigned char *ciphertext  = input + GCM_IV_LEN;
    int            cipher_len  = input_len - GCM_IV_LEN - GCM_TAG_LEN;
    unsigned char *tag         = input + input_len - GCM_TAG_LEN;

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return -1;

    int ret = -1;
    int len = 0;
    *plain_len = 0;

    if (EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL) != 1)
        goto cleanup;

    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, GCM_IV_LEN, NULL) != 1)
        goto cleanup;

    if (EVP_DecryptInit_ex(ctx, NULL, NULL, key, iv) != 1)
        goto cleanup;

    if (EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, cipher_len) != 1)
        goto cleanup;
    *plain_len = len;

    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, GCM_TAG_LEN, tag) != 1)
        goto cleanup;

    if (EVP_DecryptFinal_ex(ctx, plaintext + len, &len) != 1) {
        fprintf(stderr, "[Crypto] Authentication tag verification FAILED\n");
        goto cleanup;
    }
    *plain_len += len;
    plaintext[*plain_len] = '\0';
    ret = 0;

cleanup:
    EVP_CIPHER_CTX_free(ctx);
    return ret;
}
