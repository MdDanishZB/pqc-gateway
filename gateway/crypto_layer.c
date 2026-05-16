#include <openssl/evp.h>
#include <string.h>
#include <stdio.h>

void encrypt_data(unsigned char *plaintext,
                  unsigned char *ciphertext,
                  int *cipher_len) {

    EVP_CIPHER_CTX *ctx;

    ctx = EVP_CIPHER_CTX_new();

    unsigned char key[32] =
        "12345678901234567890123456789012";

    unsigned char iv[16] =
        "1234567890123456";

    int len;

    *cipher_len = 0;

    EVP_EncryptInit_ex(ctx,
                       EVP_aes_256_cbc(),
                       NULL,
                       key,
                       iv);

    EVP_EncryptUpdate(ctx,
                      ciphertext,
                      &len,
                      plaintext,
                      strlen((char*)plaintext));

    *cipher_len += len;

    EVP_EncryptFinal_ex(ctx,
                        ciphertext + len,
                        &len);

    *cipher_len += len;

    EVP_CIPHER_CTX_free(ctx);
}