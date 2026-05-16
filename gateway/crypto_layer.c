#include <openssl/evp.h>
#include <string.h>
#include <stdio.h>

unsigned char key[32] =
    "12345678901234567890123456789012";

unsigned char iv[16] =
    "1234567890123456";

void encrypt_data(unsigned char *plaintext,
                  unsigned char *ciphertext,
                  int *cipher_len) {

    EVP_CIPHER_CTX *ctx;

    ctx = EVP_CIPHER_CTX_new();

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

void decrypt_data(unsigned char *ciphertext,
                  int cipher_len,
                  unsigned char *plaintext,
                  int *plain_len) {

    EVP_CIPHER_CTX *ctx;

    ctx = EVP_CIPHER_CTX_new();

    int len;

    *plain_len = 0;

    EVP_DecryptInit_ex(ctx,
                       EVP_aes_256_cbc(),
                       NULL,
                       key,
                       iv);

    EVP_DecryptUpdate(ctx,
                      plaintext,
                      &len,
                      ciphertext,
                      cipher_len);

    *plain_len += len;

    EVP_DecryptFinal_ex(ctx,
                        plaintext + len,
                        &len);

    *plain_len += len;

    plaintext[*plain_len] = '\0';

    EVP_CIPHER_CTX_free(ctx);
}