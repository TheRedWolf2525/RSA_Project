#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/aes.h>
#include <openssl/err.h>
#include "crypto.h"

#define IV_SIZE 16
static unsigned char iv[IV_SIZE] = { 0 };

void generate_random_key(unsigned char *key, size_t length)
{
    static int initialized = 0;
    if (!initialized)
    {
        RAND_poll();
        initialized = 1;
    }

    if (RAND_bytes(key, length) != 1)
    {
        fprintf(stderr, "Error generating random key\n");
        for (size_t i = 0; i < length; i++)
        {
            key[i] = rand() % 256;
        }
    }
}

int encrypt_data(const unsigned char *plaintext, unsigned char *ciphertext, size_t plaintext_len, const unsigned char *key) {
    EVP_CIPHER_CTX *ctx;
    int len;
    int ciphertext_len;

    if (!(ctx = EVP_CIPHER_CTX_new())) {
        fprintf(stderr, "Error creating cipher context\n");
        return 0;
    }

    if (1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv)) {
        fprintf(stderr, "Error initializing encryption\n");
        EVP_CIPHER_CTX_free(ctx);
        return 0;
    }

    if (1 != EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len)) {
        fprintf(stderr, "Error encrypting update\n");
        EVP_CIPHER_CTX_free(ctx);
        return 0;
    }
    ciphertext_len = len;

    if (1 != EVP_EncryptFinal_ex(ctx, ciphertext + len, &len)) {
        fprintf(stderr, "Error finalizing encryption: %s\n", ERR_error_string(ERR_get_error(), NULL));
        EVP_CIPHER_CTX_free(ctx);
        return 0;
    }
    ciphertext_len += len;

    EVP_CIPHER_CTX_free(ctx);
    return ciphertext_len;
}

int decrypt_data(const unsigned char *encrypted, unsigned char *decrypted, size_t encrypted_len, const unsigned char *key) {
    EVP_CIPHER_CTX *ctx;
    int len;
    int plaintext_len;

    if (!(ctx = EVP_CIPHER_CTX_new())) {
        fprintf(stderr, "Error creating cipher context\n");
        return 0;
    }

    if (1 != EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv)) {
        fprintf(stderr, "Error initializing decryption\n");
        EVP_CIPHER_CTX_free(ctx);
        return 0;
    }

    if (1 != EVP_DecryptUpdate(ctx, decrypted, &len, encrypted, encrypted_len)) {
        fprintf(stderr, "Error decrypting update\n");
        EVP_CIPHER_CTX_free(ctx);
        return 0;
    }
    plaintext_len = len;

    char err_buf[256];
    if (1 != EVP_DecryptFinal_ex(ctx, decrypted + len, &len)) {
        fprintf(stderr, "Error finalizing decryption: %s\n", 
                ERR_error_string(ERR_get_error(), err_buf));
        EVP_CIPHER_CTX_free(ctx);
        return 0;
    }
    plaintext_len += len;

    EVP_CIPHER_CTX_free(ctx);
    return plaintext_len;
}