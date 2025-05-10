#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/aes.h>
#include "crypto.h"

#define IV_SIZE 16

void generate_random_key(unsigned char *key, size_t length) {
    static int initialized = 0;
    if (!initialized) {
        RAND_poll();
        initialized = 1;
    }
    
    if (RAND_bytes(key, length) != 1) {
        fprintf(stderr, "Error generating random key\n");
        for (size_t i = 0; i < length; i++) {
            key[i] = rand() % 256;
        }
    }
}

void encrypt_data(const unsigned char *input, unsigned char *output, size_t length, const unsigned char *key) {
    EVP_CIPHER_CTX *ctx;
    int len;
    int ciphertext_len;
    unsigned char iv[IV_SIZE];
    
    generate_random_key(iv, IV_SIZE);
    
    ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        fprintf(stderr, "Error creating cipher context\n");
        return;
    }
    
    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv) != 1) {
        fprintf(stderr, "Error initializing encryption\n");
        EVP_CIPHER_CTX_free(ctx);
        return;
    }
    
    memcpy(output, iv, IV_SIZE);
    
    if (EVP_EncryptUpdate(ctx, output + IV_SIZE, &len, input, length) != 1) {
        fprintf(stderr, "Error encrypting data\n");
        EVP_CIPHER_CTX_free(ctx);
        return;
    }
    ciphertext_len = len;
    
    if (EVP_EncryptFinal_ex(ctx, output + IV_SIZE + len, &len) != 1) {
        fprintf(stderr, "Error finalizing encryption\n");
        EVP_CIPHER_CTX_free(ctx);
        return;
    }
    ciphertext_len += len;
    
    EVP_CIPHER_CTX_free(ctx);
}

void decrypt_data(const unsigned char *input, unsigned char *output, size_t length, const unsigned char *key) {
    EVP_CIPHER_CTX *ctx;
    int len;
    int plaintext_len;
    unsigned char iv[IV_SIZE];
    
    if (length < IV_SIZE + AES_BLOCK_SIZE) {
        fprintf(stderr, "Input data too short for decryption\n");
        return;
    }
    
    memcpy(iv, input, IV_SIZE);
    
    ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        fprintf(stderr, "Error creating cipher context\n");
        return;
    }
    
    if (EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv) != 1) {
        fprintf(stderr, "Error initializing decryption\n");
        EVP_CIPHER_CTX_free(ctx);
        return;
    }
    
    if (EVP_DecryptUpdate(ctx, output, &len, input + IV_SIZE, length - IV_SIZE) != 1) {
        fprintf(stderr, "Error decrypting data\n");
        EVP_CIPHER_CTX_free(ctx);
        return;
    }
    plaintext_len = len;
    
    if (EVP_DecryptFinal_ex(ctx, output + len, &len) != 1) {
        fprintf(stderr, "Error finalizing decryption\n");
        EVP_CIPHER_CTX_free(ctx);
        return;
    }
    plaintext_len += len;
    
    output[plaintext_len] = '\0';
    
    EVP_CIPHER_CTX_free(ctx);
}