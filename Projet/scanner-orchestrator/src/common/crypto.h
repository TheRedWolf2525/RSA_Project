#ifndef CRYPTO_H
#define CRYPTO_H

#include <stddef.h>

int encrypt_data(const unsigned char *plaintext, unsigned char *ciphertext, size_t plaintext_len, const unsigned char *key);

int decrypt_data(const unsigned char *encrypted, unsigned char *decrypted, size_t encrypted_len, const unsigned char *key);

void generate_random_key(unsigned char *key, size_t length);

#endif // CRYPTO_H