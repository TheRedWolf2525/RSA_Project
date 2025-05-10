#ifndef CRYPTO_H
#define CRYPTO_H

#include <stddef.h>

void encrypt_data(const unsigned char *input, unsigned char *output, size_t length, const unsigned char *key);

void decrypt_data(const unsigned char *input, unsigned char *output, size_t length, const unsigned char *key);

void generate_random_key(unsigned char *key, size_t length);

#endif // CRYPTO_H