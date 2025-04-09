#ifndef CRYPTO_H
#define CRYPTO_H

#include <stdint.h>
#include <stdlib.h>

#if defined(HAVE_OPENSSL) || defined(__has_include)
#   if defined(HAVE_OPENSSL) ||__has_include(<openssl/evp.h>)
#       define HAVE_OPENSSL 1
#       include <openssl/evp.h>
#       include <openssl/rsa.h>
#       include <openssl/pem.h>
#       include <openssl/rand.h>
#       include <openssl/x509.h>
#   else
#       define HAVE_OPENSSSL 0
#   endif
#else
#   define HAVE_OPENSSL 0
#endif

#define KEY_LENGTH 2048
#define AES_KEY_LENGTH 32
#define AES_IV_LENGTH 16

#if !HAVE_OPENSSL
typedef struct evp_key_st EVP_PKEY;
#endif

typedef struct {
    EVP_PKEY *private_key;
    EVP_PKEY *public_key;
    EVP_PKEY *peer_public_key;
    unsigned char aes_key[AES_KEY_LENGTH];
    unsigned char aes_iv[AES_IV_LENGTH];
    int has_session_key;
} crypto_context_t;

int crypto_init(crypto_context_t *ctx);
void crypto_cleanup(crypto_context_t *ctx);

int crypto_generate_keys(crypto_context_t *ctx);
int crypto_export_public_key(crypto_context_t *ctx, unsigned char **key_data, size_t *key_len);
int crypto_import_public_key(crypto_context_t *ctx, const unsigned char *key_data, size_t key_len);

int crypto_generate_session_key(crypto_context_t *ctx);
int crypto_encrypt_session_key(crypto_context_t *ctx, unsigned char **encrypted_key, size_t *encrypted_len);
int crypto_decrypt_session_key(crypto_context_t *ctx, const unsigned char *encrypted_key, size_t encrypted_len);

int crypto_encrypt_message(crypto_context_t *ctx, const unsigned char *plaintext, size_t plaintext_len,
                          unsigned char **ciphertext, size_t *ciphertext_len);
int crypto_decrypt_message(crypto_context_t *ctx, const unsigned char *ciphertext, size_t ciphertext_len,
                          unsigned char **plaintext, size_t *plaintext_len);

#endif /* CRYPTO_H */