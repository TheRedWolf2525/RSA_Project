#include "../../include/crypto.h"
#include <string.h>
#include <stdio.h>

#if HAVE_OPENSSL
#include <openssl/err.h>
#endif

// Simple chiffrement XOR au cas où OpenSSL n'est pas disponible
static void xor_crypt(const unsigned char *input, unsigned char *output, size_t len, const unsigned char *key, size_t key_len) {
    for (size_t i = 0; i < len; i++) {
        output[i] = input[i] ^ key[i % key_len];
    }
}

int crypto_init(crypto_context_t *ctx) {
    if (!ctx) return -1;

    memset(ctx, 0, sizeof(crypto_context_t));

#if HAVE_OPENSSL
    OpenSSL_add_all_algorithms();
    ERR_load_crypto_strings();
#endif

    return 0;
}

void crypto_cleanup(crypto_context_t *ctx) {
    if (!ctx) return;

#if HAVE_OPENSSL
    if (ctx->private_key) EVP_PKEY_free(ctx->private_key);
    if (ctx->public_key) EVP_PKEY_free(ctx->public_key);
    if (ctx->peer_public_key) EVP_PKEY_free(ctx->peer_public_key);

    EVP_cleanup();
    ERR_free_strings();
#endif

    memset(ctx->aes_key, 0, AES_KEY_LENGTH);
    memset(ctx->aes_iv, 0, AES_IV_LENGTH);
}

int crypto_generate_keys(crypto_context_t *ctx) {
    if (!ctx) return -1;

#if HAVE_OPENSSL
    EVP_PKEY_CTX *key_ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL);
    if (!key_ctx) return -1;

    if (EVP_PKEY_keygen_init(key_ctx) <= 0) {
        EVP_PKEY_CTX_free(key_ctx);
        return -1;
    }

    if (EVP_PKEY_CTX_set_rsa_keygen_bits(key_ctx, KEY_LENGTH) <= 0) {
        EVP_PKEY_CTX_free(key_ctx);
        return -1;
    }

    if (EVP_PKEY_keygen(key_ctx, &ctx->private_key) <= 0) {
        EVP_PKEY_CTX_free(key_ctx);
        return -1;
    }

    ctx->public_key = EVP_PKEY_new();
    RSA *rsa = EVP_PKEY_get1_RSA(ctx->private_key);
    EVP_PKEY_set1_RSA(ctx->public_key, rsa);
    RSA_free(rsa);

    EVP_PKEY_CTX_free(key_ctx);
    return 0;
#else
    printf("WARNING: OpenSSL not available. Using less secure key generation.\n");
    // Simple génération aléatoir de clé pour le chiffrement XOR
    for (int i = 0; i < AES_KEY_LENGTH; i++) {
        ctx->aes_key[i] = rand() % 256;
    }
    for (int i = 0; i < AES_IV_LENGTH; i++) {
        ctx->aes_iv[i] = rand() % 256;
    }
    ctx->has_session_key = 1;
    return 0;
#endif
}

int crypto_export_public_key(crypto_context_t *ctx, unsigned char **key_data, size_t *key_len) {
    if (!ctx || !key_data || !key_len) return -1;

#if HAVE_OPENSSL
    if (!ctx->public_key) return -1;

    BIO *bio = BIO_new(BIO_s_mem());
    if (!bio) return -1;

    if (PEM_write_bio_PUBKEY(bio, ctx->public_key) != 1) {
        BIO_free(bio);
        return -1;
    }

    *key_len = BIO_pending(bio);
    *key_data = malloc(*key_len);
    if (!*key_data) {
        BIO_free(bio);
        return -1;
    }

    BIO_read(bio, *key_data, *key_len);
    BIO_free(bio);

    return 0;
#else
    printf("WARNING: OpenSSL not available. Using less secure key exchange.\n");
    // Simple partage de la clé XOR
    *key_len = AES_KEY_LENGTH + AES_IV_LENGTH;
    *key_data = malloc(*key_len);
    if (!*key_data) return -1;

    memcpy(*key_data, ctx->aes_key, AES_KEY_LENGTH);
    memcpy(*key_data + AES_IV_LENGTH, ctx->aes_iv, AES_IV_LENGTH);

    return 0;
#endif
}

int crypto_import_public_key(crypto_context_t *ctx, const unsigned char *key_data, size_t key_len) {
    if (!ctx || !key_data || key_len == 0) return -1;

#if HAVE_OPENSSL
    BIO *bio = BIO_new_mem_buf(key_data, key_len);
    if (!bio) return -1;

    if (ctx->peer_public_key) {
        EVP_PKEY_free(ctx->peer_public_key);
        ctx->peer_public_key = NULL;
    }

    ctx->peer_public_key = PEM_read_bio_PUBKEY(bio, NULL, NULL, NULL);
    BIO_free(bio);

    return ctx->peer_public_key ? 0 : -1;
#else
    printf("WARNING: OpenSSL not available. Using less secure key exchange.\n");
    // Simple import de la clé XOR
    if (key_len < AES_KEY_LENGTH + AES_IV_LENGTH) return -1;

    memcpy(ctx->aes_key, key_data, AES_KEY_LENGTH);
    memcpy(ctx->aes_iv, key_data + AES_KEY_LENGTH, AES_IV_LENGTH);
    ctx->has_session_key = 1;

    return 0;
#endif
}

int crypto_generate_session_key(crypto_context_t *ctx) {
    if (!ctx) return -1;

#if HAVE_OPENSSL
    if (RAND_bytes(ctx->aes_key, AES_KEY_LENGTH) != 1) {
        return -1;
    }

    if (RAND_bytes(ctx->aes_iv, AES_IV_LENGTH) != 1) {
        return -1;
    }
#else
    printf("WARNING: OpenSSL not available. Using less secure key generation.\n");
    // Utilisation de rand de stdlib (non sécurisé)
    for (int i = 0; i < AES_KEY_LENGTH; i++) {
        ctx->aes_key[i] = rand() % 256;
    }
    for (int i = 0; i < AES_IV_LENGTH; i++) {
        ctx->aes_iv[i] = rand() % 256;
    }
#endif

    ctx->has_session_key = 1;
    return 0;
}

int crypto_encrypt_session_key(crypto_context_t *ctx, unsigned char **encrypted_key, size_t *encrypted_len) {
    if (!ctx || !ctx->has_session_key || !encrypted_key || !encrypted_len) return -1;

#if HAVE_OPENSSL
    if (!ctx->peer_public_key) return -1;

    unsigned char buffer[AES_KEY_LENGTH + AES_IV_LENGTH];
    memcpy(buffer, ctx->aes_key, AES_KEY_LENGTH);
    memcpy(buffer + AES_KEY_LENGTH, ctx->aes_iv, AES_IV_LENGTH);

    EVP_PKEY_CTX *ctx_encrypt = EVP_PKEY_CTX_new(ctx->peer_public_key, NULL);
    if (!ctx_encrypt) return -1;

    if (EVP_PKEY_encrypt_init(ctx_encrypt) <= 0) {
        EVP_PKEY_CTX_free(ctx_encrypt);
        return -1;
    }

    if (EVP_PKEY_CTX_set_rsa_padding(ctx_encrypt, RSA_PKCS1_OAEP_PADDING) <= 0) {
        EVP_PKEY_CTX_free(ctx_encrypt);
        return -1;
    }

    if (EVP_PKEY_encrypt(ctx_encrypt, NULL, encrypted_len, buffer, AES_KEY_LENGTH + AES_IV_LENGTH) <= 0) {
        EVP_PKEY_CTX_free(ctx_encrypt);
        return -1;
    }

    *encrypted_key = malloc(*encrypted_len);
    if (!*encrypted_key) {
        EVP_PKEY_CTX_free(ctx_encrypt);
        return -1;
    }

    if (EVP_PKEY_encrypt(ctx_encrypt, *encrypted_key, encrypted_len, buffer, AES_KEY_LENGTH + AES_IV_LENGTH) <= 0) {
        free(*encrypted_key);
        EVP_PKEY_CTX_free(ctx_encrypt);
        return -1;
    }

    EVP_PKEY_CTX_free(ctx_encrypt);
    return 0;
#else
    printf("WARNING: OpenSSL not available. Using less secure session key exchange.\n");
    // Pas de chiffrement de la clé de session
    *encrypted_len = AES_KEY_LENGTH + AES_IV_LENGTH;
    *encrypted_key = malloc(*encrypted_len);
    if (!*encrypted_key) return -1;

    memcpy(*encrypted_key, ctx->aes_key, AES_KEY_LENGTH);
    memcpy(*encrypted_key + AES_KEY_LENGTH, ctx->aes_iv, AES_IV_LENGTH);

    return 0;
#endif
}

int crypto_decrypt_session_key(crypto_context_t *ctx, const unsigned char *encrypted_key, size_t encrypted_len) {
    if (!ctx || !encrypted_key || encrypted_len == 0) return -1;

#if HAVE_OPENSSL
    if (!ctx->private_key) return -1;

    EVP_PKEY_CTX *ctx_decrypt = EVP_PKEY_CTX_new(ctx->private_key, NULL);
    if (!ctx_decrypt) return -1;

    if (EVP_PKEY_decrypt_init(ctx_decrypt) <= 0) {
        EVP_PKEY_CTX_free(ctx_decrypt);
        return -1;
    }

    if (EVP_PKEY_CTX_set_rsa_padding(ctx_decrypt, RSA_PKCS1_OAEP_PADDING) <= 0) {
        EVP_PKEY_CTX_free(ctx_decrypt);
        return -1;
    }

    size_t outlen = 0;
    if (EVP_PKEY_decrypt(ctx_decrypt, NULL, &outlen, encrypted_key, encrypted_len) <= 0) {
        EVP_PKEY_CTX_free(ctx_decrypt);
        return -1;
    }

    unsigned char *buffer = malloc(outlen);
    if (!buffer) {
        EVP_PKEY_CTX_free(ctx_decrypt);
        return -1;
    }

    if (EVP_PKEY_decrypt(ctx_decrypt, buffer, &outlen, encrypted_key, encrypted_len) <= 0) {
        free(buffer);
        EVP_PKEY_CTX_free(ctx_decrypt);
        return -1;
    }

    if (outlen < AES_KEY_LENGTH + AES_IV_LENGTH) {
        free(buffer);
        EVP_PKEY_CTX_free(ctx_decrypt);
        return -1;
    }

    memcpy(ctx->aes_key, buffer, AES_KEY_LENGTH);
    memcpy(ctx->aes_iv, buffer + AES_KEY_LENGTH, AES_IV_LENGTH);

    free(buffer);
    EVP_PKEY_CTX_free(ctx_decrypt);

    ctx->has_session_key = 1;
    return 0;
#else
    printf("WARNING: OpenSSL not avilable. Using less secure session key handling.\n");
    if (encrypted_len < AES_KEY_LENGTH + AES_IV_LENGTH) return -1;

    memcpy(ctx->aes_key, encrypted_key, AES_KEY_LENGTH);
    memcpy(ctx->aes_iv, encrypted_key + AES_KEY_LENGTH, AES_IV_LENGTH);
    ctx->has_session_key = 1;

    return 0;
#endif
}

int crypto_encrypt_message(crypto_context_t *ctx, const unsigned char *plaintext, size_t plaintext_len,
                           unsigned char **ciphertext, size_t *ciphertext_len) {
    if (!ctx || !ctx->has_session_key || !plaintext || plaintext_len == 0 || !ciphertext || !ciphertext_len) return -1;

#if HAVE_OPENSSL
    EVP_CIPHER_CTX *cipher_ctx = EVP_CIPHER_CTX_new();
    if (!cipher_ctx) return -1;

    if (EVP_EncryptInit_ex(cipher_ctx, EVP_aes_256_cbc(), NULL, ctx->aes_key, ctx->aes_iv) != 1) {
        EVP_CIPHER_CTX_free(cipher_ctx);
        return -1;
    }

    *ciphertext = malloc(plaintext_len + EVP_CIPHER_block_size(EVP_aes_256_cbc()));
    if (!*ciphertext) {
        EVP_CIPHER_CTX_free(cipher_ctx);
        return -1;
    }

    int outlen = 0;
    if (EVP_EncryptUpdate(cipher_ctx, *ciphertext, &outlen, plaintext, plaintext_len) != 1) {
        free(*ciphertext);
        EVP_CIPHER_CTX_free(cipher_ctx);
        return -1;
    }

    int tmplen = 0;
    if (EVP_EncryptFinal_ex(cipher_ctx, *ciphertext + outlen, &tmplen) != 1) {
        free(*ciphertext);
        EVP_CIPHER_CTX_free(cipher_ctx);
        return -1;
    }

    *ciphertext_len = outlen + tmplen;
    EVP_CIPHER_CTX_free(cipher_ctx);

    return 0;
#else
    printf("WARNING: OpenSSL not available. Using less secure XOR encryption.\n");
    // Chiffrement XOR
    *ciphertext_len = plaintext_len;
    *ciphertext = malloc(*ciphertext_len);
    if (!*ciphertext) return -1;

    xor_crypt(plaintext, *ciphertext, plaintext_len, ctx->aes_key, AES_KEY_LENGTH);

    return 0;
#endif
}

int crypto_decrypt_message(crypto_context_t *ctx, const unsigned char *ciphertext, size_t ciphertext_len,
                           unsigned char **plaintext, size_t *plaintext_len) {
    if (!ctx || !ctx->has_session_key || !ciphertext || ciphertext_len == 0 || !plaintext || !plaintext_len) return -1;

#if HAVE_OPENSSL
    EVP_CIPHER_CTX *cipher_ctx = EVP_CIPHER_CTX_new();
    if (!cipher_ctx) return -1;

    if (EVP_DecryptInit_ex(cipher_ctx, EVP_aes_256_cbc(), NULL, ctx->aes_key, ctx->aes_iv) != 1) {
        EVP_CIPHER_CTX_free(cipher_ctx);
        return -1;
    }

    *plaintext = malloc(ciphertext_len);
    if (!*plaintext) {
        EVP_CIPHER_CTX_free(cipher_ctx);
        return -1;
    }

    int outlen = 0;
    if (EVP_DecryptUpdate(cipher_ctx, *plaintext, &outlen, ciphertext, ciphertext_len) != 1) {
        free(*plaintext);
        EVP_CIPHER_CTX_free(cipher_ctx);
        return -1;
    }

    int tmplen = 0;
    if (EVP_DecryptFinal_ex(cipher_ctx, *plaintext + outlen, &tmplen) != 1) {
        free(*plaintext);
        EVP_CIPHER_CTX_free(cipher_ctx);
        return -1;
    }

    *plaintext_len = outlen + tmplen;
    EVP_CIPHER_CTX_free(cipher_ctx);

    return 0;
#else
    printf("WARNING: OpenSSL not available. Using less secure XOR decryption.\n");
    // Déchiffrement XOR
    *plaintext_len = ciphertext_len;
    *plaintext = malloc(*plaintext_len);
    if (!*plaintext) return -1;

    xor_crypt(ciphertext, *plaintext, ciphertext_len, ctx->aes_key, AES_KEY_LENGTH);

    return 0;
#endif
}