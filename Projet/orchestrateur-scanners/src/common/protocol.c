#include "../../include/protocol.h"
#include "../../include/crypto.h"
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <arpa/inet.h>

int protocol_serialize_message(const message_t *message, char *buffer, size_t buffer_size) {
    if (!message || !buffer || buffer_size < 3) {
        return -1;
    }

    if (message->length > MAX_BUFFER_SIZE - 3 || message->length > buffer_size - 3) {
        return -1;
    }

    buffer[0] = message->type;
    buffer[1] = (message->length >> 8) & 0xFF;
    buffer[2] = message->length & 0xFF;

    if (message->length > 0) {
        memcpy(buffer + 3, message->data, message->length);
    }

    return 3 + message->length;
}

int protocol_deserialize_message(const char *buffer, size_t buffer_size, message_t *message) {
    if (!buffer || !message || buffer_size < 3) {
        return -1;
    }

    message->type = buffer[0];
    message->length = ((uint16_t)buffer[1] << 8) | buffer[2];

    if (message->length > MAX_BUFFER_SIZE - 3 || message->length > buffer_size - 3) {
        return -1;
    }

    if (message->length > 0) {
        memcpy(message->data, buffer + 3, message->length);
    }

    return 0;
}

int protocol_create_scan_request(uint32_t scan_id, uint32_t scan_type,
                            const char **targets, uint32_t num_targets,
                            const char *options, message_t *message) {

    if (!targets || !message || !options) {
        return -1;
    }

    message->type = MSG_TYPE_SCAN_REQUEST;

    scan_request_t request_header;
    request_header.scan_id = htonl(scan_id);
    request_header.scan_type = htonl(scan_type);
    request_header.num_targets = htonl(num_targets);

    size_t offset = 0;
    memcpy(message->data, &request_header, sizeof(scan_request_t));
    offset += sizeof(scan_request_t);

    for (uint32_t i = 0; i < num_targets; i++) {
        size_t target_len = strlen(targets[i]) + 1;
        if (offset + target_len > MAX_BUFFER_SIZE - 3) {
            return -1;
        }
        memcpy(message->data + offset, targets[i], target_len);
        offset += target_len;
    }

    size_t options_len = strlen(options) + 1;
    if (offset + options_len > MAX_BUFFER_SIZE - 3) {
        return -1;
    }
    memcpy(message->data + offset, options, options_len);
    offset += options_len;

    message->length = offset;
    return 0;
}

int protocol_parse_scan_request(const message_t *message, uint32_t *scan_id,
                            uint32_t *scan_type, char **targets, uint32_t max_targets,
                            uint32_t *num_targets, char *options, size_t options_size) {
    if (!message || !scan_id || !scan_type || !targets || !num_targets || !options) {
        return -1;
    }

    if (message->type != MSG_TYPE_SCAN_REQUEST || message->length < sizeof(scan_request_t)) {
        return -1;
    }

    scan_request_t request_header;
    memcpy(&request_header, message->data, sizeof(scan_request_t));

    *scan_id = ntohl(request_header.scan_id);
    *scan_type = ntohl(request_header.scan_type);
    *num_targets = ntohl(request_header.num_targets);

    if (*num_targets > max_targets) {
        return -1;
    }

    size_t offset = sizeof(scan_request_t);
    for (uint32_t i = 0; i < *num_targets; i++) {
        if (offset >= message->length) {
            return -1;
        }

        targets[i] = strdup(message->data + offset);
        if (!targets[i]) {
            for (uint32_t j = 0; j < i; j++) {
                free(targets[i]);
            }
            return -1;
        }

        offset += strlen(targets[i]) + 1;
    }

    if (offset >= message->length) {
        for (uint32_t i = 0; i < *num_targets; i++) {
            free(targets[i]);
        }
        return -1;
    }

    strncpy(options, message->data + offset, options_size - 1);
    options[options_size - 1] = '\0';

    return 0;
}

int protocol_create_auth_request(message_t *message) {
    if (!message) {
        return -1;
    }

    message->type = MSG_TYPE_AUTH_REQUEST;
    message->length = 0;

    return 0;
}

int protocol_create_auth_response(const char *hostname, message_t *message) {
    if (!hostname || !message) {
        return -1;
    }

    message->type = MSG_TYPE_AUTH_RESPONSE;

    size_t hostname_len = strlen(hostname);
    if (hostname_len > MAX_BUFFER_SIZE - 3) {
        return -1;
    }

    memcpy(message->data, hostname, hostname_len);
    message->length = hostname_len;

    return 0;
}

int protocol_create_capabilities_request(message_t *message) {
    if (!message) {
        return -1;
    }

    message->type = MSG_TYPE_CAPABILITIES;
    message->length = 0;

    return 0;
}

int protocol_create_capabilities_response(uint32_t capabilities, message_t *message) {
    if (!message) {
        return -1;
    }

    message->type = MSG_TYPE_CAPABILITIES;

    uint32_t cap_network = htonl(capabilities);
    memcpy(message->data, &cap_network, sizeof(uint32_t));
    message->length = sizeof(uint32_t);

    return 0;
}

int protocol_create_scan_status(uint32_t scan_id, uint32_t progress, message_t *message) {
    if (!message) {
        return -1;
    }

    message->type = MSG_TYPE_SCAN_STATUS;

    scan_status_t status;
    status.scan_id = htonl(scan_id);
    status.progress = htonl(progress);

    memcpy(message->data, &status, sizeof(scan_status_t));
    message->length = sizeof(scan_status_t);

    return 0;
}

int protocol_create_scan_result(uint32_t scan_id, const char *result,
                            size_t result_size, message_t *message) {
    if (!message || (!result && result_size > 0)) {
        return -1;
    }

    message->type = MSG_TYPE_SCAN_RESULT;

    scan_result_t header;
    header.scan_id = htonl(scan_id);

    memcpy(message->data, &header, sizeof(scan_result_t));

    if (result && result_size > 0) {
        if (result_size > MAX_BUFFER_SIZE - 3 - sizeof(scan_result_t)) {
            return -1;
        }

        memcpy(message->data + sizeof(scan_result_t), result, result_size);
    }

    message->length = sizeof(scan_result_t) + result_size;

    return 0;
}

int protocol_create_scan_cancel(uint32_t scan_id, message_t *message) {
    if (!message) {
        return -1;
    }

    message->type = MSG_TYPE_SCAN_CANCEL;

    scan_cancel_t cancel;
    cancel.scan_id = htonl(scan_id);

    memcpy(message->data, &cancel, sizeof(scan_cancel_t));
    message->length = sizeof(scan_cancel_t);

    return 0;
}

int protocol_create_error(uint32_t error_code, const char *error_msg, message_t *message) {
    if (!message || !error_msg) {
        return -1;
    }

    message->type = MSG_TYPE_ERROR;

    error_message_t header;
    header.error_code = htonl(error_code);

    memcpy(message->data, &header, sizeof(error_message_t));

    size_t msg_len = strlen(error_msg);
    if (msg_len > MAX_BUFFER_SIZE - 3 - sizeof(error_message_t)) {
        return -1;
    }

    memcpy(message->data + sizeof(error_message_t), error_msg, msg_len + 1);
    message->length = sizeof(error_message_t) + msg_len + 1;

    return 0;
}

int protocol_secure_serialize_message(crypto_context_t *ctx, const message_t *message,
                                        char **buffer, size_t *buffer_size) {
    if (!ctx || !message || !buffer || !buffer_size) return -1;

    char temp_buffer[MAX_BUFFER_SIZE];
    int serialized_size = protocol_serialize_message(message, temp_buffer, MAX_BUFFER_SIZE);

    if (serialized_size < 0) return -1;

    unsigned char *encrypted_data = NULL;
    size_t encrypted_len = 0;

    if (crypto_encrypt_message(ctx, (unsigned char *)temp_buffer, serialized_size,
                               &encrypted_data, &encrypted_len) != 0) {
        return -1;
    }

    *buffer = malloc(4 + encrypted_len);
    if (!*buffer) {
        free(encrypted_data);
        return -1;
    }

    uint32_t net_len = htonl((uint32_t)encrypted_len);
    memcpy(*buffer, &net_len, 4);

    memcpy(*buffer + 4, encrypted_data, encrypted_len);

    *buffer_size = 4 + encrypted_len;
    free(encrypted_data);

    return 0;
}

int protocol_secure_deserialize_message(crypto_context_t *ctx, const char *buffer,
                                    size_t buffer_size, message_t *message) {
    if (!ctx || !buffer || buffer_size <= 4 || !message) return -1;
    
    uint32_t encrypted_len;
    memcpy(&encrypted_len, buffer, 4);
    encrypted_len = ntohl(encrypted_len);

    if (buffer_size < 4 + encrypted_len) return -1;

    unsigned char *decrypted_data = NULL;
    size_t decrypted_len = 0;

    if (crypto_decrypt_message(ctx, (unsigned char *)(buffer + 4), encrypted_len,
                               &decrypted_data, &decrypted_len) != 0) {
        return -1;
    }

    int result = protocol_deserialize_message((char *)decrypted_data, decrypted_len, message);

    free(decrypted_data);
    return result;
}

int protocol_create_key_exchange(const unsigned char *public_key, size_t key_len, message_t *message) {
    if (!public_key || key_len == 0 || !message) return -1;

    message->type = MSG_TYPE_KEY_EXCHANGE;

    if (key_len > MAX_BUFFER_SIZE - 3) return -1;

    memcpy(message->data, public_key, key_len);
    message->length = key_len;

    return 0;
}

int protocol_create_session_key(const unsigned char *encrypted_key, size_t key_len, message_t *message) {
    if (!encrypted_key || key_len == 0 || !message) return -1;
    
    message->type = MSG_TYPE_SESSION_KEY;

    if (key_len > MAX_BUFFER_SIZE - 3) return -1;

    memcpy(message->data, encrypted_key, key_len);
    message->length = key_len;

    return 0;
}

int protocol_extract_public_key(const message_t *message, unsigned char **public_key, size_t *key_len) {
    if (!message || message->type != MSG_TYPE_KEY_EXCHANGE || !public_key || !key_len) return -1;

    *key_len = message->length;
    *public_key = malloc(*key_len);
    if (!*public_key) return -1;

    memcpy(*public_key, message->data, *key_len);

    return 0;
}

int protocol_extract_session_key(const message_t *message, unsigned char **encrypted_key, size_t *key_len) {
    if (!message ||message->type != MSG_TYPE_SESSION_KEY || !encrypted_key || !key_len) return -1;

    *key_len = message->length;
    *encrypted_key = malloc(*key_len);
    if (!*encrypted_key) return -1;

    memcpy(*encrypted_key, message->data, *key_len);

    return 0;
}