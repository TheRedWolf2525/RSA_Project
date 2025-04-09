#ifndef PROTOCOL_H
#define PROTOCOL_H

#include <stdint.h>
#include <stdlib.h>

#define MAX_BUFFER_SIZE 4096

#define CAPABILITY_NMAP (1 << 0)
#define CAPABILITY_ZAP (1 << 1)
#define CAPABILITY_NIKTO (1 << 2)

typedef enum {
   SCAN_TYPE_NMAP,
   SCAN_TYPE_ZAP,
   SCAN_TYPE_NIKTO
} scan_type_t;

/*
 * Format du message:
 * +--------+----------+--------------------+
 * | Type   | Longueur | Données            |
 * | 1 octet| 2 octets | L (Longueur) octets|
 * +--------+----------+--------------------+
 */

 #define MSG_TYPE_AUTH_REQUEST 0x01
 #define MSG_TYPE_AUTH_RESPONSE 0x02
 #define MSG_TYPE_CAPABILITIES 0x03
 #define MSG_TYPE_SCAN_REQUEST 0x04
 #define MSG_TYPE_SCAN_STATUS 0x05
 #define MSG_TYPE_SCAN_RESULT 0x06
 #define MSG_TYPE_SCAN_CANCEL 0x07
 #define MSG_TYPE_ERROR 0x08

 typedef struct {
    uint8_t type;
    uint16_t length;
    char data[MAX_BUFFER_SIZE - 3];
 } message_t;

 int protocol_serialize_message(const message_t *message, char *buffer, size_t buffer_size);
 int protocol_deserialize_message(const char *buffer, size_t buffer_size, message_t *message);

 typedef struct {
    char hostname[256];
 } auth_response_t;

 typedef struct {
    uint32_t capabilities;
 } capabilities_response_t;

 typedef struct {
    uint32_t scan_id;
    uint32_t scan_type;
    uint32_t num_targets;
 } scan_request_t;

 typedef struct {
    uint32_t scan_id;
    uint32_t progress;
 } scan_status_t;

 typedef struct {
    uint32_t scan_id;
 } scan_result_t;

 typedef struct {
    uint32_t scan_id;
 } scan_cancel_t;

 typedef struct {
    uint32_t error_code;
 } error_message_t;

 #define ERR_INVALID_MESSAGE 0x01
 #define ERR_UNSUPPORTED_SCAN 0x02
 #define ERR_SCAN_FAILED 0x03
 #define ERR_AUTHENTICATION 0x04
 #define ERR_INTERNAL 0x05

 int protocol_create_auth_request(message_t *message);
 int protocol_create_auth_response(const char *hostname, message_t *message);
 int protocol_create_capabilities_request(message_t *message);
 int protocol_create_capabilities_response(uint32_t capabilities, message_t *message);
 int protocol_create_scan_request(uint32_t scan_id, uint32_t scan_type,
                             const char **targets, uint32_t num_targets,
                             const char *options, message_t *message);
int protocol_create_scan_status(uint32_t scan_id, uint32_t progress, message_t *message);
int protocol_create_scan_result(uint32_t scan_id, const char *result,
                             size_t result_size, message_t *message);
int protocol_create_scan_cancel(uint32_t scan_id, message_t *message);
int protocol_create_error(uint32_t error_code, const char *error_msg, message_t *message);

int protocol_parse_scan_request(const message_t *message, uint32_t *scan_id,
                             uint32_t *scan_type, char **targets, uint32_t max_targets,
                             uint32_t *num_targets, char *options, size_t options_size);

 #endif /* PROTOCOL_H */