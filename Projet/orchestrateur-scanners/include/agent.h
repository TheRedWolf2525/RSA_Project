#ifndef AGENT_H
#define AGENT_H

#include <stdint.h>
#include "protocol.h"
#include "crypto.h"

#define DEFAULT_PORT 8080
#define MAX_BUFFER_SIZE 4096
#define MAX_SCANNER_OUTPUT 1048576
#define MAX_TARGETS 10
#define MAX_OPTIONS_LENGTH 1024

typedef enum {
    AGENT_STATE_DISCONNECTED,
    AGENT_STATE_CONNECTED,
    AGENT_STATE_AUTHENTICATING,
    AGENT_STATE_AUTHENTICATED,
    AGENT_STATE_SCANNING,
    AGENT_STATE_ERROR
} agent_state_t;

typedef struct {
    int socket_fd;
    agent_state_t state;
    uint32_t capabilities;
    char hostname[256];
    crypto_context_t crypto_ctx;
    int running;
    char buffer[MAX_BUFFER_SIZE];
    char scanner_output[MAX_SCANNER_OUTPUT];
    size_t scanner_output_size;
    uint32_t current_scan_id;
} agent_t;

int agent_init(agent_t *agent, const char *hostname, uint32_t capabilities);
int agent_connect(agent_t *agent, const char *server_addr, uint16_t server_port);
int agent_run(agent_t *agent);
void agent_cleanup(agent_t *agent);
void agent_stop(agent_t *agent);

int execute_nmap_scan(agent_t *agent, const char *target, const char *options);
int execute_zap_scan(agent_t *agent, const char *target, const char *options);
int execute_nikto_scan(agent_t *agent, const char *target, const char *options);

int handle_auth_request(agent_t *agent, const message_t *message);
int handle_capabilities_request(agent_t *agent, const message_t *message);
int handle_scan_request(agent_t *agent, const message_t *message);
int handle_scan_cancel(agent_t *agent, const message_t *message);
int handle_key_exchange(agent_t *agent, const message_t *message);
int handle_session_key(agent_t *agent, const message_t *message);

int send_scan_status(agent_t *agent, uint32_t scan_id, uint32_t progress);
int send_scan_result(agent_t *agent, uint32_t scan_id, const char *result, size_t result_size);
int send_error(agent_t *agent, uint32_t error_code, const char *error_msg);

#endif // AGENT_H