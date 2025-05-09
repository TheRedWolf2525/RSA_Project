#include "../../include/agent.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <signal.h>
#include <sys/socket.h>
#include <sys/select.h>
#include <arpa/inet.h>
#include <time.h>
#include <netinet/tcp.h>

static agent_t *g_agent = NULL;

static void signal_handler(int signum);
static int process_message(agent_t *agent, const message_t *message);

static void signal_handler(int signum)
{
    if (g_agent)
    {
        printf("\nSignal %d reçu. Arrêt de l'agent...\n", signum);
        agent_stop(g_agent);
    }
}

int agent_init(agent_t *agent, const char *hostname, uint32_t capabilities)
{
    if (!agent || !hostname)
        return -1;

    memset(agent, 0, sizeof(agent_t));

    strncpy(agent->hostname, hostname, sizeof(agent->hostname) - 1);
    agent->hostname[sizeof(agent->hostname) - 1] = '\0';

    agent->capabilities = capabilities;
    agent->state = AGENT_STATE_DISCONNECTED;
    agent->socket_fd = -1;
    agent->running = 0;

    if (crypto_init(&agent->crypto_ctx) != 0)
    {
        fprintf(stderr, "Failed to initialize crypto context\n");
        return -1;
    }

    g_agent = agent;
    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);

    printf("Agent initialized with hostname: %s\n", agent->hostname);
    return 0;
}

int agent_connect(agent_t *agent, const char *server_addr, uint16_t server_port)
{
    if (!agent || !server_addr)
        return -1;

    agent->socket_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (agent->socket_fd < 0)
    {
        perror("Failed to create socket");
        return -1;
    }

    int flag = 1;
    if (setsockopt(agent->socket_fd, IPPROTO_TCP, TCP_NODELAY, &flag, sizeof(flag)) < 0)
    {
        perror("Failed to set TCP_NODELAY");
        close(agent->socket_fd);
        agent->socket_fd = -1;
        return -1;
    }

    int flags = fcntl(agent->socket_fd, F_GETFL, 0);
    fcntl(agent->socket_fd, F_SETFL, flags | O_NONBLOCK);

    struct sockaddr_in server_address;
    server_address.sin_family = AF_INET;
    server_address.sin_port = htons(server_port);

    if (inet_pton(AF_INET, server_addr, &server_address.sin_addr) <= 0)
    {
        perror("Invalid address");
        close(agent->socket_fd);
        agent->socket_fd = -1;
        return -1;
    }

    int connect_result = connect(agent->socket_fd, (struct sockaddr *)&server_address, sizeof(server_address));
    if (connect_result < 0)
    {
        if (errno != EINPROGRESS)
        {
            perror("Failed to connect to server");
            close(agent->socket_fd);
            agent->socket_fd = -1;
            return -1;
        }

        fd_set write_fds;
        struct timeval timeout;
        FD_ZERO(&write_fds);
        FD_SET(agent->socket_fd, &write_fds);
        timeout.tv_sec = 10;
        timeout.tv_usec = 0;

        int select_result = select(agent->socket_fd + 1, NULL, &write_fds, NULL, &timeout);
        if (select_result <= 0)
        {
            if (select_result == 0)
            {
                fprintf(stderr, "Connection timeout\n");
            }
            else
            {
                perror("Select error");
            }
            close(agent->socket_fd);
            agent->socket_fd = -1;
            return -1;
        }

        int so_error = 0;
        socklen_t len = sizeof(so_error);
        getsockopt(agent->socket_fd, SOL_SOCKET, SO_ERROR, &so_error, &len);
        if (so_error != 0)
        {
            fprintf(stderr, "Connection error: %s\n", strerror(so_error));
            close(agent->socket_fd);
            agent->socket_fd = -1;
            return -1;
        }
    }

    agent->state = AGENT_STATE_CONNECTED;
    agent->running = 1;

    printf("Connected to orchestrator at %s:%d\n", server_addr, server_port);
    return 0;
}

void agent_cleanup(agent_t *agent)
{
    if (!agent)
        return;

    if (agent->socket_fd >= 0)
    {
        close(agent->socket_fd);
        agent->socket_fd = -1;
    }

    crypto_cleanup(&agent->crypto_ctx);
    agent->state = AGENT_STATE_DISCONNECTED;
    agent->running = 0;

    printf("Agent cleaned up\n");
}

void agent_stop(agent_t *agent)
{
    if (!agent)
        return;
    agent->running = 0;
}

static int handle_key_exchange_init(agent_t *agent)
{
    if (!agent || agent->state != AGENT_STATE_CONNECTED)
        return -1;

    printf("Initiating key exchange process\n");

    if (crypto_generate_keys(&agent->crypto_ctx) != 0)
    {
        fprintf(stderr, "Failed to generate key pair\n");
        return -1;
    }

    unsigned char *public_key = NULL;
    size_t key_len = 0;

    if (crypto_export_public_key(&agent->crypto_ctx, &public_key, &key_len) != 0)
    {
        fprintf(stderr, "Failed to export public key\n");
        return -1;
    }

    message_t key_msg;
    if (protocol_create_key_exchange(public_key, key_len, &key_msg) != 0)
    {
        free(public_key);
        fprintf(stderr, "Failed to create key exchange message\n");
        return -1;
    }

    char buffer[MAX_BUFFER_SIZE];
    int serialized_size = protocol_serialize_message(&key_msg, buffer, MAX_BUFFER_SIZE);

    if (serialized_size < 0)
    {
        free(public_key);
        fprintf(stderr, "Failed to serialize key exchange message\n");
        return -1;
    }

    if (send(agent->socket_fd, buffer, serialized_size, 0) < 0)
    {
        perror("Failed to send key exchange message");
        free(public_key);
        return -1;
    }

    free(public_key);
    agent->state = AGENT_STATE_AUTHENTICATING;
    printf("Key exchange message sent to orchestrator\n");

    return 0;
}

int handle_key_exchange(agent_t *agent, const message_t *message)
{
    if (!agent || !message || message->type != MSG_TYPE_KEY_EXCHANGE)
        return -1;

    printf("Received key exchange from orchestrator\n");

    unsigned char *peer_public_key = NULL;
    size_t key_len = 0;

    if (protocol_extract_public_key(message, &peer_public_key, &key_len) != 0)
    {
        fprintf(stderr, "Failed to extract public key\n");
        return -1;
    }

    if (crypto_import_public_key(&agent->crypto_ctx, peer_public_key, key_len) != 0)
    {
        free(peer_public_key);
        fprintf(stderr, "Failed to import public key\n");
        return -1;
    }

    free(peer_public_key);

    if (agent->state == AGENT_STATE_CONNECTED)
    {
        if (handle_key_exchange_init(agent) != 0)
        {
            fprintf(stderr, "Failed to initialize key exchange\n");
            return -1;
        }
    }

    return 0;
}

int handle_session_key(agent_t *agent, const message_t *message)
{
    if (!agent || !message || message->type != MSG_TYPE_SESSION_KEY)
        return -1;

    printf("Received session key from orchestrator\n");

    unsigned char *encrypted_key = NULL;
    size_t key_len = 0;

    if (protocol_extract_session_key(message, &encrypted_key, &key_len) != 0)
    {
        fprintf(stderr, "Failed to extract session key\n");
        return -1;
    }

    if (crypto_decrypt_session_key(&agent->crypto_ctx, encrypted_key, key_len) != 0)
    {
        free(encrypted_key);
        fprintf(stderr, "Failed to decrypt session key\n");
        return -1;
    }

    free(encrypted_key);
    printf("Session key successfully established\n");

    return 0;
}

int handle_auth_request(agent_t *agent, const message_t *message)
{
    if (!agent || !message || message->type != MSG_TYPE_AUTH_REQUEST)
        return -1;

    printf("Received authentication request\n");

    message_t auth_response;

    char auth_data[256];
    snprintf(auth_data, sizeof(auth_data), "%.220s:SECRET_TOKEN_123", agent->hostname);

    if (protocol_create_auth_response(auth_data, &auth_response) != 0)
    {
        fprintf(stderr, "Failed to create auth response\n");
        return -1;
    }

    char *secure_buffer = NULL;
    size_t secure_buffer_size = 0;

    if (protocol_secure_serialize_message(&agent->crypto_ctx, &auth_response, &secure_buffer, &secure_buffer_size) != 0)
    {
        fprintf(stderr, "Failed to securely serialize auth response\n");
        return -1;
    }

    if (send(agent->socket_fd, secure_buffer, secure_buffer_size, 0) < 0)
    {
        perror("Failed to send secure auth response");
        free(secure_buffer);
        return -1;
    }

    free(secure_buffer);
    agent->state = AGENT_STATE_AUTHENTICATED;
    printf("Authentication response sent\n");

    return 0;
}

int handle_capabilities_request(agent_t *agent, const message_t *message)
{
    if (!agent || !message || message->type != MSG_TYPE_CAPABILITIES)
        return -1;

    printf("Received capabilities request\n");

    message_t cap_response;
    if (protocol_create_capabilities_response(agent->capabilities, &cap_response) != 0)
    {
        fprintf(stderr, "Failed to create capabilities response\n");
        return -1;
    }

    char *secure_buffer = NULL;
    size_t secure_buffer_size = 0;

    if (protocol_secure_serialize_message(&agent->crypto_ctx, &cap_response, &secure_buffer, &secure_buffer_size) != 0)
    {
        fprintf(stderr, "Failed to securely serialize capabilities response\n");
        return -1;
    }

    if (send(agent->socket_fd, secure_buffer, secure_buffer_size, 0) < 0)
    {
        perror("Failed to send secure capabilities response");
        free(secure_buffer);
        return -1;
    }

    free(secure_buffer);
    printf("Capabilities response sent (0x%08X)\n", agent->capabilities);

    return 0;
}

int handle_scan_request(agent_t *agent, const message_t *message)
{
    if (!agent || !message || message->type != MSG_TYPE_SCAN_REQUEST)
        return -1;

    if (agent->state == AGENT_STATE_SCANNING)
    {
        fprintf(stderr, "Already running a scan\n");
        send_error(agent, ERR_SCAN_FAILED, "Already running a scan");
        return -1;
    }

    uint32_t scan_id, scan_type, num_targets;
    char *targets[MAX_TARGETS];
    char options[MAX_OPTIONS_LENGTH];

    if (protocol_parse_scan_request(message, &scan_id, &scan_type, targets, MAX_TARGETS,
                                    &num_targets, options, sizeof(options)) != 0)
    {
        fprintf(stderr, "Failed to parse scan request\n");
        send_error(agent, ERR_INVALID_MESSAGE, "Invalid scan request format");
        return -1;
    }

    printf("Received scan request (ID: %u, Type: %u, Targets: %u)\n",
           scan_id, scan_type, num_targets);

    uint32_t required_capability = 0;

    switch (scan_type)
    {
    case SCAN_TYPE_NMAP:
        required_capability = CAPABILITY_NMAP;
        break;
    case SCAN_TYPE_ZAP:
        required_capability = CAPABILITY_ZAP;
        break;
    case SCAN_TYPE_NIKTO:
        required_capability = CAPABILITY_NIKTO;
        break;
    default:
        fprintf(stderr, "Unsupported scan type: %u\n", scan_type);
        for (uint32_t i = 0; i < num_targets; i++)
        {
            free(targets[i]);
        }
        send_error(agent, ERR_UNSUPPORTED_SCAN, "Unsupported scan type");
        return -1;
    }

    if (!(agent->capabilities & required_capability))
    {
        fprintf(stderr, "Agent doesn't support required capability: 0x%08X\n", required_capability);
        for (uint32_t i = 0; i < num_targets; i++)
        {
            free(targets[i]);
        }
        send_error(agent, ERR_UNSUPPORTED_SCAN, "Agent doesn't support this scan type");
        return -1;
    }

    agent->state = AGENT_STATE_SCANNING;
    agent->current_scan_id = scan_id;
    agent->scanner_output_size = 0;

    int scan_result = 0;

    for (uint32_t i = 0; i < num_targets; i++)
    {
        send_scan_status(agent, scan_id, (i * 100) / num_targets);

        printf("Scanning target %u/%u: %s\n", i + 1, num_targets, targets[i]);

        switch (scan_type)
        {
        case SCAN_TYPE_NMAP:
            scan_result = execute_nmap_scan(agent, targets[i], options);
            break;
        case SCAN_TYPE_ZAP:
            scan_result = execute_zap_scan(agent, targets[i], options);
            break;
        case SCAN_TYPE_NIKTO:
            scan_result = execute_nikto_scan(agent, targets[i], options);
            break;
        }

        if (scan_result != 0)
        {
            fprintf(stderr, "Scan failed for target: %s\n", targets[i]);
        }

        free(targets[i]);
    }

    send_scan_status(agent, scan_id, 100);

    send_scan_result(agent, scan_id, agent->scanner_output, agent->scanner_output_size);

    agent->state = AGENT_STATE_AUTHENTICATED;
    printf("Scan completed for all targets\n");

    return 0;
}

int handle_scan_cancel(agent_t *agent, const message_t *message)
{
    if (!agent || !message || message->type != MSG_TYPE_SCAN_CANCEL)
        return -1;

    if (agent->state != AGENT_STATE_SCANNING)
    {
        fprintf(stderr, "Not currently scanning\n");
        return -1;
    }

    uint32_t scan_id;
    memcpy(&scan_id, message->data, sizeof(uint32_t));
    scan_id = ntohl(scan_id);

    if (scan_id != agent->current_scan_id)
    {
        fprintf(stderr, "Cancel request for unknown scan ID: %u\n", scan_id);
        return -1;
    }

    printf("Cancelling scan %u\n", scan_id);

    send_scan_status(agent, scan_id, 0);
    agent->state = AGENT_STATE_AUTHENTICATED;

    return 0;
}

static int process_message(agent_t *agent, const message_t *message)
{
    if (!agent || !message)
        return -1;

    printf("Processing message of type 0x%02X\n", message->type);

    switch (message->type)
    {
    case MSG_TYPE_KEY_EXCHANGE:
        return handle_key_exchange(agent, message);

    case MSG_TYPE_SESSION_KEY:
        return handle_session_key(agent, message);

    case MSG_TYPE_AUTH_REQUEST:
        return handle_auth_request(agent, message);

    case MSG_TYPE_CAPABILITIES:
        return handle_capabilities_request(agent, message);

    case MSG_TYPE_SCAN_REQUEST:
        return handle_scan_request(agent, message);

    case MSG_TYPE_SCAN_CANCEL:
        return handle_scan_cancel(agent, message);

    case MSG_TYPE_ERROR:
        printf("Error from orchestrator: %.*s\n", (int)(message->length - sizeof(error_message_t)),
               message->data + sizeof(error_message_t));
        return 0;

    default:
        fprintf(stderr, "Unknown message type: 0x%02X\n", message->type);
        return -1;
    }
}

int send_scan_status(agent_t *agent, uint32_t scan_id, uint32_t progress)
{
    if (!agent)
        return -1;

    message_t status_msg;
    if (protocol_create_scan_status(scan_id, progress, &status_msg) != 0)
    {
        fprintf(stderr, "Failed to create scan status message\n");
        return -1;
    }

    char *secure_buffer = NULL;
    size_t secure_buffer_size = 0;

    if (protocol_secure_serialize_message(&agent->crypto_ctx, &status_msg,
                                          &secure_buffer, &secure_buffer_size) != 0)
    {
        fprintf(stderr, "Failed to securely serialize scan status\n");
        return -1;
    }

    if (send(agent->socket_fd, secure_buffer, secure_buffer_size, 0) < 0)
    {
        perror("Failed to send scan status");
        free(secure_buffer);
        return -1;
    }

    free(secure_buffer);
    printf("Scan status update sent: %u%%\n", progress);

    return 0;
}

int send_scan_result(agent_t *agent, uint32_t scan_id, const char *result, size_t result_size)
{
    if (!agent)
        return -1;

    message_t result_msg;
    if (protocol_create_scan_result(scan_id, result, result_size, &result_msg) != 0)
    {
        fprintf(stderr, "Failed to create scan result message\n");
        return -1;
    }

    char *secure_buffer = NULL;
    size_t secure_buffer_size = 0;

    if (protocol_secure_serialize_message(&agent->crypto_ctx, &result_msg,
                                          &secure_buffer, &secure_buffer_size) != 0)
    {
        fprintf(stderr, "Failed to securely serialize scan result\n");
        return -1;
    }

    if (send(agent->socket_fd, secure_buffer, secure_buffer_size, 0) < 0)
    {
        perror("Failed to send scan result");
        free(secure_buffer);
        return -1;
    }

    free(secure_buffer);
    printf("Scan result sent (%zu bytes)\n", result_size);

    return 0;
}

int send_error(agent_t *agent, uint32_t error_code, const char *error_msg)
{
    if (!agent || !error_msg)
        return -1;

    message_t error_msg_struct;
    if (protocol_create_error(error_code, error_msg, &error_msg_struct) != 0)
    {
        fprintf(stderr, "Failed to create error message\n");
        return -1;
    }

    char *secure_buffer = NULL;
    size_t secure_buffer_size = 0;

    if (protocol_secure_serialize_message(&agent->crypto_ctx, &error_msg_struct,
                                          &secure_buffer, &secure_buffer_size) != 0)
    {
        fprintf(stderr, "Failed to securely serialize error message\n");
        return -1;
    }

    if (send(agent->socket_fd, secure_buffer, secure_buffer_size, 0) < 0)
    {
        perror("Failed to send error message");
        free(secure_buffer);
        return -1;
    }

    free(secure_buffer);
    printf("Error message sent: %s\n", error_msg);

    return 0;
}

int agent_run(agent_t *agent)
{
    if (!agent || agent->socket_fd < 0)
        return -1;

    fd_set read_fds;
    struct timeval tv;

    printf("Starting agent main loop...\n");

    if (agent->state == AGENT_STATE_CONNECTED)
    {
        if (handle_key_exchange_init(agent) != 0)
        {
            fprintf(stderr, "Failed to initiate key exchange\n");
            return -1;
        }
    }

    while (agent->running)
    {
        FD_ZERO(&read_fds);
        FD_SET(agent->socket_fd, &read_fds);

        tv.tv_sec = 1;
        tv.tv_usec = 0;

        int activity = select(agent->socket_fd + 1, &read_fds, NULL, NULL, &tv);

        if (activity < 0 && errno != EINTR)
        {
            perror("Select error");
            break;
        }

        if (activity > 0 && FD_ISSET(agent->socket_fd, &read_fds))
        {
            char buffer[MAX_BUFFER_SIZE];
            int bytes_read = recv(agent->socket_fd, buffer, sizeof(buffer), 0);

            if (bytes_read <= 0)
            {
                if (bytes_read == 0)
                {
                    printf("Connection closed by server\n");
                }
                else
                {
                    perror("Receive error");
                }
                break;
            }

            printf("Received %d bytes from orchestrator\n", bytes_read);

            if (agent->crypto_ctx.has_session_key)
            {
                message_t decrypted_msg;
                if (protocol_secure_deserialize_message(&agent->crypto_ctx, buffer, bytes_read, &decrypted_msg) == 0)
                {
                    process_message(agent, &decrypted_msg);
                    continue;
                }
            }

            message_t message;
            if (protocol_deserialize_message(buffer, bytes_read, &message) == 0)
            {
                process_message(agent, &message);
            }
            else
            {
                fprintf(stderr, "Failed to parse message\n");
            }
        }
    }

    printf("Agent main loop terminated\n");
    return 0;
}

int execute_nmap_scan(agent_t *agent, const char *target, const char *options)
{
    if (!agent || !target)
        return -1;

    printf("Executing Nmap scan on target: %s\n", target);

    char command[4096];

    snprintf(command, sizeof(command), "nmap -oX - %s %s",
             options && options[0] ? options : "-sV", target);

    printf("Executing command: %s\n", command);

    FILE *fp = popen(command, "r");
    if (fp == NULL)
    {
        perror("Failed to execute nmap");
        return -1;
    }

    size_t remaining = MAX_SCANNER_OUTPUT - agent->scanner_output_size;
    size_t bytes_read = fread(agent->scanner_output + agent->scanner_output_size,
                              1, remaining, fp);

    if (bytes_read < remaining)
    {
        agent->scanner_output_size += bytes_read;
        agent->scanner_output[agent->scanner_output_size] = '\0';
    }
    else
    {
        fprintf(stderr, "Output buffer full or read error\n");
    }

    int status = pclose(fp);

    if (status != 0)
    {
        fprintf(stderr, "Nmap exited with status: %d\n", status);
        return -1;
    }

    printf("Nmap scan completed successfully\n");
    return 0;
}

int execute_zap_scan(agent_t *agent, const char *target, const char *options)
{
    if (!agent || !target)
        return -1;

    printf("Executing ZAP scan on target: %s\n", target);

    char command[4096];

    snprintf(command, sizeof(command),
             "zap-cli --api-key 12345 quick-scan --self-contained --spider -r %s %s",
             target, options && options[0] ? options : "");

    printf("Executing command: %s\n", command);

    FILE *fp = popen(command, "r");
    if (fp == NULL)
    {
        perror("Failed to execute ZAP");
        return -1;
    }

    size_t remaining = MAX_SCANNER_OUTPUT - agent->scanner_output_size;
    size_t bytes_read = fread(agent->scanner_output + agent->scanner_output_size,
                              1, remaining, fp);

    if (bytes_read < remaining)
    {
        agent->scanner_output_size += bytes_read;
        agent->scanner_output[agent->scanner_output_size] = '\0';
    }
    else
    {
        fprintf(stderr, "Output buffer full or read error\n");
    }

    int status = pclose(fp);

    if (status != 0)
    {
        fprintf(stderr, "ZAP exited with status: %d\n", status);

        snprintf(agent->scanner_output, MAX_SCANNER_OUTPUT,
                 "<report>\n"
                 "  <site name=\"%s\">\n"
                 "    <alertitem>\n"
                 "      <name>ZAP Execution Error</name>\n"
                 "      <desc>Failed to execute ZAP scanner: exit status %d</desc>\n"
                 "      <riskcode>3</riskcode>\n"
                 "      <pluginid>0</pluginid>\n"
                 "    </alertitem>\n"
                 "  </site>\n"
                 "</report>",
                 target, status);
        agent->scanner_output_size = strlen(agent->scanner_output);
        return -1;
    }

    printf("ZAP scan completed successfully\n");
    return 0;
}

int execute_nikto_scan(agent_t *agent, const char *target, const char *options)
{
    if (!agent || !target)
        return -1;

    printf("Executing Nikto scan on target: %s\n", target);

    char command[4096];

    snprintf(command, sizeof(command), "nikto -h %s %s",
             target, options && options[0] ? options : "-Tuning 123x");

    printf("Executing command: %s\n", command);

    FILE *fp = popen(command, "r");
    if (fp == NULL)
    {
        perror("Failed to execute nikto");
        return -1;
    }

    size_t remaining = MAX_SCANNER_OUTPUT - agent->scanner_output_size;
    size_t bytes_read = fread(agent->scanner_output + agent->scanner_output_size,
                              1, remaining, fp);

    if (bytes_read < remaining)
    {
        agent->scanner_output_size += bytes_read;
        agent->scanner_output[agent->scanner_output_size] = '\0';
    }
    else
    {
        fprintf(stderr, "Output buffer full or read error\n");
    }

    int status = pclose(fp);

    if (status != 0)
    {
        fprintf(stderr, "Nikto exited with status: %d\n", status);
        return -1;
    }

    printf("Nikto scan completed successfully\n");
    return 0;
}