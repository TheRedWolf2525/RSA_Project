#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <errno.h>
#include <netinet/in.h>
#include <fcntl.h>
#include "communication.h"
#include "../common/crypto.h"
#include "../common/messages.h"
#include "../common/protocol.h"

#define BUFFER_SIZE 4096
#define KEY_SIZE 32

static int server_fd = -1;
static int *client_sockets = NULL;
static int max_clients = 10;
static int client_count = 0;
static unsigned char encryption_key[KEY_SIZE];

int init_communication(const char *address, int port) {
    struct sockaddr_in server_addr;
    int opt = 1;

    memset(encryption_key, 0x42, KEY_SIZE);
    
    client_sockets = malloc(max_clients * sizeof(int));
    if (!client_sockets) {
        perror("Failed to allocate client sockets array");
        return -1;
    }
    
    for (int i = 0; i < max_clients; i++) {
        client_sockets[i] = -1;
    }
    
    server_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (server_fd < 0) {
        perror("Socket creation failed");
        free(client_sockets);
        return -1;
    }
    
    if (setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt))) {
        perror("Setsockopt failed");
        close(server_fd);
        free(client_sockets);
        return -1;
    }
    
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(port);
    
    if (inet_pton(AF_INET, address, &server_addr.sin_addr) <= 0) {
        perror("Invalid address");
        close(server_fd);
        free(client_sockets);
        return -1;
    }

    if (bind(server_fd, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
        perror("Bind failed");
        close(server_fd);
        free(client_sockets);
        return -1;
    }
    
    if (listen(server_fd, 3) < 0) {
        perror("Listen failed");
        close(server_fd);
        free(client_sockets);
        return -1;
    }

    int flags = fcntl(server_fd, F_GETFL, 0);
    if (flags == -1) {
        perror("fcntl(F_GETFL) failed");
        close(server_fd);
        free(client_sockets);
        return -1;
    }
    if (fcntl(server_fd, F_SETFL, flags | O_NONBLOCK) == -1) {
        perror("fcntl(F_SETFL, O_NONBLOCK) failed");
        close(server_fd);
        free(client_sockets);
        return -1;
    }
    
    printf("Orchestrator listening on %s:%d\n", address, port);
    return 0;
}

void accept_connections() {
    struct sockaddr_in client_addr;
    socklen_t addrlen = sizeof(client_addr);
    int new_socket;
    
    new_socket = accept(server_fd, (struct sockaddr *)&client_addr, &addrlen);
    if (new_socket >= 0) {
        for (int i = 0; i < max_clients; i++) {
            if (client_sockets[i] < 0) {
                client_sockets[i] = new_socket;
                client_count++;
                
                char ip[INET_ADDRSTRLEN];
                inet_ntop(AF_INET, &client_addr.sin_addr, ip, INET_ADDRSTRLEN);
                printf("New agent connected: %s\n", ip);
                int client_flags = fcntl(new_socket, F_GETFL, 0);
                if (client_flags != -1) {
                    fcntl(new_socket, F_SETFL, client_flags | O_NONBLOCK);
                }
                break;
            }
        }
        if (new_socket >= 0 && client_sockets[max_clients-1] != new_socket && client_count >= max_clients) {
             printf("Max clients reached, connection from %s rejected.\n", inet_ntoa(client_addr.sin_addr));
             close(new_socket);
        }
    } else {
        if (errno == EAGAIN || errno == EWOULDBLOCK) {
            return;
        } else {
            perror("accept failed");
        }
    }
}

int start_communication() {
    printf("Communication started, waiting for agent connections...\n");
    return 0;
}

int send_command(int agent_id, const char *command) {
    if (agent_id < 0 || agent_id >= max_clients || client_sockets[agent_id] < 0) {
        fprintf(stderr, "Invalid agent ID\n");
        return -1;
    }
    
    char buffer[BUFFER_SIZE];
    char encrypted_buffer[BUFFER_SIZE];
    Message msg;
    
    memset(&msg, 0, sizeof(Message));
    
    msg.type = MSG_TYPE_COMMAND;
    msg.length = strlen(command);
    if (msg.length >= MAX_MESSAGE_LENGTH) {
        msg.length = MAX_MESSAGE_LENGTH - 1;
    }
    strncpy(msg.content, command, msg.length);
    msg.content[msg.length] = '\0';
    
    printf("Sending command: '%s' (length: %u)\n", msg.content, msg.length);
    
    size_t msg_size = serialize_message(&msg, buffer, BUFFER_SIZE);
    if (msg_size == 0) {
        fprintf(stderr, "Failed to serialize message\n");
        return -1;
    }
    
    int encrypted_size = encrypt_data((const unsigned char*)buffer, (unsigned char*)encrypted_buffer, msg_size, encryption_key);
    if (encrypted_size <= 0) {
        fprintf(stderr, "Failed to encrypt message\n");
        return -1;
    }
    
    if (send(client_sockets[agent_id], encrypted_buffer, encrypted_size, 0) < 0) {
        perror("Failed to send command");
        return -1;
    }
    
    return 0;
}

int receive_results(int agent_id, char* buffer) {
    if (agent_id < 0 || agent_id >= max_clients || client_sockets[agent_id] < 0) {
        fprintf(stderr, "Invalid agent ID\n");
        return -1;
    }
    
    char encrypted_buffer[BUFFER_SIZE];
    char decrypted_buffer[BUFFER_SIZE];
    ssize_t bytes_received;
    Message msg;
    
    bytes_received = recv(client_sockets[agent_id], encrypted_buffer, BUFFER_SIZE, MSG_DONTWAIT);
    if (bytes_received <= 0) {
        if (bytes_received < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
            return 0;
        }
        
        if (bytes_received == 0) {
            printf("Connection closed by agent %d\n", agent_id);
            client_sockets[agent_id] = -1;
        } else {
            perror("Failed to receive message");
        }
        return -1;
    }
    
    printf("Received %zd bytes from agent %d\n", bytes_received, agent_id);
    
    int decrypted_size = decrypt_data((const unsigned char*)encrypted_buffer, (unsigned char*)decrypted_buffer, bytes_received, encryption_key);
    if (decrypted_size <= 0) {
        fprintf(stderr, "Failed to decrypt message\n");
        return -1;
    }
    
    printf("Decrypted %d bytes from agent %d\n", decrypted_size, agent_id);
    
    if (!deserialize_message(decrypted_buffer, decrypted_size, &msg)) {
        fprintf(stderr, "Failed to deserialize message\n");
        return -1;
    }
    
    printf("Deserialized message of type %d with content length %d\n", msg.type, msg.length);
    
    memcpy(buffer, &msg, sizeof(Message));
    
    return sizeof(Message);
}

void close_communication() {
    for (int i = 0; i < max_clients; i++) {
        if (client_sockets[i] >= 0) {
            close(client_sockets[i]);
            client_sockets[i] = -1;
        }
    }
    
    if (server_fd >= 0) {
        close(server_fd);
        server_fd = -1;
    }
    
    free(client_sockets);
    client_sockets = NULL;
    client_count = 0;
    
    printf("Communication closed\n");
}

int get_connected_client_count() {
    return client_count;
}

int is_agent_connected(int agent_id) {
    if (agent_id < 0 || agent_id >= max_clients) {
        return 0;
    }
    return client_sockets[agent_id] >= 0;
}

int get_max_clients() {
    return max_clients;
}