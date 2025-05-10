#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include "communication.h"
#include "../common/crypto.h"
#include "../common/messages.h"

#define BUFFER_SIZE 4096
#define KEY_SIZE 32

static int socket_fd = -1;
static unsigned char encryption_key[KEY_SIZE];

int serialize_message(const Message *msg, char *buffer, size_t buffer_size) {
    if (!msg || !buffer || buffer_size < sizeof(MessageType) + sizeof(uint32_t) + msg->length) {
        return 0;
    }

    memcpy(buffer, &msg->type, sizeof(MessageType));
    
    memcpy(buffer + sizeof(MessageType), &msg->length, sizeof(uint32_t));
    
    memcpy(buffer + sizeof(MessageType) + sizeof(uint32_t), msg->content, msg->length);
    
    return sizeof(MessageType) + sizeof(uint32_t) + msg->length;
}

int deserialize_message(const char *buffer, size_t buffer_size, Message *msg) {
    if (!buffer || !msg || buffer_size < sizeof(MessageType) + sizeof(uint32_t)) {
        return 0;
    }
    
    memcpy(&msg->type, buffer, sizeof(MessageType));
    
    memcpy(&msg->length, buffer + sizeof(MessageType), sizeof(uint32_t));
    
    if (buffer_size < sizeof(MessageType) + sizeof(uint32_t) + msg->length) {
        return 0;
    }
    
    memcpy(msg->content, buffer + sizeof(MessageType) + sizeof(uint32_t), msg->length);
    
    if (msg->length < MAX_MESSAGE_LENGTH) {
        msg->content[msg->length] = '\0';
    } else {
        msg->content[MAX_MESSAGE_LENGTH - 1] = '\0';
    }
    
    return 1;
}

int initialize_communication(const char *ip, int port) {
    struct sockaddr_in server_addr;

    generate_random_key(encryption_key, KEY_SIZE);
    
    socket_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (socket_fd < 0) {
        perror("Socket creation failed");
        return -1;
    }
    
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(port);
    
    if (inet_pton(AF_INET, ip, &server_addr.sin_addr) <= 0) {
        perror("Invalid address");
        close(socket_fd);
        return -1;
    }
    
    if (connect(socket_fd, (struct sockaddr*)&server_addr, sizeof(server_addr)) < 0) {
        perror("Connection failed");
        close(socket_fd);
        return -1;
    }
    
    printf("Connected to orchestrator at %s:%d\n", ip, port);
    return 0;
}

int send_message(const Message *msg) {
    char buffer[BUFFER_SIZE];
    char encrypted_buffer[BUFFER_SIZE];
    size_t msg_size;
    
    msg_size = serialize_message(msg, buffer, BUFFER_SIZE);
    if (msg_size == 0) {
        fprintf(stderr, "Failed to serialize message\n");
        return -1;
    }
    
    encrypt_data((const unsigned char*)buffer, (unsigned char*)encrypted_buffer, msg_size, encryption_key);
    
    if (send(socket_fd, encrypted_buffer, msg_size, 0) < 0) {
        perror("Failed to send message");
        return -1;
    }
    
    return 0;
}

int receive_message(Message *msg) {
    char buffer[BUFFER_SIZE];
    char decrypted_buffer[BUFFER_SIZE];
    ssize_t bytes_received;
    
    bytes_received = recv(socket_fd, buffer, BUFFER_SIZE, 0);
    if (bytes_received <= 0) {
        if (bytes_received == 0) {
            printf("Connection closed by the orchestrator\n");
        } else {
            perror("Failed to receive message");
        }
        return -1;
    }
    
    decrypt_data((const unsigned char*)buffer, (unsigned char*)decrypted_buffer, bytes_received, encryption_key);
    
    if (!deserialize_message(decrypted_buffer, bytes_received, msg)) {
        fprintf(stderr, "Failed to deserialize message\n");
        return -1;
    }
    
    return 0;
}

void close_communication() {
    if (socket_fd != -1) {
        close(socket_fd);
        socket_fd = -1;
    }
}