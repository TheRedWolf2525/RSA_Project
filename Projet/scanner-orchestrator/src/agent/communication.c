#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include "communication.h"
#include "../common/crypto.h"
#include "../common/messages.h"
#include "../common/protocol.h"

#define BUFFER_SIZE 4096
#define KEY_SIZE 32

static int socket_fd = -1;
static unsigned char encryption_key[KEY_SIZE];


int initialize_communication(const char *ip, int port) {
    struct sockaddr_in server_addr;

    memset(encryption_key, 0x42, KEY_SIZE);
    
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
    
    printf("Serialized message of type %d with content length %u\n", 
           msg->type, msg->length);
    
    int encrypted_size = encrypt_data((const unsigned char*)buffer, 
                                      (unsigned char*)encrypted_buffer, 
                                      msg_size, 
                                      encryption_key);
    
    if (encrypted_size <= 0) {
        fprintf(stderr, "Failed to encrypt message\n");
        return -1;
    }
    
    printf("Encrypted message to %d bytes\n", encrypted_size);
    
    ssize_t sent = send(socket_fd, encrypted_buffer, encrypted_size, 0);
    if (sent < 0) {
        perror("Failed to send message");
        return -1;
    }
    
    printf("Sent %zd bytes to orchestrator\n", sent);
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
    
    printf("Received %zd bytes\n", bytes_received);
    
    int decrypted_size = decrypt_data((const unsigned char*)buffer, (unsigned char*)decrypted_buffer, bytes_received, encryption_key);
    if (decrypted_size <= 0) {
        fprintf(stderr, "Failed to decrypt message\n");
        return -1;
    }
    
    printf("Decrypted %d bytes\n", decrypted_size);
    
    if (!deserialize_message(decrypted_buffer, decrypted_size, msg)) {
        fprintf(stderr, "Failed to deserialize message\n");
        return -1;
    }
    
    printf("Deserialized message of type %d with content '%s' (length: %u)\n", 
           msg->type, msg->content, msg->length);
    
    return 0;
}

void close_communication() {
    if (socket_fd != -1) {
        close(socket_fd);
        socket_fd = -1;
    }
}