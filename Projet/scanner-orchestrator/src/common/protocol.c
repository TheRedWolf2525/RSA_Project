#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "protocol.h"
#include "messages.h"

typedef struct {
    MessageType type;
    char payload[1024];
} ProtocolMessage;

ProtocolMessage create_command_message(const char *command) {
    ProtocolMessage msg;
    msg.type = MSG_TYPE_COMMAND;
    strncpy(msg.payload, command, sizeof(msg.payload) - 1);
    msg.payload[sizeof(msg.payload) - 1] = '\0';
    return msg;
}

ProtocolMessage create_result_message(const char *result) {
    ProtocolMessage msg;
    msg.type = MSG_TYPE_RESULT;
    strncpy(msg.payload, result, sizeof(msg.payload) - 1);
    msg.payload[sizeof(msg.payload) - 1] = '\0';
    return msg;
}

ProtocolMessage create_error_message(const char *error) {
    ProtocolMessage msg;
    msg.type = MSG_TYPE_ERROR;
    strncpy(msg.payload, error, sizeof(msg.payload) - 1);
    msg.payload[sizeof(msg.payload) - 1] = '\0';
    return msg;
}

int parse_protocol_message(const char *data, ProtocolMessage *msg) {
    if (data == NULL || msg == NULL) {
        return -1;
    }

    msg->type = (MessageType)data[0];

    strncpy(msg->payload, data + 1, sizeof(msg->payload) - 1);
    msg->payload[sizeof(msg->payload) - 1] = '\0';

    return 0;
}

size_t serialize_message(const Message *msg, char *buffer, size_t buffer_size) {
    if (!msg || !buffer || buffer_size < sizeof(MessageType) + sizeof(uint32_t) + msg->length) {
        return 0;
    }

    memset(buffer, 0, buffer_size);
    
    size_t offset = 0;
    
    memcpy(buffer + offset, &msg->type, sizeof(MessageType));
    offset += sizeof(MessageType);
    
    memcpy(buffer + offset, &msg->length, sizeof(uint32_t));
    offset += sizeof(uint32_t);
    
    memcpy(buffer + offset, msg->content, msg->length);
    offset += msg->length;
    
    return offset;
}

int deserialize_message(const char *buffer, size_t buffer_size, Message *msg) {
    if (!buffer || !msg || buffer_size < sizeof(MessageType) + sizeof(uint32_t)) {
        return 0;
    }
    
    memset(msg, 0, sizeof(Message));
    
    size_t offset = 0;
    
    memcpy(&msg->type, buffer + offset, sizeof(MessageType));
    offset += sizeof(MessageType);
    
    memcpy(&msg->length, buffer + offset, sizeof(uint32_t));
    offset += sizeof(uint32_t);
    
    if (buffer_size < offset + msg->length) {
        fprintf(stderr, "Buffer too small: %zu vs needed %zu\n", buffer_size, offset + msg->length);
        return 0;
    }
    
    if (msg->length >= MAX_MESSAGE_LENGTH) {
        msg->length = MAX_MESSAGE_LENGTH - 1;
    }
    
    memcpy(msg->content, buffer + offset, msg->length);
    msg->content[msg->length] = '\0';
    
    return 1;
}