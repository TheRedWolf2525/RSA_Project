#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "protocol.h"

typedef enum {
    MSG_TYPE_COMMAND,
    MSG_TYPE_RESULT,
    MSG_TYPE_ERROR
} MessageType;

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