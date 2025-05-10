#ifndef PROTOCOL_H
#define PROTOCOL_H

#include <stdint.h>
#include "messages.h"

#define MAX_MESSAGE_SIZE 1024

typedef enum {
    CMD_START_SCAN,
    CMD_STOP_SCAN,
    CMD_GET_RESULTS,
    CMD_CONFIGURE_SCANNER,
    CMD_UNKNOWN
} CommandType;

typedef struct {
    CommandType command;
    char target[MAX_MESSAGE_SIZE];
    char options[MAX_MESSAGE_SIZE];
} CommandMessage;

typedef struct {
    uint32_t status;
    char results[MAX_MESSAGE_SIZE];
} ResultMessage;

size_t serialize_message(const Message *msg, char *buffer, size_t buffer_size);
int deserialize_message(const char *buffer, size_t buffer_size, Message *msg);

#endif // PROTOCOL_H