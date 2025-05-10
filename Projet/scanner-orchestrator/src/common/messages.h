#ifndef MESSAGES_H
#define MESSAGES_H

#include <stdint.h>

#define MAX_MESSAGE_LENGTH 1024

typedef enum {
    MSG_TYPE_COMMAND,
    MSG_TYPE_RESULT,
    MSG_TYPE_ERROR
} MessageType;

typedef struct {
    MessageType type;
    uint32_t length;
    char content[MAX_MESSAGE_LENGTH];
} Message;

#endif // MESSAGES_H