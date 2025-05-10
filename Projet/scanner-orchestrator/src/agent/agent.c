#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "agent.h"
#include "communication.h"
#include "scanner_executor.h"
#include "../common/crypto.h"
#include "../common/protocol.h"
#include "../common/messages.h"

#define BUFFER_SIZE 1024
#define DEFAULT_ORCHESTRATOR_IP "127.0.0.1"
#define DEFAULT_ORCHESTRATOR_PORT 8080

void initialize_agent() {
    printf("Initializing agent...\n");
}

void send_results(const char* results) {
    Message msg;
    msg.type = MSG_TYPE_RESULT;
    msg.length = strlen(results);
    strncpy(msg.content, results, MAX_MESSAGE_LENGTH - 1);
    msg.content[MAX_MESSAGE_LENGTH - 1] = '\0';
    
    send_message(&msg);
}

void handle_command(const char *command) {
    if (strncmp(command, "SCAN", 4) == 0) {
        char target[256];
        char scanner_type[256];
        char options[256] = "";
        
        sscanf(command + 5, "%s %s %s", scanner_type, target, options);
        
        char result_buffer[BUFFER_SIZE] = {0};
        
        int status = execute_scanner(scanner_type, target, options);
        
        if (status == 0) {
            snprintf(result_buffer, BUFFER_SIZE, "Scan completed successfully for %s on target %s", 
                    scanner_type, target);
        } else {
            snprintf(result_buffer, BUFFER_SIZE, "Scan failed for %s on target %s with status %d", 
                    scanner_type, target, status);
        }
        
        send_results(result_buffer);
    } else {
        printf("Unknown command: %s\n", command);
    }
}

void start_command_listener() {
    char buffer[BUFFER_SIZE];
    Message msg;
    
    while (1) {
        if (receive_message(&msg) == 0) {
            if (msg.type == MSG_TYPE_COMMAND) {
                handle_command(msg.content);
            }
        } else {
            printf("Error receiving message\n");
            sleep(1);
        }
    }
}