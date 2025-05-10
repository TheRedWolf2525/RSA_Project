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
    
    memset(&msg, 0, sizeof(Message));
    
    msg.type = MSG_TYPE_RESULT;
    msg.length = strlen(results);
    if (msg.length >= MAX_MESSAGE_LENGTH) {
        printf("Warning: Results truncated from %u to %d bytes\n", 
               (unsigned int)msg.length, MAX_MESSAGE_LENGTH - 1);
        msg.length = MAX_MESSAGE_LENGTH - 1;
    }
    
    strncpy(msg.content, results, msg.length);
    msg.content[msg.length] = '\0';
    
    printf("Sending results to orchestrator (length: %u)\n", msg.length);
    
    if (send_message(&msg) == 0) {
        printf("Results sent successfully\n");
    } else {
        fprintf(stderr, "Failed to send results\n");
    }
}

void handle_command(const char *command) {
    printf("Received command: '%s'\n", command);
    fflush(stdout);
    
    if (strncmp(command, "SCAN", 4) == 0) {
        char scanner_type[256] = {0};
        char target[256] = {0};
        char options[256] = {0};
        
        int items = sscanf(command + 5, "%255s %255s %255s", scanner_type, target, options);
        
        if (items < 2) {
            printf("Invalid scan command format. Expected: SCAN <scanner_type> <target> [options]\n");
            fflush(stdout);
            send_results("Error: Invalid command format");
            return;
        }
        
        printf("Executing scanner: '%s' on target: '%s' with options: '%s'\n", 
               scanner_type, target, options);
        fflush(stdout);
        
        int status = execute_scanner(scanner_type, target, items >= 3 ? options : NULL);
        
        printf("Scanner execution completed with status: %d\n", status);
        fflush(stdout);
        
        if (status != 0) {
            char result_buffer[BUFFER_SIZE] = {0};
            snprintf(result_buffer, BUFFER_SIZE, "Scan failed for %s on target %s with status %d", 
                    scanner_type, target, status);
            send_results(result_buffer);
        }
        printf("Results handling completed\n");
        fflush(stdout);
    } else {
        printf("Unknown command: '%s'\n", command);
        fflush(stdout);
        send_results("Error: Unknown command");
    }
}

void start_command_listener() {
    Message msg;
    
    while (1) {
        memset(&msg, 0, sizeof(Message));

        printf("Waiting for command...\n");
        fflush(stdout);
        
        int result = receive_message(&msg);
        
        if (result == 0) {
            if (msg.type == MSG_TYPE_COMMAND) {
                handle_command(msg.content);
            } else {
                fprintf(stderr, "Agent: Received unexpected message type: %d\n", msg.type);
                fflush(stderr);
            }
        } else if (result < 0) {
            printf("Connection to orchestrator lost or error during receive.\n");
            fflush(stdout); 
            break;
        }
    }
}