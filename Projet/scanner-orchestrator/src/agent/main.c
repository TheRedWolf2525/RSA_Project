#include <stdio.h>
#include <stdlib.h>
#include "agent.h"
#include "communication.h"

#define DEFAULT_ORCHESTRATOR_IP "127.0.0.1"
#define DEFAULT_ORCHESTRATOR_PORT 8080

int main() {
    initialize_agent();
    printf("Agent starting...\n");
    
    if (initialize_communication(DEFAULT_ORCHESTRATOR_IP, DEFAULT_ORCHESTRATOR_PORT) != 0) {
        fprintf(stderr, "Failed to connect to orchestrator\n");
        return EXIT_FAILURE;
    }
    
    printf("Connected to orchestrator\n");
    
    start_command_listener();
    
    close_communication();
    return EXIT_SUCCESS;
}