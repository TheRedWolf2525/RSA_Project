#include <stdio.h>
#include <stdlib.h>
#include "orchestrator.h"
#include "config.h"
#include "communication.h"

int main() {
    printf("Starting orchestrator...\n");

    if (orchestrator_init() != 0) {
        fprintf(stderr, "Failed to initialize orchestrator.\n");
        return EXIT_FAILURE;
    }

    if (start_communication() != 0) {
        fprintf(stderr, "Failed to start communication with agents.\n");
        return EXIT_FAILURE;
    }

    printf("Orchestrator started successfully.\n");

    while (1) {
        orchestrator_run();
    }

    orchestrator_cleanup();
    
    return EXIT_SUCCESS;
}