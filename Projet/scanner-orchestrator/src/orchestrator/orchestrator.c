#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "orchestrator.h"
#include "communication.h"
#include "scanner_manager.h"
#include "results_aggregator.h"
#include "config.h"
#include "../common/messages.h"

#define BUFFER_SIZE 4096

static Config config;
static int running = 0;

int orchestrator_init()
{
    printf("Initializing orchestrator...\n");

    config = load_config();

    init_scanner_manager();
    init_communication(config.communication.address, config.communication.port);
    init_results_aggregator();

    running = 1;
    return 0;
}

void orchestrator_run()
{
    if (!running)
    {
        fprintf(stderr, "Orchestrator not initialized\n");
        return;
    }

    accept_connections();

    static int command_sent = 0;
    int agent_count = get_connected_client_count();
    
    if (agent_count > 0 && !command_sent)
    {
        printf("Sending scan command to agent...\n");
        if (send_command(0, "SCAN nmap localhost -p80") == 0) {
            printf("Command sent successfully\n");
            command_sent = 1;
        } else {
            printf("Failed to send command\n");
        }
    }

    if (agent_count > 0)
    {
        char buffer[BUFFER_SIZE];
        int max_clients_value = get_max_clients();

        for (int i = 0; i < max_clients_value; i++)
        {
            if (is_agent_connected(i))
            {
                memset(buffer, 0, BUFFER_SIZE);
                
                int result = receive_results(i, buffer);
                if (result > 0)
                {
                    Message *msg = (Message *)buffer;
                    if (msg->type == MSG_TYPE_RESULT)
                    {
                        printf("\n========== SCAN RESULTS ==========\n");
                        printf("Received results from agent %d:\n%s\n", i, msg->content);
                        printf("==================================\n\n");
                        
                        aggregate_results("nmap", msg->content);
                        
                        get_aggregated_summary();
                    }
                }
            }
        }
    }
    
    usleep(100000);
}

void orchestrator_cleanup()
{
    printf("Cleaning up orchestrator...\n");
    running = 0;

    close_communication();
    free_results_aggregator();
    cleanup_scanner_manager();
}

int get_agent_count()
{
    return get_connected_client_count();
}