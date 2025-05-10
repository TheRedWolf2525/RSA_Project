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

    int agent_count = get_agent_count();
    if (agent_count > 0)
    {
        char buffer[1024];

        for (int i = 0; i < agent_count; i++)
        {
            if (is_agent_connected(i))
            {
                if (receive_results(i, buffer, sizeof(buffer)) == 0)
                {
                    Message *msg = (Message *)buffer;
                    if (msg->type == MSG_TYPE_RESULT)
                    {
                        aggregate_results(msg->content, "Scan results");
                    }
                }
            }
        }
    }

    usleep(100000);
    static int command_sent = 0;
    if (agent_count > 0 && !command_sent)
    {
        printf("Sending scan command to agent...\n");
        send_command(0, "SCAN nmap localhost -p 80-100");
        command_sent = 1;
    }
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