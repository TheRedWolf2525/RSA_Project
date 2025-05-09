#include "../../include/agent.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <getopt.h>

void print_usage(const char *prog_name) {
    printf("Usage: %s [OPTIONS]\n\n", prog_name);
    printf("Options:\n");
    printf("  -h, --host HOSTNAME        Hostname or IP of the orchestrator (default: 127.0.0.1)\n");
    printf("  -p, --port PORT            Port of the orchestrator (default: 8080)\n");
    printf("  -n, --hostname NAME        Name of this agent (default: hostname of the system)\n");
    printf("  --nmap                     Enable Nmap scanner capability\n");
    printf("  --zap                      Enable ZAP scanner capability\n");
    printf("  --nikto                    Enable Nikto scanner capability\n");
    printf("  --help                     Display this help message\n");
}

int main(int argc, char *argv[]) {
    char orchestrator_host[256] = "127.0.0.1";
    uint16_t orchestrator_port = DEFAULT_PORT;
    char hostname[256];
    uint32_t capabilities = 0;

    if (gethostname(hostname, sizeof(hostname)) != 0) {
        perror("Failed to get hostname");
        strcpy(hostname, "unknown-agent");
    }

    static struct option long_options[] = {
        {"host", required_argument, 0, 'h'},
        {"port", required_argument, 0, 'p'},
        {"hostname", required_argument, 0, 'n'},
        {"nmap", no_argument, 0, 1},
        {"zap", no_argument, 0, 2},
        {"nikto", no_argument, 0, 3},
        {"help", no_argument, 0, 4},
        {0, 0, 0, 0}
    };

    int opt, option_index = 0;
    while ((opt = getopt_long(argc, argv, "h:p:n", long_options, &option_index)) != -1) {
        switch (opt) {
            case 'h':
                strncpy(orchestrator_host, optarg, sizeof(orchestrator_host) - 1);
                break;
                
            case 'p':
                orchestrator_port = (uint16_t)atoi(optarg);
                break;
                
            case 'n':
                strncpy(hostname, optarg, sizeof(hostname) - 1);
                break;
                
            case 1: // --nmap
                capabilities |= CAPABILITY_NMAP;
                break;
                
            case 2: // --zap
                capabilities |= CAPABILITY_ZAP;
                break;
                
            case 3: // --nikto
                capabilities |= CAPABILITY_NIKTO;
                break;
                
            case 4: // --help
                print_usage(argv[0]);
                return EXIT_SUCCESS;
                
            default:
                print_usage(argv[0]);
                return EXIT_FAILURE;
        }
    }

    if (capabilities == 0) {
        printf("No capabilities specified, checking what's available...\n");

        if (system("which nmap >/dev/null 2>&1") == 0) {
            printf("Nmap found, enabling capability\n");
            capabilities |= CAPABILITY_NMAP;
        }
        
        if (system("which zap-cli >/dev/null 2>&1") == 0) {
            printf("ZAP CLI found, enabling capability\n");
            capabilities |= CAPABILITY_ZAP;
        }
        
        if (system("which nikto >/dev/null 2>&1") == 0) {
            printf("Nikto found, enabling capability\n");
            capabilities |= CAPABILITY_NIKTO;
        }
    }

    if (capabilities == 0) {
        fprintf(stderr, "No scanner capabilities avilable or specified!\n");
        print_usage(argv[0]);
        return EXIT_FAILURE;
    }

    printf("Starting agent with the following configuration:\n");
    printf("Orchestrator: %s:%d\n", orchestrator_host, orchestrator_port);
    printf("Agent hostname: %s\n", hostname);
    printf("Capabilities: 0x%08X\n", capabilities);
    printf(" - Nmap: %s\n", (capabilities & CAPABILITY_NMAP) ? "Yes" : "No");
    printf(" - OWASP ZAP: %s\n", (capabilities & CAPABILITY_ZAP) ? "Yes" : "No");
    printf(" - Nikto: %s\n", (capabilities & CAPABILITY_NIKTO) ? "Yes" : "No");

    agent_t agent;
    if (agent_init(&agent, hostname, capabilities) != 0) {
        fprintf(stderr, "Failed to initialize agent\n");
        return EXIT_FAILURE;
    }

    if (agent_connect(&agent, orchestrator_host, orchestrator_port) != 0) {
        fprintf(stderr, "Failed to connect to orchestrator\n");
        agent_cleanup(&agent);
        return EXIT_FAILURE;
    }

    if (agent_run(&agent) != 0) {
        fprintf(stderr, "Agent terminated with errors\n");
        agent_cleanup(&agent);
        return EXIT_FAILURE;
    }

    agent_cleanup(&agent);
    printf("Agent terminated successfully\n");

    return EXIT_SUCCESS;
}