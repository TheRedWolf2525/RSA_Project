#ifndef ORCHESTRATEUR_H
#define ORCHESTRATEUR_H

#include <stdint.h>
#include <netinet/in.h>

#define MAX_AGENTS 10
#define MAX_BUFFER_SIZE 4096
#define DEFAULT_PORT 8080

#define CAPABILITY_NMAP (1 << 0)
#define CAPABILITY_ZAP (1 << 1)
#define CAPABILITY_NIKTO (1 << 2)

typedef enum {
    AGENT_DISCONNECTED,
    AGENT_CONNECTED,
    AGENT_AUTHENTICATED,
    AGENT_SCANNING,
    AGENT_ERROR
} agent_status_t;

typedef struct {
    int socket_fd;
    struct sockaddr_in address;
    agent_status_t status;
    char hostname[256];
    uint32_t capabilities;
} agent_t;

typedef struct {
    int server_socket;
    int running;
    agent_t agents[MAX_AGENTS];
    int nb_agents;
    // Pour l'extension ultérieure : liste des scans en cours, résultats, etc. 
} orchestrateur_t;

int orchestrateur_init(orchestrateur_t *orch, uint16_t port);

void orchestrateur_cleanup(orchestrateur_t *orch);

int orchestrateur_run(orchestrateur_t *orch);

void orchestrateur_stop(orchestrateur_t *orch);

#endif /* ORCHESTRATEUR_H */