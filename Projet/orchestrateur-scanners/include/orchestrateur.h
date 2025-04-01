#ifndef ORCHESTRATEUR_H
#define ORCHESTRATEUR_H

#include <stdint.h>
#include <netinet/in.h>

#define MAX_AGENTS 10
#define MAX_BUFFER_SIZE 4096
#define DEFAULT_PORT 8080
#define MAX_TARGETS 10
#define MAX_SCANS 20
#define MAX_TARGET_LENGTH 256
#define MAX_OPTIONS_LENGTH 1024

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

typedef enum {
    SCAN_TYPE_NMAP,
    SCAN_TYPE_ZAP,
    SCAN_TYPE_NIKTO
} scan_type_t;

typedef enum {
    SCAN_STATUS_PENDING,
    SCAN_STATUS_RUNNING,
    SCAN_STATUS_COMPLETED,
    SCAN_STATUS_FAILED,
    SCAN_STATUS_CANCELED
} scan_status_t;

typedef struct {
    char target[MAX_TARGET_LENGTH];
} scan_target_t;

typedef struct {
    uint32_t id;
    scan_type_t type;
    int agent_idx;
    scan_status_t status;
    uint32_t progress;
    char options[MAX_OPTIONS_LENGTH];
    scan_target_t targets[MAX_TARGETS];
    int num_targets;
    char *results;
    size_t results_size;
    time_t start_time;
    time_t end_time;
} scan_t;

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
    scan_t scans[MAX_SCANS];
    int nb_scans;
    uint32_t next_scan_id; 
} orchestrateur_t;

int orchestrateur_init(orchestrateur_t *orch, uint16_t port);

void orchestrateur_cleanup(orchestrateur_t *orch);

int orchestrateur_run(orchestrateur_t *orch);

void orchestrateur_stop(orchestrateur_t *orch);

int orchestrateur_create_scan(orchestrateur_t *orch, scan_type_t type, const char *options);
int orchestrateur_add_target(orchestrateur_t *orch, uint32_t scan_id, const char *target);
int orchestrateur_start_scan(orchestrateur_t *orch, uint32_t scan_id);
int orchestrateur_cancel_scan(orchestrateur_t *orch, uint32_t scan_id);
scan_t *orchestrateur_get_scan(orchestrateur_t *orch, uint32_t scan_id);
int orchestrateur_list_scans(orchestrateur_t *orch, uint32_t *scan_ids, int max_ids);
const char *orchestrateur_get_scan_results(orchestrateur_t *orch, uint32_t scan_id);

#endif /* ORCHESTRATEUR_H */