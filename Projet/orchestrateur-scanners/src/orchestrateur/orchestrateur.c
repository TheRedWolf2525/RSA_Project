#include "../../include/orchestrateur.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <signal.h>
#include <sys/socket.h>
#include <sys/select.h>
#include <arpa/inet.h>
#include <fcntl.h>
#include <time.h>

static orchestrateur_t *g_orchestrateur = NULL;

#define MSG_TYPE_AUTH_REQUEST 0x01
#define MSG_TYPE_AUTH_RESPONSE 0x02
#define MSG_TYPE_CAPABILITIES 0x03
#define MSG_TYPE_SCAN_REQUEST 0x04
#define MSG_TYPE_SCAN_STATUS 0x05
#define MSG_TYPE_SCAN_RESULT 0x06
#define MSG_TYPE_SCAN_CANCEL 0x07
#define MSG_TYPE_ERROR 0xFF

typedef struct {
    uint8_t type;
    uint16_t length;
    char data[MAX_BUFFER_SIZE - 3];
} message_t;

static void signal_handler(int signum);
static int accept_new_connection(orchestrateur_t *orch);
static void request_agent_authentication(orchestrateur_t *orch, int agent_idx);
static void process_authentication_response(orchestrateur_t *orch, int agent_idx, const char *data, uint16_t length);
static void request_agent_capabilities(orchestrateur_t *orch, int agent_idx);
static void process_capabilities_response(orchestrateur_t *orch, int agent_idx, const char *data, uint16_t length);
static void disconnect_agent(orchestrateur_t *orch, int agent_idx, const char *reason);
static int parse_message(const char *buffer, int bytes_read, message_t *message);
static void process_message(orchestrateur_t *orch, int agent_idx, const message_t *message);

static int send_scan_request(orchestrateur_t *orch, int agent_idx, const scan_t *scan);
static void process_scan_status(orchestrateur_t *orch, int agent_idx, const char *data, uint16_t length);
static void process_scan_result(orchestrateur_t *orch, int agent_idx, const char *data, uint16_t length);
static int find_available_agent(orchestrateur_t *orch, uint32_t capability);

static void signal_handler(int signum) {
    if (g_orchestrateur) {
        printf("\nSignal %d reçu. Arrêt de l'orchestrateur...\n", signum);
        orchestrateur_stop(g_orchestrateur);
    }
}

int orchestrateur_init(orchestrateur_t *orch, uint16_t port) {
    if (!orch) return -1;
    
    memset(orch, 0, sizeof(orchestrateur_t));
    
    orch->server_socket = socket(AF_INET, SOCK_STREAM, 0);
    if (orch->server_socket < 0) {
        perror("Erreur lors de la création du socket");
        return -1;
    }
    
    int opt = 1;
    if (setsockopt(orch->server_socket, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) < 0) {
        perror("Erreur setsockopt");
        close(orch->server_socket);
        return -1;
    }
    
    int flags = fcntl(orch->server_socket, F_GETFL, 0);
    fcntl(orch->server_socket, F_SETFL, flags | O_NONBLOCK);
    
    struct sockaddr_in server_addr;
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = INADDR_ANY;
    server_addr.sin_port = htons(port);
    
    if (bind(orch->server_socket, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
        perror("Erreur lors du bind");
        close(orch->server_socket);
        return -1;
    }
    
    if (listen(orch->server_socket, 5) < 0) {
        perror("Erreur lors du listen");
        close(orch->server_socket);
        return -1;
    }
    
    printf("Orchestrateur initialisé et en écoute sur le port %d\n", port);
    orch->running = 1;
    
    g_orchestrateur = orch;
    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);
    
    return 0;
}

void orchestrateur_cleanup(orchestrateur_t *orch) {
    if (!orch) return;
    
    if (orch->server_socket > 0) {
        close(orch->server_socket);
        orch->server_socket = -1;
    }
    
    for (int i = 0; i < MAX_AGENTS; i++) {
        if (orch->agents[i].socket_fd > 0) {
            close(orch->agents[i].socket_fd);
            orch->agents[i].socket_fd = -1;
            orch->agents[i].status = AGENT_DISCONNECTED;
        }
    }
    
    printf("Orchestrateur nettoyé\n");
}

void orchestrateur_stop(orchestrateur_t *orch) {
    if (!orch) return;
    orch->running = 0;
}

static int accept_new_connection(orchestrateur_t *orch) {
    struct sockaddr_in client_addr;
    socklen_t client_len = sizeof(client_addr);
    
    int client_socket = accept(orch->server_socket, (struct sockaddr *)&client_addr, &client_len);
    
    if (client_socket < 0) {
        if (errno != EAGAIN && errno != EWOULDBLOCK) {
            perror("Erreur lors de l'accept");
        }
        return -1;
    }
    
    int agent_idx = -1;
    for (int i = 0; i < MAX_AGENTS; i++) {
        if (orch->agents[i].status == AGENT_DISCONNECTED) {
            agent_idx = i;
            break;
        }
    }
    
    if (agent_idx == -1) {
        printf("Nombre maximum d'agents atteint, connexion refusée\n");
        close(client_socket);
        return -1;
    }
    
    int flags = fcntl(client_socket, F_GETFL, 0);
    fcntl(client_socket, F_SETFL, flags | O_NONBLOCK);
    
    orch->agents[agent_idx].socket_fd = client_socket;
    orch->agents[agent_idx].address = client_addr;
    orch->agents[agent_idx].status = AGENT_CONNECTED;
    orch->nb_agents++;
    
    printf("Nouvel agent connecté depuis %s:%d (id: %d)\n", 
           inet_ntoa(client_addr.sin_addr), 
           ntohs(client_addr.sin_port),
           agent_idx);

    request_agent_authentication(orch, agent_idx);
    
    return agent_idx;
}

static void request_agent_authentication(orchestrateur_t *orch, int agent_idx) {
    if (agent_idx < 0 || agent_idx >= MAX_AGENTS ||
        orch->agents[agent_idx].status != AGENT_CONNECTED) {
        return;
    }

    message_t auth_request;
    auth_request.type = MSG_TYPE_AUTH_REQUEST;
    auth_request.length = 0;

    char buffer[3];
    buffer[0] = auth_request.type;
    buffer[1] = (auth_request.length >> 8) & 0xFF;
    buffer[2] = auth_request.length & 0xFF;

    if (send(orch->agents[agent_idx].socket_fd, buffer, 3, 0) < 0) {
        perror("Erreur lors de l'envoi de la demande d'authentification");
        disconnect_agent(orch, agent_idx, "Échec de la demande d'authentification");
        return;
    }

    printf("Demande d'authentification envoyée à l'agent %d\n", agent_idx);
}

static void process_authentication_response(orchestrateur_t *orch, int agent_idx, const char *data, uint16_t length) {
    if (length < 1) {
        disconnect_agent(orch, agent_idx, "Réponse d'authentification invalide");
        return;
    }

    if (length > sizeof(orch->agents[agent_idx].hostname) - 1) {
        disconnect_agent(orch, agent_idx, "Nom d'hôte trop long");
        return;
    }

    memcpy(orch->agents[agent_idx].hostname, data, length);
    orch->agents[agent_idx].hostname[length] = '\0';

    orch->agents[agent_idx].status = AGENT_AUTHENTICATED;
    printf("Agent %d authentifié: %s\n", agent_idx, orch->agents[agent_idx].hostname);

    request_agent_capabilities(orch, agent_idx);
}

static void request_agent_capabilities(orchestrateur_t *orch, int agent_idx) {
    if (agent_idx < 0 || agent_idx >= MAX_AGENTS ||
        orch->agents[agent_idx].status != AGENT_AUTHENTICATED) {
        return;
    }

    message_t cap_request;
    cap_request.type = MSG_TYPE_CAPABILITIES;
    cap_request.length = 0;

    char buffer[3];
    buffer[0] = cap_request.type;
    buffer[1] = (cap_request.length >> 8) & 0xFF;
    buffer[2] = cap_request.length & 0xFF;

    if (send(orch->agents[agent_idx].socket_fd, buffer, 3, 0) < 0) {
        perror("Erreur lors de l'envoi de la demande de capacités");
        disconnect_agent(orch, agent_idx, "Échec de la demande de capacités");
        return;
    }

    printf("Demande de capacités envoyée à l'agent %d\n", agent_idx);
}

static void process_capabilities_response(orchestrateur_t *orch, int agent_idx, const char *data, uint16_t length) {
    if (length < sizeof(uint32_t)) {
        disconnect_agent(orch, agent_idx, "Réponse de capacités invalide");
        return;
    }

    uint32_t capabilities = 0;
    memcpy(&capabilities, data, sizeof(uint32_t));
    capabilities = ntohl(capabilities);

    orch->agents[agent_idx].capabilities = capabilities;
    printf("Agent %d capacités reçues: 0x%08X\n", agent_idx, capabilities);

    printf(" - Nmap: %s\n", (capabilities & CAPABILITY_NMAP) ? "Oui" : "Non");
    printf(" - OWASP ZAP: %s\n", (capabilities & CAPABILITY_ZAP) ? "Oui" : "Non");
    printf(" - Nikto: %s\n", (capabilities & CAPABILITY_NIKTO) ? "Oui" : "Non");
}

static void disconnect_agent(orchestrateur_t *orch, int agent_idx, const char *reason) {
    if (agent_idx < 0 || agent_idx >= MAX_AGENTS ||
        orch->agents[agent_idx].status == AGENT_DISCONNECTED) {
        return;
    }

    printf("Déconnexion de l'agent %d: %s\n", agent_idx, reason);

    close(orch->agents[agent_idx].socket_fd);
    orch->agents[agent_idx].socket_fd = -1;
    orch->agents[agent_idx].status = AGENT_DISCONNECTED;
    orch->nb_agents--;
}

static int parse_message(const char *buffer, int bytes_read, message_t *message) {
    if (bytes_read < 3) return -1;

    message->type = buffer[0];
    message->length = ((uint16_t)buffer[1] << 8) | buffer[2];

    if (message->length > MAX_BUFFER_SIZE - 3) return -1;
    if (bytes_read - 3 < message->length) return -1;

    memcpy(message->data, buffer + 3, message->length);
    return 0;
}

int orchestrateur_create_scan(orchestrateur_t *orch, scan_type_t type, const char *options) {
    if (!orch) return -1;

    if (orch->nb_scans >= MAX_SCANS) {
        fprintf(stderr, "Erreur: Nombre maximum de scans atteint\n");
        return -1;
    }

    int scan_idx = -1;
    for (int i = 0; i < MAX_SCANS; i++) {
        if (orch->scans[i].id == 0) {
            scan_idx = i;
            break;
        }
    }

    if (scan_idx == -1) {
        fprintf(stderr, "Erreur: Incohérence dans la structure de données\n");
        return -1;
    }

    scan_t *scan = &orch->scans[scan_idx];
    memset(scan, 0, sizeof(scan_t));

    scan->id = ++orch->next_scan_id;
    scan->type = type;
    scan->status = SCAN_STATUS_PENDING;
    scan->agent_idx = -1;

    if (options) {
        strncpy(scan->options, options, MAX_OPTIONS_LENGTH - 1);
        scan->options[MAX_OPTIONS_LENGTH - 1] = '\0';
    }

    orch->nb_scans++;
    printf("Nouveau scan créé avec ID %u (type: %d)\n", scan->id, type);

    return scan->id;
}

int orchestrateur_add_target(orchestrateur_t *orch, uint32_t scan_id, const char *target) {
    if (!orch || !target) return -1;

    scan_t *scan = orchestrateur_get_scan(orch, scan_id);
    if (!scan) {
        fprintf(stderr, "Erreur: Scan ID %u introuvable\n", scan_id);
        return -1;
    }

    if (scan->status != SCAN_STATUS_PENDING) {
        fprintf(stderr, "Erreur: Impossible d'ajouter une cible à un scan déjà démarré\n");
        return -1;
    }

    if (scan->num_targets >= MAX_TARGETS) {
        fprintf(stderr, "Erreur: Nombre maximum de cibles atteint pour le scan %u\n", scan_id);
        return -1;
    }

    strncpy(scan->targets[scan->num_targets].target, target, MAX_TARGET_LENGTH - 1);
    scan->targets[scan->num_targets].target[MAX_TARGET_LENGTH - 1] = '\0';
    scan->num_targets++;

    printf("Cible '%s' ajoutée au scan %u\n", target, scan_id);
    return 0;
}

int orchestrateur_start_scan(orchestrateur_t *orch, uint32_t scan_id) {
    if (!orch) return -1;

    scan_t *scan = orchestrateur_get_scan(orch, scan_id);
    if (!scan) {
        fprintf(stderr, "Erreur: Scan ID %u introuvable\n", scan_id);
        return -1;
    }

    if (scan->status != SCAN_STATUS_PENDING) {
        fprintf(stderr, "Erreur: Le scan %u n'est pas en attente (status: %d)\n", scan_id, scan->status);
        return -1;
    }

    if (scan->num_targets == 0) {
        fprintf(stderr, "Erreur: Aucune cible définie pour le scan %u\n", scan_id);
        return -1;
    }

    uint32_t required_capability = 0;
    switch (scan->type) {
        case SCAN_TYPE_NMAP:
            required_capability = CAPABILITY_NMAP;
            break;
        case SCAN_TYPE_ZAP:
            required_capability = CAPABILITY_ZAP;
            break;
        case SCAN_TYPE_NIKTO:
            required_capability = CAPABILITY_NIKTO;
            break;
        default:
            fprintf(stderr, "Erreur: type de scan inconnu\n");
            return -1;
    }

    int agent_idx = find_available_agent(orch, required_capability);
    if (agent_idx == -1) {
        fprintf(stderr, "Erreur: Aucun agent disponible avec la capacité requise (0x%08X)\n", required_capability);
        return -1;
    }

    scan->agent_idx = agent_idx;
    scan->status = SCAN_STATUS_RUNNING;
    scan->start_time = time(NULL);

    if (send_scan_request(orch, agent_idx, scan) != 0) {
        fprintf(stderr, "Erreur: Échec de l'envoi de la requête de scan à l'agent\n");
        scan->status = SCAN_STATUS_FAILED;
        return -1;
    }

    orch->agents[agent_idx].status = AGENT_SCANNING;
    printf("Scan %u démarré sur l'agent %d\n", scan_id, agent_idx);

    return 0;
}

int orchestrateur_cancel_scan(orchestrateur_t *orch, uint32_t scan_id) {
    if (!orch) return -1;

    scan_t *scan = orchestrateur_get_scan(orch, scan_id);
    if (!scan) {
        fprintf(stderr, "Erreur: Scan ID %u introuvable\n", scan_id);
        return -1;
    }

    if (scan->status != SCAN_STATUS_RUNNING) {
        fprintf(stderr, "Erreur: Le scan %u n'est pas en cours d'exécution\n", scan_id);
        return -1;
    }

    int agent_idx = scan->agent_idx;
    if (agent_idx < 0 || agent_idx >= MAX_AGENTS ||
        orch->agents[agent_idx].status != AGENT_SCANNING) {
        fprintf(stderr, "Erreur: Agent invalide pour le scan %u\n", scan_id);
        return -1;
    }

    message_t cancel_msg;
    cancel_msg.type = MSG_TYPE_SCAN_CANCEL;

    uint32_t scan_id_network = htonl(scan_id);
    memcpy(cancel_msg.data, &scan_id_network, sizeof(uint32_t));
    cancel_msg.length = sizeof(uint32_t);

    char buffer[MAX_BUFFER_SIZE];
    buffer[0] = cancel_msg.type;
    buffer[1] = (cancel_msg.length >> 8) & 0xFF;
    buffer[2] = cancel_msg.length & 0xFF;
    memcpy(buffer + 3, cancel_msg.data, cancel_msg.length);

    if (send(orch->agents[agent_idx].socket_fd, buffer, 3 + cancel_msg.length, 0) < 0) {
        perror("Erreur lors de l'envoi de la demande d'annulation");
        return -1;
    }

    printf("Demande d'annulation envoyée pour le scan %u\n", scan_id);
    scan->status = SCAN_STATUS_CANCELED;

    return 0;
}

scan_t *orchestrateur_get_scan(orchestrateur_t *orch, uint32_t scan_id) {
    if (!orch ||scan_id == 0) return NULL;

    for (int i = 0; i < MAX_SCANS; i++) {
        if (orch->scans[i].id == scan_id) {
            return &orch->scans[i];
        }
    }

    return NULL;
}

int orchestrateur_list_scans(orchestrateur_t *orch, uint32_t *scan_ids, int max_ids) {
    if (!orch || !scan_ids || max_ids <= 0) return -1;

    int count = 0;
    for (int i = 0; i < MAX_SCANS && count < max_ids; i++) {
        if (orch->scans[i].id != 0) {
            scan_ids[count++] = orch->scans[i].id;
        }
    }

    return count;
}

const char *orchestrateur_get_scan_results(orchestrateur_t *orch, uint32_t scan_id) {
    scan_t *scan = orchestrateur_get_scan(orch, scan_id);
    if (!scan) {
        return NULL;
    }

    if (scan->status != SCAN_STATUS_COMPLETED) {
        return NULL;
    }

    return scan->results;
}

static int find_available_agent(orchestrateur_t *orch, uint32_t capability) {
    for (int i = 0; i < MAX_AGENTS; i++) {
        if (orch->agents[i].status == AGENT_AUTHENTICATED &&
            (orch->agents[i].capabilities & capability)) {
            return i;
        }
    }

    return -1;
}

static int send_scan_request(orchestrateur_t *orch, int agent_idx, const scan_t *scan) {
    if (!orch || agent_idx < 0 || agent_idx >= MAX_AGENTS || !scan) {
        return -1;
    }

    message_t scan_req;
    scan_req.type = MSG_TYPE_SCAN_REQUEST;

    uint32_t scan_id_network = htonl(scan->id);
    uint32_t scan_type_network = htonl(scan->type);
    uint32_t num_targets_network = htonl(scan->num_targets);

    int offset = 0;
    memcpy(scan_req.data + offset, &scan_id_network, sizeof(uint32_t));
    offset += sizeof(uint32_t);

    memcpy(scan_req.data + offset, &scan_type_network, sizeof(uint32_t));
    offset += sizeof(uint32_t);

    memcpy(scan_req.data + offset, &num_targets_network, sizeof(uint32_t));
    offset += sizeof(uint32_t);

    for (int i = 0; i < scan->num_targets; i++) {
        int target_len = strlen(scan->targets[i].target) + 1;
        if (offset + target_len > MAX_BUFFER_SIZE - 3) {
            fprintf(stderr, "Erreur: Message trop grand pour le buffer");
            return -1;
        }
        memcpy(scan_req.data + offset, scan->targets[i].target, target_len);
        offset += target_len;
    }

    int options_len = strlen(scan->options) + 1;
    if (offset + options_len > MAX_BUFFER_SIZE - 3) {
        fprintf(stderr, "Erreur: Message trop grand pour le buffer\n");
        return -1;
    }
    memcpy(scan_req.data + offset, scan->options, options_len);
    offset += options_len;

    scan_req.length = offset;

    char buffer[MAX_BUFFER_SIZE];
    buffer[0] = scan_req.type;
    buffer[1] = (scan_req.length >> 8) & 0xFF;
    buffer[2] = scan_req.length & 0xFF;
    memcpy(buffer + 3, scan_req.data, scan_req.length);

    if (send(orch->agents[agent_idx].socket_fd, buffer, 3 + scan_req.length, 0) < 0) {
        perror("Erreur lors de l'envoi de la requête de scan");
        return -1;
    }

    printf("Requête de scan %u envoyée à l'agent %d\n", scan->id, agent_idx);
    return 0;
}

static void process_scan_status(orchestrateur_t *orch, int agent_idx, const char *data, uint16_t length) {
    if (length < sizeof(uint32_t) + sizeof(uint32_t)) {
        fprintf(stderr, "Message de statut de scan invalide\n");
        return;
    }

    uint32_t scan_id;
    uint32_t progress;

    memcpy(&scan_id, data, sizeof(uint32_t));
    memcpy(&progress, data + sizeof(uint32_t), sizeof(uint32_t));

    scan_id = ntohl(scan_id);
    progress = ntohl(progress);

    scan_t *scan = orchestrateur_get_scan(orch, scan_id);
    if (!scan) {
        fprintf(stderr, "Statut reçu pour un scan inconnu (ID: %u)\n", scan_id);
        return;
    }
    
    scan->progress = progress;
    printf("Mise à jour du statut du scan %u: %u%%\n", scan_id, progress);
    
    if (progress == 100) {
        scan->status = SCAN_STATUS_COMPLETED;
        scan->end_time = time(NULL);
        orch->agents[agent_idx].status = AGENT_AUTHENTICATED;
        printf("Scan %u terminé\n", scan_id);
    }
}

static void process_scan_result(orchestrateur_t *orch, int agent_idx __attribute__((unused)), const char *data, uint16_t length) {
    if (length < sizeof(uint32_t)) {
        fprintf(stderr, "Message de résultat de scan invalide\n");
        return;
    }
    
    uint32_t scan_id;
    memcpy(&scan_id, data, sizeof(uint32_t));
    scan_id = ntohl(scan_id);
    
    scan_t *scan = orchestrateur_get_scan(orch, scan_id);
    if (!scan) {
        fprintf(stderr, "Résultat reçu pour un scan inconnu (ID: %u)\n", scan_id);
        return;
    }

    int result_size = length - sizeof(uint32_t);
    if (result_size > 0) {
        if (scan->results) {
            free(scan->results);
        }
        
        scan->results = malloc(result_size + 1);
        if (!scan->results) {
            perror("Erreur d'allocation mémoire pour les résultats");
            return;
        }
        
        memcpy(scan->results, data + sizeof(uint32_t), result_size);
        scan->results[result_size] = '\0';
        scan->results_size = result_size;
        
        printf("Résultats reçus pour le scan %u (%d octets)\n", scan_id, result_size);
    } else {
        printf("Résultat vide reçu pour le scan %u\n", scan_id);
    }
}

static void process_message(orchestrateur_t *orch, int agent_idx, const message_t *message) {
    switch (message->type) {
        case MSG_TYPE_AUTH_RESPONSE:
            process_authentication_response(orch, agent_idx, message->data, message->length);
            break;
        
        case MSG_TYPE_CAPABILITIES:
            process_capabilities_response(orch, agent_idx, message->data, message->length);
            break;
        
        case MSG_TYPE_SCAN_STATUS:
            process_scan_status(orch, agent_idx, message->data, message->length);
            break;
        
        case MSG_TYPE_SCAN_RESULT:
            process_scan_result(orch, agent_idx, message->data, message->length);
            break;
        
        case MSG_TYPE_ERROR:
            printf("Erreur reçue de l'agent %d: %.*s\n", agent_idx, message->length, message->data);
            break;
        
        default:
            printf("Message inconnu (type: 0x%02X) reçu de l'agent %d\n", message->type, agent_idx);
            break;
    }
}



int orchestrateur_run(orchestrateur_t *orch) {
    if (!orch || orch->server_socket < 0) return -1;
    
    fd_set read_fds;
    struct timeval tv;
    int max_fd;
    
    printf("Démarrage de la boucle principale de l'orchestrateur...\n");
    
    while (orch->running) {
        FD_ZERO(&read_fds);
        FD_SET(orch->server_socket, &read_fds);
        max_fd = orch->server_socket;
        
        for (int i = 0; i < MAX_AGENTS; i++) {
            if (orch->agents[i].socket_fd > 0) {
                FD_SET(orch->agents[i].socket_fd, &read_fds);
                if (orch->agents[i].socket_fd > max_fd) {
                    max_fd = orch->agents[i].socket_fd;
                }
            }
        }
        
        tv.tv_sec = 1;
        tv.tv_usec = 0;
        
        int activity = select(max_fd + 1, &read_fds, NULL, NULL, &tv);
        
        if (activity < 0 && errno != EINTR) {
            perror("Erreur lors du select");
            break;
        }
        
        if (FD_ISSET(orch->server_socket, &read_fds)) {
            accept_new_connection(orch);
        }
        
        for (int i = 0; i < MAX_AGENTS; i++) {
            if (orch->agents[i].socket_fd > 0 && FD_ISSET(orch->agents[i].socket_fd, &read_fds)) {
                char buffer[MAX_BUFFER_SIZE];
                int bytes_read = recv(orch->agents[i].socket_fd, buffer, MAX_BUFFER_SIZE - 1, 0);
                
                if (bytes_read <= 0) {
                    if (bytes_read == 0) {
                        printf("Agent %d déconnecté\n", i);
                    } else {
                        perror("Erreur de réception");
                    }
                    
                    close(orch->agents[i].socket_fd);
                    orch->agents[i].socket_fd = -1;
                    orch->agents[i].status = AGENT_DISCONNECTED;
                    orch->nb_agents--;
                } else {
                    message_t message;
                    if (parse_message(buffer, bytes_read, &message) == 0) {
                        process_message(orch, i, &message);
                    } else {
                        printf("Message invalide reçu de l'agent %d\n", i);
                    }
                }
            }
        }
    }
    
    printf("Boucle principale de l'orchestrateur terminée\n");
    orchestrateur_cleanup(orch);
    return 0;
}

int vulnerability_list_init(vulnerability_list_t *list) {
    if (!list) return -1;

    list->count = 0;
    list->capacity = 10;
    list->vulnerabilities = malloc(list->capacity * sizeof(vulnerability_t));

    if (!list->vulnerabilities) {
        perror("Failed to allocate memory for vulnerability list");
        return -1;
    }

    return 0;
}

int vulnerability_list_add(vulnerability_list_t *list, const vulnerability_t *vuln) {
    if (!list || !vuln) return -1;

    if (list->count >= list->capacity) {
        int new_capacity = list->capacity * 2;
        vulnerability_t *new_array = realloc(list->vulnerabilities,
                                        new_capacity * sizeof(vulnerability_t));
        
        if (!new_array) {
            perror("Failed to resize vulnerability list");
            return -1;
        }

        list->vulnerabilities = new_array;
        list->capacity = new_capacity;
    }

    memcpy(&list->vulnerabilities[list->count], vuln, sizeof(vulnerability_t));
    list->count++;

    return 0;
}

void vulnerability_list_cleanup(vulnerability_list_t *list) {
    if (!list) return;

    if (list->vulnerabilities) {
        free(list->vulnerabilities);
        list->vulnerabilities = NULL;
    }

    list->count = 0;
    list->capacity = 0;
}

int parse_nmap_results(const char *results, vulnerability_list_t *vuln_list) {
    if (!results || !vuln_list) return -1;

    const char *host_start = strstr(results, "<host ");
    while (host_start) {
        const char *addr_start = strstr(host_start, "addr=\"");
        char target[MAX_TARGET_LENGTH] = {0};

        if (addr_start) {
            addr_start += 6;
            const char *addr_end = strchr(addr_start, '"');
            if (addr_end) {
                int len = addr_end - addr_start;
                strncpy(target, addr_start, len < MAX_TARGET_LENGTH ? len : MAX_TARGET_LENGTH - 1);
            }
        }

        const char *port_start = strstr(host_start, "<port ");
        while (port_start && port_start < strstr(host_start, "</host>")) {
            const char *script_start = strstr(port_start, "<script id=\"");
            while (script_start && script_start < strstr(port_start, "</port>")) {
                char script_id[64] = {0};
                char output[2048] = {0};

                const char *id_start = script_start + 12;
                const char *id_end = strchr(id_start, '"');
                if (id_end) {
                    strncpy(script_id, id_start, id_end - id_start < 63 ? id_end - id_start : 63);
                }

                const char *output_start = strstr(script_start, "output=\"");
                if (output_start) {
                    output_start += 8;
                    const char *output_end = strchr(output_start, '"');
                    if (output_end) {
                        strncpy(output, output_start, output_end - output_start < 2047 ? output_end - output_start : 2047);
                    }
                }

                if (strstr(script_id, "vuln") || strstr(output, "VULNERABLE")) {
                    vulnerability_t vuln;
                    memset(&vuln, 0, sizeof(vulnerability_t));

                    snprintf(vuln.id, sizeof(vuln.id), "NMAP-%.55s", script_id);
                    snprintf(vuln.title, sizeof(vuln.title), "Nmap: %s", script_id);
                    strncpy(vuln.description, output, sizeof(vuln.description) - 1);
                    strncpy(vuln.target, target, sizeof(vuln.target) - 1);

                    if (strstr(output, "CRITICAL") || strstr(output, "Critical"))
                        strcpy(vuln.severity, "Critical");
                    else if (strstr(output, "HIGH") || strstr(output, "High"))
                        strcpy(vuln.severity, "High");
                    else if (strstr(output, "LOW") || strstr(output, "Low"))
                        strcpy(vuln.severity, "Low");
                    else
                        strcpy(vuln.severity, "Medium");
                    
                    vuln.source = SCAN_TYPE_NMAP;
                    vulnerability_list_add(vuln_list, &vuln);
                }

                script_start = strstr(script_start + 1, "<script id=\"");
            }

            port_start = strstr(port_start + 1, "<port ");
        }

        host_start = strstr(host_start + 1, "<host ");
    }

    return 0;
}

int parse_zap_results(const char *results, vulnerability_list_t *vuln_list) {
    if (!results || !vuln_list) return -1;
    
    const char *site_start = strstr(results, "<site ");
    while (site_start) {
        const char *name_start = strstr(site_start, "name=\"");
        char target[MAX_TARGET_LENGTH] = {0};
        
        if (name_start) {
            name_start += 6;
            const char *name_end = strchr(name_start, '"');
            if (name_end) {
                int len = name_end - name_start;
                strncpy(target, name_start, len < MAX_TARGET_LENGTH - 1 ? len : MAX_TARGET_LENGTH - 1);
            }
        }
        
        const char *alert_start = strstr(site_start, "<alertitem>");
        while (alert_start && alert_start < strstr(site_start, "</site>")) {
            vulnerability_t vuln;
            memset(&vuln, 0, sizeof(vulnerability_t));
            vuln.source = SCAN_TYPE_ZAP;
            strncpy(vuln.target, target, sizeof(vuln.target) - 1);
            
            const char *name_start = strstr(alert_start, "<name>");
            if (name_start) {
                name_start += 6;
                const char *name_end = strstr(name_start, "</name>");
                if (name_end) {
                    int len = name_end - name_start;
                    strncpy(vuln.title, name_start, len < (int)sizeof(vuln.title) - 1 ? len : (int)sizeof(vuln.title) - 1);
                }
            }
            
            const char *desc_start = strstr(alert_start, "<desc>");
            if (desc_start) {
                desc_start += 6;
                const char *desc_end = strstr(desc_start, "</desc>");
                if (desc_end) {
                    int len = desc_end - desc_start;
                    strncpy(vuln.description, desc_start, len < (int)sizeof(vuln.description) - 1 ? len : (int)sizeof(vuln.description) - 1);
                }
            }
            
            const char *risk_start = strstr(alert_start, "<riskcode>");
            if (risk_start) {
                risk_start += 10;
                const char *risk_end = strstr(risk_start, "</riskcode>");
                if (risk_end) {
                    int risk_code = 0;
                    sscanf(risk_start, "%d", &risk_code);
                    
                    switch (risk_code) {
                        case 0: strcpy(vuln.severity, "Info"); break;
                        case 1: strcpy(vuln.severity, "Low"); break;
                        case 2: strcpy(vuln.severity, "Medium"); break;
                        case 3: strcpy(vuln.severity, "High"); break;
                        default: strcpy(vuln.severity, "Unknown");
                    }
                }
            }
            
            const char *pluginid_start = strstr(alert_start, "<pluginid>");
            if (pluginid_start) {
                pluginid_start += 10;
                const char *pluginid_end = strstr(pluginid_start, "</pluginid>");
                if (pluginid_end) {
                    char pluginid[32] = {0};
                    int len = pluginid_end - pluginid_start;
                    strncpy(pluginid, pluginid_start, len < 31 ? len : 31);
                    snprintf(vuln.id, sizeof(vuln.id), "ZAP-%s", pluginid);
                }
            }
            
            vulnerability_list_add(vuln_list, &vuln);
            
            alert_start = strstr(alert_start + 1, "<alertitem>");
        }
        
        site_start = strstr(site_start + 1, "<site ");
    }
    
    return 0;
}

int parse_nikto_results(const char *results, vulnerability_list_t *vuln_list) {
    if (!results || !vuln_list) return -1;
    
    const char *line_start = results;
    char target[MAX_TARGET_LENGTH] = {0};
    
    const char *target_line = strstr(results, "Target: ");
    if (target_line) {
        target_line += 8;
        const char *target_end = strchr(target_line, '\n');
        if (target_end) {
            int len = target_end - target_line;
            strncpy(target, target_line, len < MAX_TARGET_LENGTH - 1 ? len : MAX_TARGET_LENGTH - 1);
        }
    }
    
    while ((line_start = strstr(line_start, "+ "))) {
        line_start += 2;
        
        const char *line_end = strchr(line_start, '\n');
        if (!line_end) line_end = line_start + strlen(line_start);
        
        if (strstr(line_start, "OSVDB-") || strstr(line_start, "CVE-") || 
            strstr(line_start, "vulnerable") || strstr(line_start, "Vulnerable")) {
            
            vulnerability_t vuln;
            memset(&vuln, 0, sizeof(vulnerability_t));
            vuln.source = SCAN_TYPE_NIKTO;
            strncpy(vuln.target, target, sizeof(vuln.target) - 1);
            
            const char *id_start = strstr(line_start, "OSVDB-");
            if (!id_start) id_start = strstr(line_start, "CVE-");
            
            if (id_start) {
                const char *id_end = strchr(id_start, ':');
                if (!id_end) id_end = strchr(id_start, ' ');
                if (!id_end) id_end = line_end;
                
                int len = id_end - id_start;
                strncpy(vuln.id, id_start, len < (int)sizeof(vuln.id) - 1 ? len : (int)sizeof(vuln.id) - 1);
            } else {
                snprintf(vuln.id, sizeof(vuln.id), "NIKTO-%d", vuln_list->count + 1);
            }
            
            int desc_len = line_end - line_start;
            strncpy(vuln.description, line_start, desc_len < (int)sizeof(vuln.description) - 1 ? desc_len : (int)sizeof(vuln.description) - 1);
            
            const char *title_end = strchr(line_start, ':');
            if (!title_end || title_end > line_start + 50) title_end = line_start + 50;
            
            int title_len = title_end - line_start;
            strncpy(vuln.title, line_start, title_len < (int)sizeof(vuln.title) - 1 ? title_len : (int)sizeof(vuln.title) - 1);
            
            if (strstr(line_start, "critical") || strstr(line_start, "Critical"))
                strcpy(vuln.severity, "Critical");
            else if (strstr(line_start, "high") || strstr(line_start, "High"))
                strcpy(vuln.severity, "High");
            else if (strstr(line_start, "medium") || strstr(line_start, "Medium"))
                strcpy(vuln.severity, "Medium");
            else if (strstr(line_start, "low") || strstr(line_start, "Low"))
                strcpy(vuln.severity, "Low");
            else
                strcpy(vuln.severity, "Medium");
            
            vulnerability_list_add(vuln_list, &vuln);
        }
        
        line_start = line_end;
    }
    
    return 0;
}

int orchestrateur_aggregate_results(orchestrateur_t *orch, uint32_t *scan_ids, int scan_count, vulnerability_list_t *aggregated) {
    if (!orch || !scan_ids || scan_count <= 0 || !aggregated) return -1;
    
    vulnerability_list_init(aggregated);
    
    for (int i = 0; i < scan_count; i++) {
        scan_t *scan = orchestrateur_get_scan(orch, scan_ids[i]);
        if (!scan || scan->status != SCAN_STATUS_COMPLETED || !scan->results) {
            fprintf(stderr, "Scan %u non disponible ou incomplet\n", scan_ids[i]);
            continue;
        }
        
        printf("Analyse des résultats du scan %u (type: %d)\n", scan_ids[i], scan->type);
        
        switch (scan->type) {
            case SCAN_TYPE_NMAP:
                parse_nmap_results(scan->results, aggregated);
                break;
                
            case SCAN_TYPE_ZAP:
                parse_zap_results(scan->results, aggregated);
                break;
                
            case SCAN_TYPE_NIKTO:
                parse_nikto_results(scan->results, aggregated);
                break;
                
            default:
                fprintf(stderr, "Type de scan non supporté: %d\n", scan->type);
                break;
        }
    }
    
    printf("Agrégation terminée: %d vulnérabilités trouvées\n", aggregated->count);
    return aggregated->count;
}

char *orchestrateur_generate_summary(vulnerability_list_t *vuln_list) {
    if (!vuln_list) return NULL;
    
    int critical_count = 0;
    int high_count = 0;
    int medium_count = 0;
    int low_count = 0;
    
    for (int i = 0; i < vuln_list->count; i++) {
        const char *severity = vuln_list->vulnerabilities[i].severity;
        
        if (strcasecmp(severity, "Critical") == 0)
            critical_count++;
        else if (strcasecmp(severity, "High") == 0)
            high_count++;
        else if (strcasecmp(severity, "Medium") == 0)
            medium_count++;
        else if (strcasecmp(severity, "Low") == 0)
            low_count++;
    }
    
    char *summary = malloc(8192);
    if (!summary) {
        perror("Erreur d'allocation mémoire pour le résumé");
        return NULL;
    }
    
    int offset = 0;
    
    offset += snprintf(summary + offset, 8192 - offset,
                     "========== RÉSUMÉ DES VULNÉRABILITÉS ==========\n\n");
    
    offset += snprintf(summary + offset, 8192 - offset,
                     "Nombre total de vulnérabilités: %d\n"
                     "- Critique: %d\n"
                     "- Haute: %d\n"
                     "- Moyenne: %d\n"
                     "- Basse: %d\n\n",
                     vuln_list->count, critical_count, high_count, medium_count, low_count);
    
    if (critical_count > 0) {
        offset += snprintf(summary + offset, 8192 - offset,
                         "========== VULNÉRABILITÉS CRITIQUES ==========\n\n");
        
        for (int i = 0; i < vuln_list->count; i++) {
            const vulnerability_t *vuln = &vuln_list->vulnerabilities[i];
            if (strcasecmp(vuln->severity, "Critical") == 0) {
                offset += snprintf(summary + offset, 8192 - offset,
                                "ID: %s\n"
                                "Cible: %s\n"
                                "Titre: %s\n"
                                "Description: %s\n"
                                "Source: %s\n\n",
                                vuln->id, vuln->target, vuln->title, vuln->description,
                                (vuln->source == SCAN_TYPE_NMAP) ? "Nmap" :
                                (vuln->source == SCAN_TYPE_ZAP) ? "OWASP ZAP" :
                                (vuln->source == SCAN_TYPE_NIKTO) ? "Nikto" : "Inconnu");
            }
        }
    }
    
    if (high_count > 0) {
        offset += snprintf(summary + offset, 8192 - offset,
                         "========== VULNÉRABILITÉS HAUTES ==========\n\n");
        
        for (int i = 0; i < vuln_list->count; i++) {
            const vulnerability_t *vuln = &vuln_list->vulnerabilities[i];
            if (strcasecmp(vuln->severity, "High") == 0) {
                offset += snprintf(summary + offset, 8192 - offset,
                                "ID: %s\n"
                                "Cible: %s\n"
                                "Titre: %s\n"
                                "Description: %s\n"
                                "Source: %s\n\n",
                                vuln->id, vuln->target, vuln->title, vuln->description,
                                (vuln->source == SCAN_TYPE_NMAP) ? "Nmap" :
                                (vuln->source == SCAN_TYPE_ZAP) ? "OWASP ZAP" :
                                (vuln->source == SCAN_TYPE_NIKTO) ? "Nikto" : "Inconnu");
            }
        }
    }
    
    return summary;
}

int orchestrateur_export_results(vulnerability_list_t *vuln_list, const char *filename, const char *format) {
    if (!vuln_list || !filename || !format) return -1;
    
    FILE *file = fopen(filename, "w");
    if (!file) {
        perror("Erreur lors de l'ouverture du fichier");
        return -1;
    }
    
    if (strcasecmp(format, "txt") == 0) {
        // Export as text
        fprintf(file, "========== RAPPORT DE VULNÉRABILITÉS ==========\n\n");
        fprintf(file, "Nombre total de vulnérabilités: %d\n\n", vuln_list->count);
        
        for (int i = 0; i < vuln_list->count; i++) {
            const vulnerability_t *vuln = &vuln_list->vulnerabilities[i];
            fprintf(file, "Vulnérabilité #%d\n", i + 1);
            fprintf(file, "ID: %s\n", vuln->id);
            fprintf(file, "Cible: %s\n", vuln->target);
            fprintf(file, "Titre: %s\n", vuln->title);
            fprintf(file, "Description: %s\n", vuln->description);
            fprintf(file, "Sévérité: %s\n", vuln->severity);
            fprintf(file, "Source: %s\n\n", 
                   (vuln->source == SCAN_TYPE_NMAP) ? "Nmap" :
                   (vuln->source == SCAN_TYPE_ZAP) ? "OWASP ZAP" :
                   (vuln->source == SCAN_TYPE_NIKTO) ? "Nikto" : "Inconnu");
        }
    } 
    else if (strcasecmp(format, "csv") == 0) {
        fprintf(file, "ID,Cible,Titre,Description,Sévérité,Source\n");
        
        for (int i = 0; i < vuln_list->count; i++) {
            const vulnerability_t *vuln = &vuln_list->vulnerabilities[i];
            
            fprintf(file, "\"%s\",\"%s\",\"%s\",\"%s\",\"%s\",\"%s\"\n",
                   vuln->id, vuln->target, vuln->title, vuln->description, vuln->severity,
                   (vuln->source == SCAN_TYPE_NMAP) ? "Nmap" :
                   (vuln->source == SCAN_TYPE_ZAP) ? "OWASP ZAP" :
                   (vuln->source == SCAN_TYPE_NIKTO) ? "Nikto" : "Inconnu");
        }
    } 
    else if (strcasecmp(format, "json") == 0) {
        fprintf(file, "{\n");
        fprintf(file, "  \"total_vulnerabilities\": %d,\n", vuln_list->count);
        fprintf(file, "  \"vulnerabilities\": [\n");
        
        for (int i = 0; i < vuln_list->count; i++) {
            const vulnerability_t *vuln = &vuln_list->vulnerabilities[i];
            
            fprintf(file, "    {\n");
            fprintf(file, "      \"id\": \"%s\",\n", vuln->id);
            fprintf(file, "      \"target\": \"%s\",\n", vuln->target);
            fprintf(file, "      \"title\": \"%s\",\n", vuln->title);
            fprintf(file, "      \"description\": \"%s\",\n", vuln->description);
            fprintf(file, "      \"severity\": \"%s\",\n", vuln->severity);
            fprintf(file, "      \"source\": \"%s\"\n", 
                   (vuln->source == SCAN_TYPE_NMAP) ? "Nmap" :
                   (vuln->source == SCAN_TYPE_ZAP) ? "OWASP ZAP" :
                   (vuln->source == SCAN_TYPE_NIKTO) ? "Nikto" : "Inconnu");
            
            if (i < vuln_list->count - 1) {
                fprintf(file, "    },\n");
            } else {
                fprintf(file, "    }\n");
            }
        }
        
        fprintf(file, "  ]\n");
        fprintf(file, "}\n");
    } 
    else {
        fclose(file);
        fprintf(stderr, "Format d'export non supporté: %s\n", format);
        return -1;
    }
    
    fclose(file);
    printf("Résultats exportés dans %s au format %s\n", filename, format);
    return 0;
}