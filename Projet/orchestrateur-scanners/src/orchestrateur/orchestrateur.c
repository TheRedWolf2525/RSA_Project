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

static orchestrateur_t *g_orchestrateur = NULL;

#define MSG_TYPE_AUTH_REQUEST 0x01
#define MSG_TYPE_AUTH_RESPONSE 0x02
#define MSG_TYPE_CAPABILITIES 0x03
#define MSG_TYPE_SCAN_REQUEST 0x04
#define MSG_TYPE_SCAN_STATUS 0x05
#define MSG_TYPE_SCAN_RESULT 0x06
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

static void process_message(orchestrateur_t *orch, int agent_idx, const message_t *message) {
    switch (message->type) {
        case MSG_TYPE_AUTH_RESPONSE:
            process_authentication_response(orch, agent_idx, message->data, message->length);
            break;
        
        case MSG_TYPE_CAPABILITIES:
            process_capabilities_response(orch, agent_idx, message->data, message->length);
            break;
        
        case MSG_TYPE_SCAN_STATUS:
            // Implémentation à venir
            printf("Statut du scan reçu de l'agent %d\n", agent_idx);
            break;
        
        case MSG_TYPE_SCAN_RESULT:
            // Implémentation à venir
            printf("Résultat du scan reçu de l'agent %d\n", agent_idx);
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