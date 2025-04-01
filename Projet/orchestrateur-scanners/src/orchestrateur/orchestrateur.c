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
    
    return agent_idx;
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
                    buffer[bytes_read] = '\0';
                    printf("Message reçu de l'agent %d: %s\n", i, buffer);
                    
                    // Traitement ultérieur des messages du protocole
                }
            }
        }
    }
    
    printf("Boucle principale de l'orchestrateur terminée\n");
    orchestrateur_cleanup(orch);
    return 0;
}