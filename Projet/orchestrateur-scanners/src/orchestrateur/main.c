#include "../../include/orchestrateur.h"
#include <stdio.h>
#include <stdlib.h>

int main(int argc, char *argv[]) {
    orchestrateur_t orchestrateur;
    uint16_t port = DEFAULT_PORT;

    if (argc > 1) {
        port = (uint16_t)atoi(argv[1]);
    }

    printf("Démarrage de l'orchestrateur sur le port %d\n", port);

    if (orchestrateur_init(&orchestrateur, port) != 0) {
        fprintf(stderr, "Erreur lors de l'initialisation de l'orchestrateur\n");
        return EXIT_FAILURE;;
    }

    orchestrateur_run(&orchestrateur);

    printf("Orchestrateur arrêté\n");
    return EXIT_SUCCESS;
}