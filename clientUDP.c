// clientUDP.c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/timeb.h>
#include <time.h>

int main(int argc, char *argv[]) {
    if (argc != 3){
        perror("Erreur arguments : forme attendu = ./clientUDP <servAddr> <NumPort>");
        exit(1);
    }

    int sockfd = socket(AF_INET, SOCK_DGRAM, 0);

    struct sockaddr_in serv_addr;
    memset(&serv_addr, 0, sizeof(serv_addr));
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port = htons(atoi(argv[2]));
    inet_pton(AF_INET, argv[1], &serv_addr.sin_addr);

    // Obtenir l'heure
    struct timeb tb;
    ftime(&tb);
    time_t now = tb.time;
    char *time_str = ctime(&now);  // ctime retourne déjà une chaîne lisible

    // Envoyer au serveur
    sendto(sockfd, time_str, strlen(time_str), 0,
           (struct sockaddr *)&serv_addr, sizeof(serv_addr));

    close(sockfd);
    return 0;
}
