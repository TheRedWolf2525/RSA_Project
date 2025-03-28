// serveurUDP.c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

int main(int argc, char *argv[]) {
    int servPort;
    if (argc == 2){
        servPort = atoi(argv[1]);
    } else if (argc == 1){
        servPort = 2000;
    } else{
        perror("Erreur arguments : forme attendu = ./serveurUDP <NumPort(optionnel)>");
        exit(1);
    }
    printf("Num Port. socket d'ouverture : %d\n", servPort);

    int sockfd = socket(AF_INET, SOCK_DGRAM, 0);

    struct sockaddr_in serv_addr, cli_addr;
    socklen_t cli_len = sizeof(cli_addr);
    char buffer[1024];

    memset(&serv_addr, 0, sizeof(serv_addr));
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port = htons(servPort);
    serv_addr.sin_addr.s_addr = INADDR_ANY;

    char ip_str[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &serv_addr.sin_addr, ip_str, sizeof(ip_str));
    printf("IP serveur : %s\n", ip_str);

    bind(sockfd, (struct sockaddr *)&serv_addr, sizeof(serv_addr));

    // Attendre un message
    ssize_t n = recvfrom(sockfd, buffer, sizeof(buffer) - 1, 0,
                         (struct sockaddr *)&cli_addr, &cli_len);
    buffer[n] = '\0';

    printf("Heure reçue du client : %s\n", buffer);

    close(sockfd);
    return 0;
}
