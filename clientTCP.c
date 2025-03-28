#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <unistd.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <string.h>
#include <arpa/inet.h>
#include <netdb.h>


struct addrinfo hints, *res, *p;

int main(int argc, char* argv[]){
    if (argc != 3){
        perror("Erreur arguments : forme attendu = ./clientTCP <servAddr> <NumPort>");
        exit(1);
    }

    memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;

    getaddrinfo(argv[1], argv[2], &hints, &res);
    int sockfd = sockfd = socket(res->ai_family, res->ai_socktype, 0);

    if (connect(sockfd, res->ai_addr, res->ai_addrlen) < 0){
        perror ("cliecho : erreur connect");
        exit (1);
    }

    char buffer[1024];
    ssize_t n = read(sockfd, buffer, sizeof(buffer) - 1);
    if (n < 0) {
        perror("read");
        exit(EXIT_FAILURE);
    }
    buffer[n] = '\0';  // pour s'assurer que c'est bien une string
    printf("Message reçu : %s", buffer);

    close(sockfd);
    return 0;
}
