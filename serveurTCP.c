#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <string.h>

#define SERV_PORT 2000
#define MAX_CONN 1

// Socket d'ouverture en IPv4
struct sockaddr_in serv_addr;
int serverSocket;

// Socket de dialogue
struct sockaddr_in cli_addr;
int clilen;
int dialogSocket;

int main(){
    // Création socket
    if ((serverSocket = socket(PF_INET, SOCK_STREAM, 0)) < 0){
        perror("erreur création socket");
        exit(-1);
    }

    // RaZ de la struct serv_addr
    memset (&serv_addr, 0, sizeof(serv_addr) );
    serv_addr.sin_family = AF_INET ;
    serv_addr.sin_addr.s_addr = htonl(INADDR_ANY);
    serv_addr.sin_port = htons(SERV_PORT);

    // Attachement socket
    if ((bind(serverSocket, (struct sockaddr *)&serv_addr, sizeof(serv_addr))) < 0){
        perror("erreur attachement socket");
        exit(1);
    }

    // Ouverture du service
    if(listen(serverSocket, MAX_CONN) < 0){
        perror("erreur ouverture de service");
        exit(1);
    }

    // Création socket de dialogue 
    clilen = sizeof(cli_addr);
    if ((dialogSocket = accept(serverSocket, (struct sockaddr *)&cli_addr, (socklen_t *)&clilen)) < 0){
        perror("erreur création socket dialogue");
        exit(1);
    }

    char* message = "salut\n";
    write(dialogSocket, message, sizeof(message));

    return 0;
}



