#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <arpa/inet.h>
#include <netinet/sctp.h>

#define SERVER_PORT 5000
#define SERVER_IP "127.0.0.1"

int main() {

    int sockfd;

    struct sockaddr_in server_addr;

    char message[] = "Hello from SCTP Client";

    sockfd = socket(AF_INET,
                    SOCK_STREAM,
                    IPPROTO_SCTP);

    if(sockfd < 0) {
        perror("Socket creation failed");
        exit(1);
    }

    memset(&server_addr, 0, sizeof(server_addr));

    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(SERVER_PORT);

    inet_pton(AF_INET,
              SERVER_IP,
              &server_addr.sin_addr);

    if(connect(sockfd,
               (struct sockaddr*)&server_addr,
               sizeof(server_addr)) < 0) {

        perror("Connection failed");
        exit(1);
    }

    send(sockfd,
         message,
         strlen(message),
         0);

    printf("Message Sent\n");

    close(sockfd);

    return 0;
}