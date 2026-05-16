#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <arpa/inet.h>

#define TCP_PORT 4000
#define SERVER_IP "127.0.0.1"

int main() {

    int sockfd;

    struct sockaddr_in server_addr;

    char message[] = "Message from Legacy TCP Client";

    sockfd = socket(AF_INET, SOCK_STREAM, 0);

    if(sockfd < 0) {
        perror("TCP socket failed");
        exit(1);
    }

    memset(&server_addr, 0, sizeof(server_addr));

    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(TCP_PORT);

    inet_pton(AF_INET,
              SERVER_IP,
              &server_addr.sin_addr);

    if(connect(sockfd,
               (struct sockaddr*)&server_addr,
               sizeof(server_addr)) < 0) {

        perror("TCP connection failed");
        exit(1);
    }

    send(sockfd,
         message,
         strlen(message),
         0);

    printf("TCP Message Sent\n");

    close(sockfd);

    return 0;
}