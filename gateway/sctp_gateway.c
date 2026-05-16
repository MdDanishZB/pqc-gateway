#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <arpa/inet.h>
#include <netinet/sctp.h>

#define PORT 5000
#define BUFFER_SIZE 1024

void start_sctp_server() {

    int server_fd, client_fd;

    struct sockaddr_in server_addr;

    char buffer[BUFFER_SIZE];

    server_fd = socket(AF_INET,
                       SOCK_STREAM,
                       IPPROTO_SCTP);

    if(server_fd < 0) {
        perror("Socket creation failed");
        exit(1);
    }

    memset(&server_addr, 0, sizeof(server_addr));

    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(PORT);
    server_addr.sin_addr.s_addr = INADDR_ANY;

    if(bind(server_fd,
            (struct sockaddr*)&server_addr,
            sizeof(server_addr)) < 0) {

        perror("Bind failed");
        exit(1);
    }

    if(listen(server_fd, 5) < 0) {

        perror("Listen failed");
        exit(1);
    }

    printf("SCTP Server Listening on port %d\n", PORT);

    while(1) {

        client_fd = accept(server_fd, NULL, NULL);

        if(client_fd < 0) {
            perror("Accept failed");
            continue;
        }

        memset(buffer, 0, BUFFER_SIZE);

        int bytes = recv(client_fd,
                         buffer,
                         BUFFER_SIZE,
                         0);

        if(bytes > 0) {

            buffer[bytes] = '\0';

            printf("Received: %s\n", buffer);

        } else {

            printf("No data received\n");
        }

        close(client_fd);
    }

    close(server_fd);
}