#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <arpa/inet.h>
#include <netinet/sctp.h>

#define SCTP_PORT 5000
#define BUFFER_SIZE 1024

int main() {

    int server_fd, client_fd;

    struct sockaddr_in server_addr;

    char buffer[BUFFER_SIZE];

    server_fd = socket(AF_INET,
                       SOCK_STREAM,
                       IPPROTO_SCTP);

    if(server_fd < 0) {
        perror("SCTP socket failed");
        exit(1);
    }

    memset(&server_addr, 0, sizeof(server_addr));

    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(SCTP_PORT);
    server_addr.sin_addr.s_addr = INADDR_ANY;

    bind(server_fd,
         (struct sockaddr*)&server_addr,
         sizeof(server_addr));

    listen(server_fd, 5);

    printf("SCTP Receiver Listening...\n");

    client_fd = accept(server_fd, NULL, NULL);

    int bytes = recv(client_fd,
                     buffer,
                     BUFFER_SIZE,
                     0);

    buffer[bytes] = '\0';

    printf("SCTP Receiver Got: %s\n", buffer);

    close(client_fd);
    close(server_fd);

    return 0;
}