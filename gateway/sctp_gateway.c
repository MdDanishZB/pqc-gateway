#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <arpa/inet.h>
#include <netinet/sctp.h>

#define TCP_PORT 4000
#define SCTP_PORT 5000

#define BUFFER_SIZE 1024


void start_gateway() {

    int tcp_server_fd, tcp_client_fd;

    int sctp_fd;

    struct sockaddr_in tcp_addr;
    struct sockaddr_in sctp_addr;

    char buffer[BUFFER_SIZE];

    tcp_server_fd = socket(AF_INET,
                           SOCK_STREAM,
                           0);

    if(tcp_server_fd < 0) {
        perror("TCP socket failed");
        exit(1);
    }

    memset(&tcp_addr, 0, sizeof(tcp_addr));

    tcp_addr.sin_family = AF_INET;
    tcp_addr.sin_port = htons(TCP_PORT);
    tcp_addr.sin_addr.s_addr = INADDR_ANY;

    bind(tcp_server_fd,
         (struct sockaddr*)&tcp_addr,
         sizeof(tcp_addr));

    listen(tcp_server_fd, 5);

    printf("Gateway Listening for TCP Clients...\n");

    while(1) {

        tcp_client_fd = accept(tcp_server_fd,
                               NULL,
                               NULL);

        printf("TCP Client Connected\n");

        memset(buffer, 0, BUFFER_SIZE);

        int bytes = recv(tcp_client_fd,
                         buffer,
                         BUFFER_SIZE,
                         0);

        if(bytes <= 0) {
            close(tcp_client_fd);
            continue;
        }

        buffer[bytes] = '\0';

        printf("Gateway Received TCP Data: %s\n", buffer);

        sctp_fd = socket(AF_INET,
                         SOCK_STREAM,
                         IPPROTO_SCTP);

        memset(&sctp_addr, 0, sizeof(sctp_addr));

        sctp_addr.sin_family = AF_INET;
        sctp_addr.sin_port = htons(SCTP_PORT);

        inet_pton(AF_INET,
                  "127.0.0.1",
                  &sctp_addr.sin_addr);

        if(connect(sctp_fd,
                   (struct sockaddr*)&sctp_addr,
                   sizeof(sctp_addr)) < 0) {

            perror("SCTP connect failed");

            close(tcp_client_fd);
            continue;
        }

        send(sctp_fd,
             buffer,
             strlen(buffer),
             0);

        printf("Forwarded to SCTP Receiver\n");

        close(sctp_fd);
        close(tcp_client_fd);
    }
}