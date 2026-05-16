#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <arpa/inet.h>
#include <netinet/sctp.h>

#include <pthread.h>

#define TCP_PORT 4000
#define SCTP_PORT 5000

#define BUFFER_SIZE 1024

void* handle_client(void* arg) {

    int tcp_client_fd = *(int*)arg;

    int sctp_fd;

    struct sockaddr_in sctp_addr;

    char buffer[1024];

    memset(buffer, 0, sizeof(buffer));

    int bytes = recv(tcp_client_fd,
                     buffer,
                     sizeof(buffer),
                     0);

    if(bytes <= 0) {

        close(tcp_client_fd);

        pthread_exit(NULL);
    }

    buffer[bytes] = '\0';

    printf("\n[Gateway] Received TCP Data: %s\n",
           buffer);

    sctp_fd = socket(AF_INET,
                     SOCK_STREAM,
                     IPPROTO_SCTP);

    if(sctp_fd < 0) {

        perror("SCTP socket failed");

        close(tcp_client_fd);

        pthread_exit(NULL);
    }

    memset(&sctp_addr, 0, sizeof(sctp_addr));

    sctp_addr.sin_family = AF_INET;
    sctp_addr.sin_port = htons(5000);

    inet_pton(AF_INET,
              "127.0.0.1",
              &sctp_addr.sin_addr);

    if(connect(sctp_fd,
               (struct sockaddr*)&sctp_addr,
               sizeof(sctp_addr)) < 0) {

        perror("SCTP connect failed");

        close(sctp_fd);
        close(tcp_client_fd);

        pthread_exit(NULL);
    }

    send(sctp_fd,
         buffer,
         strlen(buffer),
         0);

    printf("[Gateway] Forwarded to SCTP Receiver\n");

    close(sctp_fd);
    close(tcp_client_fd);

    pthread_exit(NULL);
}

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

        if(tcp_client_fd < 0) {

            perror("Accept failed");

            continue;
        }

        printf("\n[Gateway] TCP Client Connected\n");

        pthread_t tid;

        pthread_create(&tid,
                    NULL,
                    handle_client,
                    &tcp_client_fd);

        pthread_detach(tid);
    }
}