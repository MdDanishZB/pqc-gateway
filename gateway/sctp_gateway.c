#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>

#include <arpa/inet.h>
#include <netinet/sctp.h>

#include <pthread.h>

#include <time.h>

typedef struct {

    int session_id;

    char client_ip[64];

    time_t start_time;

    int bytes_transferred;

} Session;

int global_session_id = 1;

#define TCP_PORT 4000
#define SCTP_PORT 5000

#define BUFFER_SIZE 1024

void encrypt_data(unsigned char *plaintext,
                  unsigned char *ciphertext,
                  int *cipher_len);

void* handle_client(void* arg) {

    int tcp_client_fd = *((int*)arg);

    Session session;

    session.session_id = global_session_id++;

    strcpy(session.client_ip, "127.0.0.1");

    session.start_time = time(NULL);

    session.bytes_transferred = 0;

    free(arg);

    int sctp_fd;

    struct sockaddr_in sctp_addr;

    char buffer[1024];

    memset(buffer, 0, sizeof(buffer));

    int bytes = recv(tcp_client_fd,
                     buffer,
                     sizeof(buffer),
                     0);
    
    session.bytes_transferred += bytes;

    if(bytes <= 0) {

        close(tcp_client_fd);

        pthread_exit(NULL);
    }

    buffer[bytes] = '\0';

    printf("\n========== SESSION INFO ==========\n");

    printf("Session ID: %d\n",
        session.session_id);

    printf("Client IP: %s\n",
        session.client_ip);

    printf("Bytes Received: %d\n",
        session.bytes_transferred);

    printf("Start Time: %ld\n",
        session.start_time);

    printf("==================================\n");

    printf("\n[Gateway] Received TCP Data: %s\n",buffer);

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

    unsigned char encrypted[1024];

    int encrypted_len;

    encrypt_data((unsigned char*)buffer,
                encrypted,
                &encrypted_len);

    if (send(sctp_fd,
        encrypted,
        encrypted_len,
        0) < 0) {
        perror("Send encrypted failed");
    } else {
        printf("[Gateway] Encrypted and Forwarded\n");
    }

    if (send(sctp_fd,
         buffer,
         strlen(buffer),
         0) < 0) {
        perror("Send plaintext failed");
    } else {
        printf("[Gateway] Forwarded to SCTP Receiver\n");
    }

    close(sctp_fd);
    close(tcp_client_fd);

    return NULL;
}

void start_gateway() {

    int tcp_server_fd, tcp_client_fd;

    struct sockaddr_in tcp_addr;

    signal(SIGPIPE, SIG_IGN);

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

    int opt = 1;
    setsockopt(tcp_server_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    if (bind(tcp_server_fd,
         (struct sockaddr*)&tcp_addr,
         sizeof(tcp_addr)) < 0) {
        perror("Bind failed");
        exit(1);
    }

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

        int *client_ptr = malloc(sizeof(int));

        *client_ptr = tcp_client_fd;

        pthread_create(&tid,
                    NULL,
                    handle_client,
                    client_ptr);

        pthread_detach(tid);
    }
}