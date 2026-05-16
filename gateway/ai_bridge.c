#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <sys/socket.h>
#include <sys/un.h>

void query_ai(char *metrics,
              char *response) {

    int sockfd;

    struct sockaddr_un addr;

    sockfd = socket(AF_UNIX,
                    SOCK_STREAM,
                    0);

    if(sockfd < 0) {

        perror("AI socket failed");

        return;
    }

    memset(&addr, 0, sizeof(addr));

    addr.sun_family = AF_UNIX;

    strcpy(addr.sun_path,
           "/tmp/ai_gateway.sock");

    if(connect(sockfd,
               (struct sockaddr*)&addr,
               sizeof(addr)) < 0) {

        perror("AI connect failed");

        close(sockfd);

        return;
    }

    send(sockfd,
         metrics,
         strlen(metrics),
         0);

    recv(sockfd,
         response,
         100,
         0);

    close(sockfd);
}