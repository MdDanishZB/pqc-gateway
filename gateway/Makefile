CC     = gcc
CFLAGS = -Wall -Wextra -I/home/danish/liboqs/install/usr/local/include
LIBS   = -L/home/danish/liboqs/install/usr/local/lib -lsctp -lpthread -lssl -lcrypto -loqs

all: gateway sctp_receiver tcp_client

gateway: main.c sctp_gateway.c crypto_layer.c ai_bridge.c \
         pqc_handshake.c metrics.c multihoming.c path_monitor.c \
         metrics_reporter.c
	$(CC) $^ -o $@ $(CFLAGS) $(LIBS)

sctp_receiver: sctp_receiver.c crypto_layer.c pqc_handshake.c multihoming.c
	$(CC) $^ -o $@ $(CFLAGS) $(LIBS)

tcp_client: tcp_client.c
	$(CC) $^ -o $@ $(CFLAGS)

clean:
	rm -f gateway sctp_receiver tcp_client
