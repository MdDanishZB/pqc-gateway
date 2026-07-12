CC     = gcc
CFLAGS = -Wall -Wextra -I/home/danish/liboqs/install/usr/local/include
LIBS   = -L/home/danish/liboqs/install/usr/local/lib -lsctp -lpthread -lssl -lcrypto -loqs -lm

all: gateway sctp_receiver tcp_client

gateway: main.c sctp_gateway.c crypto_layer.c ai_bridge.c \
         pqc_handshake.c metrics.c multihoming.c path_monitor.c \
         metrics_reporter.c crypto_policy.c transport_policy.c net_config.c
	$(CC) $^ -o $@ $(CFLAGS) $(LIBS)

sctp_receiver: sctp_receiver.c crypto_layer.c pqc_handshake.c multihoming.c net_config.c
	$(CC) $^ -o $@ $(CFLAGS) $(LIBS)

tcp_client: tcp_client.c
	$(CC) $^ -o $@ $(CFLAGS)

# ── Unit tests (no liboqs/openssl/sctp needed) ─────────────────────────────
test: tests/test_policy tests/test_metrics
	./tests/test_policy
	./tests/test_metrics

tests/test_policy: tests/test_policy.c crypto_policy.c transport_policy.c
	$(CC) $^ -o $@ $(CFLAGS)

tests/test_metrics: tests/test_metrics.c metrics.c
	$(CC) $^ -o $@ $(CFLAGS) -lpthread -lm

clean:
	rm -f gateway sctp_receiver tcp_client tests/test_policy tests/test_metrics
