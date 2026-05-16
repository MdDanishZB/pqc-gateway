CC=gcc

CFLAGS=-Wall

LIBS=-lsctp -lpthread -lssl -lcrypto

all:
	$(CC) main.c sctp_gateway.c crypto_layer.c ai_bridge.c -o gateway $(CFLAGS) $(LIBS)

clean:
	rm -f gateway