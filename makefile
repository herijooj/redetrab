CC=gcc
CFLAGS=-Wall -g

all: server client

server: server.c sockets.c
	$(CC) $(CFLAGS) -o server server.c sockets.c

client: client.c sockets.c
	$(CC) $(CFLAGS) -o client client.c sockets.c

clean:
	rm -f server client *.o

debug: CFLAGS += -DDEBUG=1
debug: all

test: all
	./test_script.sh

.PHONY: all clean debug test
