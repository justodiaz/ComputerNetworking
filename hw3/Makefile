TARGETS = client server
CFLAGS = -Wall -std=c++11 -g -O0

server: wrappers.cpp server.cpp wrappers.h
	g++ $(CFLAGS) wrappers.cpp server.cpp -o server

all: $(TARGETS)

client: client.cpp
	g++ $(CFLAGS) client.cpp -o client

clean:
	rm -f $(TARGETS)
