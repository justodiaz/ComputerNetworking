TARGETS=client server

CFLAGS=-Wall -std=c++11 -g -O0

client: client.cpp
	g++ $(CFLAGS) client.cpp -o client
server: server.cpp
	g++ -Wall -std=c++11 -g -O0 server.cpp -o server

all: $(TARGETS)

clean:
	rm $(TARGETS)
