TARGETS=client server

CFLAGS=-Wall -std=c++11 -g -O0

all: $(TARGETS)

client: client.cpp
	g++ $(CFLAGS) client.cpp -o client
server: server.cpp
	g++ $(CFLAGS) server.cpp -o server
install:
	sudo apt-get install g++

clean:
	rm $(TARGETS)
