TARGETS = client server
CFLAGS = -Wall -std=c++11 -g -O0

server: wrappers.cpp game.cpp server.cpp wrappers.h game.h
	g++ $(CFLAGS) wrappers.cpp game.cpp server.cpp -o server

testclient: testclient.cpp
	g++ -std=c++11 -g -O0 testclient.cpp -o testclient
	./testclient ::1 5000

all: $(TARGETS)

client: client.cpp
	g++ $(CFLAGS) client.cpp -o client

clean:
	rm -f $(TARGETS)
