TARGETS=hw6_sender hw6_receiver

all: $(TARGETS)

hw6_sender: hw6_sender.c hw6.cpp
	g++ -Wall -std=c++11 -o hw6_sender hw6_sender.c hw6.cpp

hw6_receiver: hw6_receiver.c hw6.cpp
	g++ -Wall -std=c++11 -o hw6_receiver hw6_receiver.c hw6.cpp

clean:
	rm -f $(TARGETS)
