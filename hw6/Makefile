TARGETS=hw6_sender hw6_receiver
OPTIONS=-Wall -std=c++11

all: $(TARGETS)

hw6_sender: hw6_sender.c hw6.cpp
	g++ $(OPTIONS) -o hw6_sender hw6_sender.c hw6.cpp

hw6_receiver: hw6_receiver.c hw6.cpp
	g++ $(OPTIONS) -o hw6_receiver hw6_receiver.c hw6.cpp

clean:
	rm -f $(TARGETS)
