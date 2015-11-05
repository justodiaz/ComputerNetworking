TARGETS=hw6_sender hw6_receiver

all: $(TARGETS)

hw6_sender: hw6_sender.c hw6.c
	gcc --std=gnu99 -o hw6_sender hw6_sender.c hw6.c

hw6_receiver: hw6_receiver.c hw6.c
	gcc --std=gnu99 -o hw6_receiver hw6_receiver.c hw6.c

clean:
	rm -f $(TARGETS)
