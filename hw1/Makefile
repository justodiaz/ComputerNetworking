TARGETS=hw1

CFLAGS=-Wall -g -O0

hw1: hw1.c
	gcc $(CFLAGS) -o hw1 hw1.c

run: hw1
	./hw1 http://www.google.com/
	./hw1 http://www.google.com/intl/en_ALL/images/logo.gif
	./hw1 http://www.google.com/thispagedoesnotexist
	./hw1 http://www.thissitedoesnotexist1776.com
	./hw1 http://www.engadget.com/2010/08/27/amazon-kindle-review
	./hw1 http://www.engadget.com/2010/08/27/amazon-kindle-review/
all: $(TARGETS)

clean:
	rm -f $(TARGETS) *.gif *.html amazon*

