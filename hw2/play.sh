#!/bin/bash
hash g++ 2>/dev/null || make install;
hash g++ 2>/dev/null || { echo >&2 "g++ is not installed in bin. Aborting."; exit 1; }
if [ "$1" = "client" ]; then
	make client;
	./client $2 $3;
elif [ "$1" = "server" ]; then
	make server;
	./server $2;
else
	echo "Usage: $0 (client|server) [hostname] [portnumber]"
fi
exit 0
