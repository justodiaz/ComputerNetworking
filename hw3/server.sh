#!/bin/bash
case $1 in
	[0-9]* ) 
		make server;
		./server $1;
		;;
	* ) 
		echo "Usage: $0 [portnumber]"
esac

exit 0
