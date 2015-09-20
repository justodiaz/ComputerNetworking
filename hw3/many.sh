#!/bin/bash

i=1
if [ "$1" != ''  -a  "$2" != ''  ]; then 
	make client;
	while [ $i -le 100 ]; do
		./client $1 $2 &
		i=$((i+1))
	done
else
	echo "Usage: $0 [hostname] [portnumber]"
fi

exit 0
