#!/bin/bash
# My first script

if [ $# -ne 1 ]; then
    echo "Error: Your command line contains $# arguments. You must provide exactly 1 argument."
		echo "./lotsOfClients.sh [portnumber]"
		exit 1
fi

x=0
while [ $x -lt 300 ]
do
	#gnome-terminal -e 
	./lazy_1sec_client client localhost $1 &
	(( x++ ))
done

