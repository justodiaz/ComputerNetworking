#!/bin/bash
case $1 in
	"-p" )
		case $2 in
		[0-9]* ) 
			make;
			./hw4 -p $2;
			;;

		*)
			echo "Usage: $0 -p [portnumber]";
			exit 1;
			;;
		
		esac
		;;

	*) 
		echo "Usage: $0 -p [portnumber]";
		exit 1;
		;;
esac

exit $? 


