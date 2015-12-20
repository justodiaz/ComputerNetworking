#!/bin/bash

i=1
	while [ $i -le 10 ]; do
		dig @localhost -p 5454 nibbles.cs.uic.edu &
		dig @localhost -p 5454 www.uic.edu &
		dig @localhost -p 5454 www.internic.net &
		dig @localhost -p 5454 www.cs.uic.edu &
		i=$((i+1))
	done
