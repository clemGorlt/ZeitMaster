#!/bin/bash

usage(){
	echo "usage: $0 file"
}

if [ $# -ne 1 ];then
	usage
	exit 1
fi
#editcap -t -3600 $1 $1
tshark -E separator=/ -E header=yes -Tfields -e frame.time -e ip.proto -e udp.port -e tcp.port -e http.response -e http.date -e frame.number -r $1 | python ../ini_test/r.py -f $1
#bla
