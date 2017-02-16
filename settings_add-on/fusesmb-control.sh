#!/bin/sh

mountpoint="/SMB Network"

if [ "$1" == "start" ]
then
	mkdir "$mountpoint"
	mount -t userlandfs -p fusesmb "$mountpoint"
elif [ "$1" == "stop" ]
then
	unmount "$mountpoint"
	rmdir "$mountpoint"
else
	echo "Usage: fusesmb-control.sh [start|stop]"
fi
