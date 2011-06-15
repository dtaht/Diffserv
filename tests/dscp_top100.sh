#!/bin/sh

WGET_OPTS="-q -t 5 "
TEMP=/tmp/transcripts/
mkdir $TEMP

for i in `cat top100.txt`
do
	wget $WGET_OPTS -O $TEMP/$i http://$i &
done
wait
