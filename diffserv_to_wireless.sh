#!/bin/sh

WIRELESS_DEVS=`ip link | grep wlan | awk '{print $2}' | cut -f1 -d:`
# Convert diffserv markings to wireless queues

# CS6 = video
# CS5 & EF = telephony
# 
# additionally classify

# CS1 = bulk


# And possibly

# AF41,AF42,AF43 video
# CS4 = video
# SF31,32,33 = video

# Simple internal shaper for wireless traffic
# Make dhcp, nd, etc, work well
# Make DNS fast
# Prioritize syn and synack traffic to make starting new connections faster

# This is the external setup

#    This is the relevant table from the RFC

#    |===============+=========+=============+==========================|
#    |Network Control|  CS6    |   110000    | Network routing          |
#    |---------------+---------+-------------+--------------------------|
#    | Telephony     |   EF    |   101110    | IP Telephony bearer      |
#    |---------------+---------+-------------+--------------------------|
#    |  Signaling    |  CS5    |   101000    | IP Telephony signaling   |
#    |---------------+---------+-------------+--------------------------|
#    | Multimedia    |AF41,AF42|100010,100100|   H.323/V2 video         |
#    | Conferencing  |  AF43   |   100110    |  conferencing (adaptive) |
#    |---------------+---------+-------------+--------------------------|
#    |  Real-Time    |  CS4    |   100000    | Video conferencing and   |
#    |  Interactive  |         |             | Interactive gaming       |
#    |---------------+---------+-------------+--------------------------|
#    | Multimedia    |AF31,AF32|011010,011100| Streaming video and      |
#    | Streaming     |  AF33   |   011110    |   audio on demand        |
#    |---------------+---------+-------------+--------------------------|
#    |Broadcast Video|  CS3    |   011000    |Broadcast TV & live events|
#    |---------------+---------+-------------+--------------------------|
#    | Low-Latency   |AF21,AF22|010010,010100|Client/server transactions|
#    |   Data        |  AF23   |   010110    | Web-based ordering       |
#    |---------------+---------+-------------+--------------------------|
#    |     OAM       |  CS2    |   010000    |         OAM&P            |
#    |---------------+---------+-------------+--------------------------|
#    |High-Throughput|AF11,AF12|001010,001100|  Store and forward       |
#    |    Data       |  AF13   |   001110    |     applications         |
#    |---------------+---------+-------------+--------------------------|
#    |    Standard   | DF (CS0)|   000000    | Undifferentiated         |
#    |               |         |             | applications             |
#    |---------------+---------+-------------+--------------------------|
#    | Low-Priority  |  CS1    |   001000    | Any flow that has no BW  |
#    |     Data      |         |             | assurance                |
#     ------------------------------------------------------------------

# So we take CS5 and CS6 m
# Similarly, the codepoints '11x000' may remain to be used for network control traffic.

# 2001:db8::/32 Block entirely
# 2001::/32 Teredo
# fec0::/10 Deprecated

# . ./diffserv.cfg

do_qos() {
local iptables=$1
$iptables -X Wireless 
$iptables -N Wireless
$iptables -F Wireless 
$iptables -A Wireless -o wlan+ -m dscp --dscp-class CS6 -j CONNMARK --set-mark 261
$iptables -A Wireless -o wlan+ -m dscp --dscp-class CS5 -j CONNMARK --set-mark 263
$iptables -A Wireless -o wlan+ -m dscp --dscp-class EF -j CONNMARK --set-mark 263
$iptables -A Wireless -o wlan+ -m dscp --dscp-class CS1 -j CONNMARK --set-mark 257
$iptables -A Wireless -o wlan+ -m dscp --dscp-class CS2 -j CONNMARK --set-mark 257
}

do_qos iptables 
do_qos ip6tables 

#iptables -t mangle -F POSTROUTING
#ip6tables -t mangle -F POSTROUTING

#for DEV in $WIRELESS_DEVS
#3do

iptables -A OUTPUT -j Wireless
ip6tables -A OUTPUT -j Wireless
iptables -A FORWARD -j Wireless
ip6tables -A FORWARD -j Wireless

#done

