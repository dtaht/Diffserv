#!/bin/sh

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

