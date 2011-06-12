# Functions for classifying packets into DIFFSERV buckets

dscp_recreate_filter() {
    local iptables=$1
    local filter=$2
    local chain=$3
    $iptables -t $filter -F $chain 2> $DEBUG_LOG
    $iptables -t $filter -X $chain 2> $DEBUG_LOG
    $iptables -t $filter -N $chain 2> $DEBUG_LOG
}

# I am not sure why I used tcp and udp distinctions. 
# would probably have been saner in many cases
# FIXME: Do other protocols (41,50,51,58) Be thorough.

dscp_classify() {
    local iptables
    for iptables in iptables ip6tables
    do
	dscp_recreate_filter $iptables mangle Mice_END
	dscp_recreate_filter $iptables mangle Mice
	dscp_recreate_filter $iptables mangle D_CLASSIFIER_END
	dscp_recreate_filter $iptables mangle D_CLASSIFIER 

# I'm not certain this is a good idea, but the initial syn and syn/ack is a mouse.

	$iptables -t mangle -A D_CLASSIFIER_END -p tcp -m tcp --syn -j DSCP \
	    --set-dscp-class AF21 -m comment --comment 'Expedite new connections' 
	$iptables -t mangle -A D_CLASSIFIER_END -p tcp -m tcp --tcp-flags ALL SYN,ACK -j DSCP \
	    --set-dscp-class AF21 -m comment --comment 'Expedite new connection ack' 

# FIXME: Maybe make ECN enabled streams mildly higher priority. 
# This just counts the number of ECN and non-ECN streams
# FIXME: Also mark against IP not TCP

	$iptables -t mangle -A D_CLASSIFIER_END -p tcp -m tcp \
	    --tcp-flags ALL SYN,ACK -m ecn --ecn-tcp-ece -m recent \
	--name ecn_enabled --set -m comment --comment 'ECN enabled streams' 
	$iptables -t mangle -A D_CLASSIFIER_END -p tcp -m tcp \
	    --tcp-flags ALL SYN,ACK -m ecn ! --ecn-tcp-ece -m recent \
	    --name ecn_disabled --set -m comment --comment 'ECN disabled streams' 

# not sure if this matches dhcp actually
# And we should probably have different classes for multicast vs non multicast
# Wedging all these mice into the CS6 catagory is probably a bit much

	$iptables -t mangle -A Mice -p udp -m multiport --ports 53,67,68 \
	    -j DSCP --set-dscp $MICE -m comment \
	    --comment 'DNS, DHCP, NTP, are very important' 
	$iptables -t mangle -A Mice -p udp -m multiport --ports $SIGNALPORTS \
	    -j DSCP --set-dscp-class CS5 -m comment \
	    --comment 'VOIP Signalling'
	$iptables -t mangle -A Mice -p udp -m multiport --ports $VOIPPORTS,$NTPPORTS \
	    -j DSCP --set-dscp-class EF -m comment --comment 'VOIP'
	$iptables -t mangle -A Mice -p udp -m multiport --ports $GAMINGPORTS \
	    -j DSCP --set-dscp-class CS4 -m comment --comment 'Gaming'
	$iptables -t mangle -A Mice -p udp -m multiport --ports $MONITORPORTS \
	    -j DSCP --set-dscp-class CS6 -m comment --comment 'SNMP'
	$iptables -t mangle -A Mice -p udp -m udp -m multiport \
	    --ports $GAMINGPORTS -j DSCP --set-dscp-class CS4 \
	    -m comment --comment 'Gaming'

	if [ "$iptables" = "ip6tables" ]
	then
# addrtype for ipv6 isn't compiled in by default
# Perhaps tracking ICMP is important
	    $iptables -t mangle -A Mice -s fe80::/10 -d fe80::/10 \
		-j DSCP --set-dscp $MICE \
		-m comment --comment 'Link Local sorely needed'
	    $iptables -t mangle -A Mice -d ff00::/12 \
		-j DSCP --set-dscp-class AF43 \
		-m comment --comment 'Multicast far less needed'
	    $iptables -t mangle -A Mice -s fe80::/10 -d ff00::/12 \
		-j DSCP --set-dscp $MICE \
		-m comment --comment 'But link local multicast is good'

# As is neighbor discovery, etc, but I haven't parsed 
# http://tools.ietf.org/html/rfc4861 well yet
# $iptables -t mangle -A Mice -s fe80::/10 -d ff00::/12 \
# -j DSCP --set-dscp-class AF12 -m comment 
# --comment 'ND working is good too' \
# As for other forms of icmp, don't know
	else
#didn't work
#$iptables -t mangle -A Mice -m addrtype --dst-type MULTICAST 
#-j DSCP --set-dscp-class AF22 -m comment --comment 'Multicast'
#Some forms of multicast are good, others bad, but for now...
	    $iptables -t mangle -A Mice --pkt-type MULTICAST \
		-j DSCP --set-dscp-class AF43 \
		-m comment --comment 'Multicast'
# Arp replies? DHCP replies?
fi

# Main stuff

	$iptables -t mangle -A D_CLASSIFIER ! -p tcp -g Mice

# FIXME: SSH rule needs to distinguish between interactive and bulk sessions
# Actually simply codifying current practice (0x04, I think) would be
# Better. Call it the 'IT' field. Interactive Text

	$iptables -t mangle -A D_CLASSIFIER -p tcp -m tcp -m multiport \
	    --ports $INTERACTIVEPORTS -j DSCP --set-dscp $BOFH \
	    -m comment --comment 'SSH'
# CS4 for Xwin almost makes sense
	$iptables -t mangle -A D_CLASSIFIER -p tcp -m tcp -m multiport \
	    --ports $XWINPORTS -j DSCP --set-dscp-class CS4 \
	    -m comment --comment 'Xwindows'
# Probably incorrect for gaming, which uses udp usually
	$iptables -t mangle -A D_CLASSIFIER -p tcp -m tcp -m multiport \
	    --ports $GAMINGPORTS -j DSCP --set-dscp-class CS4 \
	    -m comment --comment 'Gaming'
	$iptables -t mangle -A D_CLASSIFIER -p tcp -m tcp -m multiport \
	    --ports $ROUTINGPORTS -j DSCP --set-dscp-class CS6 \
	    -m comment --comment 'Routing'
	$iptables -t mangle -A D_CLASSIFIER -p tcp -m tcp -m multiport \
	    --ports $BROWSINGPORTS -j DSCP --set-dscp-class AF23 \
	    -m comment --comment 'BROWSING'
	$iptables -t mangle -A D_CLASSIFIER -p tcp -m tcp -m multiport \
	    --ports $PROXYPORTS -j DSCP --set-dscp-class AF22 \
	    -m comment --comment 'Web proxies better for browsing'
	$iptables -t mangle -A D_CLASSIFIER -p tcp -m tcp -m multiport \
	    --ports $SCMPORTS -j DSCP --set-dscp-class CS2 \
	    -m comment --comment 'SCM'

# FIXME: Streaming Ports? Database Ports? What else did I miss?

	$iptables -t mangle -A D_CLASSIFIER -p tcp -m tcp -m multiport \
	    --ports $DBPORTS -j DSCP --set-dscp-class AF12 \
	    -m comment --comment 'DB'
	$iptables -t mangle -A D_CLASSIFIER -p tcp -m tcp -m multiport \
	    --ports $V_STREAMINGPORTS -j DSCP --set-dscp-class AF43 \
	    -m comment --comment 'Video Streaming'
	$iptables -t mangle -A D_CLASSIFIER -p tcp -m tcp -m multiport \
	    --ports $A_STREAMINGPORTS -j DSCP --set-dscp-class AF41 \
	    -m comment --comment 'Internet Radio'
	$iptables -t mangle -A D_CLASSIFIER -p tcp -m tcp -m multiport \
	    --ports $FILEPORTS -j DSCP --set-dscp-class AF22 \
	    -m comment --comment 'Normal File sharing'
	$iptables -t mangle -A D_CLASSIFIER -p tcp -m tcp -m multiport \
	    --ports $MAILPORTS -j DSCP --set-dscp-class AF32 \
	    -m comment --comment 'MAIL clients'
# FIXME: we really want backups to take precedence over more traffic
	$iptables -t mangle -A D_CLASSIFIER -p tcp -m tcp -m multiport \
	    --ports $BACKUPPORTS -j DSCP --set-dscp-class CS3 \
	    -m comment --comment 'Backups'
	$iptables -t mangle -A D_CLASSIFIER -p tcp -m tcp -m multiport \
	    --ports $BULKPORTS -j DSCP --set-dscp-class CS2 \
	    -m comment --comment 'BULK'
	$iptables -t mangle -A D_CLASSIFIER -p tcp -m tcp -m multiport \
	    --ports $TESTPORTS -j DSCP --set-dscp-class CS1 -m comment \
	    --comment 'Bandwidth Tests'
# There is no codepoint for torrent. Perhaps we need to invent one
	$iptables -t mangle -A D_CLASSIFIER -p tcp -m tcp -m multiport \
	    --ports $P2PPORTS -j DSCP --set-dscp-class CS1 -m comment \
	    --comment 'P2P'

# It would be nice if network radio had not gone tcp, AF3X
# should probably make these rules separate on a per class basis

	$iptables -t mangle -A D_CLASSIFIER_END -p tcp -m tcp --syn -j DSCP \
	    --set-dscp-class AF21 -m comment --comment 'Expedite new connections' 
	$iptables -t mangle -A D_CLASSIFIER_END -p tcp -m tcp \
	    --tcp-flags ALL SYN,ACK -j DSCP --set-dscp-class AF21 \
	    -m comment --comment 'Expedite new connection ack' 

# FIXME: Maybe make ECN enabled streams mildly higher priority. 
# This just counts the number of ECN and non-ECN streams

	$iptables -t mangle -A D_CLASSIFIER_END -p tcp -m tcp \
	    --tcp-flags ALL SYN,ACK -m ecn --ecn-tcp-ece -m recent \
	    --name ecn_enabled --set -m comment --comment 'ECN enabled streams' 
	$iptables -t mangle -A D_CLASSIFIER_END -p tcp -m tcp \
	    --tcp-flags ALL SYN,ACK -m ecn ! --ecn-tcp-ece -m recent \
	    --name ecn_disabled --set -m comment --comment 'ECN disabled streams' 

done
}

# Ya know, I care about ipv6. Nobody else does
# This could be more detailed, but right now...

dscp_icmpv6() {
    dscp_recreate_filter ip6tables filter ICMP6
    ip6tables -A ICMP6 -p icmpv6 --comment 'ICMPv6 MICE' -j DSCP --set-dscp $MICE 
}

dscp_icmpv6_stats() {
    dscp_recreate_filter ip6tables filter ICMP6_STATS
    ip6tables -A ICMP6_STATS -p icmpv6 --icmpv6-type 1 -m comment --comment 'dest unreachable'
    ip6tables -A ICMP6_STATS -p icmpv6 --icmpv6-type 2 -m comment --comment 'packet too big'
    ip6tables -A ICMP6_STATS -p icmpv6 --icmpv6-type 3 -m comment --comment 'parameter problem'
    ip6tables -A ICMP6_STATS -p icmpv6 --icmpv6-type 128 -m comment --comment 'ping'
    ip6tables -A ICMP6_STATS -p icmpv6 --icmpv6-type 129 -m comment --comment 'pong'
    ip6tables -A ICMP6_STATS -p icmpv6 --icmpv6-type 130 -m comment --comment 'Group Membership query'
    ip6tables -A ICMP6_STATS -p icmpv6 --icmpv6-type 131 -m comment --comment 'Group Membership report'
    ip6tables -A ICMP6_STATS -p icmpv6 --icmpv6-type 132 -m comment --comment 'Group Membership Reduciton'
    ip6tables -A ICMP6_STATS -p icmpv6 --icmpv6-type 133 -m comment --comment 'Router Solicitation'
    ip6tables -A ICMP6_STATS -p icmpv6 --icmpv6-type 134 -m comment --comment 'Router Advertisement'
    ip6tables -A ICMP6_STATS -p icmpv6 --icmpv6-type 135 -m comment --comment 'Neighbor Solicitation'
    ip6tables -A ICMP6_STATS -p icmpv6 --icmpv6-type 136 -m comment --comment 'Neighbor Advertisement'
    ip6tables -A ICMP6_STATS -p icmpv6 --icmpv6-type 137 -m comment --comment 'Redirect'
    ip6tables -A ICMP6_STATS -p icmpv6 --icmpv6-type 138 -m comment --comment 'Router Renumbering'
    ip6tables -A ICMP6_STATS -p icmpv6 --icmpv6-type 139 -m comment --comment 'Node info query'
    ip6tables -A ICMP6_STATS -p icmpv6 --icmpv6-type 140 -m comment --comment 'Node info response'
    ip6tables -A ICMP6_STATS -p icmpv6 --icmpv6-type 141 -m comment --comment 'Inverse NDS'
    ip6tables -A ICMP6_STATS -p icmpv6 --icmpv6-type 142 -m comment --comment 'Inverse ADV'
    ip6tables -A ICMP6_STATS -p icmpv6 --icmpv6-type 143 -m comment --comment 'MLDv2 Listener Report'
    ip6tables -A ICMP6_STATS -p icmpv6 --icmpv6-type 144 -m comment --comment 'Home agent disc req'
    ip6tables -A ICMP6_STATS -p icmpv6 --icmpv6-type 145 -m comment --comment 'Home agent reply'
    ip6tables -A ICMP6_STATS -p icmpv6 --icmpv6-type 146 -m comment --comment 'Mobile prefix solicit'
    ip6tables -A ICMP6_STATS -p icmpv6 --icmpv6-type 147 -m comment --comment 'Mobile prefix Adv'
    ip6tables -A ICMP6_STATS -p icmpv6 --icmpv6-type 148 -m comment --comment 'Cert path solicit'
    ip6tables -A ICMP6_STATS -p icmpv6 --icmpv6-type 149 -m comment --comment 'Cert path Adv'
    ip6tables -A ICMP6_STATS -p icmpv6 --icmpv6-type 150 -m comment --comment 'Experimental mobility'
    ip6tables -A ICMP6_STATS -p icmpv6 --icmpv6-type 151 -m comment --comment 'MRD advertisment'
    ip6tables -A ICMP6_STATS -p icmpv6 --icmpv6-type 152 -m comment --comment 'MRD Solicitation'
    ip6tables -A ICMP6_STATS -p icmpv6 --icmpv6-type 153 -m comment --comment 'MRD Termination'
    ip6tables -A ICMP6_STATS -p icmpv6 --icmpv6-type 154 -m comment --comment 'FMIPv6'
}

# Classify Diffserv marked packets into the right 802.11e buckets
# I think I need to set the skb priority field using tc however

dscp_80211e() {
    local iptables
    local device=$1
#   if [ -s $device ]

    for iptables in iptables ip6tables
    do
    dscp_recreate_filter $iptables filter Wireless 
    $iptables -A Wireless -o $device -m dscp --dscp-class CS6 -j CONNMARK --set-mark 261
    $iptables -A Wireless -o $device -m dscp --dscp-class CS5 -j CONNMARK --set-mark 263
    $iptables -A Wireless -o $device -m dscp --dscp-class EF -j CONNMARK --set-mark 263
    $iptables -A Wireless -o $device -m dscp --dscp-class CS1 -j CONNMARK --set-mark 257
    $iptables -A Wireless -o $device -m dscp --dscp-class CS2 -j CONNMARK --set-mark 257
    done
}

dscp_8021d() {
local device=$1
:
}


# This attempts to keep track of DSCP classified packets in one chain.
# This should really be sorted by frequency and done more cleverly but for now...
# -j RETURN might make more sense
# It would be cooler if this was on a per device basis.

dscp_stats() {
    local iptables
    for iptables in iptables ip6tables
    do
    dscp_recreate_filter $iptables filter DSCP_END
    dscp_recreate_filter $iptables filter DSCP_STATS
    
    $iptables -t filter -A DSCP_STATS -p udp -m multiport --ports $VPNPORTS -m comment --comment  'VPN'    
    $iptables -t filter -A DSCP_STATS -m dscp --dscp-class BE -m comment --comment  'BE'    -g DSCP_END
    $iptables -t filter -A DSCP_STATS -m dscp --dscp-class EF -m comment --comment  'EF'    -g DSCP_END
    $iptables -t filter -A DSCP_STATS -m dscp --dscp-class AF11 -m comment --comment 'AF11' -g DSCP_END
    $iptables -t filter -A DSCP_STATS -m dscp --dscp-class AF12 -m comment --comment 'AF12' -g DSCP_END
    $iptables -t filter -A DSCP_STATS -m dscp --dscp-class AF13 -m comment --comment 'AF13' -g DSCP_END
    $iptables -t filter -A DSCP_STATS -m dscp --dscp-class AF21 -m comment --comment 'AF21' -g DSCP_END
    $iptables -t filter -A DSCP_STATS -m dscp --dscp-class AF22 -m comment --comment 'AF22' -g DSCP_END
    $iptables -t filter -A DSCP_STATS -m dscp --dscp-class AF23 -m comment --comment 'AF23' -g DSCP_END
    $iptables -t filter -A DSCP_STATS -m dscp --dscp-class AF31 -m comment --comment 'AF31' -g DSCP_END
    $iptables -t filter -A DSCP_STATS -m dscp --dscp-class AF32 -m comment --comment 'AF32' -g DSCP_END
    $iptables -t filter -A DSCP_STATS -m dscp --dscp-class AF33 -m comment --comment 'AF33' -g DSCP_END
    $iptables -t filter -A DSCP_STATS -m dscp --dscp-class AF41 -m comment --comment 'AF41' -g DSCP_END
    $iptables -t filter -A DSCP_STATS -m dscp --dscp-class AF42 -m comment --comment 'AF42' -g DSCP_END
    $iptables -t filter -A DSCP_STATS -m dscp --dscp-class AF43 -m comment --comment 'AF43' -g DSCP_END
    $iptables -t filter -A DSCP_STATS -m dscp --dscp-class CS7 -m comment --comment 'CS7'   -g DSCP_END
    $iptables -t filter -A DSCP_STATS -m dscp --dscp-class CS6 -m comment --comment 'CS6'   -g DSCP_END
    $iptables -t filter -A DSCP_STATS -m dscp --dscp-class CS5 -m comment --comment 'CS5'   -g DSCP_END
    $iptables -t filter -A DSCP_STATS -m dscp --dscp-class CS4 -m comment --comment 'CS4'   -g DSCP_END
    $iptables -t filter -A DSCP_STATS -m dscp --dscp-class CS3 -m comment --comment 'CS3'   -g DSCP_END
    $iptables -t filter -A DSCP_STATS -m dscp --dscp-class CS2 -m comment --comment 'CS2'   -g DSCP_END
    $iptables -t filter -A DSCP_STATS -m dscp --dscp-class CS1 -m comment --comment 'CS1'   -g DSCP_END
# Some non-standardized classifications
    $iptables -t filter -A DSCP_STATS -m dscp --dscp $BOFH -m comment --comment 'BOFH' -g DSCP_END
    $iptables -t filter -A DSCP_STATS -m dscp --dscp $MICE -m comment --comment 'MICE' -g DSCP_END
    $iptables -t filter -A DSCP_STATS -m dscp --dscp $LB -m comment --comment 'LB' -g DSCP_END
    $iptables -t filter -A DSCP_STATS -m dscp --dscp $PTP -m comment --comment 'P2P' -g DSCP_END
    $iptables -t filter -A DSCP_STATS -m comment --comment 'Unmatched' -j LOG
    done
}

dscp_reset() {
:
}

# The only way I know how to cope with this is brute force

dscp_clean() {
	ip6tables -F
	ip6tables -t mangle -F
	iptables -F
	iptables -t mangle -F
}

dscp_finalize() {
    for iptables in iptables ip6tables
    do
# Not quite convinced this is right
	$iptables -t mangle -A PREROUTING -j D_CLASSIFIER
	$iptables -t mangle -A PREROUTING -j D_CLASSIFIER_END
	$iptables -t mangle -A OUTPUT -j D_CLASSIFIER
	$iptables -t mangle -A OUTPUT -j D_CLASSIFIER_END
	$iptables -A OUTPUT -j Wireless
	$iptables -A FORWARD -j Wireless
	$iptables -A OUTPUT -j DSCP_STATS
	$iptables -A FORWARD -j DSCP_STATS
    done
# Not clear I have to treat ICMPv6 specially but...
        ip6tables -A OUTPUT -p 58 -s fe80::/10 -j ICMP6
        ip6tables -A FORWARD -p 58 -s fe80::/10 -j ICMP6
	ip6tables -A OUTPUT -p 58 -j ICMP6_STATS 
	ip6tables -A FORWARD -p 58 -j ICMP6_STATS

}

dscp_start() {
    dscp_clean
    dscp_icmpv6
    dscp_icmpv6_stats
    dscp_stats
    dscp_classify
# Ultimately drive these with variables
    dscp_80211e wlan+
    dscp_8021d eth+
    dscp_finalize
}

dscp_stop() {
dscp_clean
}

dscp_restart() {
    dscp_stop
    dscp_start
}

dscp_status4() {
    iptables -v -n -L DSCP_STATS
}

dscp_status6() {
    ip6tables -v -n -L DSCP_STATS
    ip6tables -v -n -L ICMP6_STATS
}

dscp_status() {
    echo "IPV6 Stats"
    dscp_status6
    echo "IPV4 Stats"
    dscp_status4
}

dscp_help() {
:
}
