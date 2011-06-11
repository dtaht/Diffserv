#!/bin/sh

# Some new codepoints

BOFH=04
MICE=42
LB=63

# This attempts to keep track of DSCP classified packets in one chain.
# This should really be sorted by frequency and done more cleverly but for now...
# -j RETURN might make more sense

do_cp_stats() {
    local iptables=$1
    $iptables -t filter -F DSCP_END
    $iptables -t filter -X DSCP_END
    $iptables -t filter -N DSCP_END

    $iptables -t filter -F DSCP_STATS
    $iptables -t filter -X DSCP_STATS
    $iptables -t filter -N DSCP_STATS
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
    $iptables -t filter -A DSCP_STATS -m dscp --dscp $BOFH -m comment --comment 'BOFH' -g DSCP_END
    $iptables -t filter -A DSCP_STATS -m dscp --dscp $MICE -m comment --comment 'MICE' -g DSCP_END
    $iptables -t filter -A DSCP_STATS -m dscp --dscp $LB -m comment --comment 'LB' -g DSCP_END
    $iptables -t filter -A DSCP_STATS -m comment --comment 'Unmatched' -j LOG

}

do_cp_stats iptables
do_cp_stats ip6tables


