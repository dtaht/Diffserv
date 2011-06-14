#!/bin/sh -x

insmod /lib/modules/$KVER/sch_dsmark.o
insmod /lib/modules/$KVER/cls_tcindex.o
insmod /lib/modules/$KVER/sch_htb.o
insmod /lib/modules/$KVER/sch_gred.o
insmod /lib/modules/$KVER/sch_red.o

interface=eth0
rate=15Mbit
ceil=15Mbit

qrate=1500Kbit

limit=128KB
min=20KB
max=60KB

burst=20
avpkt=1000

bandwidth=15Mbit

# Creating tcindex table
# Interestingly we could treat ecn packets differently if we wanted to
aqm_dscp_table() {

tc qdisc add dev $interface handle 1:0 root dsmark indices 64 set_tc_index
tc filter add dev $interface parent 1:0 protocol ip prio 1 tcindex mask 0xfc shift 2 pass_on

# Classification's elements / Architecture elements

# Class AF1X
tc filter add dev $interface parent 1:0 protocol ip prio 1 handle 10 tcindex classid 1:111
tc filter add dev $interface parent 1:0 protocol ip prio 1 handle 12 tcindex classid 1:112
tc filter add dev $interface parent 1:0 protocol ip prio 1 handle 14 tcindex classid 1:113
# Class AF2X
tc filter add dev $interface parent 1:0 protocol ip prio 1 handle 18 tcindex classid 1:121
tc filter add dev $interface parent 1:0 protocol ip prio 1 handle 20 tcindex classid 1:122
tc filter add dev $interface parent 1:0 protocol ip prio 1 handle 22 tcindex classid 1:123
# Class AF3
tc filter add dev $interface parent 1:0 protocol ip prio 1 handle 26 tcindex classid 1:131
tc filter add dev $interface parent 1:0 protocol ip prio 1 handle 28 tcindex classid 1:132
tc filter add dev $interface parent 1:0 protocol ip prio 1 handle 30 tcindex classid 1:133
# Class AF4
tc filter add dev $interface parent 1:0 protocol ip prio 1 handle 34 tcindex classid 1:141
tc filter add dev $interface parent 1:0 protocol ip prio 1 handle 36 tcindex classid 1:142
tc filter add dev $interface parent 1:0 protocol ip prio 1 handle 38 tcindex classid 1:143
# Class BE
tc filter add dev $interface parent 1:0 protocol ip prio 2 handle 0 tcindex mask 0 classid 1:1
# Class EF
tc filter add dev $interface parent 1:0 protocol ip prio 1 handle 46 tcindex classid 1:150
}

aqm_shaper() {
# HTB filter

tc qdisc add dev $interface parent 1:0 handle 2:0 htb
tc class add dev $interface parent 2:0 classid 2:1 htb rate $rate ceil $ceil
tc filter add dev $interface parent 2:0 protocol ip prio 1 tcindex mask 0xf0 shift 4 pass_on

# AF class 1
tc class add dev $interface parent 2:1 classid 2:10 htb rate $qrate ceil $ceil
tc qdisc add dev $interface parent 2:10 gred setup DPs 3 default 2 grio
tc filter add dev $interface parent 2:0 protocol ip prio 1 handle 1 tcindex classid 2:10
# AF Class 11
tc qdisc change dev $interface parent 2:10 gred limit $limit min $min max $max burst $burst avpkt $avpkt bandwidth $bandwidth DP 1 probability 0.02 prio 2
# AF Class 12
tc qdisc change dev $interface parent 2:10 gred limit $limit min $min max $max burst $burst avpkt $avpkt bandwidth $bandwidth DP 2 probability 0.04 prio 3
# AF Class 13
tc qdisc change dev $interface parent 2:10 gred limit $limit min $min max $max burst $burst avpkt $avpkt bandwidth $bandwidth DP 3 probability 0.06 prio 4

# AF Class 2
tc class add dev $interface parent 2:1 classid 2:20 htb rate $qrate ceil $ceil
tc qdisc add dev $interface parent 2:20 gred setup DPs 3 default 2 grio
tc filter add dev $interface parent 2:0 protocol ip prio 1 handle 2 tcindex classid 2:20
# AF Class 21
tc qdisc change dev $interface parent 2:20 gred limit $limit min $min max $max burst $burst avpkt $avpkt bandwidth $bandwidth DP 1 probability 0.02 prio 2
# AF Class 22
tc qdisc change dev $interface parent 2:20 gred limit $limit min $min max $max burst $burst avpkt $avpkt bandwidth $bandwidth DP 2 probability 0.04 prio 3
# AF Class 23
tc qdisc change dev $interface parent 2:20 gred limit $limit min $min max $max burst $burst avpkt $avpkt bandwidth $bandwidth DP 3 probability 0.06 prio 4

# AF Class 3
tc class add dev $interface parent 2:1 classid 2:30 htb rate $qrate ceil $ceil
tc qdisc add dev $interface parent 2:30 gred setup DPs 3 default 2 grio
tc filter add dev $interface parent 2:0 protocol ip prio 1 handle 3 tcindex classid 2:30
# AF Class 31
tc qdisc change dev $interface parent 2:30 gred limit $limit min $min max $max burst $burst avpkt $avpkt bandwidth $bandwidth DP 1 probability 0.02 prio 2
# AF Class 32
tc qdisc change dev $interface parent 2:30 gred limit $limit min $min max $max burst $burst avpkt $avpkt bandwidth $bandwidth DP 2 probability 0.04 prio 3
# AF Class 33
tc qdisc change dev $interface parent 2:30 gred limit $limit min $min max $max burst $burst avpkt $avpkt bandwidth $bandwidth DP 3 probability 0.06 prio 4

# AF Class 4

tc class add dev $interface parent 2:1 classid 2:40 htb rate $qrate ceil $ceil tc qdisc add dev $interface parent 2:40 gred setup DPs 3 default 2 grio
tc filter add dev $interface parent 2:0 protocol ip prio 1 handle 4 tcindex classid 2:40
# AF Class 41
tc qdisc change dev $interface parent 2:40 gred limit $limit min $min max $max burst $burst avpkt $avpkt bandwidth $bandwidth DP 1 probability 0.02 prio 2
# AF Class 42
tc qdisc change dev $interface parent 2:40 gred limit $limit min $min max $max burst $burst avpkt $avpkt bandwidth $bandwidth DP 2 probability 0.04 prio 3
# AF Class 43
tc qdisc change dev $interface parent 2:40 gred limit $limit min $min max $max burst $burst avpkt $avpkt bandwidth $bandwidth DP 3 probability 0.06 prio 4

# BE

tc class add dev $interface parent 2:1 classid 2:50 htb rate $qrate ceil $ceil

tc qdisc add dev $interface parent 2:50 red limit $limit min $min max $max burst $burst avpkt $avpkt bandwidth $bandwidth probability 0.4
tc filter add dev $interface parent 2:0 protocol ip prio 1 handle 0 tcindex classid 2:50

# EF
tc class add dev $interface parent 2:1 classid 2:60 htb rate $qrate ceil $ceil
tc qdisc add dev $interface parent 2:60 red limit $limit min $min max $max burst $burst avpkt $avpkt bandwidth $bandwidth probability 0.2
tc filter add dev $interface parent 2:0 protocol ip prio 1 handle 5 tcindex classid 2:60
}



aqm_dscp_table
aqm_shaper