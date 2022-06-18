#!/usr/bin/env bash

function log {
    GREEN="\033[32m"
    NORMAL="\033[0;39m"
    msg=$1
    echo -e "${GREEN}"${msg}"${NORMAL}"
}

function check_error {
    RED="\033[31m"
    NORMAL="\033[0;39m"
    code=$1
    msg=$2

    if [ $code -eq 1 ]
    then
        echo -e "${RED}"${msg}"${NORMAL}"
        exit 1
    fi
}

function check_root {
	if [[ $EUID -ne 0 ]]; then
		log "You must be root to run this script"
		exit 1
	fi
}

function setup_host {
	# Maximize tcp window size
	echo 134217728 > /proc/sys/net/core/rmem_max
	echo 134217728 > /proc/sys/net/core/wmem_max
	echo '4096 87380 67108864' > /proc/sys/net/ipv4/tcp_rmem
	echo '4096 87380 67108864' > /proc/sys/net/ipv4/tcp_wmem

	# Set CPU freq to performance
	# Doesn't work on Xeons due to BIOS settings...need to fix.
	# For Debian/Ubuntu systems:
	cpufreq-set -r -g performance
T	# To watch the CPU governor in action, you can do this:
	#watch -n 1 grep MHz /proc/cpuinfo

	# Enable IP-forwarding.
	echo 1 > /proc/sys/net/ipv4/ip_forward
	log "enable ip forwarding"

	# Flush forward rules.
	iptables -P FORWARD ACCEPT
	log "change default forward policy"
	iptables -F FORWARD
	log "flush iptables rules"

	# Flush nat rules.
	iptables -t nat -F
	log "flush nat rules"
}

function clear {
	log "deleting namespace ${NODE_NS}"
	ip netns del ${NODE_NS} &>/dev/null

	log "ensure ${NODE_VETH} is down"
	ip link set ${NODE_VETH} down

	log "deleting veth ${NODE_VETH}"
	ip link del ${NODE_VETH} type veth

	log "ensure ${NODE_GENEVE} is down"
	ip link set ${NODE_GENEVE} down

	log "deleting geneve interface ${NODE_GENEVE}"
	ip link del ${NODE_GENEVE} type geneve

	log "ensure bridge is down ${GENEVE_BRIDGE}"
	ip link set ${GENEVE_BRIDGE} down

	log "delete bridge ${GENEVE_BRIDGE}"
	ip link del ${GENEVE_BRIDGE} type bridge

	log "Clear arp table"
	arp -d
}

function setup {
	set -e

	setup_host

	# Create namespace
	ip netns add ${NODE_NS}
	log "created namespace ${NODE_NS}"

	# Create veth link.
	ip link add ${NODE_VETH} type veth peer name ${NODE_VPEER}
	log "created veth pair ${NODE_VETH} <-> ${NODE_VPEER}"

	# Add peer-1 to NODE_NS.
	ip link set ${NODE_VPEER} netns ${NODE_NS}
	log "moved veth ${NODE_VPEER} in ${NODE_NS}"

	# Setup IP address of ${NODE_VETH}.
	#ip addr add ${NODE_VETH_ADDR}/24 dev ${NODE_VETH}
	ip link set ${NODE_VETH} up
	log "set ${NODE_VETH} up"

	ip link set ${NODE_GENEVE} up
	#ip addr add ${NODE_GENEVE_ADDR}/24 dev ${NODE_GENEVE}
	ip route add ${NODE_GENEVE_REMOTE_CIDR} dev ${NODE_GENEVE}
	log "setup ${NODE_GENEVE}"

	# Create bridge
	ip link add ${GENEVE_BRIDGE} type bridge
	#ip addr add ${NODE_BR0_ADDR}/24 dev ${GENEVE_BRIDGE}
	ip link set ${GENEVE_BRIDGE} up
	log "Create bridge ${GENEVE_BRIDGE}"

	ip link set ${NODE_VETH} master ${GENEVE_BRIDGE}
	log "set ${NODE_VETH} in bridge ${GENEVE_BRIDGE}"

	ip link set ${NODE_GENEVE} master ${GENEVE_BRIDGE}
	log "set ${NODE_GENEVE} in bridge ${GENEVE_BRIDGE}"

	# Setup IP ${NODE_VPEER}.
	ip netns exec ${NODE_NS} ip link set lo up
	ip netns exec ${NODE_NS} ip link set ${NODE_VPEER} up
	ip netns exec ${NODE_NS} ip addr add ${NODE_VPEER_ADDR}/24 dev ${NODE_VPEER}
	#ip netns exec ${NODE_NS} ip route add ${NODE_GENEVE_ADDR} dev ${NODE_VPEER}
	#ip netns exec ${NODE_NS} ip route add default via ${NODE_GENEVE_ADDR}
	log "set veth ${NODE_VPEER} networking"

	# Enable masquerading of 10.200.1.0.
	# MANGLE rule should ensure outer ip src becomes eth0 ip
	#iptables -t nat -A POSTROUTING -s ${NODE_VETH_ADDR}/24 -o ${NODE_IFACE} -j MASQUERADE
	#iptables -t mangle -A POSTROUTING  -j CHECKSUM --checksum-fill

	#iptables -A FORWARD -i ${NODE_IFACE}    -o ${GENEVE_BRIDGE} -j ACCEPT
	#iptables -A FORWARD -i ${GENEVE_BRIDGE} -o ${NODE_IFACE}    -j ACCEPT

	#iptables -A FORWARD -i ${NODE_IFACE}  -o ${NODE_VETH}   -j ACCEPT
	#iptables -A FORWARD -i ${NODE_VETH}   -o ${NODE_IFACE}  -j ACCEPT

	#iptables -A FORWARD -i ${NODE_VETH}   -o ${NODE_GENEVE} -j ACCEPT
	#iptables -A FORWARD -i ${NODE_GENEVE} -o ${NODE_VETH}   -j ACCEPT
	log "Added more iptable rules"

	set +e
}

function test_cmds {

	iperf3 -s -B 10.20.20.1 -p 5101
	iperf3 -c 10.20.20.1 -T s1 -p 5101 -t 180 | tee iperf-single-stream-180s-tcp-1.out

	# -A 4,4
	iperf3 -l8948 -Ts1 -u -w4m -b0 -c 10.20.20.1 -p 5101 -t 180 | tee iperf-single-stream-180s-udp-2.out

	iperf3 -s -B 10.20.20.1 -p 5101

iperf3 -s -B 10.20.20.1 -p 5101 &\
iperf3 -s -B 10.20.20.1 -p 5102 &\
iperf3 -s -B 10.20.20.1 -p 5103 &\
iperf3 -s -B 10.20.20.1 -p 5104 &

ip netns exec ns1 iperf3 -s -p 5101 &\
ip netns exec ns1 iperf3 -s -p 5102 &\
ip netns exec ns1 iperf3 -s -p 5103 &\
ip netns exec ns1 iperf3 -s -p 5104 &

iperf3 -s -B 10.200.1.100 -p 5101 &\
iperf3 -s -B 10.200.1.100 -p 5102 &\
iperf3 -s -B 10.200.1.100 -p 5103 &\
iperf3 -s -B 10.200.1.100 -p 5104 &

# TCP Single and parallel streams non jumbo

iperf3 -c 10.200.1.100 -T s1 -p 5101 -t 180 > iperf-vns-single-stream-180s-tcp-1.out &&\
iperf3 -c 10.200.1.100 -T s1 -p 5101 -t 180 > iperf-vns-single-stream-180s-tcp-2.out &&\
iperf3 -c 10.200.1.100 -T s1 -p 5101 -t 180 > iperf-vns-single-stream-180s-tcp-3.out 

# TCP parallel streams three 

iperf3 -c 10.200.1.100 -T s1 -p 5101 -t 180 > iperf-vns-parallel-stream-3-180s-tcp-t1-1.out &\
iperf3 -c 10.200.1.100 -T s2 -p 5102 -t 180 > iperf-vns-parallel-stream-3-180s-tcp-t2-1.out &\
iperf3 -c 10.200.1.100 -T s3 -p 5103 -t 180 > iperf-vns-parallel-stream-3-180s-tcp-t3-1.out

iperf3 -c 10.200.1.100 -T s1 -p 5101 -t 180 > iperf-vns-parallel-stream-3-180s-tcp-t1-2.out &\
iperf3 -c 10.200.1.100 -T s2 -p 5102 -t 180 > iperf-vns-parallel-stream-3-180s-tcp-t2-2.out &\
iperf3 -c 10.200.1.100 -T s3 -p 5103 -t 180 > iperf-vns-parallel-stream-3-180s-tcp-t3-2.out

iperf3 -c 10.200.1.100 -T s1 -p 5101 -t 180 > iperf-vns-parallel-stream-3-180s-tcp-t1-3.out &\
iperf3 -c 10.200.1.100 -T s2 -p 5102 -t 180 > iperf-vns-parallel-stream-3-180s-tcp-t2-3.out &\
iperf3 -c 10.200.1.100 -T s3 -p 5103 -t 180 > iperf-vns-parallel-stream-3-180s-tcp-t3-3.out \

# TCP parallel streams four

iperf3 -c 10.200.1.100 -T s1 -p 5101 -t 180 > iperf-vns-parallel-stream-4-180s-tcp-t1-1.out &\
iperf3 -c 10.200.1.100 -T s2 -p 5102 -t 180 > iperf-vns-parallel-stream-4-180s-tcp-t2-1.out &\
iperf3 -c 10.200.1.100 -T s3 -p 5103 -t 180 > iperf-vns-parallel-stream-4-180s-tcp-t3-1.out &\
iperf3 -c 10.200.1.100 -T s3 -p 5104 -t 180 > iperf-vns-parallel-stream-4-180s-tcp-t4-1.out

iperf3 -c 10.200.1.100 -T s1 -p 5101 -t 180 > iperf-vns-parallel-stream-4-180s-tcp-t1-2.out &\
iperf3 -c 10.200.1.100 -T s2 -p 5102 -t 180 > iperf-vns-parallel-stream-4-180s-tcp-t2-2.out &\
iperf3 -c 10.200.1.100 -T s3 -p 5103 -t 180 > iperf-vns-parallel-stream-4-180s-tcp-t3-2.out &\
iperf3 -c 10.200.1.100 -T s3 -p 5104 -t 180 > iperf-vns-parallel-stream-4-180s-tcp-t4-2.out

iperf3 -c 10.200.1.100 -T s1 -p 5101 -t 180 > iperf-vns-parallel-stream-4-180s-tcp-t1-3.out &\
iperf3 -c 10.200.1.100 -T s2 -p 5102 -t 180 > iperf-vns-parallel-stream-4-180s-tcp-t2-3.out &\
iperf3 -c 10.200.1.100 -T s3 -p 5103 -t 180 > iperf-vns-parallel-stream-4-180s-tcp-t3-3.out &\
iperf3 -c 10.200.1.100 -T s3 -p 5104 -t 180 > iperf-vns-parallel-stream-4-180s-tcp-t4-3.out

# TCP parallel streams five

iperf3 -c 10.200.1.100 -T s1 -p 5101 -t 180 > iperf-vns-parallel-stream-5-180s-tcp-t1-1.out &\
iperf3 -c 10.200.1.100 -T s2 -p 5102 -t 180 > iperf-vns-parallel-stream-5-180s-tcp-t2-1.out &\
iperf3 -c 10.200.1.100 -T s3 -p 5103 -t 180 > iperf-vns-parallel-stream-5-180s-tcp-t3-1.out &\
iperf3 -c 10.200.1.100 -T s3 -p 5104 -t 180 > iperf-vns-parallel-stream-5-180s-tcp-t4-1.out &\
iperf3 -c 10.200.1.100 -T s3 -p 5105 -t 180 > iperf-vns-parallel-stream-5-180s-tcp-t5-1.out

iperf3 -c 10.200.1.100 -T s1 -p 5101 -t 180 > iperf-vns-parallel-stream-5-180s-tcp-t1-2.out &\
iperf3 -c 10.200.1.100 -T s2 -p 5102 -t 180 > iperf-vns-parallel-stream-5-180s-tcp-t2-2.out &\
iperf3 -c 10.200.1.100 -T s3 -p 5103 -t 180 > iperf-vns-parallel-stream-5-180s-tcp-t3-2.out &\
iperf3 -c 10.200.1.100 -T s3 -p 5104 -t 180 > iperf-vns-parallel-stream-5-180s-tcp-t4-2.out &\
iperf3 -c 10.200.1.100 -T s3 -p 5105 -t 180 > iperf-vns-parallel-stream-5-180s-tcp-t5-2.out &

iperf3 -c 10.200.1.100 -T s1 -p 5101 -t 180 > iperf-vns-parallel-stream-5-180s-tcp-t1-3.out &\
iperf3 -c 10.200.1.100 -T s2 -p 5102 -t 180 > iperf-vns-parallel-stream-5-180s-tcp-t2-3.out &\
iperf3 -c 10.200.1.100 -T s3 -p 5103 -t 180 > iperf-vns-parallel-stream-5-180s-tcp-t3-3.out &\
iperf3 -c 10.200.1.100 -T s3 -p 5104 -t 180 > iperf-vns-parallel-stream-5-180s-tcp-t4-3.out &\
iperf3 -c 10.200.1.100 -T s3 -p 5105 -t 180 > iperf-vns-parallel-stream-5-180s-tcp-t5-3.out &

# TCP parallel streams six

iperf3 -c 10.200.1.100 -T s1 -p 5101 -t 180 > iperf-vns-parallel-stream-6-180s-tcp-t1-1.out &\
iperf3 -c 10.200.1.100 -T s2 -p 5102 -t 180 > iperf-vns-parallel-stream-6-180s-tcp-t2-1.out &\
iperf3 -c 10.200.1.100 -T s3 -p 5103 -t 180 > iperf-vns-parallel-stream-6-180s-tcp-t3-1.out &\
iperf3 -c 10.200.1.100 -T s3 -p 5104 -t 180 > iperf-vns-parallel-stream-6-180s-tcp-t4-1.out &\
iperf3 -c 10.200.1.100 -T s3 -p 5105 -t 180 > iperf-vns-parallel-stream-6-180s-tcp-t5-1.out &\
iperf3 -c 10.200.1.100 -T s3 -p 5106 -t 180 > iperf-vns-parallel-stream-6-180s-tcp-t6-1.out &

iperf3 -c 10.200.1.100 -T s1 -p 5101 -t 180 > iperf-vns-parallel-stream-6-180s-tcp-t1-2.out &\
iperf3 -c 10.200.1.100 -T s2 -p 5102 -t 180 > iperf-vns-parallel-stream-6-180s-tcp-t2-2.out &\
iperf3 -c 10.200.1.100 -T s3 -p 5103 -t 180 > iperf-vns-parallel-stream-6-180s-tcp-t3-2.out &\
iperf3 -c 10.200.1.100 -T s3 -p 5104 -t 180 > iperf-vns-parallel-stream-6-180s-tcp-t4-2.out &\
iperf3 -c 10.200.1.100 -T s3 -p 5105 -t 180 > iperf-vns-parallel-stream-6-180s-tcp-t5-2.out &\
iperf3 -c 10.200.1.100 -T s3 -p 5106 -t 180 > iperf-vns-parallel-stream-6-180s-tcp-t6-2.out &

iperf3 -c 10.200.1.100 -T s1 -p 5101 -t 180 > iperf-vns-parallel-stream-6-180s-tcp-t1-3.out &\
iperf3 -c 10.200.1.100 -T s2 -p 5102 -t 180 > iperf-vns-parallel-stream-6-180s-tcp-t2-3.out &\
iperf3 -c 10.200.1.100 -T s3 -p 5103 -t 180 > iperf-vns-parallel-stream-6-180s-tcp-t3-3.out &\
iperf3 -c 10.200.1.100 -T s3 -p 5104 -t 180 > iperf-vns-parallel-stream-6-180s-tcp-t4-3.out &\
iperf3 -c 10.200.1.100 -T s3 -p 5105 -t 180 > iperf-vns-parallel-stream-6-180s-tcp-t5-3.out &\
iperf3 -c 10.200.1.100 -T s3 -p 5106 -t 180 > iperf-vns-parallel-stream-6-180s-tcp-t6-3.out &

# TCP Jumbo

iperf3 -c 10.200.1.100 -T s1 -p 5101 -t 180 > iperf-parallel-stream-4-180s-tcp-jumbo-t1-3.out &\
iperf3 -c 10.200.1.100 -T s2 -p 5102 -t 180 > iperf-parallel-stream-4-180s-tcp-jumbo-t2-3.out &\
iperf3 -c 10.200.1.100 -T s3 -p 5103 -t 180 > iperf-parallel-stream-4-180s-tcp-jumbo-t3-3.out &\
iperf3 -c 10.200.1.100 -T s4 -p 5104 -t 180 > iperf-parallel-stream-4-180s-tcp-jumbo-t4-3.out &

iperf3 -c 10.20.20.1 -T s1 -p 5101 -t 180 > iperf-parallel-stream-4-180s-tcp-jumbo-t1-3.out &\
iperf3 -c 10.20.20.1 -T s2 -p 5102 -t 180 > iperf-parallel-stream-4-180s-tcp-jumbo-t2-3.out &\
iperf3 -c 10.20.20.1 -T s3 -p 5103 -t 180 > iperf-parallel-stream-4-180s-tcp-jumbo-t3-3.out &\
iperf3 -c 10.20.20.1 -T s4 -p 5104 -t 180 > iperf-parallel-stream-4-180s-tcp-jumbo-t4-3.out &\
sleep 10\
iperf3 -c 10.20.20.1 -T s1 -p 5101 -t 180 > iperf-parallel-stream-4-180s-tcp-jumbo-t1-3.out &\
iperf3 -c 10.20.20.1 -T s2 -p 5102 -t 180 > iperf-parallel-stream-4-180s-tcp-jumbo-t2-3.out &\
iperf3 -c 10.20.20.1 -T s3 -p 5103 -t 180 > iperf-parallel-stream-4-180s-tcp-jumbo-t3-3.out &\
iperf3 -c 10.20.20.1 -T s4 -p 5104 -t 180 > iperf-parallel-stream-4-180s-tcp-jumbo-t4-3.out &\
sleep 10\
iperf3 -c 10.20.20.1 -T s1 -p 5101 -t 180 > iperf-parallel-stream-4-180s-tcp-jumbo-t1-3.out &\
iperf3 -c 10.20.20.1 -T s2 -p 5102 -t 180 > iperf-parallel-stream-4-180s-tcp-jumbo-t2-3.out &\
iperf3 -c 10.20.20.1 -T s3 -p 5103 -t 180 > iperf-parallel-stream-4-180s-tcp-jumbo-t3-3.out &\
iperf3 -c 10.20.20.1 -T s4 -p 5104 -t 180 > iperf-parallel-stream-4-180s-tcp-jumbo-t4-3.out &

iperf3 -c 10.20.20.1 -l8948 -T s1 -u -w4m -b0 -T s1 -p 5101 -t 180 > iperf-parallel-stream-4-180s-udp-jumbo-t1-3.out &\
iperf3 -c 10.20.20.1 -l8948 -T s2 -u -w4m -b0 -T s2 -p 5102 -t 180 > iperf-parallel-stream-4-180s-udp-jumbo-t2-3.out &\
iperf3 -c 10.20.20.1 -l8948 -T s3 -u -w4m -b0 -T s3 -p 5103 -t 180 > iperf-parallel-stream-4-180s-udp-jumbo-t3-3.out &\
iperf3 -c 10.20.20.1 -l8948 -T s4 -u -w4m -b0 -T s4 -p 5104 -t 180 > iperf-parallel-stream-4-180s-udp-jumbo-t4-3.out &

iperf3 -c 10.20.20.1 -l8948 -T s1 -u -w4m -b0 -T s1 -p 5101 -t 180 > iperf-parallel-stream-3-180s-udp-jumbo-t1-3.out &\
iperf3 -c 10.20.20.1 -l8948 -T s2 -u -w4m -b0 -T s2 -p 5102 -t 180 > iperf-parallel-stream-3-180s-udp-jumbo-t2-3.out &\
iperf3 -c 10.20.20.1 -l8948 -T s3 -u -w4m -b0 -T s3 -p 5103 -t 180 > iperf-parallel-stream-3-180s-udp-jumbo-t3-3.out &
}

ACTION=${1}
check_root

NODE=${2}
source ./env-node${NODE}.sh
log "loaded environment"

if [ "${ACTION}" = "clear" ];
then
    clear
elif [ "${ACTION}" = "setup" ];
then
    setup
elif [ "${ACTION}" = "both" ];
then
	clear
    setup
else
    log "USAGE ./setup_node2.sh clear/setup/both"
fi