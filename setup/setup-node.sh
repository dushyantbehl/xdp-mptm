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

function setup_host {
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

function setup {
	set -e

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
	log "setup ${NODE_VETH}"

	ip link add name ${NODE_GENEVE} type geneve id 0 remote ${NODE_GENEVE_REMOTE_ADDR}
	ip link set ${NODE_GENEVE} up
	ip route add ${NODE_GENEVE_REMOTE_CIDR} dev ${NODE_GENEVE}
	log "setup ${NODE_GENEVE}"

	# Create bridge
	ip link add ${GENEVE_BRIDGE} type bridge
	ip addr add ${NODE_BR0_ADDR}/24 dev ${GENEVE_BRIDGE}
	ip link set ${GENEVE_BRIDGE} up
	ip link set ${NODE_VETH} master ${GENEVE_BRIDGE}
	ip link set ${NODE_GENEVE} master ${GENEVE_BRIDGE}

	# Setup IP ${NODE_VPEER}.
	ip netns exec ${NODE_NS} ip link set lo up
	ip netns exec ${NODE_NS} ip link set ${NODE_VPEER} up
	ip netns exec ${NODE_NS} ip addr add ${NODE_VPEER_ADDR}/24 dev ${NODE_VPEER}
	ip netns exec ${NODE_NS} ip route add ${NODE_BR0_ADDR} dev ${NODE_VPEER}
	ip netns exec ${NODE_NS} ip route add default via ${NODE_BR0_ADDR}
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
	#log "Added more iptable rules"

	set +e
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
	setup_host
    setup
elif [ "${ACTION}" = "both" ];
then
	clear
	setup_host
    setup
else
    log "USAGE ./setup_node2.sh clear/setup/both"
fi