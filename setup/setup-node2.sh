#!/usr/bin/env bash

set -x

if [[ $EUID -ne 0 ]]; then
	echo "You must be root to run this script"
	exit 1
fi

export NODE2_IFACE="ens6f1np1"
export NODE2_NS="ns2"
export NODE2_VETH="veth-node2"
export NODE2_VPEER="veth-ns2"
export NODE2_GENEVE="geneve2"
export NODE2_VETH_ADDR="10.200.2.1"
export NODE2_VPEER_ADDR="10.200.2.100"
# Create gevene interface for decapsulation
export NODE2_GENEVE_ADDR="10.200.2.2"
# this is the address of eth0 on node1
export NODE2_GENEVE_REMOTE_ADDR="10.20.20.1"
# Geneve CIDR
export NODE2_GENEVE_REMOTE_CIDR="10.200.1.0/24"


# Remove namespace if it exists.
ip netns del ${NODE2_NS} &>/dev/null
ip link del ${NODE2_VETH} type veth
ip link del ${NODE2_GENEVE} type geneve 

# Create namespace
ip netns add ${NODE2_NS}

# Create veth link.
ip link add ${NODE2_VETH} type veth peer name ${NODE2_VPEER}

# Add peer-1 to NODE2_NS.
ip link set ${NODE2_VPEER} netns ${NODE2_NS}

# Setup IP address of ${NODE2_VETH}.
ip addr add ${NODE2_VETH_ADDR}/24 dev ${NODE2_VETH}
ip link set ${NODE2_VETH} up

# Setup IP ${NODE2_VPEER}.
ip netns exec ${NODE2_NS} ip addr add ${NODE2_VPEER_ADDR}/24 dev ${NODE2_VPEER}
ip netns exec ${NODE2_NS} ip link set ${NODE2_VPEER} up
ip netns exec ${NODE2_NS} ip link set lo up
ip netns exec ${NODE2_NS} ip route add ${NODE2_VETH_ADDR} dev ${NODE2_VPEER}
ip netns exec ${NODE2_NS} ip route add default via ${NODE2_VETH_ADDR}

# Enable IP-forwarding.
echo 1 > /proc/sys/net/ipv4/ip_forward

# Flush forward rules.
iptables -P FORWARD DROP
iptables -F FORWARD

# Flush nat rules.
iptables -t nat -F

# Enable masquerading of 10.200.1.0.
iptables -t nat -A POSTROUTING -s ${NODE2_VETH_ADDR}/24 -o ${NODE2_IFACE} -j MASQUERADE
iptables -t mangle -A POSTROUTING  -j CHECKSUM --checksum-fill

iptables -A FORWARD -i ${NODE2_IFACE} -o ${NODE2_VETH} -j ACCEPT
iptables -A FORWARD -o ${NODE2_IFACE} -i ${NODE2_VETH} -j ACCEPT

ip link add name ${NODE2_GENEVE} type geneve id 0 remote ${NODE2_GENEVE_REMOTE_ADDR}
ip link set ${NODE2_GENEVE} up
ip route add ${NODE2_GENEVE_REMOTE_CIDR} dev ${NODE2_GENEVE}