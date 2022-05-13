#!/usr/bin/env bash

 set -x

if [[ $EUID -ne 0 ]]; then
	echo "You must be root to run this script"
	exit 1
fi


export NODE1_IFACE="ens6f1"
export NODE1_NS="ns1"
export NODE1_VETH="veth-node1"
export NODE1_VPEER="veth-ns1"
export NODE1_GENEVE="geneve1"
export NODE1_VETH_ADDR="10.200.1.1"
export NODE1_VPEER_ADDR="10.200.1.100"
# Create gevene interface for decapsulation
export NODE1_GENEVE_ADDR="10.200.1.10"
# this is the address of eth0 on node2
export NODE1_GENEVE_REMOTE_ADDR="10.20.20.2"
# Geneve CIDR
export NODE1_GENEVE_REMOTE_CIDR="10.200.2.0/24"

# Remove namespace if it exists.
ip netns del ${NODE1_NS} &>/dev/null
ip link del ${NODE1_VETH} type veth peer name ${NODE1_VPEER}

# Create namespace
ip netns add ${NODE1_NS}

# Create veth link.
ip link add ${NODE1_VETH} type veth peer name ${NODE1_VPEER}

# Add peer-1 to NODE1_NS.
ip link set ${NODE1_VPEER} netns $NODE1_NS

# Setup IP address of ${NODE1_VETH}.
ip addr add ${NODE1_VETH_ADDR}/24 dev ${NODE1_VETH}
ip link set ${NODE1_VETH} up

# Setup IP ${NODE1_VPEER}.
ip netns exec $NODE1_NS ip addr add ${NODE1_VPEER_ADDR}/24 dev ${NODE1_VPEER}
ip netns exec $NODE1_NS ip link set ${NODE1_VPEER} up
ip netns exec $NODE1_NS ip link set lo up
ip netns exec $NODE1_NS ip route add ${NODE1_VETH_ADDR} dev ${NODE1_VPEER}
ip netns exec $NODE1_NS ip route add default via ${NODE1_VETH_ADDR}

# Enable IP-forwarding.
echo 1 > /proc/sys/net/ipv4/ip_forward

# Flush forward rules.
iptables -P FORWARD DROP
iptables -F FORWARD

# Flush nat rules.
iptables -t nat -F

# Enable masquerading of 10.200.1.0.
iptables -t nat -A POSTROUTING -s ${NODE1_VETH_ADDR}/24 -o ${NODE1_IFACE} -j MASQUERADE
iptables -t mangle -A POSTROUTING  -j CHECKSUM --checksum-fill

iptables -A FORWARD -i ${NODE1_IFACE} -o ${NODE1_VETH} -j ACCEPT
iptables -A FORWARD -o ${NODE1_IFACE} -i ${NODE1_VETH} -j ACCEPT

ip link add name ${NODE1_GENEVE} type geneve id 0 remote ${NODE1_GENEVE_REMOTE_ADDR}
ip link set ${NODE1_GENEVE} up
ip route add ${NODE1_GENEVE_REMOTE_CIDR} dev ${NODE1_GENEVE}