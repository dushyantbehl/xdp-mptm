#!/usr/bin/env bash

 set -x

if [[ $EUID -ne 0 ]]; then
	echo "You must be root to run this script"
	exit 1
fi


# this will be the address which geneve header writes
GENEVE_ADDR="10.200.2.10"
# this is the address of eth0 on node1
REMOTE_ADDR="10.10.10.1"
# Geneve CIDR
REMOTE_CIDR="10.200.1.0/24"

ip link add name geneve0 type geneve id 0 remote ${REMOTE_ADDR}
ip link set geneve0 up
ip route add ${REMOTE_CIDR} dev geneve0
