#!/usr/bin/env bash

 set -x

if [[ $EUID -ne 0 ]]; then
	echo "You must be root to run this script"
	exit 1
fi


GENEVE_ADDR="10.200.2.10"
REMOTE_ADDR="10.162.185.158"
REMOTE_CIDR="10.200.1.0/24"

ip link add name geneve0 type geneve id 0 remote ${REMOTE_ADDR}
ip link set geneve0 up
ip route add ${REMOTE_CIDR} dev geneve0
