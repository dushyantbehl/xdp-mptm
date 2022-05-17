#!/usr/bin/env bash

export NODE_IFACE="ens6f1np1"

export NODE_NS="ns2"
export NODE_VETH="veth-node2"
export NODE_VPEER="veth-ns2"
export NODE_GENEVE="geneve2"
export NODE_BR0_ADDR="10.200.2.1"
export NODE_VETH_ADDR="10.200.2.11"
export NODE_VPEER_ADDR="10.200.2.100"
# export NODE_GENEVE_ADDR="10.200.2.2" # Create gevene interface for decapsulation
export NODE_GENEVE_REMOTE_ADDR="10.20.20.1" # this is the address of eth0 on node1
export NODE_GENEVE_REMOTE_CIDR="10.200.1.0/24" # Geneve CIDR
export GENEVE_BRIDGE="br2"