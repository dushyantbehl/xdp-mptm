XDP code for tunnel experiments go here.

Our code is built off the XDP tutorial available at: [[https://github.com/xdp-project/xdp-tutorial][XDP Tutorial]].

Adding info regarding appropriate licenses etc. is WIP.


* Based on libbpf
This XDP-tutorial leverages [[https://github.com/libbpf/libbpf/][libbpf]]


* Build
run ``make`` in xdp folder, after installing necessary dependencies.

* How to run *
# Flush nat rules.
iptables -t nat -F

# Enable masquerading of 10.200.1.0.
iptables -t nat -A POSTROUTING -s ${VPEER_ADDR}/24 -o ${IFACE} -j MASQUERADE
iptables -t mangle -A POSTROUTING  -j CHECKSUM --checksum-fill


iptables -A FORWARD -i ${IFACE} -o ${VETH} -j ACCEPT
iptables -A FORWARD -o ${IFACE} -i ${VETH} -j ACCEPTx

rm /sys/fs/bpf/genevenew -rf
rm /sys/fs/bpf/tunnel_map_iface

prog loadall
bpftool map pin id map /sys/fs/bpf/tunnel_map_iface
xdpdump net attach

export LD_LIBRARY_PATH=${PWD}/deps/libbpf/src
xdp_geneve_user -s IP_ADDRESS_OF_VETH_INSIDE_NS -d IP_OF_OTHER_NODE -e VETH_MAC_INSIDE_NS -t VETH_MAC_IN_ROOT_NS?
#xdp_geneve_user -f 0 -v 0 -p 51234 -i 19 -c 2 -s 10.200.1.2 -d 10.162.185.12 -e 22:31:45:ea:9e:23 -t a6:89:61:a3:e2:d5 -o  ADD
#MANGLE rule should ensure outer ip src becomes eth0 ip

./xdp_geneve_user -f 0 -v 152 -p 51234 -i 10 -c 4 -s 10.200.1.2 -d 9.109.124.154 -e 5e:2b:e9:95:77:9b -t 4e:85:96:d3:15:d0 -q 5e:81:0b:8b:15:46 -o ADD

#xdp_geneve_user -f 0 -v 0 -p 51234 -i 19 -c 2 -s 10.162.185.158 -d 10.162.185.12 -e 22:31:45:ea:9e:23 -t a6:89:61:a3:e2:d5 -q 66:02:f4:4e:79:91 -o  ADD 

# Other README

Setting up the namespaces

We need to set up two nodes/machines and create a namespace within each  to act as end-points for the tunnel. We use the following instruction to set the namespaces up

XXX: Add diagram

On `node1`  we create a namespace ns1 and add a veth interface to the namespace. We assign ip addresses in the 10.200.1/24 range to interfaces in the ns1 and root namespaces as follows:

`ip netns add ns1`
`ip link add v-eth1 type veth peer name v-peer1`
`ip link set v-peer1 netns ns1`
`ip addr add 10.200.1.1/24 dev v-eth1`
`ip link set v-eth1 up`

`ip netns exec ns1 ip addr add 10.200.1.2/24 dev v-peer1`
`ip netns exec ns1 ip link set v-peer1 up`
`ip netns exec ns1 ip link set lo up`
`ip netns exec ns1 ip route add default via 10.200.1.1`



Similarly on `node2` we create a namespace ns2 and assign ip addresses in  10.200.2/24 to the veth interface in the root and ns2 namespace as follows:

`ip netns add ns2`
`ip link add v-eth2 type veth peer name v-peer2`
`ip link set v-peer2 netns ns2`
`ip addr add 10.200.2.1/24 dev v-eth2`
`ip link set v-eth2 up`

`ip netns exec ns2 ip addr add 10.200.2.2/24 dev v-peer2`
`ip netns exec ns2 ip link set v-peer2 up`
`ip netns exec ns2 ip link set lo up`
`ip netns exec ns2 ip route add default via 10.200.2.1`

We then need to setup routing entries in the root namespaces to route traffic to the  tunnel. We first enable IP-forwarding on the nodes with
`echo 1 > /proc/sys/net/ipv4/ip_forward`

On node1:
`ip route add 10.200.2.0/24 dev v-eth1`

On node2:
`ip route add 10.200.1.0/24 dev v-eth2`

Attaching XDP Geneve Implementation to interfaces:

Generating Traffic: