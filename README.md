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
xdp_geneve_user -s IP_ADDRESS_OF_VETH_INSIDE_NS -d IP_OF_OTHER_NODE -e VETH_MAC_INSIDE_NS -t VETH_MAC_IN_ROOT_NS?
#xdp_geneve_user -f 0 -v 0 -p 51234 -i 19 -c 2 -s 10.200.1.2 -d 10.162.185.12 -e 22:31:45:ea:9e:23 -t a6:89:61:a3:e2:d5 -o  ADD
#MANGLE rule should ensure outer ip src becomes eth0 ip

#xdp_geneve_user -f 0 -v 0 -p 51234 -i 19 -c 2 -s 10.162.185.158 -d 10.162.185.12 -e 22:31:45:ea:9e:23 -t a6:89:61:a3:e2:d5 -q 66:02:f4:4e:79:91 -o  ADD 