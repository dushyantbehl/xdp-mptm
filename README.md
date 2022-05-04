* MPTM

This repository contains code for **Multi Protocol Tunnel Multiplexer (MPTM)** implemented using [ebpf](https://ebpf.io/).
MPTM implements code for multiple tunnel protocols and hooks them in linux at [XDP](https://www.iovisor.org/technology/xdp) hook points.

This code is built on top of the XDP tutorial available at: [[https://github.com/xdp-project/xdp-tutorial][XDP Tutorial]].

Adding info regarding appropriate licenses etc. is WIP.

* Based on libbpf

This XDP-tutorial leverages [[https://github.com/libbpf/libbpf/][libbpf]]

* Build

Run ``make`` in root folder.

* How to run
![System setup for testing](docs/setup.png "System setup for testing")

We provide 2 files to setup system according to the architecture above

[setup-node1.sh](./setup/setup-node1.sh) is for setting up Node 1 while [setup-node2.sh](./setup/setup-node2.sh) is for setting up Node 2.


* Attaching MPTM implementation to interfaces:

TODO: Expand

prog loadall
bpftool map pin id map /sys/fs/bpf/tunnel_map_iface
xdpdump net attach

export LD_LIBRARY_PATH=${PWD}/deps/libbpf/src
xdp_geneve_user -s IP_ADDRESS_OF_VETH_INSIDE_NS -d IP_OF_OTHER_NODE -e VETH_MAC_INSIDE_NS -t VETH_MAC_IN_ROOT_NS?
#xdp_geneve_user -f 0 -v 0 -p 51234 -i 19 -c 2 -s 10.200.1.2 -d 10.162.185.12 -e 22:31:45:ea:9e:23 -t a6:89:61:a3:e2:d5 -o  ADD
#MANGLE rule should ensure outer ip src becomes eth0 ip

./xdp_geneve_user -f 0 -v 152 -p 51234 -i 10 -c 4 -s 10.200.1.2 -d 9.109.124.154 -e 5e:2b:e9:95:77:9b -t 4e:85:96:d3:15:d0 -q 5e:81:0b:8b:15:46 -o ADD

#xdp_geneve_user -f 0 -v 0 -p 51234 -i 19 -c 2 -s 10.162.185.158 -d 10.162.185.12 -e 22:31:45:ea:9e:23 -t a6:89:61:a3:e2:d5 -q 66:02:f4:4e:79:91 -o  ADD 


* Generating Traffic: