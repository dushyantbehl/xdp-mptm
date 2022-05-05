# MPTM

This repository contains code for **Multi Protocol Tunnel Multiplexer (MPTM)** implemented using [ebpf](https://ebpf.io/).
MPTM implements code for multiple tunnel protocols and hooks them in linux at [XDP](https://www.iovisor.org/technology/xdp) hook points.

This code is built on top of the [XDP Tutorial](https://github.com/xdp-project/xdp-tutorial).

Adding info regarding appropriate licenses etc. is WIP.

## Based on libbpf

This XDP-tutorial leverages [libbpf](https://github.com/libbpf/libbpf/).

## Build

Run ``make`` in root folder.

# How to Run
![System setup for testing](docs/setup.png "System setup for testing")

We provide 2 files to setup system according to the architecture above

[setup-node1.sh](./setup/setup-node1.sh) is for setting up Node 1 while,

[setup-node2.sh](./setup/setup-node2.sh) is for setting up Node 2.


## Attaching MPTM implementation to interfaces:

Load the bpf programs
```
$ cd build/
$ bpftool prog loadall xdp_redirect.o /sys/fs/bpf/xdp-redirect type xdp -d
$ bpftool prog loadall xdp_geneve.o /sys/fs/bpf/xdp-geneve type xdp -d
$ ls /sys/fs/bpf/
xdp-geneve  xdp-redirect
$ bpftool prog show
1236: xdp  name mptm_xdp_geneve  tag 3882107b0c8fafd5  gpl
        loaded_at 2022-05-04T10:58:05+0000  uid 0
        xlated 2640B  jited 1478B  memlock 4096B  map_ids 195,196
        btf_id 250
1237: xdp  name xdp_pass_func  tag 3b185187f1855c4c  gpl
        loaded_at 2022-05-04T10:58:05+0000  uid 0
        xlated 16B  jited 18B  memlock 4096B
        btf_id 250
1241: xdp  name xdp_prog_redire  tag 0af5eaf32951b2e9  gpl
        loaded_at 2022-05-04T10:58:31+0000  uid 0
        xlated 328B  jited 189B  memlock 4096B  map_ids 197
        btf_id 255
```

Check the maps created using below command
```
$ bpftool map show
195: hash  name tunnel_map_ifac  flags 0x0
        key 4B  value 40B  max_entries 30  memlock 12288B
196: percpu_array  name xdp_stats_map  flags 0x0
        key 4B  value 16B  max_entries 5  memlock 8192B
197: hash  name redirect_map  flags 0x0
        key 4B  value 4B  max_entries 30  memlock 8192B
202: array  flags 0x0
        key 4B  value 32B  max_entries 1  memlock 4096B
204: array  name pid_iter.rodata  flags 0x480
        key 4B  value 4B  max_entries 1  memlock 8192B
        btf_id 265  frozen
        pids bpftool(1094964)
205: array  flags 0x0
        key 4B  value 32B  max_entries 1  memlock 4096B
```

Notice the `tunnel_map_ifac` and `redirect_map` needed by `mptm_xdp_geneve` and `xdp_prog_redirect` respectively

Now pin the maps using these commands below, the map ids are taken from map show command, notice that the `bpftool prog show`
command output lists the *map_ids* being used by the programs, if you see multiple maps then use those *ids* below which are
listed with program.

```
$ bpftool map pin id 195 /sys/fs/bpf/tunnel_map_iface
$ bpftool map pin id 197 /sys/fs/bpf/redirect_map
$ ls /sys/fs/bpf/
redirect_map  tunnel_map_iface  xdp-geneve  xdp-redirect
```

## Programming the maps

We need to populate the maps with information regarding tunnel, ip address to mangle, mac addresses and interfaces to look for.
We will use the [`xdp_geneve_user`](./xdp_geneve_user.c) binary we compiled in the [build](#build) step to do that.

The binary `xdp_geneve_user` needs [libbpf](./deps/libbpf/) shared library for running which gets compiled on your system the
first time you run `make`. To pass shared libary to the binary at runtime you can use this command,

```
export LD_LIBRARY_PATH=${PWD}/deps/libbpf/src
```

run from inside the root directory of project.



xdpdump net attach

xdp_geneve_user -s IP_ADDRESS_OF_VETH_INSIDE_NS -d IP_OF_OTHER_NODE -e VETH_MAC_INSIDE_NS -t VETH_MAC_IN_ROOT_NS?
#xdp_geneve_user -f 0 -v 0 -p 51234 -i 19 -c 2 -s 10.200.1.2 -d 10.162.185.12 -e 22:31:45:ea:9e:23 -t a6:89:61:a3:e2:d5 -o  ADD
#MANGLE rule should ensure outer ip src becomes eth0 ip

./xdp_geneve_user -f 0 -v 152 -p 51234 -i 10 -c 4 -s 10.200.1.2 -d 9.109.124.154 -e 5e:2b:e9:95:77:9b -t 4e:85:96:d3:15:d0 -q 5e:81:0b:8b:15:46 -o ADD

 xdp_geneve_user -f 0 -v 0 -p 51234 -i 19 -c 2 -s 10.162.185.158 -d 10.162.185.12 -e 22:31:45:ea:9e:23 -t a6:89:61:a3:e2:d5 -q 66:02:f4:4e:79:91 -o  ADD 

## Generating Traffic:
