# MPTM

This repository contains code for **Multi Protocol Tunnel Multiplexer (MPTM)** implemented using [ebpf](https://ebpf.io/).
MPTM implements code for multiple tunnel protocols and hooks them in linux at [XDP](https://www.iovisor.org/technology/xdp) hook points.

For detailed description of depedencies, intent, usage etc. please check the blogs:

1. [Towards building an eBPF Based Network Data Plane](https://medium.com/@palani.kodeswaran/towards-building-a-ebpf-based-network-datapath-f6135067c03e)
1. [Towards building an eBPF based Newtork Data plane: Part 2](https://medium.com/@palani.kodeswaran/towards-an-ebpf-based-datapath-part-2-2afd10ada603)

This code is built on top of the [XDP Tutorial](https://github.com/xdp-project/xdp-tutorial).

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
$ bpftool prog loadall xdp_redirect.o /sys/fs/bpf/xdp-redirect type xdp -d
$ ls /sys/fs/bpf/
mptm_xdp_tunnels  xdp-redirect
$ bpftool prog show
295: xdp  name xdp_prog_redire  tag 003a56830efdd07e  gpl
        loaded_at 2022-07-06T07:14:26+0000  uid 0
        xlated 496B  jited 282B  memlock 4096B  map_ids 148
        btf_id 225
299: xdp  name mptm_xdp_tunnel  tag 50719ae3b21776a6  gpl
        loaded_at 2022-07-06T07:15:01+0000  uid 0
        xlated 4752B  jited 2618B  memlock 8192B  map_ids 149,150
        btf_id 230
300: xdp  name mptm_xdp_pass_f  tag 3b185187f1855c4c  gpl
        loaded_at 2022-07-06T07:15:01+0000  uid 0
        xlated 16B  jited 18B  memlock 4096B
        btf_id 230
```

Attach to the interfaces ingress

```
$ bpftool net attach xdp id 299 dev veth-node1 overwrite
$ bpftool net attach xdp id 110 dev geneve0 overwrite
```

## Programming the maps

Check the maps created using below command
```
$ bpftool map show
148: hash  name mptm_redirect_m  flags 0x0
        key 4B  value 4B  max_entries 30  memlock 8192B
149: hash  name mptm_tunnel_ifa  flags 0x0
        key 4B  value 64B  max_entries 30  memlock 16384B
150: percpu_array  name xdp_stats_map  flags 0x0
        key 4B  value 16B  max_entries 5  memlock 8192B
155: array  flags 0x0
        key 4B  value 32B  max_entries 1  memlock 4096B
157: array  name pid_iter.rodata  flags 0x480
        key 4B  value 4B  max_entries 1  memlock 8192B
        btf_id 240  frozen
        pids bpftool(459604)
158: array  flags 0x0
        key 4B  value 32B  max_entries 1  memlock 4096B
```

Notice the `mptm_tunnel_ifa` and `mptm_redirect_m` needed by `mptm_xdp_tunnels` and `xdp_prog_redirect` respectively

Now pin the maps using these commands below, the map ids are taken from map show command, notice that the `bpftool prog show`
command output lists the *map_ids* being used by the programs, if you see multiple maps then use those *ids* below which are
listed with program.

```
$ bpftool map pin id 195 /sys/fs/bpf/mptm_tunnels_map
$ bpftool map pin id 197 /sys/fs/bpf/redirect_map
$ ls /sys/fs/bpf/
redirect_map  mptm_tunnels_map  xdp-geneve  xdp-redirect
```

We need to populate the maps with information regarding tunnel outer packet header, ip address to mangle, mac addresses and interfaces to look for.
We will use the [`mptm_xdp_tunnels_user`](./src/user/mptm_xdp_tunnels_user.c  binary we compiled in the [build](#build) step to do that.

The binary `xdp_geneve_user` needs [libbpf](./deps/libbpf/) shared library for running which gets compiled on your system the
first time you run `make`.

The command is run as,

```
$ ./build/mptm_xdp_tunnels_user --verbose 1 --redirect 0 --flags 0 --tunnel 3 --vlid 0 --source_port 51234 --ingress_iface 48 --source_ip 10.200.1.100 --source_mac 16:d5:6c:3a:46:95 --dest_ip 10.20.20.2 --dest_mac b8:ce:f6:27:93:39 --inner_dest_mac c2:92:e5:ab:9d:88 -a ADD
opt: V arg: 1 
opt: r arg: 0 
opt: f arg: 0 
opt: t arg: 3 
opt: v arg: 0 
opt: p arg: 51234 
opt: I arg: 48 
opt: s arg: 10.200.1.100 
opt: S arg: 16:d5:6c:3a:46:95 
opt: d arg: 10.20.20.2 
opt: D arg: b8:ce:f6:27:93:39 
opt: M arg: c2:92:e5:ab:9d:88 
opt: a arg: ADD 
Arguments verified
Opened bpf map file /sys/fs/bpf/mptm_tunnels_map
Creating tunnel info object
Tunnel info object created
Key (dest ip) is 169088002
action is add, adding mptm_tunnels_map entry
```

Check if map entry got created by - 

```
$ bpftool map show
148: hash  name mptm_redirect_m  flags 0x0
        key 4B  value 4B  max_entries 30  memlock 8192B
149: hash  name mptm_tunnel_ifa  flags 0x0
        key 4B  value 64B  max_entries 30  memlock 16384B
150: percpu_array  name xdp_stats_map  flags 0x0
        key 4B  value 16B  max_entries 5  memlock 8192B
159: array  flags 0x0
        key 4B  value 32B  max_entries 1  memlock 4096B
161: array  name pid_iter.rodata  flags 0x480
        key 4B  value 4B  max_entries 1  memlock 8192B
        btf_id 245  frozen
        pids bpftool(460357)
162: array  flags 0x0
        key 4B  value 32B  max_entries 1  memlock 4096B
$ bpftool map dump id 149
key:
02 14 14 0a
value:
01 03 00 00 00 00 00 00  00 00 00 00 00 00 00 00
00 00 00 00 00 00 00 00  22 c8 00 00 02 14 14 0a
64 01 c8 0a c2 92 e5 ab  9d 88 16 d5 6c 3a 46 95
b8 ce f6 27 93 39 00 00  00 00 00 00 00 00 00 00
Found 1 element
```

TODO: Update

Add an entry to the redirect map for reverse path traffic as,
`xdp_geneve_user -c CAPTURE_INTERFACE -i IFACE_ID_OF_VETH_NODE1_ROOTNS -r IFACE_ID_OF_GENEVE0_NODE1 -o ADD`

```
$ ./build/xdp_geneve_user -c 15 -i 18 -r 20 -o ADD
opt: c arg: 15 
opt: i arg: 18 
opt: r arg: 20 
opt: o arg: ADD 
Using map dir: /sys/fs/bpf, iface 18 
redirect iface id is set to 20
operation is add, adding redirect entry
$ bpftool map dump id 197
key: 14 00 00 00  value: 12 00 00 00
Found 1 element
```

## Show packets coming on xdp interface

```
$ xdpdump -i veth-node1 -x --rx-capture entry,exit
```

## Generating Traffic:

```
ip netns exec NS1 ping 10.200.1.2
```

# License

Adding info regarding appropriate licenses etc. is WIP.

# Extra

Cleaning iptables completely

```
iptables -F && iptables -t nat -F && iptables -t mangle -F && iptables -X

```

If the `libbpf` library doesn't load then to pass shared libary to the binary at runtime you can use this command,
```
export LD_LIBRARY_PATH=${PWD}/deps/libbpf/src
```

run from inside the root directory of project.
