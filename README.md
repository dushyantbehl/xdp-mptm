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
$ bpftool prog loadall build/mptm.o /sys/fs/bpf/mptm type xdp -d
$ bpftool prog loadall build/mptm_extras.o /sys/fs/bpf/mptm_extras type xdp -d
$ ls /sys/fs/bpf/
mptm  mptm_extras
$ bpftool prog show
655: xdp  name mptm_push_tunne  tag add336b96316eaae  gpl
        loaded_at 2022-09-17T11:15:44+0000  uid 0
        xlated 4680B  jited 2573B  memlock 8192B  map_ids 392,393,394,395
        btf_id 495
656: xdp  name mptm_pop_tunnel  tag 3a9514c008460de8  gpl
        loaded_at 2022-09-17T11:15:44+0000  uid 0
        xlated 2248B  jited 1337B  memlock 4096B  map_ids 392,393,394,395
        btf_id 495
660: xdp  name mptm_redirect  tag 45631072cbc131ed  gpl
        loaded_at 2022-09-17T11:15:50+0000  uid 0
        xlated 64B  jited 44B  memlock 4096B  map_ids 396
        btf_id 500
661: xdp  name mptm_pass  tag 3b185187f1855c4c  gpl
        loaded_at 2022-09-17T11:15:50+0000  uid 0
        xlated 16B  jited 18B  memlock 4096B
        btf_id 500
```

Attach to the interfaces ingress

```
$ bpftool net attach xdp id 655 dev veth-node1 overwrite
$ bpftool net attach xdp id 660 dev geneve1 overwrite
```

```
$ ip a | ack --passthru 'xdp'
146: veth-node1@if145: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 `xdp/id:655` qdisc noqueue state UP group default qlen 1000
    link/ether 62:d6:7b:d3:e8:9f brd ff:ff:ff:ff:ff:ff link-netns vns1
    inet6 fe80::60d6:7bff:fed3:e89f/64 scope link 
       valid_lft forever preferred_lft forever
147: geneve1: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 `xdpgeneric/id:660` qdisc noqueue state UNKNOWN group default qlen 1000
    link/ether ea:bf:69:38:7f:14 brd ff:ff:ff:ff:ff:ff
    inet6 fe80::e8bf:69ff:fe38:7f14/64 scope link 
       valid_lft forever preferred_lft forever
```

Note:- If we need to perform redirect from veth to eth0 interface, we need to attach an XDP_PASS program on the eth0 interface.

```
$ bpftool net attach xdp id 661 dev ens4f0 overwrite
```

## Programming the maps

Check the maps created using below command
```
$ $ bpftool map show
392: hash  name mptm_tunnel_inf  flags 0x0
        key 8B  value 64B  max_entries 1024  memlock 151552B
393: hash  name mptm_tunnel_red  flags 0x0
        key 4B  value 4B  max_entries 2048  memlock 172032B
394: devmap  name mptm_tunnel_red  flags 0x80
        key 4B  value 4B  max_entries 2048  memlock 16384B
395: percpu_array  name xdp_stats_map  flags 0x0
        key 4B  value 16B  max_entries 5  memlock 8192B
396: devmap  name mptm_redirect_d  flags 0x80
        key 4B  value 4B  max_entries 1024  memlock 8192B
401: array  flags 0x0
        key 4B  value 32B  max_entries 1  memlock 4096B
403: array  name pid_iter.rodata  flags 0x480
        key 4B  value 4B  max_entries 1  memlock 8192B
        btf_id 510  frozen
        pids bpftool(4072625)
404: array  flags 0x0
        key 4B  value 32B  max_entries 1  memlock 4096B
```

Notice the `mptm_*` maps needed by `mptm` and `mptm_extras` programs

Now pin the maps using these commands below, the map ids are taken from map show command, notice that the `bpftool prog show`
command output lists the *map_ids* being used by the programs, if you see multiple maps then use those *ids* below which are
listed with program.

```
$ bpftool map pin id 392 /sys/fs/bpf/mptm_tunnel_info_map
$ bpftool map pin id 393 /sys/fs/bpf/mptm_redirect_info_map
$ bpftool map pin id 394 /sys/fs/bpf/mptm_redirect_if_devmap
$ bpftool map pin id 396 /sys/fs/bpf/redirect_devmap
$ ls /sys/fs/bpf/
mptm  mptm_extras  mptm_redirect_if_devmap  mptm_redirect_info_map  mptm_tunnel_info_map  redirect_devmap
```

We need to populate the maps with information regarding tunnel outer packet header, ip address to mangle, mac addresses and interfaces to look for.
We will use the [`mptm_user`](./src/user/mptm_user.c  binary we compiled in the [build](#build) step to do that.

The binary `mptm_user` needs [libbpf](./deps/libbpf/) shared library for running which gets compiled on your system the
first time you run `make`.

The command is run as,

```
$ ./build/mptm_user --enable_logs 0 --redirect 1 --eth0_iface 2 --veth_iface 146 --vpeer_iface 145 --flags 0 --tunnel GENEVE --vlid 0 --source_port 51234 --source_ip 10.30.30.1 --source_mac 68:05:ca:d4:7c:ac --dest_ip 10.30.30.2 --dest_mac 68:05:ca:d4:5c:28 --inner_dest_mac 9e:5c:c2:da:ee:5b -a ADD
opt: l arg: 0 
opt: r arg: 1 
opt: Z arg: 2 
opt: Y arg: 146 
opt: X arg: 145 
opt: f arg: 0 
opt: t arg: GENEVE 
opt: v arg: 0 
opt: p arg: 51234 
opt: s arg: 10.30.30.1 
opt: S arg: 68:05:ca:d4:7c:ac 
opt: d arg: 10.30.30.2 
opt: D arg: 68:05:ca:d4:5c:28 
opt: M arg: 9e:5c:c2:da:ee:5b 
opt: a arg: ADD 
Arguments verified
Opened bpf map file /sys/fs/bpf/mptm_tunnel_info_map at fd 3
Opened bpf map file /sys/fs/bpf/mptm_redirect_info_map at fd 4
Opened bpf map file /sys/fs/bpf/mptm_redirect_if_devmap at fd 5
Creating tunnel info object......created
action is add, map fd 3 adding mptm_tunnel_info_map entry
action is add, map fd 4 adding mptm_redirect_info_map entry
action is add, map fd 5 adding mptm_redirect_if_devmap entry
action is add, map fd 4 adding mptm_redirect_info_map entry
action is add, map fd 5 adding mptm_redirect_if_devmap entry
```

Check if map entry got created by - 

```
$ root@tcnode6:/home/dushyant/xdp-mptm# bpftool map show
392: hash  name mptm_tunnel_inf  flags 0x0
        key 8B  value 64B  max_entries 1024  memlock 151552B
393: hash  name mptm_tunnel_red  flags 0x0
        key 4B  value 4B  max_entries 2048  memlock 172032B
394: devmap  name mptm_tunnel_red  flags 0x80
        key 4B  value 4B  max_entries 2048  memlock 16384B
395: percpu_array  name xdp_stats_map  flags 0x0
        key 4B  value 16B  max_entries 5  memlock 8192B
396: devmap  name mptm_redirect_d  flags 0x80
        key 4B  value 4B  max_entries 1024  memlock 8192B
429: array  flags 0x0
        key 4B  value 32B  max_entries 1  memlock 4096B
431: array  name pid_iter.rodata  flags 0x480
        key 4B  value 4B  max_entries 1  memlock 8192B
        btf_id 545  frozen
        pids bpftool(24012)
432: array  flags 0x0
        key 4B  value 32B  max_entries 1  memlock 4096B
$ root@tcnode6:/home/dushyant/xdp-mptm# bpftool map dump id 392
key:
0a 1e 1e 01 0a 1e 1e 02
value:
00 03 01 00 00 00 00 00  00 00 00 00 00 00 00 00
00 00 00 00 00 00 00 00  c8 22 00 00 0a 1e 1e 02
0a 1e 1e 01 9e 5c c2 da  ee 5b 68 05 ca d4 7c ac
68 05 ca d4 5c 28 00 00  00 00 00 00 00 00 00 00
Found 1 element
root@tcnode6:/home/dushyant/xdp-mptm# bpftool map dump id 393
key: 0a 1e 1e 01  value: 02 00 00 00
key: 00 00 00 00  value: 08 00 00 00
key: 0a 1e 1e 02  value: 92 00 00 00
Found 3 elements
```

and so on...

You can also view the entries which got added by running a lookup via `mptm_user`

```
$ ./build/mptm_user --source_ip 10.30.30.1 --dest_ip 10.30.30.2 -a GET
opt: s arg: 10.30.30.1 
opt: d arg: 10.30.30.2 
opt: a arg: GET 
Arguments verified
Opened bpf map file /sys/fs/bpf/mptm_tunnel_info_map at fd 3
Opened bpf map file /sys/fs/bpf/mptm_redirect_info_map at fd 4
Opened bpf map file /sys/fs/bpf/mptm_redirect_if_devmap at fd 5
Tunnel info element - {
        debug = 0
        redirect = 1
        flags = 0
        tunnel_type = GENEVE
        vlan_id = 0
        source_port = 8904
        source_mac = 68:5:ca:d4:7c:ac
        outer_dest_mac = 68:5:ca:d4:5c:28
        inner_dest_mac = 9e:5c:c2:da:ee:5b
        dest_addr = 10.30.30.2
        source_addr = 10.30.30.1
}
Ingrese redirect if for key 10.30.30.2, 10.30.30.1 to 10.30.30.2 is 2
Egrese redirect if for key 10.30.30.1, 10.30.30.2 to 10.30.30.1 is 146
```

In case you need to delete the entry action can be set to `DEL`

```
$ ./build/mptm_user --source_ip 10.30.30.1 --dest_ip 10.30.30.2 -a DEL
```

Add an entry to the redirect map for reverse path traffic as,
`mptm_extras_user -i IFACE_ID_OF_GENEVE0_NODE1 -r IFACE_ID_OF_VETH_NODE1_ROOTNS -o ADD`

```
$ ./build/mptm_extras_user -i 147 -r 146 -a ADD
opt: i arg: 147 
opt: r arg: 146 
opt: a arg: ADD 
ingress iface:147, redirect iface:146, action:ADD
action is add, map fd 3 adding redirect_devmap entry
```

## Generating Traffic:

```
ip netns exec vns1 ping 10.250.1.101
```

## Show packets coming on xdp interface

```
$ xdpdump -i veth-node1 -x --rx-capture entry,exit
```

# License

Our program is present under GPL 2.0 license.
If separate license terms are needed for any file it is mentioned on top of the file.

# Extra

Command to flush iptables completely

```
iptables -F && iptables -t nat -F && iptables -t mangle -F && iptables -X

```

If the `libbpf` library doesn't load then to pass shared libary to the binary at runtime you can use this command,
```
export LD_LIBRARY_PATH=${PWD}/deps/libbpf/src
```
run from inside the root directory of project.

ip tables command to add checksum fill inside the container.
```
iptables -A POSTROUTING -j CHECKSUM --checksum-fill
```