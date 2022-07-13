
// SPDX-License-Identifier: GPL-2.0-or-later
/**
 * @file transit_kern.h
 * @author Sherif Abdelwahab (@zasherif)
 *
 * @brief Helper functions, macros and data structures.
 *
 * @copyright Copyright (c) 2019 The Authors.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; version 2 of the License.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 *
 */
#pragma once

#include <linux/bpf.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <linux/tcp.h>
#include <stddef.h>

#ifndef __inline
#define __inline inline __attribute__((always_inline))
#endif

#define __ALWAYS_INLINE__ __attribute__((__always_inline__))

#ifndef __ALWAYS_INLINE__
#define __ALWAYS_INLINE__ __attribute__((__always_inline__))
#endif

enum mptm_tunnel_type {
    NONE = 0,
    VLAN = 1,
    VXLAN = 2,
    GENEVE = 3
};

typedef struct geneve_info {
    __be64 vlan_id;
    __u16 source_port;
    __be32 dest_addr;
    __be32 source_addr;
    __u8 inner_dest_mac[6];
    __u8 source_mac[6] ;
    __u8 dest_mac[6];
} geneve_tunnel_info;

typedef struct vxlan_info {
    __be64 vlan_id;
    // TODO: Expand
} vxlan_tunnel_info;

typedef struct vlan_info {
    __u16 vlan_id;
} vlan_tunnel_info;

typedef struct tunnel_info {
    __u8 debug;
    __u8 tunnel_type;
    __u8 redirect;
    __u16 redirect_if;
    __u16 flags;
    union {
        struct geneve_info geneve;
        struct vxlan_info vxlan;
        struct vlan_info vlan;
    } tnl_info __attribute__((aligned));
} __attribute__((packed)) mptm_tunnel_info;

struct geneve_opt {
    __be16 opt_class;
    __u8 type;
    __u8 length : 5;
    __u8 r3 : 1;
    __u8 r2 : 1;
    __u8 r1 : 1;
    __u8 opt_data[];
};

struct genevehdr {
    /* Big endian! */
    __u8 opt_len : 6;
    __u8 ver : 2;
    __u8 rsvd1 : 6;
    __u8 critical : 1;
    __u8 oam : 1;
    __be16 proto_type;
    __u8 vni[3];
    __u8 rsvd2;
    //struct geneve_opt options[];
};

struct ipv4_tuple_t {
    __u32 saddr;
    __u32 daddr;

    /* ports */
    __u16 sport;
    __u16 dport;

    /* Addresses */
    __u8 protocol;

    /*TODO: include TCP flags, no use case for the moment! */
} __attribute__((packed));

