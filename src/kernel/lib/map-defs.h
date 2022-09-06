/* SPDX-License-Identifier: GPL-2.0-or-later
 * 
 * Authors:
 * Dushyant Behl <dushyantbehl@in.ibm.com>
 * Sayandeep Sen <sayandes@in.ibm.com>
 * Palanivel Kodeswaran <palani.kodeswaran@in.ibm.com>
 */
#pragma once

#include <linux/bpf.h>

#ifndef __inline
#define __inline inline __attribute__((always_inline))
#endif

#define __ALWAYS_INLINE__ __attribute__((__always_inline__))

#ifndef __ALWAYS_INLINE__
#define __ALWAYS_INLINE__ __attribute__((__always_inline__))
#endif

/* Taken from Katran.
 * ETH_P_IP and ETH_P_IPV6 in Big Endian format.
 * So we don't have to do htons on each packet
 */
#define BE_ETH_P_IP 8
#define BE_ETH_P_IPV6 56710

/* structs used in bpf maps */

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