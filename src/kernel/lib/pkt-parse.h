/* SPDX-License-Identifier: (GPL-2.0-or-later OR BSD-2-clause)
 *
 * Authors:
 * Dushyant Behl <dushyantbehl@in.ibm.com>
 * Sayandeep Sen <sayandes@in.ibm.com>
 * Palanivel Kodeswaran <palani.kodeswaran@in.ibm.com>
*/

#ifndef __PKT_PARSE__
#define __PKT_PARSE__

#pragma once

#include <stddef.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/icmp.h>
#include <linux/icmpv6.h>
#include <linux/udp.h>
#include <linux/tcp.h>

#include <kernel/lib/map-defs.h>
#include <kernel/lib/mptm-debug.h>

extern struct bpf_map_def mptm_tunnel_iface_map;

static __always_inline int parse_tunnel_info(struct xdp_md *ctx,
                        struct ethhdr **ethhdr,
                        mptm_tunnel_info **mptm_tn)
{
    int ret = 1;
    struct hdr_cursor nh;
    mptm_tunnel_info *tn;

    /* These keep track of the next header type and iterator pointer */
    struct ethhdr *eth;
    int nh_type;
    struct iphdr *iphdr;

    void *data = (void *)((long)ctx->data);
    void *data_end = (void *)((long)ctx->data_end);

    nh.pos = data;
    nh_type = parse_ethhdr(&nh, data_end, &eth);
    if (nh_type == -1)
      goto out;
    if (eth->h_proto == bpf_htons(ETH_P_ARP))
      goto out;
    if (eth->h_proto != __constant_htons(ETH_P_IP))
        // We don't support ipv6 for now.
        goto out;

    nh_type = parse_iphdr(&nh, data_end, &iphdr);
    if (nh_type == -1)
      goto out;

    __u32 key = bpf_ntohl(iphdr->saddr);
    tn = bpf_map_lookup_elem(&mptm_tunnel_iface_map, &key);
    if(tn == NULL) {
      mptm_print("[ERR] map entry missing for key %d\n", key);
      goto out;
    }

    /* set return values */
    *ethhdr = eth;
    *mptm_tn = tn;
    ret = 0;

    out:
        return ret;
}

#endif /*  __PKT_PARSE__ */
