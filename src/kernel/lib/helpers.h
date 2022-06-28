/* SPDX-License-Identifier: (GPL-2.0-or-later OR BSD-2-clause) */

#ifndef __KERNEL_LIB_HELPERS_H
#define __KERNEL_LIB_HELPERS_H

#include <stddef.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/icmp.h>
#include <linux/icmpv6.h>
#include <linux/udp.h>
#include <linux/tcp.h>

#include <common/rewrite_helpers.h>

#include <kernel/lib/headers.h>
#include <kernel/lib/geneve.h>

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

    __u32 key = bpf_ntohl(iphdr->daddr);
    tn = bpf_map_lookup_elem(&mptm_tunnel_iface_map, &key);
    if(tn == NULL) {
      bpf_debug("[ERR] map entry missing for key %d\n", key);
      goto out;
    }

    /* set return values */
    *ethhdr = eth;
    *mptm_tn = tn;
    ret = 0;

    out:
        return ret;
}

static __always_inline int trigger_geneve_push(struct xdp_md *ctx,
                                               struct ethhdr *eth,
                                               mptm_tunnel_info *tn) {
     // typecast the union to geneve
    struct geneve_info *geneve = (geneve_tunnel_info *)(&tn->tnl_info.geneve);
    if (tn->debug) {
        __u8 *inner_mac = geneve->inner_dest_mac;
        // debug print the contents of map entry
        bpf_debug("mptm_geneve eth_iface:%d f:%d v:%d\n",
                    tn->redirect_if, geneve->vlan_id, tn->flags);
        bpf_debug("mptm_geneve inner_d_mac: %x %x %x\n",
                    inner_mac[0], inner_mac[1], inner_mac[2]);
        bpf_debug("mptm_geneve inner_d_mac: %x %x %x\n",
                    inner_mac[3], inner_mac[4], inner_mac[5]);
    }
    return geneve_tag_push(ctx, eth, geneve);
}

static __always_inline int trigger_vlan_push(struct xdp_md *ctx,
                                             struct ethhdr *eth,
                                             mptm_tunnel_info *tn) {
    // typecast the union to vlan
    struct vlan_info *vlan = (vlan_tunnel_info *)(&tn->tnl_info.vlan);
    if (tn->debug) {
      // debug print the contents of map entry
      bpf_debug("mptm_vlan eth_iface:%d v:%d f:%d \n",
       tn->redirect_if, vlan->vlan_id, tn->flags);
    }
    if (vlan_tag_push(ctx, eth, vlan->vlan_id) != 0) {
        bpf_debug("[ERR] vlan tag push failed %d\n", vlan->vlan_id);
        return XDP_ABORTED;
    }
    return XDP_PASS;
}

#endif /* __KERNEL_LIB_HELPERS_H */
