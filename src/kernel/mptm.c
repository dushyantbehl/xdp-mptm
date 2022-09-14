/* SPDX-License-Identifier: GPL-2->0 
 *  
 * Authors:
 * Dushyant Behl <dushyantbehl@in.ibm.com>
 * Sayandeep Sen <sayandes@in.ibm.com>
 * Palanivel Kodeswaran <palani.kodeswaran@in.ibm.com>
 */

#include <linux/bpf.h>
#include <linux/in.h>

#include <linux/if_ether.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#include <common/parsing_helpers.h>

#include <kernel/lib/pkt-parse.h>
#include <kernel/lib/pkt-encap.h>
#include <kernel/lib/geneve.h>
#include <kernel/lib/map-defs.h>

/* Defines xdp_stats_map */
#include <common/xdp_stats_kern_user.h>
#include <common/xdp_stats_kern.h>

#define MAX_ENTRIES 1024

struct bpf_map_def SEC("maps") mptm_tunnel_info_map = {
    .type        = BPF_MAP_TYPE_HASH,
    .key_size    = sizeof(tunnel_map_key_t),
    .value_size  = sizeof(mptm_tunnel_info),
    .max_entries = MAX_ENTRIES,
};

struct bpf_map_def SEC("maps") mptm_tunnel_redirect_map = {
    .type        = BPF_MAP_TYPE_HASH,
    .key_size    = sizeof(redirect_map_key_t),
    .value_size  = sizeof(__u32),
    .max_entries = MAX_ENTRIES*2,
};

struct bpf_map_def SEC("maps") mptm_tunnel_redirect_if_devmap = {
    .type        = BPF_MAP_TYPE_DEVMAP,
    .key_size    = sizeof(__u32),
    .value_size  = sizeof(__u32),
    .max_entries = MAX_ENTRIES*2,
};

SEC("mptm_push")
int mptm_xdp_tunnel_push(struct xdp_md *ctx) {
    int action = XDP_PASS;  //default action
    struct ethhdr *eth;
    struct iphdr *ip;
    struct tunnel_info* tn;
    tunnel_map_key_t key;
    __u8 tun_type;

    /* Parse the ethhdr and iphdr from ctx */
    if (parse_pkt_headers(ctx, &eth, &ip) != 0){
        goto out;
    }

    key.s_addr = ip->saddr;
    key.d_addr = ip->daddr;

    tn = bpf_map_lookup_elem(&mptm_tunnel_info_map, &key);
    if(tn == NULL) {
      mptm_print("[ERR] map entry missing for key-{saddr:%x,daddr:%x}\n",
                 key.s_addr, key.d_addr);
      goto out;
    }

    tun_type = tn->tunnel_type;
    if (tun_type == VLAN) {
        action = trigger_vlan_push(ctx, eth, tn);
    }
    else if (tun_type == GENEVE) {
        action = trigger_geneve_push(ctx, eth, tn);
    } else {
        bpf_debug("[ERR] tunnel type is unknown");
        goto out;
    }

    if (tn->redirect) {
        __u64 flags = 0; // keep redirect flags zero for now
        __u32 *counter;

        redirect_map_key_t redirect_key = ip->daddr;
        counter = bpf_map_lookup_elem(&mptm_tunnel_redirect_map, &redirect_key);
        if(counter == NULL) {
            bpf_debug("[ERR] map entry missing for redirect key %d\n", redirect_key);
            goto out;
        }

        action = bpf_redirect_map(&mptm_tunnel_redirect_if_devmap, *counter, flags);
    }

  out:
    return xdp_stats_record_action(ctx, action);
}

SEC("mptm_pop")
int mptm_xdp_tunnel_pop(struct xdp_md *ctx) {
    int action = XDP_PASS;  //default action

    // If packet is ENCAPSULATED
    // Check packet tunnel - VLAN? GENEVE? VXLAN? ETC?
    // check inner destination of packet
    // use inner destination ip as the key in the tunnel iface map
    // if present then do decap and send to the ingress interface present
    // in the tunnel map

    /* get key as follows */
    // redirect_map_key_t key = ip->daddr;

    goto out;

  out:
    return xdp_stats_record_action(ctx, action);
}

char _license[] SEC("license") = "GPL";
