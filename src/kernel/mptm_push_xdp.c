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

#define MAX_ENTRIES 30
struct bpf_map_def SEC("maps") mptm_tunnel_iface_map = {
    .type        = BPF_MAP_TYPE_HASH,
    .key_size    = sizeof(__u32),
    .value_size  = sizeof(mptm_tunnel_info),
    .max_entries = MAX_ENTRIES,
};

SEC("mptm_push")
int mptm_xdp_tunnel_push(struct xdp_md *ctx) {
    int action = XDP_PASS;  //default action
    struct ethhdr *eth;
    mptm_tunnel_info* tn;
    __u8 tun_type;

    /* Parse the ethhdr and tunnel info from ctx,
     * the key based lookup happens inside this function
     */
    if (parse_tunnel_info(ctx, &eth, &tn) != 0){
        goto out;
    }

    tun_type = tn->tunnel_type;
    if (tun_type == VLAN) {
        action = trigger_vlan_push(ctx, eth, tn);
    }
    else if (tun_type == GENEVE) {
        action = trigger_geneve_push(ctx, eth, tn);
    } else {
        // Unknown tunnel type
        goto out;
    }

    if (tn->redirect) {
        action = bpf_redirect(tn->redirect_if, tn->flags);
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
}

SEC("mptm_pass")
int mptm_xdp_pass_func(struct xdp_md *ctx) {
    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
