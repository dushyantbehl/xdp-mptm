/* SPDX-License-Identifier: GPL-2->0 */

#include <linux/bpf.h>
#include <linux/in.h>

#include <linux/if_ether.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
//#include <iproute2/bpf_elf.h>

#include <common/redirect_helpers.h>
#include <common/parsing_helpers.h>

#include <kernel/lib/headers.h>
#include <kernel/lib/helpers.h>

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

/* Move to a common function and then multiplex the code */

/* TODO: these functions have a lot of overlap
 * maybe move common stuff to a header
 */
SEC("mptm_geneve_push")
int mptm_geneve_push(struct xdp_md *ctx) {
    int action = XDP_PASS;  //default action
    struct ethhdr *eth;
    mptm_tunnel_info* tn;

    /* Parse the ethhdr and tunnel info from ctx,
     * the key based lookup happens inside this function
     */
    if (parse_tunnel_info(ctx, &eth, &tn) != 0){
        goto out;
    }

    switch (tn->tunnel_type)
    {
    case VLAN:
        action = trigger_vlan_push(ctx, eth, tn);
        break;
    case GENEVE:
        action = trigger_geneve_push(ctx, eth, tn);
        break;
    case NONE:
    default:
        break;
    }

    if (tn->redirect) {
        action = bpf_redirect(tn->redirect_if, tn->flags);
    }
  out:
    return xdp_stats_record_action(ctx, action);
}

SEC("mptm_xdp_pass")
int mptm_xdp_pass_func(struct xdp_md *ctx) {
    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
