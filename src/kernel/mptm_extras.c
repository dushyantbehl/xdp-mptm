/* SPDX-License-Identifier: GPL-2.0
 *  
 * Authors:
 * Dushyant Behl <dushyantbehl@in.ibm.com>
 * Sayandeep Sen <sayandes@in.ibm.com>
 * Palanivel Kodeswaran <palani.kodeswaran@in.ibm.com>
 */

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

#include <kernel/lib/mptm-debug.h>

#define MAX_ENTRIES 30

struct bpf_map_def SEC("maps") mptm_redirect_devmap = {
    .type        = BPF_MAP_TYPE_DEVMAP_HASH,
    .key_size    = sizeof(__u32),
    .value_size  = sizeof(__u32),
    .max_entries = MAX_ENTRIES,
};

SEC("mptm_redirect")
int  xdp_prog_redirect(struct xdp_md *ctx) {
    __u64 flags = 0;
    __u32 key = ctx->ingress_ifindex;

    return bpf_redirect_map(&mptm_redirect_devmap, key, flags);
}

SEC("mptm_pass")
int mptm_xdp_pass_func(struct xdp_md *ctx) {
    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
