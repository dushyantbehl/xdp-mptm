/* SPDX-License-Identifier: GPL-2.0
 *  
 * Authors:
 * Dushyant Behl <dushyantbehl@in.ibm.com>
 * Sayandeep Sen <sayandes@in.ibm.com>
 * Palanivel Kodeswaran <palani.kodeswaran@in.ibm.com>
 */

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

#include <kernel/lib/mptm_debug.h>

#define MAX_ENTRIES 30

struct bpf_map_def SEC("maps") mptm_redirect_devmap = {
    .type        = BPF_MAP_TYPE_DEVMAP,
    .key_size    = sizeof(int),
    .value_size  = sizeof(int),
    .max_entries = MAX_ENTRIES,
};

SEC("mptm_devmap_redirect")
int  xdp_prog_redirect(struct xdp_md *ctx) {
    __u64 flags = 0;
    __u32 key = ctx->ingress_ifindex;

    return bpf_redirect_map(&mpatm_redirect_devmap, key, flags);
}

char _license[] SEC("license") = "GPL";
