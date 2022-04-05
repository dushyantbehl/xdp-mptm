/* SPDX-License-Identifier: GPL-2.0 */
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <common/headers.h>

#define MAX_ENTRIES 30
struct bpf_map_def SEC("maps") redirect_map = {
	.type        = BPF_MAP_TYPE_HASH,	
	.key_size    = sizeof(__u32),
	.value_size  = sizeof(__u32),
	.max_entries = MAX_ENTRIES,
};


SEC("xdp")
int  xdp_prog_redirect(struct xdp_md *ctx)
{
        __u64 flags = 0;
	__u32 key = ctx->ingress_ifindex;
	__u32 *val = bpf_map_lookup_elem(&redirect_map,&key);
	if(val==NULL){
	  bpf_debug("[ERR] map entry missing for iface= %d\n",key);
	  goto out;
	}
	return bpf_redirect(*val,flags);//veth1 interface
out:
	return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
