/* SPDX-License-Identifier: GPL-2->0 */

#include <linux/bpf.h>
#include <linux/in.h>

#include <linux/if_ether.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
//#include <iproute2/bpf_elf.h>


// The parsing helper functions from the packet01 lesson have moved here
#include <common/parsing_helpers.h>
#include <common/rewrite_helpers.h>

/* Defines xdp_stats_map */
#include <common/xdp_stats_kern_user.h>
#include <common/xdp_stats_kern.h>

#define MAX_ENTRIES 30
struct bpf_map_def SEC("maps") tunnel_map_iface = {
    .type        = BPF_MAP_TYPE_HASH,
    .key_size    = sizeof(__u32),
    .value_size  = sizeof(tunnel_info),
    .max_entries = MAX_ENTRIES,
};

SEC("xdp_geneve")
int axon_xdp_geneve_push(struct xdp_md *ctx) {
    void *data_end = (void *)((long)ctx->data_end);
    void *data = (void *)((long)ctx->data);

    /* These keep track of the next header type and iterator pointer */
    struct hdr_cursor nh;
    nh.pos = data;
    int action = XDP_PASS;

    struct ethhdr *eth;
    int nh_type = parse_ethhdr(&nh, data_end, &eth);
    if (nh_type == -1)
      goto out;
    if (eth->h_proto == bpf_htons(ETH_P_ARP))
      goto out;
    tunnel_info* tn;
    __u32 key = ctx->ingress_ifindex;
    tn = bpf_map_lookup_elem(&tunnel_map_iface, &key);
    if(tn == NULL){
      bpf_debug("[ERR] map entry missing for iface=%d\n", key);
      goto out;
    }

    /*if(tn != NULL){
      //check if map entry is actually 
      bpf_debug(" if:  %d %d %d \n",tn->iface,tn->vlid,tn->flags);
      bpf_debug(" inner_d_mac:  %x %x %x  \n",tn->inner_d_mac[0],tn->inner_d_mac[1],tn->inner_d_mac[2]);
      bpf_debug(" inner_d_mac:  %x %x %x  \n",tn->inner_d_mac[3],tn->inner_d_mac[4],tn->inner_d_mac[5]);
    }*/

//  __builtin_memcpy(&tn, lookup(ctx->ingress_ifindex), sizeof(tunnel_info));
    geneve_tag_push(ctx, eth, tn);
    //IRL: Commented for debugging
    //action = bpf_redirect(tn->iface, tn->flags);
 out:
    //bpf_debug("a: %d t: %d\n",action, nh_type);
    return xdp_stats_record_action(ctx, action);
}

SEC("xdp_pass")
int xdp_pass_func(struct xdp_md *ctx) {
    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
