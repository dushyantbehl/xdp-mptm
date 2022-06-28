/* SPDX-License-Identifier: (GPL-2.0-or-later OR BSD-2-clause) */

#ifndef __GENEVE_HELPERS_H
#define __GENEVE_HELPERS_H

/*
 * The functions are marked as __always_inline, and
 * fully defined in this header file to be included in the BPF program.
 */

#include <linux/bpf.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/if_ether.h>

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#define DEFAULT_TTL 64
#define GEN_DSTPORT 0xc117

__ALWAYS_INLINE__
static inline void set_dst_mac(void *data, unsigned char *dst_mac)
{
    unsigned short *p = data;
    unsigned short *dst = (unsigned short *)dst_mac;

    p[0] = dst[0];
    p[1] = dst[1];
    p[2] = dst[2];
}

__ALWAYS_INLINE__
static inline void set_src_mac(void *data, unsigned char *src_mac)
{
    unsigned short *p = data;
    unsigned short *src = (unsigned short *)src_mac;

    p[3] = src[0];
    p[4] = src[1];
    p[5] = src[2];
}

__ALWAYS_INLINE__
static inline __u16 csum_fold_helper(__u64 csum)
{
    int i;
#pragma unroll
    for (i = 0; i < 4; i++) {
        if (csum >> 16)
            csum = (csum & 0xffff) + (csum >> 16);
    }
    return ~csum;
}

__ALWAYS_INLINE__
static inline void ipv4_csum_inline(void *iph, __u64 *csum)
{
    __u16 *next_iph_u16 = (__u16 *)iph;
#pragma clang loop unroll(full)
    for (int i = 0; i<sizeof(struct iphdr)>> 1; i++) {
        *csum += *next_iph_u16++;
    }
    *csum = csum_fold_helper(*csum);
}

/* Pushes a new GENEVE header after the Ethernet header.
 *  Returns 0 on success, -1 on failure.
 */
static __always_inline int geneve_tag_push(struct xdp_md *ctx,
        struct ethhdr *eth, geneve_tunnel_info* tn)
{
    int gnv_hdr_size = sizeof(struct genevehdr);
    int udp_hdr_size = sizeof(struct udphdr);
    int ip_hdr_size  = sizeof(struct iphdr);
    int eth_hdr_size = sizeof(struct ethhdr);

    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    int old_size = (int)(data_end - data);

    struct ethhdr *eth_inner_hdr = (struct ethhdr *)data;
    if (eth_inner_hdr + 1 > data_end ){
        bpf_debug("[Agent: ] ABORTED: Bad ETH header offset \n");
        return XDP_ABORTED;
    }

    //TODO: IRL Read from arp map table
    set_dst_mac(data, tn->inner_dest_mac);

    int outer_hdr_size =
        gnv_hdr_size + udp_hdr_size + ip_hdr_size + eth_hdr_size;

    long ret = bpf_xdp_adjust_head(ctx, (0-outer_hdr_size));
           if (ret != 0l) {
        bpf_debug("[Agent:] DROP (BUG): Failure adjusting packet header!\n");
        return XDP_DROP;
    }

    data = (void *)(long)ctx->data;
    data_end = (void *)(long)ctx->data_end;

    struct ethhdr *ethcpy;
    ethcpy = data;

    if (ethcpy + 1 > data_end ) {
        bpf_debug("[Agent: ] ABORTED: Bad ETH header offset \n");
        return XDP_ABORTED;
    }
    struct iphdr *ip = (struct iphdr *)(ethcpy + 1);
    if (ip + 1 > data_end){
        bpf_debug("ABORTED: Bad ip header offset ip: %x data_end:%x \n", ip+1, data_end);
        return XDP_ABORTED;
    }
    struct udphdr *udp = (struct udphdr*)(ip + 1);
    if (udp + 1 > data_end){
        bpf_debug("ABORTED: Bad udp header offset \n");
        return XDP_ABORTED;
    }
    struct genevehdr *geneve = (struct genevehdr*)(udp +1);
    if (geneve + 1 > data_end){
        bpf_debug("ABORTED: Bad GENEVE header offset \n");
        return XDP_ABORTED;
    }

    //TODO: Attach options
    //pkt->rts_opt = (void *)&pkt->geneve->options[0];

    // Populate the outer header fields 
    ethcpy->h_proto = bpf_htons(ETH_P_IP);
    set_dst_mac(data, tn->dest_mac);
    set_src_mac(data, tn->source_mac);
    
    int outer_ip_payload = gnv_hdr_size + udp_hdr_size + ip_hdr_size + old_size;
    int outer_udp_payload = gnv_hdr_size + udp_hdr_size + old_size;

    ip->version = 4;
    ip->ihl = ip_hdr_size >> 2;
    ip->frag_off = 0;
    ip->protocol = IPPROTO_UDP;
    ip->check = 0;
    ip->tos = 0;
    ip->tot_len = bpf_htons(outer_ip_payload);
 
    ip->daddr = bpf_htonl(tn->dest_addr);
    ip->saddr = bpf_htonl(tn->source_addr);
    ip->ttl = DEFAULT_TTL;
        
    __u64 c_sum = 0;
    ipv4_csum_inline(ip, &c_sum);
    ip->check = c_sum;

    //TODO: Put right checksum.
    //IRL: For now Make check 0
    udp->check = 0;
    udp->source = bpf_htons(tn->source_port); // TODO: a hash value based on inner IP packet
    udp->dest = GEN_DSTPORT;
    udp->len = bpf_htons(outer_udp_payload);

    __builtin_memset(geneve, 0, gnv_hdr_size);

    //TODO: Need to support geneve options
    
    //pkt->geneve->opt_len = gnv_opt_size / 4;
    geneve->opt_len = 0 / 4;
    geneve->ver = 0;
    geneve->rsvd1 = 0;
    geneve->rsvd2 = 0;
    geneve->oam = 0;
    geneve->critical = 0;
    geneve->proto_type = bpf_htons(ETH_P_TEB);

    //TODO: IRL make vni paramater
    //trn_tunnel_id_to_vni(tn->vlid, pkt->geneve->vni);

    geneve->vni[0] = (__u8)(tn->vlan_id >> 16);
    geneve->vni[1] = (__u8)(tn->vlan_id >> 8);
    geneve->vni[2] = (__u8)tn->vlan_id;
    return XDP_PASS;
}


#endif /* __GENEVE_HELPERS_H */
