
// SPDX-License-Identifier: GPL-2.0-or-later
/**
 * @file transit_kern.h
 * @author Sherif Abdelwahab (@zasherif)
 *
 * @brief Helper functions, macros and data structures.
 *
 * @copyright Copyright (c) 2019 The Authors.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; version 2 of the License.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 *
 */
#pragma once

#include <linux/bpf.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <linux/tcp.h>
#include <stddef.h>

//#include "rewrite_helpers.h"

#ifndef __inline
#define __inline inline __attribute__((always_inline))
#endif

#define bpf_debug(fmt, ...) \
({ \
const char ____fmt[] = fmt; \
bpf_trace_printk(____fmt, sizeof(____fmt), \
##__VA_ARGS__); \
})


//#else
//#define bpf_debug(fmt, ...) { } while (0)
//#endif

#ifndef __ALWAYS_INLINE__
#define __ALWAYS_INLINE__ __attribute__((__always_inline__))
#endif

typedef struct tnl_inf{
	__u16 iface;
	__be64 vlid;
        __u16 flags;
	__u16 s_port;
	__be32 d_addr;
	__be32 s_addr;
	__u8 inner_d_mac[6];
	__u8 s_mac[6] ;
	__u8 d_mac[6];

} __attribute__((packed)) tunnel_info;

struct geneve_opt {
	__be16 opt_class;
	__u8 type;
	__u8 length : 5;
	__u8 r3 : 1;
	__u8 r2 : 1;
	__u8 r1 : 1;
	__u8 opt_data[];
};

struct genevehdr {
	/* Big endian! */
	__u8 opt_len : 6;
	__u8 ver : 2;
	__u8 rsvd1 : 6;
	__u8 critical : 1;
	__u8 oam : 1;
	__be16 proto_type;
	__u8 vni[3];
	__u8 rsvd2;
  //struct geneve_opt options[];
};

struct ipv4_tuple_t {
	__u32 saddr;
	__u32 daddr;

	/* ports */
	__u16 sport;
	__u16 dport;

	/* Addresses */
	__u8 protocol;

	/*TODO: include TCP flags, no use case for the moment! */
} __attribute__((packed));

