/* SPDX-License-Identifier: GPL-2.0 */
#include <stddef.h>
#include <linux/bpf.h>
#include <linux/in.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <linux/ipv6.h>
#include <linux/ip.h>
#include <linux/icmpv6.h>
#include <linux/icmp.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
/* Defines xdp_stats_map from packet04 */
#include "../common/xdp_stats_kern_user.h"
#include "../common/xdp_stats_kern.h"

#define VLAN_VID_MASK		0x0fff /* VLAN Identifier */
/* Header cursor to keep track of current parsing position */
struct hdr_cursor {
	void *pos;
};

/*
 *	struct vlan_hdr - vlan header
 *	@h_vlan_TCI: priority and VLAN ID
 *	@h_vlan_encapsulated_proto: packet type ID or len
 */
struct vlan_hdr {
	__be16	h_vlan_TCI;
	__be16	h_vlan_encapsulated_proto;
};

struct collect_vlans {
	__u16 id[2];
};

static __always_inline int proto_is_vlan(__u16 h_proto)
{
        return !!(h_proto == bpf_htons(ETH_P_8021Q) ||
                  h_proto == bpf_htons(ETH_P_8021AD));
}
/* Packet parsing helpers.
 *
 * Each helper parses a packet header, including doing bounds checking, and
 * returns the type of its contents if successful, and -1 otherwise.
 *
 * For Ethernet and IP headers, the content type is the type of the payload
 * (h_proto for Ethernet, nexthdr for IPv6), for ICMP it is the ICMP type field.
 * All return values are in network byte order.
 */
static __always_inline int parse_ethhdr(struct hdr_cursor *nh,
					void *data_end,
					struct ethhdr **ethhdr,
					struct collect_vlans *vlans)
{
	struct ethhdr *eth = nh->pos;
	int hdrsize = sizeof(*eth);
	struct vlan_hdr *vlh;
	__u16 h_proto;
	int i;

	/* Byte-count bounds check; check if current pointer + size of header
	 * is after data_end.
	 */
	if (nh->pos + hdrsize > data_end)
		return -1;

	nh->pos += hdrsize;
	*ethhdr = eth;
	vlh = nh->pos;
	h_proto = eth->h_proto;

	bpf_printk("Ethernet header: h_proto: %x\n", bpf_htons(h_proto));
	/* Use loop unrolling to avoid the verifier restriction on loops;
	 * support up to VLAN_MAX_DEPTH layers of VLAN encapsulation.
	 */
	#pragma unroll
	for (i = 0; i < 2; i++) {
		if (!proto_is_vlan(h_proto)) // 检查当前协议类型是否是 VLAN
		{
			bpf_printk("Not a VLAN, h_proto: %x\n", bpf_htons(h_proto));
			break; // 如果不是 VLAN，说明已经到达最内层协议，跳出循环
		}
			
 
		if (vlh + 1 > data_end) // 检查是否有足够的空间容纳下一个 VLAN 头部
		{
			bpf_printk("No more VLAN headers, h_proto: %x\n", bpf_htons(h_proto));
			break; // 如果没有，说明数据包不完整，跳出循环
		}
		// 如果是 VLAN，则解析 VLAN 头部
		h_proto = vlh->h_vlan_encapsulated_proto; // 获取 VLAN 内部封装的协议类型
		bpf_printk("VLAN encapsulated protocol: %x\n", bpf_htons(h_proto));
		if (vlans) /* collect VLAN ids */
			vlans->id[i] =
				(bpf_ntohs(vlh->h_vlan_TCI) & VLAN_VID_MASK); // 提取 VLAN ID 并存储
		bpf_printk("VLAN ID: %d\n", (bpf_ntohs(vlh->h_vlan_TCI) & VLAN_VID_MASK)); // 打印 VLAN ID 以供调试
		vlh++; // 移动 vlh 指针到下一个可能的 VLAN 头部或上层协议头部
	}
 
	nh->pos = vlh; // 更新 nh->pos 到最终解析到的位置（所有 VLAN 标签之后）
	return h_proto; /* network-byte-order */ // 返回最内层封装的协议类型
}

static __always_inline int parse_iphdr(struct hdr_cursor *nh,
				       void *data_end,
				       struct iphdr **iphdr)
{
	struct iphdr *iph = nh->pos;
	int hdrsize;

	if (iph + 1 > data_end)
		return -1;

	hdrsize = iph->ihl * 4;
	/* Sanity check packet field is valid */
	if(hdrsize < sizeof(*iph))
		return -1;

	/* Variable-length IPv4 header, need to use byte-based arithmetic */
	if (nh->pos + hdrsize > data_end)
		return -1;

	nh->pos += hdrsize;
	*iphdr = iph;

	return iph->protocol;
}
/* Assignment 2: Implement and use this */
static __always_inline int parse_ip6hdr(struct hdr_cursor *nh,
					void *data_end,
					struct ipv6hdr **ip6hdr)
{

	struct ipv6hdr *ip6h = nh->pos;

	if (ip6h + 1 > data_end)
    return -1;
	nh->pos += sizeof(*ip6h);
	*ip6hdr = ip6h;

	return ip6h->nexthdr; /* network-byte-order */
}

static __always_inline int parse_icmphdr(struct hdr_cursor *nh,
					  void *data_end,
					  struct icmphdr **icmp6hdr)
{
	struct icmphdr *icmph = nh->pos;

	if (icmph + 1 > data_end)
		return -1;

	nh->pos += sizeof(*icmph);
	*icmp6hdr = icmph;

	return icmph->un.echo.sequence; /* network-byte-order */
}


/* Assignment 3: Implement and use this */
static __always_inline int parse_icmp6hdr(struct hdr_cursor *nh,
					  void *data_end,
					  struct icmp6hdr **icmp6hdr)
{
	struct icmp6hdr *icmp6h = nh->pos;

	if (icmp6h + 1 > data_end)
		return -1;

	nh->pos += sizeof(*icmp6h);
	*icmp6hdr = icmp6h;

	return icmp6h->icmp6_sequence; /* network-byte-order */
}

SEC("xdp")
int  xdp_parser_func(struct xdp_md *ctx)
{
	void *data_end = (void *)(long)ctx->data_end;
	void *data = (void *)(long)ctx->data;
	struct ethhdr *eth;

	/* Default action XDP_PASS, imply everything we couldn't parse, or that
	 * we don't want to deal with, we just pass up the stack and let the
	 * kernel deal with it.
	 */
	__u32 action = XDP_PASS; /* Default action */

        /* These keep track of the next header type and iterator pointer */
	struct hdr_cursor nh;
	int nh_type;
	int nexthdr;
	int icmpsequence;

	/* Start next header cursor position at data start */
	nh.pos = data;

	/* Packet parsing in steps: Get each header one at a time, aborting if
	 * parsing fails. Each helper function does sanity checking (is the
	 * header type in the packet correct?), and bounds checking.
	 */
	nh_type = parse_ethhdr(&nh, data_end, &eth, NULL);
	bpf_printk("nh_type: %x\n",bpf_htons(nh_type));
	if (nh_type == bpf_htons(ETH_P_IPV6)){
		struct ipv6hdr *ip6h;
		nexthdr = parse_ip6hdr(&nh, data_end, &ip6h);
		bpf_printk("nexthdr: %x\n", bpf_htons(nexthdr));
		struct icmp6hdr *icmp6h;
		icmpsequence = parse_icmp6hdr(&nh, data_end, &icmp6h);
		bpf_printk("icmp_sequence: %x\n", bpf_htons(icmpsequence));
		if (bpf_htons(icmpsequence)%2 == 1 )
			goto out;
	}else if (nh_type == bpf_htons(ETH_P_IP)){
		struct iphdr *iph;
		nexthdr = parse_iphdr(&nh, data_end, &iph);
		bpf_printk("nexthdr: %x\n", bpf_htons(nexthdr));
		struct icmphdr *icmph;
		icmpsequence = parse_icmphdr(&nh, data_end, &icmph);
		bpf_printk("icmp_sequence: %x\n", bpf_htons(icmpsequence));
		if (bpf_htons(icmpsequence)%2 == 1 )
			goto out;
	}

	/* Assignment additions go below here */

	action = XDP_DROP;
out:
	return xdp_stats_record_action(ctx, action); /* read via xdp_stats */
}

char _license[] SEC("license") = "GPL";
