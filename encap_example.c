/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright 2020 Mellanox Technologies, Ltd
 */

#include <rte_net.h>
#include <rte_ethdev.h>
#include <rte_flow.h>
#include <rte_gtp.h>
#include <rte_gre.h>
#include <rte_ip.h>
#include <rte_ether.h>

#include "vnf_examples.h"

/* Layer names, to be used inorder to access the relevent item. */
enum layer_name {
	L2,
	L3,
	L4,
	TUNNEL,
	L2_INNER,
	L3_INNER,
	L4_INNER,
	END
};

/* The pattern list, this list is used inorder to save reallocation of each
 * for each call, RTE_FLOW_TYPE_VOID marks that his item should be ignored
 * and dosn't affect the the matching. Using the void action type allows this
 * list to be shared between number of different flows.
 * RTE_FLOW_TYPE_END marks the last item in the list and must appear.
 * spec = NULL, will result that all traffic that includes header from the
 * selected type will be hit.
 */
static struct rte_flow_item pattern[] = {
	[L2] = { /* ETH type is set since we always start from ETH. */
		.type = RTE_FLOW_ITEM_TYPE_ETH,
		.spec = NULL,
		.mask = NULL,
		.last = NULL },
	[L3] = {
		.type = RTE_FLOW_ITEM_TYPE_VOID,
		.spec = NULL,
		.mask = NULL,
		.last = NULL },
	[L4] = {
		.type = RTE_FLOW_ITEM_TYPE_VOID,
		.spec = NULL,
		.mask = NULL,
		.last = NULL },
	[TUNNEL] = {
		.type = RTE_FLOW_ITEM_TYPE_VOID,
		.spec = NULL,
		.mask = NULL,
		.last = NULL },
	[L2_INNER] = {
		.type = RTE_FLOW_ITEM_TYPE_VOID,
		.spec = NULL,
		.mask = NULL,
		.last = NULL },
	[L3_INNER] = {
		.type = RTE_FLOW_ITEM_TYPE_VOID,
		.spec = NULL,
		.mask = NULL,
		.last = NULL },
	[L4_INNER] = {
		.type = RTE_FLOW_ITEM_TYPE_VOID,
		.spec = NULL,
		.mask = NULL,
		.last = NULL },
	[END] = {
		.type = RTE_FLOW_ITEM_TYPE_END,
		.spec = NULL,
		.mask = NULL,
		.last = NULL },
};

/* Encap GTP-U type traffic. */
struct rte_flow *
create_gtp_u_encap_flow(uint16_t port)
{
	struct rte_flow *flow;
	struct rte_flow_error error;
	struct rte_flow_attr attr = { /* Holds the flow attributes. */
				.group = 0, /* set the rule on the main group. */
				.egress = 1, };/* Tx flow. */
	/* Create the items that will be needed for the encap. */
	struct rte_gtp_hdr gtp = {
			.teid = rte_cpu_to_be_32(1234), /* Set the teid */
			.msg_type = 255 , /* The expected value. */
			.s = 1 }; /*Set Sequence Number flag = 1*/
	struct rte_ether_hdr eth = {
			.ether_type = RTE_BE16(RTE_ETHER_TYPE_IPV4),
			.d_addr.addr_bytes = "\x01\x02\x03\x04\x05\x06",
			.s_addr.addr_bytes = "\x06\x05\x04\x03\x02\x01" };
	struct rte_ipv4_hdr ipv4 = {
			.version_ihl = 0x45,
			.src_addr = rte_cpu_to_be_32(0x0C0C0C0C),
			/* Set src address 12.12.12.12 */
			.dst_addr = rte_cpu_to_be_32(0x0D0D0D0D),
			/* Set dst address 13.13.13.13 */
			.next_proto_id = IPPROTO_UDP };
	struct rte_udp_hdr udp = {
			.dst_port = rte_cpu_to_be_16(2152) };
			/* Set dst port of GTP-U */
	/* Create the items that will be needed for the matching. */
	struct rte_flow_item_ipv4 ipv4_spec = {
			.hdr = {
				.src_addr = rte_cpu_to_be_32(0x0A0A0A0A),
				/* Match src address 10.10.10.10 */
				.dst_addr = rte_cpu_to_be_32(0x0B0B0B0B),
				/* Match dst address 11.11.11.11 */
				.next_proto_id = IPPROTO_UDP }};
	struct rte_flow_item_ipv4 ipv4_mask = {
			.hdr = {
				.src_addr = RTE_BE32(0xffffffff),
				.dst_addr = RTE_BE32(0xffffffff)}};
	struct rte_flow_item_udp udp_spec = {
			.hdr = {
				.dst_port = rte_cpu_to_be_16(4000) }};
	struct rte_flow_item_udp udp_mask = {
			.hdr = {
				.dst_port = RTE_BE16(0xffff) }};
;
	size_t encap_size = sizeof(eth) + sizeof(ipv4) + sizeof(udp) +
				sizeof(gtp);
	size_t decap_size = sizeof(eth);
	uint8_t decap_buf[decap_size];
	uint8_t encap_buf[encap_size];
	uint8_t *bptr; /* Used to copy the headers to the buffer. */

	struct rte_flow_action_raw_decap decap = {
			.size = decap_size ,
			.data = decap_buf };
	struct rte_flow_action_raw_encap encap = {
			.size = encap_size ,
			.data = encap_buf };
	struct rte_flow_action actions[] = {
			[0] = { /*Decap L2 of the packet. */
				.type = RTE_FLOW_ACTION_TYPE_RAW_DECAP,
				.conf = &decap },
			[1] = { /* Encap the packet with all layers. */
				.type = RTE_FLOW_ACTION_TYPE_RAW_ENCAP,
				.conf = &encap },
			[2] = { /* End action must be the last action. */
				.type = RTE_FLOW_ACTION_TYPE_END,
				.conf = NULL }
			};

	/* Configure matching on IPv4 and UDP.
	 * search for any header that matches eth /
	 * ipv4 src addr is 10.10.10.10 dst addr is 11.11.11.11 /
	 *  udp proto is 4000.
	 * The corresponding testpmd commands:
	 * testpmd> set raw_decap 0 eth / end_set
	 * testpmd> set raw_encap 0 eth src is 06:05:04:03:02:01
	 *          dst is 01:02:03:04:05:06 type is 0x0800 /
	 *          ipv4 src is 12.12.12.12 dst is 13.13.13.13 /
	 *          udp dst is 2152 /
	 *          gtp teid is 1234 msg_type is 255 v_pt_rsv_flags is 2 /
	 *          end_set
	 * testpmd> flow create 0 egress group 0 pattern eth /
	 *          ipv4 src is 10.10.10.10 dst is 11.11.11.11 /
	 *          udp dst is 4000 / end actions
	 *          raw_decap index 0 / raw_encap index 0 / end 
	 */
	pattern[L2].type = RTE_FLOW_ITEM_TYPE_ETH;
	pattern[L3].type = RTE_FLOW_ITEM_TYPE_IPV4;
	pattern[L3].spec = &ipv4_spec;
	pattern[L3].mask = &ipv4_mask;
	pattern[L4].type = RTE_FLOW_ITEM_TYPE_UDP;
	pattern[L4].spec = &udp_spec;
	pattern[L4].mask = &udp_mask;

	/* Configure the buffer for the decap action. needs to remove L2. */
	bptr = decap_buf;
	memcpy(bptr, &eth, sizeof(eth));
	/* Configure the buffer for the encap action.*/
	bptr = encap_buf;
	memcpy(bptr, &eth, sizeof(eth));
	bptr += sizeof(eth);
	memcpy(bptr, &ipv4, sizeof(ipv4));
	bptr += sizeof(ipv4);
	memcpy(bptr, &udp, sizeof(udp));
	bptr += sizeof(udp);
	memcpy(bptr, &gtp, sizeof(gtp));


	/* Create the flow. */
	flow = rte_flow_create(port, &attr, pattern, actions, &error);
	if (!flow)
		printf("Can't create encap flow. %s\n", error.message);

	return flow;
}

/* Encap GTP PDU Session Container type traffic. */
struct rte_flow *
create_gtp_u_psc_encap_flow(uint16_t port)
{
	struct rte_flow *flow;
	struct rte_flow_error error;
	struct rte_flow_attr attr = { /* Holds the flow attributes. */
			.group = 0, /* set the rule on group 1. */
			.egress = 1, };/* Tx flow. */
	/* Create the items that will be needed for the matching. */
	struct rte_flow_item_ipv4 ipv4_spec = {
			.hdr = {
				.src_addr = rte_cpu_to_be_32(0x31313131),
				/* Match src address 49.49.49.49 */
				.dst_addr = rte_cpu_to_be_32(0x13131313),
				/* Match dst address 19.19.19.19 */
				.next_proto_id = IPPROTO_UDP }};
	struct rte_flow_item_ipv4 ipv4_mask = {
			.hdr = {
				.src_addr = RTE_BE32(0xffffffff),
				.dst_addr = RTE_BE32(0xffffffff) }};
	struct rte_flow_item_udp udp_spec = {
			.hdr = {
				.dst_port = rte_cpu_to_be_16(4000) }};
	struct rte_flow_item_udp udp_mask = {
			.hdr = {
				.dst_port = RTE_BE16(0xffff) }};

	/* Create the items that will be needed for the encap. */
	struct rte_ether_hdr eth = {
			.ether_type = RTE_BE16(RTE_ETHER_TYPE_IPV4),
			.d_addr.addr_bytes = "\x01\x02\x03\x04\x05\x06",
			.s_addr.addr_bytes = "\x06\x05\x04\x03\x02\x01" };
	struct rte_ipv4_hdr ipv4 = {
			.version_ihl = 0x45,
			.src_addr = rte_cpu_to_be_32(0x0C0C0C0C),
			/* Set src address 12.12.12.12 */
			.dst_addr = rte_cpu_to_be_32(0x0D0D0D0D),
			/* Set dst address 13.13.13.13 */
			.next_proto_id = IPPROTO_UDP };
	struct rte_udp_hdr udp = {
			.dst_port = rte_cpu_to_be_16(2152) };
			/* Set dst port of GTP-U */
	struct rte_gtp_hdr gtp = {
			.teid = rte_cpu_to_be_32(1234), /* Set the teid */
			.msg_type = 255, /* The expected value. */
			.ver = 1, /* Set Version Flag = 1 */
			.pt =1, /* Set Protocol Type Flag = 1 */
			.e = 1 };  /* Set Extension Header Flag= 1 */
	struct rte_gtp_hdr_ext_word gtp_extra_word = {
			.next_ext = 0x85 };
			/* Next extension header type  PDU session container */
	struct {
			uint8_t len;
			uint8_t type_flags;
			uint8_t qfi;
			uint8_t reserved;
	} gtp_psc;
	gtp_psc.len = 1;
	gtp_psc.type_flags = 0x10;
	/* Type is 1 for UL PDU Session information. */
	gtp_psc.qfi = 9;
	size_t encap_size = sizeof(eth) + sizeof(ipv4) + sizeof(udp) +
			    sizeof(gtp) + sizeof(gtp_extra_word) +
			    sizeof(gtp_psc);
	size_t decap_size = sizeof(eth);
	uint8_t decap_buf[decap_size];
	uint8_t encap_buf[encap_size];
	uint8_t *bptr; /* Used to copy the headers to the buffer. */

	struct rte_flow_action_raw_decap decap = {
			.size = decap_size ,
			.data = decap_buf };
	struct rte_flow_action_raw_encap encap = {
			.size = encap_size ,
			.data = encap_buf };
	struct rte_flow_action actions[] = {
			[0] = { /*Decap L2 of the packet. */
				.type = RTE_FLOW_ACTION_TYPE_RAW_DECAP,
				.conf = &decap },
			[1] = { /* Encap the packet with all layers. */
				.type = RTE_FLOW_ACTION_TYPE_RAW_ENCAP,
				.conf = &encap },
			[2] = { /* End action must be the last action. */
				.type = RTE_FLOW_ACTION_TYPE_END,
				.conf = NULL }
			};

	/* Configure matching on IPv4 and UDP and encap with GTP PDU session
	 * container. search for any header that matches eth /
	 * ipv4 src addr is 49.49.49.49 dst addr is 19.19.19.19 /
	 *  udp proto is 4000.
	 * The corresponding testpmd commands:
	 * testpmd> set raw_decap 0 eth / end_set
	 * testpmd> set raw_encap 0 eth src is 06:05:04:03:02:01
	 *          dst is 01:02:03:04:05:06 type is 0x0800 /
	 *          ipv4 src is 12.12.12.12 dst is 13.13.13.13 /
	 *          udp dst is 2152 /
	 *          gtp teid is 1234 msg_type is 255 v_pt_rsv_flags is 34 /
	 *          gtp_psc qfi is 9 pdu_t is 1 /
	 *          end_set
	 * testpmd> flow create 0 egress group 0 pattern eth /
	 *          ipv4 src is 49.49.49.49 dst is 19.19.19.19 /
	 *          udp dst is 4000 / end actions
	 *          raw_decap index 0 / raw_encap index 0 / end
	 */
	pattern[L2].type = RTE_FLOW_ITEM_TYPE_ETH;
	pattern[L3].type = RTE_FLOW_ITEM_TYPE_IPV4;
	pattern[L3].spec = &ipv4_spec;
	pattern[L3].mask = &ipv4_mask;
	pattern[L4].type = RTE_FLOW_ITEM_TYPE_UDP;
	pattern[L4].spec = &udp_spec;
	pattern[L4].mask = &udp_mask;

	/* Configure the buffer for the decap action. needs to remove L2. */
	bptr = decap_buf;
	memcpy(bptr, &eth, sizeof(eth));
	/* Configure the buffer for the encap action.*/
	bptr = encap_buf;
	memcpy(bptr, &eth, sizeof(eth));
	bptr += sizeof(eth);
	memcpy(bptr, &ipv4, sizeof(ipv4));
	bptr += sizeof(ipv4);
	memcpy(bptr, &udp, sizeof(udp));
	bptr += sizeof(udp);
	memcpy(bptr, &gtp, sizeof(gtp));
	bptr += sizeof(gtp);
	memcpy(bptr, &gtp_extra_word, sizeof(gtp_extra_word));
	bptr += sizeof(gtp_extra_word);
	memcpy(bptr, &gtp_psc, sizeof(gtp_psc));

	/* Create the flow. */
	flow = rte_flow_create(port, &attr, pattern, actions, &error);
	if (!flow)
		printf("Can't create encap flow. %s\n", error.message);

	return flow;
}

/*
 * Encap GRE type traffic.
 * The corresponding testpmd commands:
 * testpmd> set raw_decap 0 eth / end_set
 * testpmd> set raw_encap 0 eth dst is 01:02:03:04:05:06
 *          src is 06:05:04:03:02:01 /
 *          ipv4 src is 12.12.12.12 dst is 13.13.13.13 proto is 47 /
 * 	    gre protocol is 0x0800 / end_set
 * testpmd> flow create 0 egress group 0 pattern eth /
 *          ipv4 src is 10.10.11.11 dst is 11.11.12.12 /
 *          udp dst is 4001 / end actions raw_decap index 0 /
 *          raw_encap index 0 / end
 */
struct rte_flow *
create_gre_encap_flow(uint16_t port)
{
	struct rte_flow *flow;
	struct rte_flow_error error;
	struct rte_flow_attr attr = { /* Holds the flow attributes. */
				.group = 0, /* set the rule on the main group. */
				.egress = 1, };/* Tx flow. */
	/* Create the headers that will be needed for the encap. */
	struct rte_ether_hdr eth = {
			.ether_type = RTE_BE16(RTE_ETHER_TYPE_IPV4),
			.d_addr.addr_bytes = "\x01\x02\x03\x04\x05\x06",
			.s_addr.addr_bytes = "\x06\x05\x04\x03\x02\x01" };
	struct rte_ipv4_hdr ipv4 = {
		.version_ihl = 0x45,
		.src_addr = RTE_BE32(0x0C0C0C0C),
		/* Set src address 12.12.12.12. */
		.dst_addr = RTE_BE32(0x0D0D0D0D),
		/* Set dst address 13.13.13.13 */
		.next_proto_id = IPPROTO_GRE };
	struct rte_gre_hdr gre = { .proto = RTE_BE16(RTE_ETHER_TYPE_IPV4) };
	/* Create the items that will be needed for the matching. */
	struct rte_flow_item_ipv4 ipv4_spec = {
			.hdr = {
				.src_addr = rte_cpu_to_be_32(0x0A0A0B0B),
				/* Match src address 10.10.11.11 */
				.dst_addr = rte_cpu_to_be_32(0x0B0B0C0C),
				/* Match dst address 11.11.12.12 */
				.next_proto_id = IPPROTO_UDP }};
	struct rte_flow_item_ipv4 ipv4_mask = {
			.hdr = {
				.src_addr = RTE_BE32(0xffffffff),
				.dst_addr = RTE_BE32(0xffffffff)}};
	struct rte_flow_item_udp udp_spec = {
			.hdr = {
				.dst_port = rte_cpu_to_be_16(4001) }};
	struct rte_flow_item_udp udp_mask = {
			.hdr = {
				.dst_port = RTE_BE16(0xffff) }};

	size_t encap_size = sizeof(eth) + sizeof(ipv4) + sizeof(gre);
	size_t decap_size = sizeof(eth);
	uint8_t decap_buf[decap_size];
	uint8_t encap_buf[encap_size];
	uint8_t *bptr; /* Used to copy the headers to the buffer. */

	struct rte_flow_action_raw_decap decap = {
			.size = decap_size ,
			.data = decap_buf };
	struct rte_flow_action_raw_encap encap = {
			.size = encap_size ,
			.data = encap_buf };
	struct rte_flow_action actions[] = {
			[0] = { /*Decap L2 of the packet. */
				.type = RTE_FLOW_ACTION_TYPE_RAW_DECAP,
				.conf = &decap },
			[1] = { /* Encap the packet with all layers. */
				.type = RTE_FLOW_ACTION_TYPE_RAW_ENCAP,
				.conf = &encap },
			[2] = { /* End action must be the last action. */
				.type = RTE_FLOW_ACTION_TYPE_END,
				.conf = NULL }
			};

	/* Configure matching on IPv4 and UDP.
	 * search for any header that matches eth /
	 * ipv4 src addr is 10.10.11.11 dst addr is 11.11.12.12 /
	 *  udp proto is 4001.
	 */
	pattern[L2].type = RTE_FLOW_ITEM_TYPE_ETH;
	pattern[L3].type = RTE_FLOW_ITEM_TYPE_IPV4;
	pattern[L3].spec = &ipv4_spec;
	pattern[L3].mask = &ipv4_mask;
	pattern[L4].type = RTE_FLOW_ITEM_TYPE_UDP;
	pattern[L4].spec = &udp_spec;
	pattern[L4].mask = &udp_mask;

	/* Configure the buffer for the decap action. needs to remove L2. */
	bptr = decap_buf;
	memcpy(bptr, &eth, sizeof(eth));
	/* Configure the buffer for the encap action.*/
	bptr = encap_buf;
	memcpy(bptr, &eth, sizeof(eth));
	bptr += sizeof(eth);
	memcpy(bptr, &ipv4, sizeof(ipv4));
	bptr += sizeof(ipv4);
	memcpy(bptr, &gre, sizeof(gre));


	/* Create the flow. */
	flow = rte_flow_create(port, &attr, pattern, actions, &error);
	if (!flow)
		printf("Can't create encap flow. %s\n", error.message);

	return flow;
}
