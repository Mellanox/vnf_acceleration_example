/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright 2020 Mellanox Technologies, Ltd
 */

#include <rte_net.h>
#include <rte_ethdev.h>
#include <rte_flow.h>
#include <rte_gre.h>

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

/* Decap GTP-U type traffic and do RSS based on the inner IPv4 src. */
struct rte_flow *
create_gtp_u_decap_rss_flow(uint16_t port, uint32_t nb_queues,
			    uint16_t *queues)
{
	struct rte_flow *flow;
	struct rte_flow_error error;
	struct rte_flow_attr attr = { /* Holds the flow attributes. */
				.group = 0, /* set the rule on the main group. */
				.ingress = 1,/* Rx flow. */
				.priority = 0, }; /* add priority to rule
				to give the Decap rule higher priority since
				it is more specific than RSS */
	struct rte_flow_item_gtp gtp_spec = {
			.teid = rte_cpu_to_be_32(1234), /* Set the teid */
			.msg_type = 255 , /* The expected value. */
			.v_pt_rsv_flags = 2}; /*set sequence number flag*/
	struct rte_flow_item_gtp gtp_mask = {
			.teid = RTE_BE32(0xffffffff),/* Set teid mask*/
			.msg_type = 0xff , /* match on message type.*/
			.v_pt_rsv_flags = 0x07}; /*Set flags mask*/
			/*mask bit equal to 1 means match on this bit. */
	struct rte_flow_action_rss rss = {
			.level = 0, /* Since the RSS will be done after decap
			which mean there will be only outer layer. */
			.queue = queues, /* Set the selected target queues. */
			.queue_num = nb_queues, /* The number of queues. */
			.types =  ETH_RSS_IP | ETH_RSS_L3_SRC_ONLY };
	/* Create the items that will be needed for the decap. */
	struct rte_ether_hdr eth = {
			.ether_type = RTE_BE16(RTE_ETHER_TYPE_IPV4),
			.d_addr.addr_bytes = "\x01\x02\x03\x04\x05\x06",
			.s_addr.addr_bytes = "\x06\x05\x04\x03\x02\01" };
	struct rte_flow_item_ipv4 ipv4 = {
			.hdr = {
				.next_proto_id = IPPROTO_UDP }};
	struct rte_flow_item_udp udp = {
			.hdr = {
				.dst_port = rte_cpu_to_be_16(2152) }};
				/* Match on UDP dest port 2152 (GTP-U) */
	struct rte_flow_item_gtp gtp;
	struct rte_flow_item_ipv4 ipv4_inner = {
			.hdr = {
				.src_addr = rte_cpu_to_be_32(0x0A0A0A0A),
				/* Match on 10.10.10.10 src address */
				.next_proto_id = IPPROTO_UDP }};
	struct rte_flow_item_ipv4 ipv4_mask = {
			.hdr = {
				.src_addr = RTE_BE32(0xffffffff)}};
	struct rte_flow_item_udp udp_inner = {
			.hdr = {
				.dst_port = rte_cpu_to_be_16(4000) }};
				/* Match on udp dest port 4000 */
	struct rte_flow_item_udp udp_mask = {
			.hdr = {
				.dst_port = RTE_BE16(0xffff) }};

	struct rte_flow_action_set_ipv4 set_ipv4 = {
			.ipv4_addr = rte_cpu_to_be_32(0x0E0E0E0E)};
			/* Set the inner IP src address to 14.14.14.14 */

	size_t decap_size = sizeof(eth) + sizeof(ipv4) + sizeof(udp) +
			sizeof(gtp);
	size_t encap_size = sizeof(eth);
	uint8_t decap_buf[decap_size];
	uint8_t encap_buf[encap_size];
	uint8_t *bptr; /* Used to copy the headers to the buffer. */
	/* Since GTP is L3 tunnel type (no inner L2) it means that we need to
	 * first decap the outer header, and secondly encap the
	 * remaining packet with ETH header.
	 */
	struct rte_flow_action_raw_decap decap = {
			.size = decap_size ,
			.data = decap_buf };
	struct rte_flow_action_raw_encap encap = {
			.size = encap_size ,
			.data = encap_buf };
	struct rte_flow_action actions[] = {
			[0] = { /*Decap the outer part beginning from the
			 outermost L2 up to including the tunnel item. */
				.type = RTE_FLOW_ACTION_TYPE_RAW_DECAP,
				.conf = &decap },
			[1] = { /* Encap the packet with the missing L2. */
				.type = RTE_FLOW_ACTION_TYPE_RAW_ENCAP,
				.conf = &encap },
			[2] = { /* Change the inner ipv4 src address. */
				.type = RTE_FLOW_ACTION_TYPE_SET_IPV4_SRC,
				.conf = &set_ipv4 },
			[3] = { /* The RSS action to be used. */
				.type = RTE_FLOW_ACTION_TYPE_RSS,
				.conf = &rss },
			[4] = { /* End action must be the last action. */
				.type = RTE_FLOW_ACTION_TYPE_END,
				.conf = NULL }
			};

	/* Configure matching on outer IPv4 UDP and GTP-U.
	 * This case we don't care about specific outer values we just 
	 * serach for any header that maches eth / ipv4 / udp / gtp type 255 /
	 * ipv4 src addr is 10.10.10.10/ udp proto is 4000.
	 * The RSS will only be done on the inner ipv4 src file, in order to 
	 * make sure that all of the packets from a given user (inner source
	 * ip) will be routed to the same core.
	 */
	pattern[L2].type = RTE_FLOW_ITEM_TYPE_ETH;
	pattern[L3].type = RTE_FLOW_ITEM_TYPE_IPV4;
	pattern[L4].type = RTE_FLOW_ITEM_TYPE_UDP;
	pattern[TUNNEL].type = RTE_FLOW_ITEM_TYPE_GTP;
	pattern[TUNNEL].spec = &gtp_spec;
	pattern[TUNNEL].mask = &gtp_mask;
	pattern[L3_INNER].type = RTE_FLOW_ITEM_TYPE_IPV4;
	pattern[L3_INNER].spec = &ipv4_inner;
	pattern[L3_INNER].mask = &ipv4_mask;
	pattern[L4_INNER].type = RTE_FLOW_ITEM_TYPE_UDP;
	pattern[L4_INNER].spec = &udp_inner;
	pattern[L4_INNER].mask = &udp_mask;

	/* Configure the buffer for the decap action.
	   The important part is the size of the buffer*/
	bptr = decap_buf;
	memcpy(bptr, &eth, sizeof(eth));
	bptr += sizeof(eth);
	memcpy(bptr, &ipv4, sizeof(ipv4));
	bptr += sizeof(ipv4);
	memcpy(bptr, &udp, sizeof(udp));
	bptr += sizeof(udp);
	memcpy(bptr, &gtp, sizeof(gtp));
	bptr += sizeof(gtp);
	/* Configure the buffer for the encap action. needs to add L2. */
	bptr = encap_buf;
	memcpy(bptr, &eth, sizeof(eth));

	/* Create the flow. */
	flow = rte_flow_create(port, &attr, pattern, actions, &error);
	if (!flow)
		printf("Can't create decap flow. %s\n", error.message);
	
	return flow;
}

/*
 * Decap GRE type traffic and do RSS based on the inner IPv4 src.
 *
 * Corresponding testpmd cmds:
 * testpmd> set raw_decap 0 eth / ipv4 / gre / end_set
 * testpmd> set raw_encap 0 eth src is 01:02:03:04:05:06
 * 	    dst is 06:05:04:03:02:01 type is 0x0800 / end_set
 * testpmd> flow create 0 ingress pattern eth / ipv4 / gre /
 *          ipv4 src is 10.10.11.11 / udp dst is 4001 / end
 *          actions raw_decap index 0 / raw_encap index 0 /
 *          rss queues 0 1 2 3 end types ipv4 l3-src-only end / end
 **/
struct rte_flow *
create_gre_decap_rss_flow(uint16_t port, uint32_t nb_queues,
			    uint16_t *queues)
{
	struct rte_flow *flow;
	struct rte_flow_error error;
	struct rte_flow_attr attr = { /* Holds the flow attributes. */
				.group = 0, /* set the rule on the main group. */
				.ingress = 1,/* Rx flow. */
				.priority = 0, }; /* add priority to rule
				to give the Decap rule higher priority since
				it is more specific than RSS */
	struct rte_flow_action_rss rss = {
			.level = 0, /* Since the RSS will be done after decap
			which mean there will be only outer layer. */
			.queue = queues, /* Set the selected target queues. */
			.queue_num = nb_queues, /* The number of queues. */
			.types =  ETH_RSS_IP | ETH_RSS_L3_SRC_ONLY };
	/* Create the items that will be needed for the decap. */
	struct rte_ether_hdr eth = {
			.ether_type = RTE_BE16(RTE_ETHER_TYPE_IPV4),
			.d_addr.addr_bytes = "\x01\x02\x03\x04\x05\x06",
			.s_addr.addr_bytes = "\x06\x05\x04\x03\x02\01" };
	struct rte_flow_item_ipv4 ipv4 = {
			.hdr = {
				.next_proto_id = IPPROTO_GRE }};
	struct rte_gre_hdr gre = { .proto = RTE_ETHER_TYPE_IPV4};
	struct rte_flow_item_ipv4 ipv4_inner = {
			.hdr = {
				.src_addr = rte_cpu_to_be_32(0x0A0A0B0B),
				/* Match on 10.10.11.11 src address */
				.next_proto_id = IPPROTO_UDP }};
	struct rte_flow_item_ipv4 ipv4_mask = {
			.hdr = {
				.src_addr = RTE_BE32(0xffffffff)}};
	struct rte_flow_item_udp udp_inner = {
			.hdr = {
				.dst_port = rte_cpu_to_be_16(4001) }};
				/* Match on udp dest port 4001 */
	struct rte_flow_item_udp udp_mask = {
			.hdr = {
				.dst_port = RTE_BE16(0xffff) }};


	size_t decap_size = sizeof(eth) + sizeof(ipv4) + sizeof(gre);
	size_t encap_size = sizeof(eth);
	uint8_t decap_buf[decap_size];
	uint8_t encap_buf[encap_size];
	uint8_t *bptr; /* Used to copy the headers to the buffer. */
	/* Since GTP is L3 tunnel type (no inner L2) it means that we need to
	 * first decap the outer header, and secondly encap the
	 * remaining packet with ETH header.
	 */
	struct rte_flow_action_raw_decap decap = {
			.size = decap_size ,
			.data = decap_buf };
	struct rte_flow_action_raw_encap encap = {
			.size = encap_size ,
			.data = encap_buf };
	struct rte_flow_action actions[] = {
			[0] = { /*Decap the outer part beginning from the
			 outermost L2 up to including the tunnel item. */
				.type = RTE_FLOW_ACTION_TYPE_RAW_DECAP,
				.conf = &decap },
			[1] = { /* Encap the packet with the missing L2. */
				.type = RTE_FLOW_ACTION_TYPE_RAW_ENCAP,
				.conf = &encap },
			[2] = { /* The RSS action to be used. */
				.type = RTE_FLOW_ACTION_TYPE_RSS,
				.conf = &rss },
			[3] = { /* End action must be the last action. */
				.type = RTE_FLOW_ACTION_TYPE_END,
				.conf = NULL }
			};

	/* Configure matching on GRE.
	 * This case we don't care about specific outer values we just 
	 * serach for any header that maches eth / ipv4 / gre /
	 * ipv4 src addr is 10.10.11.11/ udp proto is 4001.
	 * The RSS will only be done on the inner ipv4 src file, in order to 
	 * make sure that all of the packets from a given user (inner source
	 * ip) will be routed to the same core.
	 */
	pattern[L2].type = RTE_FLOW_ITEM_TYPE_ETH;
	pattern[L3].type = RTE_FLOW_ITEM_TYPE_IPV4;
	pattern[L4].type = RTE_FLOW_ITEM_TYPE_VOID;
	pattern[TUNNEL].type = RTE_FLOW_ITEM_TYPE_GRE;
	pattern[TUNNEL].mask = NULL;
	pattern[TUNNEL].spec = NULL;
	pattern[L3_INNER].type = RTE_FLOW_ITEM_TYPE_IPV4;
	pattern[L3_INNER].spec = &ipv4_inner;
	pattern[L3_INNER].mask = &ipv4_mask;
	pattern[L4_INNER].type = RTE_FLOW_ITEM_TYPE_UDP;
	pattern[L4_INNER].spec = &udp_inner;
	pattern[L4_INNER].mask = &udp_mask;

	/* Configure the buffer for the decap action.
	   The important part is the size of the buffer*/
	bptr = decap_buf;
	memcpy(bptr, &eth, sizeof(eth));
	bptr += sizeof(eth);
	memcpy(bptr, &ipv4, sizeof(ipv4));
	bptr += sizeof(ipv4);
	memcpy(bptr, &gre, sizeof(gre));
	bptr += sizeof(gre);
	/* Configure the buffer for the encap action. needs to add L2. */
	bptr = encap_buf;
	memcpy(bptr, &eth, sizeof(eth));

	/* Create the flow. */
	flow = rte_flow_create(port, &attr, pattern, actions, &error);
	if (!flow)
		printf("Can't create decap flow. %s\n", error.message);
	
	return flow;
}
