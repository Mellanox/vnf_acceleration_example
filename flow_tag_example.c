/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright 2020 Mellanox Technologies, Ltd
 */

#include <rte_net.h>
#include <rte_ethdev.h>
#include <rte_flow.h>
#include <rte_gtp.h>
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

struct rte_flow *
create_flow_with_tag(uint16_t port_id)
{
	struct rte_flow *flow;
	struct rte_flow_error error;
	struct rte_flow_attr attr = { /* Holds the flow attributes. */
				.group = 0, /* set the rule on the main group. */
				.ingress = 1,/* Rx flow. */
				.priority = 0, }; /* add priority to rule
				to give the Decap rule higher priority since
				it is more specific than RSS */
	/* Create the items that will be needed for the decap. */
	struct rte_ether_hdr eth = { 
		.ether_type = RTE_BE16(RTE_ETHER_TYPE_IPV4),
		.d_addr.addr_bytes = "\x01\x02\x03\x04\x05\x06",
		.s_addr.addr_bytes = "\x06\x05\x04\x03\x02\x01",
	};
	struct rte_ipv4_hdr ipv4 = { 0 };
	struct rte_udp_hdr udp = { 0 };
	struct rte_gtp_hdr gtp = { 0 };
	/* Create the items that will be needed for the encap. */
	struct rte_flow_item_gtp gtp_spec = {
			.teid = RTE_BE32(1234), /* Set the teid */
			.msg_type = 255 , /* The expected value. */
			.v_pt_rsv_flags = 0}; /* No extension header. */
			/**
			* Version (3b), protocol type (1b), reserved (1b),
			* Extension header flag (1b),
			* Sequence number flag (1b),
			* N-PDU number flag (1b).
			*/
	struct rte_flow_item_gtp gtp_mask = {
			.teid = RTE_BE32(0xffffffff),/* Set teid mask*/
			.msg_type = 0xff , /* match on message type.*/
			.v_pt_rsv_flags = 0x07}; /*Set flags mask*/
			/*mask bit equal to 1 means match on this bit. */
	struct rte_flow_item_ipv4 ipv4_inner = {
			.hdr = {
				.src_addr = rte_cpu_to_be_32(0x0B0A0A0A),
				/* Match on 11.10.10.10 src address */
				.next_proto_id = IPPROTO_TCP }};
	struct rte_flow_item_ipv4 ipv4_mask = {
			.hdr = {
				.src_addr = RTE_BE32(0xffffffff)}};

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
	/* Configure the buffer for the decap action.
	   The important part is the size of the buffer*/
	bptr = decap_buf;
	rte_memcpy(bptr, &eth, sizeof(eth));
	bptr += sizeof(eth);
	rte_memcpy(bptr, &ipv4, sizeof(ipv4));
	bptr += sizeof(ipv4);
	rte_memcpy(bptr, &udp, sizeof(udp));
	bptr += sizeof(udp);
	rte_memcpy(bptr, &gtp, sizeof(gtp));
	bptr += sizeof(gtp);
	/* Configure the buffer for the encap action. needs to add L2. */
	bptr = encap_buf;
	rte_memcpy(bptr, &eth, sizeof(eth));
	struct rte_flow_action_set_tag set_tag = {
		.data = 0xdeadbeef,
		.index = 0,
		.mask = UINT32_MAX,
	};
	struct rte_flow_action_jump jump = {
		.group = 1,
	};
	struct rte_flow_action root_actions[] = {
		[0] = {
			.type = RTE_FLOW_ACTION_TYPE_SET_TAG,
			.conf = &set_tag,
		},
		[1] = {
			.type = RTE_FLOW_ACTION_TYPE_JUMP,
			.conf = &jump,
		},
		[2] = {
			.type = RTE_FLOW_ACTION_TYPE_END,
		},
	};
	pattern[L2].type = RTE_FLOW_ITEM_TYPE_ETH;
	pattern[L2].spec = NULL;
	pattern[L3].type = RTE_FLOW_ITEM_TYPE_IPV4;
	pattern[L3].spec = NULL;
	pattern[L4].type = RTE_FLOW_ITEM_TYPE_UDP;
	pattern[L4].spec = NULL;
	pattern[TUNNEL].type = RTE_FLOW_ITEM_TYPE_GTP;
	pattern[TUNNEL].spec = &gtp_spec;
	pattern[TUNNEL].mask = &gtp_mask;
	pattern[L3_INNER].type = RTE_FLOW_ITEM_TYPE_IPV4;
	pattern[L3_INNER].spec = &ipv4_inner;
	pattern[L3_INNER].mask = &ipv4_mask;
	pattern[L4_INNER].type = RTE_FLOW_ITEM_TYPE_TCP;
	pattern[L4_INNER].spec = NULL;
	pattern[END].type = RTE_FLOW_ITEM_TYPE_END;
	flow = rte_flow_create(port_id, &attr, pattern, root_actions, &error);
	if (!flow) {
		printf("Can't create tag flow on port: %u, group: %d, error: %s\n",
				port_id, attr.group, error.message);
		return flow;
	}
	struct rte_flow_item_tag tag = {
		.data = 0xdeadbeef,
		.index = 0,
	};
	pattern[L2].type = RTE_FLOW_ITEM_TYPE_TAG;
	pattern[L2].spec = &tag;
	pattern[L2].mask = NULL; /* use default mask. */
	pattern[L3].type = RTE_FLOW_ITEM_TYPE_END;
	struct rte_flow_action_queue queue = {
		.index = 0,
	};
	struct rte_flow_action actions[] = {
		[0] = {
			.type = RTE_FLOW_ACTION_TYPE_RAW_DECAP,
			.conf = &decap,
		},
		[1] = {
			.type = RTE_FLOW_ACTION_TYPE_RAW_ENCAP,
			.conf = &encap,
		},
		[2] = {
			.type = RTE_FLOW_ACTION_TYPE_QUEUE,
			.conf = &queue,
		},
		[3] = {
			.type = RTE_FLOW_ACTION_TYPE_END,
		},
	};
	attr.group = 1;
	flow = rte_flow_create(port_id, &attr, pattern, actions, &error);
	if (!flow)
		printf("Can't create tag flow on port: %u, group: %d, error: %s\n",
				port_id, attr.group, error.message);
	return flow;
}
