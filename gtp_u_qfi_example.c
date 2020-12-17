/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright 2020 Mellanox Technologies, Ltd
 */

#include <rte_net.h>
#include <rte_ethdev.h>
#include <rte_flow.h>

#include "vnf_examples.h"

/* Layer names, to be used inorder to access the relevent item. */
enum layer_name {
	L2,
	L3,
	L4,
	TUNNEL,
	TUNNEL_EXTENSION,
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
	[TUNNEL_EXTENSION] = {
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

/* Match on GTP-U QFI traffic. */
int
create_gtp_u_qfi_flow(uint16_t port_id)
{
	struct rte_flow *flow;
	struct rte_flow_error error;
	struct rte_flow_attr attr = { /* Holds the flow attributes. */
				.group = 0, /* set the rule on the main group. */
				.ingress = 1,/* Rx flow. */
				.priority = 0, };
	struct rte_flow_item_gtp gtp_spec = {
			.teid = rte_cpu_to_be_32(1234), /* Set the teid */
			.msg_type = 255 , /* The expected value. */
			.v_pt_rsv_flags = 4}; /*set extension flag*/
	struct rte_flow_item_gtp gtp_mask = {
			.teid = RTE_BE32(0xffffffff),/* Set teid mask*/
			.msg_type = 0xff, /* match on message type.*/
			.v_pt_rsv_flags = 0x07}; /*Set flags mask*/
			/*mask bit equal to 1 means match on this bit. */
	struct rte_flow_item_ipv4 ipv4_spec = {
			.hdr = {
				.src_addr = rte_cpu_to_be_32(0x03030101),
				/* Match on 3.3.1.1 src address */
				.next_proto_id = IPPROTO_UDP }};
	struct rte_flow_item_ipv4 ipv4_mask = {
			.hdr = {
				.src_addr = RTE_BE32(0xffffffff)}};
	struct rte_flow_action_jump jump = {.group = 1};
	struct rte_flow_action root_actions[] = {
		[0] = {
			.type = RTE_FLOW_ACTION_TYPE_JUMP,
			.conf = &jump,
		},
		[1] = {
			.type = RTE_FLOW_ACTION_TYPE_END,
		},
	};
	pattern[L2].type = RTE_FLOW_ITEM_TYPE_ETH;
	pattern[L3].type = RTE_FLOW_ITEM_TYPE_IPV4;
	pattern[L3].spec = &ipv4_spec;
	pattern[L3].mask = &ipv4_mask;
	pattern[L4].type = RTE_FLOW_ITEM_TYPE_UDP;
	pattern[TUNNEL].type = RTE_FLOW_ITEM_TYPE_GTP;
	pattern[TUNNEL].spec = &gtp_spec;
	pattern[TUNNEL].mask = &gtp_mask;
	flow = rte_flow_create(port_id, &attr, pattern, root_actions, &error);
	if (!flow) {
		printf("can't create jump flow on root table\n");
		return -1;
	}
	struct rte_flow_action_mark mark = {.id = 0x0303};
	struct rte_flow_action_queue queue = {.index = 0};
	struct rte_flow_action actions[] = {
		[0] = {
			.type = RTE_FLOW_ACTION_TYPE_MARK,
			.conf = &mark,
		},
		[1] = {
			.type = RTE_FLOW_ACTION_TYPE_QUEUE,
			.conf = &queue,
		},
		[2] = {
			.type = RTE_FLOW_ACTION_TYPE_END,
		},
	};
	struct rte_flow_item_gtp_psc gtp_psc_spec = {
			.pdu_type = 0x10, /* UL PDU Session Information. */
			.qfi = 9};
	struct rte_flow_item_gtp_psc gtp_psc_mask = {
			.pdu_type = 0xFF,
			.qfi = 0x3F}; /* QFI field is 6 bits. */
	pattern[TUNNEL_EXTENSION].type = RTE_FLOW_ITEM_TYPE_GTP_PSC;
	pattern[TUNNEL_EXTENSION].spec = &gtp_psc_spec;
	pattern[TUNNEL_EXTENSION].mask = &gtp_psc_mask;
	attr.group = 1; /* GTP PSC only suppot on non-group talbe. */
	flow = rte_flow_create(port_id, &attr, pattern, actions, &error);
	if (!flow) {
		printf("can't create flow match on GTP QFI on port: %u, error: %s\n",
				port_id, error.message);
		return -1;
	}
	return 0;
}
