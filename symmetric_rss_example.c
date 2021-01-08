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

/* create two flows by using symmetric rss key.
 * The corresponding testpmd commands:
 * testpmd> flow create 0 group 0 ingress pattern eth / ipv4 / udp /
 *          gtp msg_type is 255 / ipv4 src is 2.0.0.1 / tcp / end
 *          actions mark id 0x2001 /
 *          rss level 2
 *          key 6d5a6d5a6d5a6d5a6d5a6d5a6d5a6d5a6d5a6d5a6d5a6d5a6d5a6d5a6d5a6d5a6d5a6d5a6d5a6d5a
 *          key_len 40 types ip l3-src-only end / end
 * testpmd> flow create 0 group 0 ingress pattern eth / ipv4 dst is 2.0.0.1 /
 *          tcp / end actions mark id 0x2001 /
 *          rss level 1
 *          key 6d5a6d5a6d5a6d5a6d5a6d5a6d5a6d5a6d5a6d5a6d5a6d5a6d5a6d5a6d5a6d5a6d5a6d5a6d5a6d5a
 *          key_len 40 types ip l3-dst-only end / end
 */

int
create_symmetric_rss_flow(uint16_t port_id, uint32_t nb_queues,
		uint16_t *queues)
{
	struct rte_flow *flow;
	struct rte_flow_error error;
	struct rte_flow_attr attr = { /* holds the flow attributes. */
				.group = 0, /* set the rule on the main group. */
				.ingress = 1,/* rx flow. */
				.priority = 1, }; /* add priority to rule
				to give the decap rule higher priority since
				it is more specific */
	struct rte_flow_item_gtp gtp_spec = {
			.msg_type = 255 }; /* the expected value. */
	struct rte_flow_item_gtp gtp_mask = {
			.msg_type = 0xff }; /* match only message type.
			mask bit equal to 1 means match on this bit. */
	uint8_t symmetric_rss_key[] = {
		0x6D, 0x5A, 0x6D, 0x5A,
		0x6D, 0x5A, 0x6D, 0x5A,
		0x6D, 0x5A, 0x6D, 0x5A,
		0x6D, 0x5A, 0x6D, 0x5A,
		0x6D, 0x5A, 0x6D, 0x5A,
		0x6D, 0x5A, 0x6D, 0x5A,
		0x6D, 0x5A, 0x6D, 0x5A,
		0x6D, 0x5A, 0x6D, 0x5A,
		0x6D, 0x5A, 0x6D, 0x5A,
		0x6D, 0x5A, 0x6D, 0x5A,
	};
	struct rte_flow_action_mark mark = {.id = 0x2001};
	struct rte_flow_action_rss rss = {
			.level = 2, /* rss should be done on inner header. */
			.queue = queues, /* set the selected target queues. */
			.queue_num = nb_queues, /* the number of queues. */
			.types =  ETH_RSS_IP,
			.key = symmetric_rss_key,
			.key_len = 40,
	};
	struct rte_flow_action actions[] = {
			[0] = { /* mark action. */
				.type = RTE_FLOW_ACTION_TYPE_MARK,
				.conf = &mark },
			[1] = { /* the rss action to be used. */
				.type = RTE_FLOW_ACTION_TYPE_RSS,
				.conf = &rss },
			[2] = { /* end action mast be the last action. */
				.type = RTE_FLOW_ACTION_TYPE_END,},
	};
	/* Uplink match UE IP. */
	struct rte_flow_item_ipv4 ipv4_inner = {
			.hdr = {
				.src_addr = rte_cpu_to_be_32(0x02000001),
				/* match on 2.0.0.1 src address */
				.next_proto_id = IPPROTO_TCP }};
	struct rte_flow_item_ipv4 ipv4_mask = {
			.hdr = {
				.src_addr = RTE_BE32(0xffffffff)}};

	/* configure matching on inner ipv4 src field which is UE's IP.
	 * RSS on inner IP src and dst with symmetric key.
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
	pattern[L4_INNER].type = RTE_FLOW_ITEM_TYPE_TCP;

	/* create the Uplink flow match on UE's IP. */
	flow = rte_flow_create(port_id, &attr, pattern, actions, &error);
	if (!flow) {
		printf("can't create UL symmetric RSS flow on inner ip. %s\n",
		       error.message);
		return -1;
	}
	/* Downlink match on UE's IP too, which is dst address. */
	ipv4_inner.hdr.dst_addr = rte_cpu_to_be_32(0x02000001);
	memset(&ipv4_mask.hdr, 0, sizeof(ipv4_mask.hdr));
	ipv4_mask.hdr.dst_addr = RTE_BE32(0xFFFFFFFF);
	pattern[L3].spec = &ipv4_inner;
	pattern[L3].mask = &ipv4_mask;
	pattern[L4].type = RTE_FLOW_ITEM_TYPE_TCP;
	pattern[L4].spec = NULL;
	pattern[TUNNEL].type = RTE_FLOW_ITEM_TYPE_VOID;
	pattern[L3_INNER].type = RTE_FLOW_ITEM_TYPE_VOID;
	pattern[L4_INNER].type = RTE_FLOW_ITEM_TYPE_VOID;
	pattern[END].type = RTE_FLOW_ITEM_TYPE_END;
	rss.level = 1;
	/* create the Downlink flow match on UE's IP. */
	flow = rte_flow_create(port_id, &attr, pattern, actions, &error);
	if (!flow) {
		printf("can't create DL symmetric RSS flow on inner ip. %s\n",
		       error.message);
		return -1;
	}
	return 0;
}

