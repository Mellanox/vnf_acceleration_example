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

struct rte_flow_action_count shared_counter = {
	.shared = 1,
	.id = 100,
};

struct rte_flow_action_count dedicated_counter = {
	.shared = 0,
};

struct rte_flow *flow1, *flow2, *flow3, *flow4;

int
create_flow_with_counter(uint16_t port)
{
	struct rte_flow_error error;
	struct rte_flow_attr attr = { /* Holds the flow attributes. */
				.group = 0, /* set the rule on the main group. */
				.ingress = 1,/* Rx flow. */
				.priority = 0, }; 
	struct rte_flow_action_queue queue = {
		.index = 0,
	};
	struct rte_flow_action actions[] = {
			[0] = { /* Shared counter. */
				.type = RTE_FLOW_ACTION_TYPE_COUNT,
				.conf = &shared_counter },
			[1] = {
				.type = RTE_FLOW_ACTION_TYPE_QUEUE,
				.conf = &queue},
			[2] = { /* End action mast be the last action. */
				.type = RTE_FLOW_ACTION_TYPE_END,
				.conf = NULL }
			};
	struct rte_flow_item_ipv4 ipv4_spec = {
		.hdr = {
			.src_addr = RTE_BE32(RTE_IPV4(1, 1, 1, 1)),
		},
	};
	struct rte_flow_item_ipv4 ipv4_mask = {
		.hdr = {
			.src_addr = RTE_BE32(UINT32_MAX),
		},
	};
	pattern[L2].type = RTE_FLOW_ITEM_TYPE_ETH;
	pattern[L3].type = RTE_FLOW_ITEM_TYPE_IPV4;
	pattern[L3].spec = &ipv4_spec;
	pattern[L3].mask = &ipv4_mask;
	pattern[L4].type = RTE_FLOW_ITEM_TYPE_TCP;
	/* Create the flow. */
	flow1 = rte_flow_create(port, &attr, pattern, actions, &error);
	if (!flow1) {
		printf("Can't create first flow with shared count. %s\n",
		       error.message);
		return -1;
	}
	ipv4_spec.hdr.src_addr = RTE_BE32(RTE_IPV4(1, 1, 1, 2));
	flow2 = rte_flow_create(port, &attr, pattern, actions, &error);
	if (!flow2) {
		printf("Can't create second flow with shared count. %s\n",
		       error.message);
		return -1;
	}
	actions[0].conf = &dedicated_counter;
	ipv4_spec.hdr.src_addr = RTE_BE32(RTE_IPV4(1, 1, 1, 3));
	flow3 = rte_flow_create(port, &attr, pattern, actions, &error);
	if (!flow3) {
		printf("Can't create third flow with dedicated count. %s\n",
		       error.message);
		return -1;
	}
	actions[0].conf = &dedicated_counter;
	ipv4_spec.hdr.src_addr = RTE_BE32(RTE_IPV4(1, 1, 1, 4));
	flow4 = rte_flow_create(port, &attr, pattern, actions, &error);
	if (!flow4) {
		printf("Can't create third flow with dedicated count. %s\n",
		       error.message);
		return -1;
	}
	return 0;
}

int
query_counters(uint16_t port)
{
	struct rte_flow_query_count query_counter;
	struct rte_flow_error error;
	struct rte_flow_action action = {.type = RTE_FLOW_ACTION_TYPE_COUNT};
	struct rte_flow_action actions[2];
	actions[1].type = RTE_FLOW_ACTION_TYPE_END;
	actions[0].type = RTE_FLOW_ACTION_TYPE_COUNT;
	actions[0].conf = &shared_counter;
	if (rte_flow_query(port, flow1, actions, &query_counter, &error)) {
		printf("Can't query flow1's counter, msg: %s\n", error.message);
		return -1;
	}
	printf("flow1 counter: hits_set[%u], bytes_set[%u], hits[%"PRIu64"], "
			"bytes[%"PRIu64"]\n", query_counter.hits_set,
			query_counter.bytes_set, query_counter.hits,
			query_counter.bytes);
	if (rte_flow_query(port, flow2, actions, &query_counter, &error)) {
		printf("Can't query flow2's counter, msg: %s\n", error.message);
		return -1;
	}
	printf("flow2 counter: hits_set[%u], bytes_set[%u], hits[%"PRIu64"], "
			"bytes[%"PRIu64"]\n", query_counter.hits_set,
			query_counter.bytes_set, query_counter.hits,
			query_counter.bytes);
	actions[0].conf = &dedicated_counter;
	if (rte_flow_query(port, flow3, actions, &query_counter, &error)) {
		printf("Can't query flow3's counter, msg: %s\n", error.message);
		return -1;
	}
	printf("flow3 counter: hits_set[%u], bytes_set[%u], hits[%"PRIu64"], "
			"bytes[%"PRIu64"]\n", query_counter.hits_set,
			query_counter.bytes_set, query_counter.hits,
			query_counter.bytes);
	if (rte_flow_query(port, flow4, actions, &query_counter, &error)) {
		printf("Can't query flow4's counter, msg: %s\n", error.message);
		return -1;
	}
	printf("flow4 counter: hits_set[%u], bytes_set[%u], hits[%"PRIu64"], "
			"bytes[%"PRIu64"]\n", query_counter.hits_set,
			query_counter.bytes_set, query_counter.hits,
			query_counter.bytes);
	return 0;
}
