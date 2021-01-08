/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright 2020 Mellanox Technologies, Ltd
 */

#include <rte_net.h>
#include <rte_ethdev.h>
#include <rte_flow.h>
#include <rte_ethdev.h>

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

enum direction {
	UL, /* Uplink. */
	DL, /* Downlink. */
};

struct flow_meta {
	uint64_t ue; /* UE index. */
	uint64_t pdu; /* PDU session index. */
	uint64_t flow_idx; /* flow idx in this PDU session. */
	struct rte_flow *flow; /* The handler of rte flow. */
};

#define MAX_USER_FLOWS 4

static struct flow_meta user_flows[MAX_USER_FLOWS];

static void
flow_aged_callback(void *arg)
{
	uint16_t port_id = (intptr_t)arg;
	void **contexts;
	int nb_context, total = 0, idx;
	struct rte_flow_error error;
	struct flow_meta *user_flow;

	total = rte_flow_get_aged_flows(port_id, NULL, 0, &error);
	if (total == 0)
		return;
	contexts = malloc(sizeof(void *) * total);
	if (contexts == NULL) {
		printf("Cannot allocate contexts for aged flow\n");
		return;
	}
	nb_context = rte_flow_get_aged_flows(port_id, contexts, total, &error);
	if (nb_context != total) {
		printf("Port:%d get aged flows count(%d) != total(%d)\n",
			port_id, nb_context, total);
		free(contexts);
		return;
	}
	total = 0;
	for (idx = 0; idx < nb_context; idx++) {
		if (!contexts[idx]) {
			printf("Error: get Null context in port %u\n", port_id);
			continue;
		}
		user_flow = (struct flow_meta *)contexts[idx];
		printf("UE: %lu, Session: %lu, flow idx: %lu is aged, deleting...",
				user_flow->ue, user_flow->pdu,
				user_flow->flow_idx);
		if (user_flow->flow &&
				rte_flow_destroy(port_id,
					user_flow->flow, &error))
			printf("Error: can't destroy aged flow!\n");
		user_flow->flow = NULL;
		printf("done\n");
	}
	free(contexts);
}

/* This callback is in intr thread, we need to finish it as soon as possible. */
static int
aged_event_callback(uint16_t port_id, enum rte_eth_event_type type,
		void *param, void *ret_param)
{
	RTE_SET_USED(param);
	RTE_SET_USED(ret_param);
	if (type == RTE_ETH_EVENT_FLOW_AGED) {
		if (rte_eal_alarm_set(1000,
				flow_aged_callback, (void *)(intptr_t)port_id))
			printf("Could not set up deffered delete aged flow");
	}
	return 0;
}

int
register_aged_event(uint16_t port_id)
{
	return rte_eth_dev_callback_register(port_id, RTE_ETH_EVENT_FLOW_AGED,
			aged_event_callback, NULL);
}

/*
 * create three flows with different age time.
 * The corresponding testpmd commands:
 * testpmd> flow create 0 group 0 ingress pattern eth / ipv4 src is 3.3.2.1 / udp /
 *          gtp teid is 1234 msg_type is 255 / end actions jump group 1 / end
 * testpmd> flow create 0 group 1 ingress pattern eth / ipv4 src is 3.3.2.1 / udp /
 *          gtp teid is 1234 msg_type is 255 / ipv4 src is 2.0.0.1 / tcp / end
 *          actions age  timeout 10 / mark id 0x0201 / queue index 0 / end
 * testpmd> flow create 0 group 1 ingress pattern eth / ipv4 src is 3.3.2.1 / udp /
 *          gtp teid is 1234 msg_type is 255 / ipv4 src is 2.0.0.2 / tcp / end
 *          actions age  timeout 20 / mark id 0x0202 / queue index 0 / end
 * testpmd> flow create 0 group 1 ingress pattern eth / ipv4 src is 3.3.2.1 / udp /
 *          gtp teid is 1234 msg_type is 255 / ipv4 src is 2.0.0.3 / tcp / end
 *          actions age  timeout 30 / mark id 0x0203 / queue index 0 / end
 */
int
create_flow_with_age(uint16_t port_id)
{
	struct rte_flow *flow;
	struct rte_flow_error error;
	struct rte_flow_attr attr = { /* Holds the flow attributes. */
				.group = 0, /* set the rule on the main group. */
				.ingress = 1,/* Rx flow. */
				.priority = 0, };
	struct rte_flow_item_gtp gtp_spec = {
			.teid = rte_cpu_to_be_32(1234), /* Set the teid */
			.msg_type = 255 }; /* The expected value. */
	struct rte_flow_item_gtp gtp_mask = {
			.teid = RTE_BE32(0xffffffff),/* Set teid mask*/
			.msg_type = 0xff }; /* match on message type.*/
			/*mask bit equal to 1 means match on this bit. */
	struct rte_flow_item_ipv4 ipv4_spec = {
			.hdr = {
				.src_addr = rte_cpu_to_be_32(0x03030201),
				/* Match on 3.3.2.1 src address */
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
	if (register_aged_event(port_id)) {
		printf("can't register for aged event!\n");
		return -1;
	}
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
	struct rte_flow_action_mark mark = {.id = 0x0201};
	struct rte_flow_action_queue queue = {.index = 0};
	struct rte_flow_action_age age;
	struct rte_flow_action actions[] = {
		[0] = {
			.type = RTE_FLOW_ACTION_TYPE_AGE,
			.conf = &age,
		},
		[1] = {
			.type = RTE_FLOW_ACTION_TYPE_MARK,
			.conf = &mark,
		},
		[2] = {
			.type = RTE_FLOW_ACTION_TYPE_QUEUE,
			.conf = &queue,
		},
		[3] = {
			.type = RTE_FLOW_ACTION_TYPE_END,
		},
	};
	struct rte_flow_item_ipv4 ipv4_inner = {
			.hdr = {
				.src_addr = rte_cpu_to_be_32(0x02000001),
				/* Match on 2.0.0.1 src address */
				.next_proto_id = IPPROTO_TCP }};
	pattern[L3_INNER].type = RTE_FLOW_ITEM_TYPE_IPV4;
	pattern[L3_INNER].spec = &ipv4_inner;
	pattern[L3_INNER].mask = &ipv4_mask;
	pattern[L4_INNER].type = RTE_FLOW_ITEM_TYPE_TCP;
	/* Let's create three flows. */
	attr.group = 1; /* must be in non-root table. */
	uint8_t i;
	for (i = 0; i < 3; i++) {
		ipv4_inner.hdr.src_addr = RTE_BE32(0x02000001 + i);
		mark.id = 0x0201 + i;
		/* When flow aged, context will pass back to us so we can know which flow. */
		age.context = &user_flows[i];
		age.timeout = 10 + i * 10; /* 10s, 20s, 30s. */
		flow = rte_flow_create(port_id, &attr, pattern, actions,
				&error);
		if (!flow) {
			printf("can't create flow with action age on port: %u, group: %u\n",
					port_id, attr.group);
			return -1;
		}
		user_flows[i].flow = flow;
		user_flows[i].flow_idx = i;
		user_flows[i].pdu = i;
		user_flows[i].ue = i;
	}
	return 0;
}
