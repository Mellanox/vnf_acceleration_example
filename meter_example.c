/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright 2020 Mellanox Technologies, Ltd
 */

#include <rte_net.h>
#include <rte_ethdev.h>
#include <rte_flow.h>
#include <rte_mtr.h>

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

static int
add_meter_profile(uint16_t port_id, uint32_t profile_id,
		struct rte_mtr_error *error)
{
	struct rte_mtr_meter_profile profile;

	memset(&profile, 0, sizeof(profile));
	profile.alg = RTE_MTR_SRTCM_RFC2697; /* the one supported. */
	profile.srtcm_rfc2697.cir = 1*1024*1024; /* 1MBps. */
	profile.srtcm_rfc2697.cbs = 64*1024; /* allow burst in 64KB. */
	profile.srtcm_rfc2697.ebs = 0; /* ignored. */

	return rte_mtr_meter_profile_add(port_id, profile_id, &profile, error);
}

static int
create_meter(uint16_t port_id, uint32_t mtr_id, uint32_t profile_id,
		int shared, struct rte_mtr_error *error)
{
	struct rte_mtr_params params;

	memset(&params, 0, sizeof(params));
	params.meter_enable = 1;
	params.use_prev_mtr_color = 0;
	params.dscp_table = NULL; /* no input color. */
	params.action[RTE_COLOR_GREEN] = MTR_POLICER_ACTION_COLOR_GREEN;
	params.action[RTE_COLOR_YELLOW] = MTR_POLICER_ACTION_COLOR_YELLOW;
	params.action[RTE_COLOR_RED] = MTR_POLICER_ACTION_DROP;
	/* Enable all stats. */
	params.stats_mask = RTE_MTR_STATS_N_BYTES_GREEN |
				RTE_MTR_STATS_N_BYTES_YELLOW |
				RTE_MTR_STATS_N_BYTES_RED |
				RTE_MTR_STATS_N_BYTES_DROPPED |
				RTE_MTR_STATS_N_PKTS_GREEN |
				RTE_MTR_STATS_N_PKTS_YELLOW |
				RTE_MTR_STATS_N_PKTS_RED |
				RTE_MTR_STATS_N_PKTS_DROPPED;

	return rte_mtr_create(port_id, mtr_id, &params, shared, error);
}

/*
 * create flow with meter.
 * The corresponding testpmd commands:
 * testpmd> add port meter profile srtcm_rfc2697 0 0 1048576 65536 0
 * testpmd> create port meter 0 0 0 yes G Y D 0xFFFF 1 0
 * testpmd> flow create 0 priority 1 group 0 ingress pattern eth / ipv4 / udp /
 *          gtp msg_type is 255 / ipv4 src is 13.10.10.10 / tcp / end
 *          actions set_tag data 0xD0A0 index 1 mask 0xFFFFFFFF /
 *          jump group 1 / end
 * testpmd> flow create 0 group 1 priority 1 ingress pattern tag data is 0xD0A0
 *          index is 1 / end actions mark id 0xD0A0 / meter mtr_id 0 /
 *          queue index 0 / end
 */
int
create_flow_with_meter(uint16_t port_id)
{
	int ret;
	struct rte_mtr_error mtr_error;
	uint32_t profile_id = 0;
	uint32_t mtr_id = 0;
	int shared = 1; /* mtr is shared. */

	ret = add_meter_profile(port_id, profile_id, &mtr_error);
	if (ret) {
		printf("cannot add meter profile, error: %s\n",
				mtr_error.message);
		return ret;
	}
	ret = create_meter(port_id, mtr_id, profile_id, shared, &mtr_error);
	if (ret) {
		printf("cannot create meter: %u with profile: %u, error: %s\n",
				mtr_id, profile_id, mtr_error.message);
		return ret;
	}
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
	struct rte_flow_action_set_tag set_tag = {
		.data = 0xD0A0,
		.index = 1,
		.mask = 0xFFFFFFFF,
	};
	struct rte_flow_action_jump jump = {.group = 1};
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
	struct rte_flow_item_ipv4 ipv4_inner = {
			.hdr = {
				.src_addr = rte_cpu_to_be_32(0x0D0A0A0A),
				/* match on 13.10.10.10 src address */
				.next_proto_id = IPPROTO_TCP }};
	struct rte_flow_item_ipv4 ipv4_mask = {
			.hdr = {
				.src_addr = RTE_BE32(0xffffffff)}};

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
	flow = rte_flow_create(port_id, &attr, pattern, root_actions, &error);
	if (!flow) {
		printf("can't create jump flow on root table\n");
		return -1;
	}

	struct rte_flow_action_mark mark = {.id = 0xD0A0};
	struct rte_flow_action_queue queue = {.index = 0};
	struct rte_flow_action_meter meter = {.mtr_id = mtr_id};
	struct rte_flow_action actions[] = {
			[0] = { /* mark action. */
				.type = RTE_FLOW_ACTION_TYPE_MARK,
				.conf = &mark },
			[1] = { /* meter action. */
				.type = RTE_FLOW_ACTION_TYPE_METER,
				.conf = &meter},
			[2] = { /* the queue action to be used. */
				.type = RTE_FLOW_ACTION_TYPE_QUEUE,
				.conf = &queue },
			[3] = { /* end action mast be the last action. */
				.type = RTE_FLOW_ACTION_TYPE_END,},
	};
	struct rte_flow_item_tag tag = {
		.data = 0xD0A0,
		.index = 1,
	};
	pattern[L2].type = RTE_FLOW_ITEM_TYPE_TAG;
	pattern[L2].spec = &tag;
	pattern[L3].type = RTE_FLOW_ITEM_TYPE_END;
	attr.group = 1;
	flow = rte_flow_create(port_id, &attr, pattern, actions, &error);
	if (!flow) {
		printf("can't create flow with with mtr id: %u, mtr profile: %u on port: %u, error: %s\n",
				mtr_id, profile_id, port_id, error.message);
		return -1;
	}
	return 0;
}
