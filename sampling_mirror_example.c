#include <stdint.h>
#include <rte_flow.h>

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
create_flow_with_sampling(uint16_t port_id)
{
	struct rte_flow *flow;
	struct rte_flow_error error;
	struct rte_flow_attr attr = { /* Holds the flow attributes. */
				.group = 0, /* set the rule on the main group. */
				.ingress = 1,/* Rx flow. */
				.priority = 0,
	};
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
				.src_addr = rte_cpu_to_be_32(0x0C0A0A0A),
				/* Match on 12.10.10.10 src address */
				.next_proto_id = IPPROTO_TCP }};
	struct rte_flow_item_ipv4 ipv4_mask = {
			.hdr = {
				.src_addr = RTE_BE32(0xffffffff)}};

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
	flow = rte_flow_create(port_id, &attr, pattern, root_actions, &error);
	if (!flow) {
		printf("Can't create sampling flow on port: %u, group: %d, error: %s\n",
				port_id, attr.group, error.message);
		return flow;
	}
	struct rte_flow_action_queue queue = {.index = 0};
	struct rte_flow_action_mark sample_mark = {.id = 0xbeef};
	struct rte_flow_action_mark normal_mark = {.id = 0x1210};
	struct rte_flow_action sample_actions[] = {
		[0] = {
			.type = RTE_FLOW_ACTION_TYPE_MARK,
			.conf = &sample_mark,
		},
		[1] = {
			.type = RTE_FLOW_ACTION_TYPE_QUEUE,
			.conf = &queue, /* use same queue as normal packet. */
		},
		[2] = {
			.type = RTE_FLOW_ACTION_TYPE_END,
		},
	};
	struct rte_flow_action_sample sample_conf = {
		.ratio = 2, /* 50% sampling. */
		.actions = sample_actions,
	};
	struct rte_flow_action actions[] = {
		[0] = {
			.type = RTE_FLOW_ACTION_TYPE_SAMPLE,
			.conf = &sample_conf,
		},
		[1] = {
			.type = RTE_FLOW_ACTION_TYPE_MARK,
			.conf = &normal_mark,
		},
		[2] = {
			.type = RTE_FLOW_ACTION_TYPE_QUEUE,
			.conf = &queue,
		},
		[3] = {
			.type = RTE_FLOW_ACTION_TYPE_END,
		},
	};
	attr.group = 1; /* sampling action only available on non-root table. */
	flow = rte_flow_create(port_id, &attr, pattern, actions, &error);
	if (!flow)
		printf("Can't create sampling flow on port: %u, group: %d, error: %s\n",
				port_id, attr.group, error.message);
	return flow;
}

struct rte_flow *
create_flow_with_mirror(uint16_t port_id, uint16_t mirror2port,
		uint16_t fwd2port)
{
	struct rte_flow *flow;
	struct rte_flow_error error;
	struct rte_flow_attr attr = { /* Holds the flow attributes. */
				.group = 0, /* set the rule on the main group. */
				.ingress = 1,/* Rx flow. */
				.priority = 0,
				.transfer = 1, /* FDB flow. */
	};
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
				.src_addr = rte_cpu_to_be_32(0x0D0A0A0A),
				/* Match on 13.10.10.10 src address */
				.next_proto_id = IPPROTO_TCP }};
	struct rte_flow_item_ipv4 ipv4_mask = {
			.hdr = {
				.src_addr = RTE_BE32(0xffffffff)}};

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
	struct rte_flow_action_port_id mirror2port_conf = {.id = mirror2port};
	struct rte_flow_action_port_id fwd2port_conf = {.id = fwd2port};
	struct rte_flow_action mirror_actions[] = {
		[0] = {
			.type = RTE_FLOW_ACTION_TYPE_PORT_ID,
			.conf = &mirror2port_conf,
		},
		[1] = {
			.type = RTE_FLOW_ACTION_TYPE_END,
		},
	};
	struct rte_flow_action_sample mirror_conf = {
		.ratio = 1, /* mirror. */
		.actions = mirror_actions,
	};
	struct rte_flow_action actions[] = {
		[0] = {
			.type = RTE_FLOW_ACTION_TYPE_SAMPLE,
			.conf = &mirror_conf,
		},
		[1] = {
			.type = RTE_FLOW_ACTION_TYPE_PORT_ID,
			.conf = &fwd2port_conf,
		},
		[2] = {
			.type = RTE_FLOW_ACTION_TYPE_END,
		},
	};
	flow = rte_flow_create(port_id, &attr, pattern, actions, &error);
	if (!flow)
		printf("Can't create flow with mirror on port: %u, group: %d, error: %s\n",
				port_id, attr.group, error.message);
	return flow;

}
