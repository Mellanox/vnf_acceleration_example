#include <stdint.h>
#include <rte_ethdev.h>
#include <rte_net.h>
#include <rte_gre.h>

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

/*
 * create hairpin rx flow by using set_meta action
 * and match meta data on haripin tx side with GRE encap action.
 * The corresponding testpmd commands:
 * testpmd> set raw_decap 0 eth / end_set
 * testpmd> set raw_encap 0 eth dst is 01:02:03:04:05:06
 *          src is 06:05:04:03:02:01 / ipv4 src is 12.12.12.12
 *          dst is 13.13.13.13 proto is 47 /
 *          gre protocol is 0x0800 / end_set
 * testpmd> flow create 0 ingress group 0 pattern eth /
 *          ipv4 src is 10.10.12.12 / udp dst is 4002 / end
 *          actions set_meta data 0x1234 mask 0xffff /
 *          queue index 1 / end 
 * testpmd> flow create 1 egress group 0 pattern meta data spec 0x1234
 *          data mask 0x1234 / end actions raw_decap index 0 /
 *          raw_encap index 0 / end
 */
int
create_hairpin_meta_flow(void)
{
	struct rte_flow *flow;
	struct rte_flow_error error;
	struct rte_flow_attr attr = { /* Holds the flow attributes. */
				.group = 0, /* set the rule on the main group. */
				.ingress = 1,/* Rx flow. */
				.priority = 0, }; /* add priority to rule
				to give the Decap rule higher priority since
				it is more specific than RSS */
	/* Create the headers that will be needed for the encap. */
	struct rte_ether_hdr eth = {
			.ether_type = RTE_BE16(RTE_ETHER_TYPE_IPV4),
			.d_addr.addr_bytes = "\x01\x02\x03\x04\x05\x06",
			.s_addr.addr_bytes = "\x06\x05\x04\x03\x02\01" };
	struct rte_ipv4_hdr ipv4 = {
		.version_ihl = 0x45,
		.src_addr = RTE_BE32(0x0C0C0C0C),
		/* Set src address 12.12.12.12. */
		.dst_addr = RTE_BE32(0x0D0D0D0D),
		/* Set dst address 13.13.13.13 */
		.next_proto_id = IPPROTO_GRE };
	struct rte_gre_hdr gre = { .proto = RTE_BE16(RTE_ETHER_TYPE_IPV4) };
	size_t encap_size = sizeof(eth) + sizeof(ipv4) + sizeof(gre);
	size_t decap_size = sizeof(eth);
	uint8_t decap_buf[decap_size];
	uint8_t encap_buf[encap_size];
	uint8_t *bptr; /* Used to copy the headers to the buffer. */
	/* Since GRE is L3 tunnel type (no inner L2) it means that we need to
	 * first decap the outer header, and secondly encap the
	 * remaining packet with ETH header.
	 */
	struct rte_flow_action_raw_decap decap = {
			.size = decap_size,
			.data = decap_buf};
	struct rte_flow_action_raw_encap encap = {
			.size = encap_size,
			.data = encap_buf};
	/* Configure the buffer for the decap action.
	   The important part is the size of the buffer*/
	bptr = encap_buf;
	rte_memcpy(bptr, &eth, sizeof(eth));
	bptr += sizeof(eth);
	rte_memcpy(bptr, &ipv4, sizeof(ipv4));
	bptr += sizeof(ipv4);
	rte_memcpy(bptr, &gre, sizeof(gre));
	bptr += sizeof(gre);
	/* Configure the buffer for the encap action. needs to add L2. */
	bptr = decap_buf;
	rte_memcpy(bptr, &eth, sizeof(eth));

	/* create flow on first port and first hairpin queue. */
	uint16_t port_id = rte_eth_find_next_owned_by(0, RTE_ETH_DEV_NO_OWNER);
	RTE_ASSERT(port_id != RTE_MAX_ETHPORTS);
	struct rte_eth_dev_info dev_info;
	int ret = rte_eth_dev_info_get(port_id, &dev_info);
	if (ret)
		rte_exit(EXIT_FAILURE, "Cannot get device info");
	uint16_t qi;
	for (qi = 0; qi < dev_info.nb_rx_queues; qi++) {
		struct rte_eth_dev *dev = &rte_eth_devices[port_id];
		if (rte_eth_dev_is_rx_hairpin_queue(dev, qi))
			break;
	}
	struct rte_flow_action_queue queue;
        struct rte_flow_action_set_meta set_meta = {
                .data = 0x1234,
                .mask = 0xFFFF,
        };
	struct rte_flow_action actions[] = {
                [0] = {
                        .type = RTE_FLOW_ACTION_TYPE_SET_META,
                        .conf = &set_meta,
                },
		[1] = {
			.type = RTE_FLOW_ACTION_TYPE_QUEUE,
			.conf = &queue,
		},
		[2] = {
			.type = RTE_FLOW_ACTION_TYPE_END,
		},
	};
	queue.index = qi; /* rx hairpin queue index. */
        struct rte_flow_item_ipv4 ipv4_spec = {
                .hdr = {
                        /* match src addr 10.10.12.12. */
                        .src_addr = RTE_BE32(0x0A0A0C0C)}};
        struct rte_flow_item_ipv4 ipv4_mask = {
                .hdr = {
                        .src_addr = RTE_BE32(0xFFFFFFFF)}};
        struct rte_flow_item_udp udp_spec = {
                .hdr = {
                        .dst_port = RTE_BE16(4002)}};
        struct rte_flow_item_udp udp_mask = {
                .hdr = {
                        .dst_port = RTE_BE16(0xFFFF)}};
	pattern[L3].type = RTE_FLOW_ITEM_TYPE_IPV4;
	pattern[L3].spec = &ipv4_spec;
	pattern[L3].mask = &ipv4_mask;
	pattern[L4].type = RTE_FLOW_ITEM_TYPE_UDP;
        pattern[L4].spec = &udp_spec;
        pattern[L4].mask = &udp_mask;
	flow = rte_flow_create(port_id, &attr, pattern, actions, &error);
	if (!flow) {
		printf("Can't create hairpin flows on port: %u\n", port_id);
                return -1;
        }
	/* get peer port id. */
	uint16_t pair_port_list[RTE_MAX_ETHPORTS];
	int pair_port_num = rte_eth_hairpin_get_peer_ports(port_id,
			pair_port_list, RTE_MAX_ETHPORTS, 0);
	if (pair_port_num < 0)
		rte_exit(EXIT_FAILURE, "Can't get pair port !");
	RTE_ASSERT(pair_port_num == 1);
	/* create pattern to match hairpin flow from hairpin RX queue. */
        struct rte_flow_item_meta meta_spec = {
                .data = 0x1234};
        struct rte_flow_item_meta meta_mask = {
                .data = 0xFFFF};
	pattern[L2].type = RTE_FLOW_ITEM_TYPE_META;
	pattern[L2].spec = &meta_spec;
        pattern[L2].mask = &meta_mask;
	pattern[L3].type = RTE_FLOW_ITEM_TYPE_VOID;
	pattern[L4].type = RTE_FLOW_ITEM_TYPE_VOID;
	pattern[END].type = RTE_FLOW_ITEM_TYPE_END;
	/* create actions. */
	actions[0].type = RTE_FLOW_ACTION_TYPE_RAW_DECAP;
	actions[0].conf = &decap;
	actions[1].type = RTE_FLOW_ACTION_TYPE_RAW_ENCAP;
	actions[1].conf = &encap;
	actions[2].type = RTE_FLOW_ACTION_TYPE_END;
	attr.egress = 1;
	attr.ingress = 0;
	flow = rte_flow_create(pair_port_list[0], &attr, pattern, actions,
			&error);
	if (!flow)
		printf("Can't create hairpin flows on pair port: %u, "
			"error: %s\n", pair_port_list[0], error.message);
        return 0;
}