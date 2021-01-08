#include <stdint.h>
#include <rte_ethdev.h>
#include <rte_net.h>
#include <rte_gtp.h>

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


static int
hairpin_port_unbind(uint16_t port_id)
{
	uint16_t pair_port_list[RTE_MAX_ETHPORTS];
	int pair_port_num, i;

	/* unbind current port's hairpin TX queues. */
	rte_eth_hairpin_unbind(port_id, RTE_MAX_ETHPORTS);
	/* find all peer TX queues bind to current ports' RX queues. */
	pair_port_num = rte_eth_hairpin_get_peer_ports(port_id,
			pair_port_list, RTE_MAX_ETHPORTS, 0);
	if (pair_port_num < 0)
		return pair_port_num;

	for (i = 0; i < pair_port_num; i++) {
		if (!rte_eth_devices[i].data->dev_started)
			continue;
		rte_eth_hairpin_unbind(pair_port_list[i], port_id);
	}
	return 0;
}

static int
hairpin_port_bind(uint16_t port_id, int direction)
{
	int i, ret = 0;
	uint16_t peer_ports[RTE_MAX_ETHPORTS];
	int peer_ports_num = 0;

	peer_ports_num = rte_eth_hairpin_get_peer_ports(port_id,
			peer_ports, RTE_MAX_ETHPORTS, direction);
	if (peer_ports_num < 0 )
		return peer_ports_num; /* errno. */
	for (i = 0; i < peer_ports_num; i++) {
		if (!rte_eth_devices[i].data->dev_started)
			continue;
		ret = rte_eth_hairpin_bind(port_id, peer_ports[i]);
		if (ret)
			return ret;
	}
	return ret;
}


static int
setup_hairpin_queues(uint16_t port_id, uint16_t prev_port_id,
		uint16_t port_num, uint64_t nr_hairpin_queues)
{
	/*
	 * Configure hairpin queue with so called port pair mode,
	 * which pair two consequece port together:
	 * P0 <-> P1, P2 <-> P3, etc
	 */
	uint16_t peer_port_id = RTE_MAX_ETHPORTS;
	uint32_t hairpin_queue, peer_hairpin_queue, nr_queues = 0;
	int ret = 0;
	struct rte_eth_hairpin_conf hairpin_conf = {
		.peer_count = 1,
		.manual_bind = 1,
		.tx_explicit = 1,
	};
	struct rte_eth_dev_info dev_info = { 0 };
	struct rte_eth_dev_info peer_dev_info = { 0 };
	struct rte_eth_rxq_info rxq_info = { 0 };
	struct rte_eth_txq_info txq_info = { 0 };
	uint16_t nr_std_rxq, nr_std_txq, peer_nr_std_rxq, peer_nr_std_txq;

	ret = rte_eth_dev_info_get(port_id, &dev_info);
	if (ret)
		rte_exit(EXIT_FAILURE, "Error: can't get device info, port id:"
				" %u\n", port_id);
	nr_std_rxq = dev_info.nb_rx_queues - nr_hairpin_queues;
	nr_std_txq = dev_info.nb_tx_queues - nr_hairpin_queues;
	nr_queues = dev_info.nb_rx_queues;
	/* only get first q info. */
	rte_eth_rx_queue_info_get(port_id, 0, &rxq_info);
	rte_eth_tx_queue_info_get(port_id, 0, &txq_info);
	if (port_num & 0x1) {
		peer_port_id = prev_port_id;
	}
	else {
		peer_port_id = rte_eth_find_next_owned_by(port_id + 1,
				RTE_ETH_DEV_NO_OWNER);
		if (peer_port_id >= RTE_MAX_ETHPORTS)
			peer_port_id = port_id;
	}
	ret = rte_eth_dev_info_get(peer_port_id, &peer_dev_info);
	if (ret)
		rte_exit(EXIT_FAILURE, "Error: can't get peer device info, "
				"peer port id: %u", peer_port_id);
	peer_nr_std_rxq = peer_dev_info.nb_rx_queues - nr_hairpin_queues;
	peer_nr_std_txq = peer_dev_info.nb_tx_queues - nr_hairpin_queues;
	for (hairpin_queue = nr_std_rxq, peer_hairpin_queue = peer_nr_std_txq;
			hairpin_queue < nr_queues;
			hairpin_queue++, peer_hairpin_queue++) {
		hairpin_conf.peers[0].port = peer_port_id;
		hairpin_conf.peers[0].queue = peer_hairpin_queue;
		ret = rte_eth_rx_hairpin_queue_setup(
				port_id, hairpin_queue,
				rxq_info.nb_desc, &hairpin_conf);
		if (ret != 0)
			return ret;
	}
	for (hairpin_queue = nr_std_txq, peer_hairpin_queue = peer_nr_std_rxq;
			hairpin_queue < nr_queues;
			hairpin_queue++, peer_hairpin_queue++) {
		hairpin_conf.peers[0].port = peer_port_id;
		hairpin_conf.peers[0].queue = peer_hairpin_queue;
		ret = rte_eth_tx_hairpin_queue_setup(
				port_id, hairpin_queue,
				txq_info.nb_desc, &hairpin_conf);
		if (ret != 0)
			return ret;
	}
	return ret;
}

int
hairpin_one_port_setup(uint16_t port_id, uint64_t nr_hairpin_queues)
{
	int ret;
	struct rte_eth_hairpin_conf hairpin_conf = {
		.peer_count = 1,
		.manual_bind = 0,
		.tx_explicit = 0,
	};
	struct rte_eth_dev_info dev_info = { 0 };
	uint16_t nr_std_rxq, nr_std_txq, nr_queues;
	uint16_t hairpin_rx_queue, hairpin_tx_queue;
	struct rte_eth_rxq_info rxq_info = { 0 };
	struct rte_eth_txq_info txq_info = { 0 };

	ret = rte_eth_dev_info_get(port_id, &dev_info);
	if (ret)
		rte_exit(EXIT_FAILURE, "Error: can't get device info, port id:"
				" %u\n", port_id);
	nr_std_rxq = dev_info.nb_rx_queues - nr_hairpin_queues;
	nr_std_txq = dev_info.nb_tx_queues - nr_hairpin_queues;
	nr_queues = dev_info.nb_rx_queues;
	/* only get first q info. */
	rte_eth_rx_queue_info_get(port_id, 0, &rxq_info);
	rte_eth_tx_queue_info_get(port_id, 0, &txq_info);
	for (hairpin_rx_queue = nr_std_rxq, hairpin_tx_queue = nr_std_txq; /* start from self TX queue. */
			hairpin_rx_queue < nr_queues;
			hairpin_rx_queue++, hairpin_tx_queue++) {
		hairpin_conf.peers[0].port = port_id; /* one port hairpin, peer is self. */
		hairpin_conf.peers[0].queue = hairpin_tx_queue;
		ret = rte_eth_rx_hairpin_queue_setup(
				port_id, hairpin_rx_queue,
				rxq_info.nb_desc, &hairpin_conf);
		if (ret != 0)
			return ret;
	}
	for (hairpin_tx_queue = nr_std_txq, hairpin_rx_queue = nr_std_rxq;
			hairpin_tx_queue < nr_queues;
			hairpin_tx_queue++, hairpin_rx_queue++) {
		hairpin_conf.peers[0].port = port_id;
		hairpin_conf.peers[0].queue = hairpin_rx_queue;
		ret = rte_eth_tx_hairpin_queue_setup(
				port_id, hairpin_tx_queue,
				txq_info.nb_desc, &hairpin_conf);
		if (ret != 0)
			return ret;
	}

	return 0;
}

int
hairpin_two_ports_setup(uint64_t nr_hairpin_queue)
{
	uint16_t port_id, prev_port_id = RTE_MAX_ETHPORTS;
	uint16_t port_num = 0;
	int ret = 0;

	RTE_ETH_FOREACH_DEV(port_id) {
		ret = setup_hairpin_queues(port_id, prev_port_id,
				port_num, nr_hairpin_queue);
		if (ret)
			rte_exit(EXIT_FAILURE, "Error to setup hairpin queues"
					" on port: %u", port_id);
		port_num++;
		prev_port_id = port_id;
	}
	return 0;
}

int
hairpin_two_ports_bind(void)
{
	int ret = 0;
	uint16_t port_id;

	RTE_ETH_FOREACH_DEV(port_id) {
		/* Let's find our peer RX ports, TXQ -> RXQ. */
		ret = hairpin_port_bind(port_id, 1);
		if (ret)
			return ret;
		/* Let's find our peer TX ports, RXQ -> TXQ. */
		ret = hairpin_port_bind(port_id, 0);
		if (ret)
			return ret;
	}
	return ret;
}

int
hairpin_two_ports_unbind(void)
{
	uint16_t port_id;
	int ret, error = 0;

	RTE_ETH_FOREACH_DEV(port_id) {
		ret = hairpin_port_unbind(port_id);
		if (ret) {
			printf("Error on unbind hairpin port: %u\n", port_id);
			error = ret;
		}
	}
	return error;
}

/*
 * create flows for two ports hairpin.
 * The corresponding testpmd commands:
 * start testpmd with one rxq, one txq, two ports, and hairpin-mode=0x12:
 * > sudo build/app/dpdk-testpmd -n 4 -w 0000:af:00.0 -w 0000:af:00.1 -- \
 *   -i --rxq=1 --txq=1 --flow-isolate-all --forward-mode=io \
 *   --hairpinq=1 --hairpin-mode=0x12
 * 
 * testpmd> set raw_decap 0 eth / end_set
 * testpmd> set raw_encap 0 eth src is 06:05:04:03:02:01
 *          dst is 01:02:03:04:05:06 type is 0x0800 /
 *          ipv4 src is 160.160.160.160 dst is 161.161.160.160 ttl is 20 /
 *          udp dst is 2152 /
 *          gtp teid is 0x1234 msg_type is 0xFF v_pt_rsv_flags is 0x30 / end_set
 * testpmd> flow create 0 group 0 ingress pattern eth / ipv4 src is 10.10.10.10 /
 *          tcp / end actions queue index 1 / end
 * testpmd> flow create 1 group 0 egress pattern eth / ipv4 src is 10.10.10.10 /
 *          tcp / end actions raw_decap index 0 / raw_encap index 0 / end
 */
struct rte_flow *
hairpin_two_ports_flows_create(void)
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
		.s_addr.addr_bytes = "\x06\x05\x04\x03\x02\01",
	};
	struct rte_ipv4_hdr ipv4 = {
		.dst_addr = RTE_BE32(0xA0A0A0A0),
		.src_addr = RTE_BE32(0xA1A1A0A0),
		.time_to_live = 20,
		.next_proto_id = 17,
		.version_ihl = 0x45,
	};
	struct rte_udp_hdr udp = {
		.dst_port = RTE_BE16(RTE_GTPU_UDP_PORT),
	};
	struct rte_gtp_hdr gtp = {
		.teid = RTE_BE32(0x1234),
		.msg_type = 0xFF,
		.gtp_hdr_info = 0x30,
	};
	struct rte_flow_item_ipv4 ipv4_inner = {
			.hdr = {
				.src_addr = rte_cpu_to_be_32(0x0A0A0A0A),
				/* Match on 10.10.10.10 src address */
				.next_proto_id = IPPROTO_TCP }};
	struct rte_flow_item_ipv4 ipv4_mask = {
			.hdr = {
				.src_addr = RTE_BE32(0xffffffff)}};

	size_t encap_size = sizeof(eth) + sizeof(ipv4) + sizeof(udp) +
			sizeof(gtp);
	size_t decap_size = sizeof(eth);
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
	bptr = encap_buf;
	rte_memcpy(bptr, &eth, sizeof(eth));
	bptr += sizeof(eth);
	rte_memcpy(bptr, &ipv4, sizeof(ipv4));
	bptr += sizeof(ipv4);
	rte_memcpy(bptr, &udp, sizeof(udp));
	bptr += sizeof(udp);
	rte_memcpy(bptr, &gtp, sizeof(gtp));
	bptr += sizeof(gtp);
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
	struct rte_flow_action actions[] = {
		[0] = {
			.type = RTE_FLOW_ACTION_TYPE_QUEUE,
			.conf = &queue,
		},
		[1] = {
			.type = RTE_FLOW_ACTION_TYPE_END,
		},
		[2] = {
			.type = RTE_FLOW_ACTION_TYPE_END,
		},
	};
	queue.index = qi; /* rx hairpin queue index. */
	pattern[L3].type = RTE_FLOW_ITEM_TYPE_IPV4;
	pattern[L3].spec = &ipv4_inner;
	pattern[L3].mask = &ipv4_mask;
	pattern[L4].type = RTE_FLOW_ITEM_TYPE_TCP;
	flow = rte_flow_create(port_id, &attr, pattern, actions, &error);
	if (!flow)
		printf("Can't create hairpin flows on port: %u\n", port_id);
	/* get peer port id. */
	uint16_t pair_port_list[RTE_MAX_ETHPORTS];
	int pair_port_num = rte_eth_hairpin_get_peer_ports(port_id,
			pair_port_list, RTE_MAX_ETHPORTS, 0);
	if (pair_port_num < 0)
		rte_exit(EXIT_FAILURE, "Can't get pair port !");
	RTE_ASSERT(pair_port_num == 1);
	/* create pattern to match hairpin flow from hairpin RX queue. */
	pattern[L2].type = RTE_FLOW_ITEM_TYPE_ETH;
	pattern[L2].spec = NULL;
	pattern[L3].type = RTE_FLOW_ITEM_TYPE_IPV4;
	pattern[L3].spec = &ipv4_inner;
	pattern[L3].mask = &ipv4_mask;
	pattern[L4].type = RTE_FLOW_ITEM_TYPE_TCP;
	pattern[L4].spec = NULL;
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
	return flow;
}

/*
 * create flows for one port hairpin.
 * The corresponding testpmd commands:
 * start testpmd with one rxq, one txq, one ports:
 * > sudo build/app/dpdk-testpmd -n 4 -w 0000:af:00.0 -- \
 *   -i --rxq=1 --txq=1 --flow-isolate-all --forward-mode=io \
 *   --hairpinq=1
 * 
 * testpmd> set raw_decap 0 eth / end_set
 * testpmd> set raw_encap 0 eth src is 06:05:04:03:02:01
 *          dst is 01:02:03:04:05:06 type is 0x0800 /
 *          ipv4 src is 160.160.160.160 dst is 161.161.160.160 ttl is 20 /
 *          udp dst is 2152 /
 *          gtp teid is 0x1234 msg_type is 0xFF v_pt_rsv_flags is 0x30 / end_set
 * testpmd> flow create 0 group 0 ingress pattern eth / ipv4 src is 10.10.10.10 /
 *          tcp / end actions raw_decap index 0 / raw_encap index 0 /
 *          queue index 1 / end
 */
struct rte_flow *
hairpin_one_port_flows_create(void)
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
		.s_addr.addr_bytes = "\x06\x05\x04\x03\x02\01",
	};
	struct rte_ipv4_hdr ipv4 = {
		.dst_addr = RTE_BE32(0xA0A0A0A0),
		.src_addr = RTE_BE32(0xA1A1A0A0),
		.time_to_live = 20,
		.next_proto_id = 17,
		.version_ihl = 0x45,
	};
	struct rte_udp_hdr udp = {
		.dst_port = RTE_BE16(RTE_GTPU_UDP_PORT),
	};
	struct rte_gtp_hdr gtp = {
		.teid = RTE_BE32(0x1234),
		.msg_type = 0xFF,
		.gtp_hdr_info = 0x30,
	};
	struct rte_flow_item_ipv4 ipv4_inner = {
			.hdr = {
				.src_addr = rte_cpu_to_be_32(0x0A0A0A0A),
				/* Match on 10.10.10.10 src address */
				.next_proto_id = IPPROTO_TCP }};
	struct rte_flow_item_ipv4 ipv4_mask = {
			.hdr = {
				.src_addr = RTE_BE32(0xffffffff)}};

	size_t encap_size = sizeof(eth) + sizeof(ipv4) + sizeof(udp) +
			sizeof(gtp);
	size_t decap_size = sizeof(eth);
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
	bptr = encap_buf;
	rte_memcpy(bptr, &eth, sizeof(eth));
	bptr += sizeof(eth);
	rte_memcpy(bptr, &ipv4, sizeof(ipv4));
	bptr += sizeof(ipv4);
	rte_memcpy(bptr, &udp, sizeof(udp));
	bptr += sizeof(udp);
	rte_memcpy(bptr, &gtp, sizeof(gtp));
	bptr += sizeof(gtp);
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
	pattern[L2].type = RTE_FLOW_ITEM_TYPE_ETH;
	pattern[L2].spec = NULL;
	pattern[L3].type = RTE_FLOW_ITEM_TYPE_IPV4;
	pattern[L3].spec = &ipv4_inner;
	pattern[L3].mask = &ipv4_mask;
	pattern[L4].type = RTE_FLOW_ITEM_TYPE_TCP;
	queue.index = qi; /* rx hairpin queue index. */
	flow = rte_flow_create(port_id, &attr, pattern, actions, &error);
	if (!flow)
		printf("Can't create hairpin flows on port: %u\n", port_id);
	return flow;
}
