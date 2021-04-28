#include <stdint.h>
#include <rte_flow.h>
#include <rte_errno.h>

#define MAX_PATTERN_NUM 5

struct rte_flow *
generate_set_tag_flow(uint16_t port_id, uint8_t tag_id, uint32_t tag_value,
		      uint32_t src_ip, uint32_t src_mask,
		      uint32_t dest_ip, uint32_t dest_mask,
		      struct rte_flow_error *error)
{
	struct rte_flow_attr attr = {0};
	struct rte_flow_action action[MAX_PATTERN_NUM] = {{0}};
	struct rte_flow_item pattern[MAX_PATTERN_NUM] = {{0}};
	struct rte_flow *flow = NULL;
	struct rte_flow_item_eth eth;
	struct rte_flow_item_ipv4 ip_spec;
	struct rte_flow_item_ipv4 ip_mask;
	struct rte_flow_item_udp udp;
	struct rte_flow_action_set_tag tag_spec;
	struct rte_flow_action_jump jump_spec;

	/* Match specified IP src and dst addresses */
	memset(&eth, 0, sizeof(struct rte_flow_item_eth));
	pattern[0].type = RTE_FLOW_ITEM_TYPE_ETH;
	pattern[0].spec = &eth;
	pattern[0].mask = &eth;
	memset(&ip_spec, 0, sizeof(struct rte_flow_item_ipv4));
	memset(&ip_mask, 0, sizeof(struct rte_flow_item_ipv4));
	ip_spec.hdr.src_addr = rte_cpu_to_be_32(dest_ip);
	ip_mask.hdr.dst_addr = rte_cpu_to_be_32(dest_mask);
	ip_spec.hdr.src_addr = rte_cpu_to_be_32(src_ip);
	ip_mask.hdr.src_addr = rte_cpu_to_be_32(src_mask);
	pattern[1].type = RTE_FLOW_ITEM_TYPE_IPV4;
	pattern[1].spec = &ip_spec;
	pattern[1].mask = &ip_mask;
	memset(&udp, 0, sizeof(struct rte_flow_item_udp));
	pattern[2].type = RTE_FLOW_ITEM_TYPE_UDP;
	pattern[2].spec = &udp;
	pattern[2].mask = &udp;
	/* the final level must be always type end */
	pattern[3].type = RTE_FLOW_ITEM_TYPE_END;
	
	/* Set Tag. */
	tag_spec.data =rte_cpu_to_be_32(tag_value);
	tag_spec.mask = RTE_BE32(0xffffffff);
	tag_spec.index = tag_id;
	action[0].type = RTE_FLOW_ACTION_TYPE_SET_TAG;
	action[0].conf = &tag_spec;
	/* Jump to next group. */
	jump_spec.group = 2;
	action[1].type = RTE_FLOW_ACTION_TYPE_JUMP;
	action[1].conf = &jump_spec;
	/* the final level must be always type end */
	action[2].type = RTE_FLOW_ACTION_TYPE_END;

	attr.egress = 1;
	attr.group = 1;

	int res = rte_flow_validate(port_id, &attr, pattern, action, error);
	if(!res)
		flow = rte_flow_create(port_id, &attr, pattern, action, error);
	return flow;
}

struct rte_flow *
generate_decap_encap_flow(uint16_t port_id, struct rte_flow_error *error)
{
	struct rte_flow_attr attr = {0};
	struct rte_flow_action action[MAX_PATTERN_NUM] = {{0}};
	struct rte_flow_item pattern[MAX_PATTERN_NUM] = {{0}};
	struct rte_flow *flow = NULL;
	struct rte_flow_item_eth eth;
	struct rte_flow_item_ipv4 ip;
	struct rte_flow_item_udp udp;
	struct rte_flow_item_gtp gtp;
	struct rte_flow_action_raw_decap decap_spec;
	struct rte_flow_action_raw_encap encap_spec;
	struct rte_flow_action_jump jump_spec;
	uint8_t *bptr; /* Used to copy the headers to the buffer. */

	/* Match all the UDP packets */
	memset(&eth, 0, sizeof(struct rte_flow_item_eth));
	pattern[0].type = RTE_FLOW_ITEM_TYPE_ETH;
	pattern[0].spec = &eth;
	pattern[0].mask = &eth;
	memset(&ip, 0, sizeof(struct rte_flow_item_ipv4));
	pattern[1].type = RTE_FLOW_ITEM_TYPE_IPV4;
	pattern[1].spec = &ip;
	pattern[1].mask = &ip;
	memset(&udp, 0, sizeof(struct rte_flow_item_udp));
	pattern[2].type = RTE_FLOW_ITEM_TYPE_UDP;
	pattern[2].spec = &udp;
	pattern[2].mask = &udp;
	/* the final level must be always type end */
	pattern[3].type = RTE_FLOW_ITEM_TYPE_END;
	
	/* Remove old ETH header. */
	
	decap_spec.size = sizeof(eth);
	uint8_t decap_buf[decap_spec.size];
	decap_spec.data = decap_buf;
	bptr = decap_buf;
	memcpy(bptr, &eth, sizeof(eth));
	action[0].type = RTE_FLOW_ACTION_TYPE_RAW_DECAP;
	action[0].conf = &decap_spec;
	/* Encapsulate packet. */
	encap_spec.size = sizeof(eth) + sizeof(ip) + sizeof(udp) + sizeof(gtp);
	uint8_t encap_buf[encap_spec.size];
	encap_spec.data = encap_buf;
	bptr = encap_buf;
	memcpy(bptr, &eth, sizeof(eth));
	bptr += sizeof(eth);
	memcpy(bptr, &ip, sizeof(ip));
	bptr += sizeof(ip);
	memcpy(bptr, &udp, sizeof(udp));
	bptr += sizeof(udp);
	gtp.v_pt_rsv_flags = 0x30;
	gtp.msg_type = 0xff;
	gtp.teid = 0x0;
	memcpy(bptr, &gtp, sizeof(gtp));
	bptr += sizeof(gtp);
	action[1].type = RTE_FLOW_ACTION_TYPE_RAW_ENCAP;
	action[1].conf = &encap_spec;
	/* Jump to next group. */
	jump_spec.group = 3;
	action[2].type = RTE_FLOW_ACTION_TYPE_JUMP;
	action[2].conf = &jump_spec;
	/* the final level must be always type end */
	action[3].type = RTE_FLOW_ACTION_TYPE_END;

	attr.egress = 1;
	attr.group = 2;

	int res = rte_flow_validate(port_id, &attr, pattern, action, error);
	if(!res)
		flow = rte_flow_create(port_id, &attr, pattern, action, error);
	return flow;
}

struct rte_flow *
generate_modify_gtp_teid_flow(uint16_t port_id, uint16_t tag_id,
			      struct rte_flow_error *error)
{
	struct rte_flow_attr attr;
	struct rte_flow_action action[MAX_PATTERN_NUM] = {{0}};
	struct rte_flow_item pattern[MAX_PATTERN_NUM] = {{0}};
	struct rte_flow *flow = NULL;
	struct rte_flow_item_eth eth;
	struct rte_flow_item_ipv4 ip;
	struct rte_flow_item_udp udp;
	struct rte_flow_item_gtp gtp;
	struct rte_flow_action_modify_data dst = {
		.field = RTE_FLOW_FIELD_GTP_TEID,
		.level = 0,
		.offset = 0,
	};
	struct rte_flow_action_modify_data src = {
		.field = RTE_FLOW_FIELD_TAG,
		.level = tag_id,
		.offset = 0,
	};
	struct rte_flow_action_modify_field spec = {
		.operation = RTE_FLOW_MODIFY_SET,
		.dst = dst,
		.src = src,
		.width = 32,
	};

	/* Match all the GTP packets */
	memset(&eth, 0, sizeof(struct rte_flow_item_eth));
	pattern[0].type = RTE_FLOW_ITEM_TYPE_ETH;
	pattern[0].spec = &eth;
	pattern[0].mask = &eth;
	memset(&ip, 0, sizeof(struct rte_flow_item_ipv4));
	pattern[1].type = RTE_FLOW_ITEM_TYPE_IPV4;
	pattern[1].spec = &ip;
	pattern[1].mask = &ip;
	memset(&udp, 0, sizeof(struct rte_flow_item_udp));
	pattern[2].type = RTE_FLOW_ITEM_TYPE_UDP;
	pattern[2].spec = &udp;
	pattern[2].mask = &udp;
	memset(&gtp, 0, sizeof(struct rte_flow_item_gtp));
	pattern[3].type = RTE_FLOW_ITEM_TYPE_GTP;
	pattern[3].spec = &gtp;
	pattern[3].mask = &gtp;
	/* the final level must be always type end */
	pattern[4].type = RTE_FLOW_ITEM_TYPE_END;
	
	/* Replace GTP TEID with a specified value. */
	action[0].type = RTE_FLOW_ACTION_TYPE_MODIFY_FIELD;
	action[0].conf = &spec;
	/* the final level must be always type end */
	action[1].type = RTE_FLOW_ACTION_TYPE_END;

	attr.egress = 1;
	attr.group = 3;

	int res = rte_flow_validate(port_id, &attr, pattern, action, error);
	if(!res)
		flow = rte_flow_create(port_id, &attr, pattern, action, error);
	return flow;
}

static int
generate_gtp_flows(uint16_t port_id, uint16_t tag_id, uint32_t tag_value,
		   uint32_t src_ip, uint32_t src_mask, uint32_t dest_ip,
		   uint32_t dest_mask, struct rte_flow_error *error)
{
	struct rte_flow *flow = NULL;
	flow = generate_set_tag_flow(port_id, tag_id, tag_value,
		src_ip, src_mask, dest_ip, dest_mask, error);
	if (flow == NULL)
		return rte_errno;
	flow = generate_decap_encap_flow(port_id, error);
	if (flow == NULL)
		return rte_errno;
	flow = generate_modify_gtp_teid_flow(port_id, tag_id, error);
	if (flow == NULL)
		return rte_errno;
	return 0;
}

int
create_modify_gtp_teid_flows(uint16_t port_id)
{
	uint16_t tag_id = 2;
	uint32_t tag_value = 0xdeadbeef;
	uint32_t ip_src = RTE_IPV4(14,14,14,14);
	uint32_t ip_dst = RTE_IPV4(14,14,14,15);
	uint32_t ip_addr_mask = UINT32_MAX;
	struct rte_flow_error error = {0};
	int ret;

	ret = generate_gtp_flows(port_id, tag_id, tag_value, ip_src,
				 ip_addr_mask, ip_dst, ip_addr_mask, &error);
	if (ret)
		printf("Can't create modify gtp teid flows, %s\n",
			error.message);
	return ret;
}
