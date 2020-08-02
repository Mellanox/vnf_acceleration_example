/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright 2020 Mellanox Technologies, Ltd
 */

#include <rte_net.h>
#include <rte_ethdev.h>
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
struct rte_flow_item pattern[] = {
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

/* Create RSS on inner source IP. */
static struct rte_flow *
create_gtp_u_inner_ip_rss_flow(uint16_t port, uint32_t nb_queues,
			       uint16_t *queues)
{
	struct rte_flow *flow;
	struct rte_flow_error error;
	__rte_unused struct rte_flow_attr attr = { /* Holds the flow attributes. */
				.group = 0, /* set the rule on the main group. */
				.ingress = 1, };/* Rx flow. */
	struct rte_flow_item_gtp gtp_spec = {
			.msg_type = 255 }; /* The expected value. */
	struct rte_flow_item_gtp gtp_mask = {
			.msg_type = 0xff }; /* match only message type.
			mask bit equal to 1 means match on this bit. */
	struct rte_flow_action_rss rss = {
			.level = 2, /* RSS should be done on inner header. */
			.queue = queues, /* Set the selected target queues. */
			.queue_num = nb_queues, /* The number of queues. */
			.types =  ETH_RSS_IP | ETH_RSS_L3_SRC_ONLY };
	struct rte_flow_action actions[] = {
			[0] = { /* The RSS action to be used. */
				.type = RTE_FLOW_ACTION_TYPE_RSS,
				.conf = &rss },
			[1] = { /* End action mast be the last action. */
				.type = RTE_FLOW_ACTION_TYPE_END,
				.conf = NULL }
			};

	/* Configure matching on outer ipv4 and GTP-U.
	 * This case we don't care about specific outer ipv4 or UDP we just 
	 * seach for any header that maches eth / ipv4 / udp / gtp type 255 / 
	 * ipv4 / udp.
	 * The RSS will only be done on the inner ipv4 src file, in order to 
	 * make sure that all of the packets from a given user (inner source
	 * ip) will be routed to the same core.
	 */
	pattern[L3].type = RTE_FLOW_ITEM_TYPE_IPV4;
	pattern[L4].type = RTE_FLOW_ITEM_TYPE_UDP;
	pattern[TUNNEL].type = RTE_FLOW_ITEM_TYPE_GTP;
	pattern[TUNNEL].spec = &gtp_spec;
	pattern[TUNNEL].mask = &gtp_mask;

	/* Create the flow. */
	flow = rte_flow_create(port, &attr, pattern, actions, &error);
	if (!flow)
		printf("Can't create the RSS flow on inner ip. %s\n",
		       error.message);
	
	return flow;

}


int
main(__rte_unused int argc, __rte_unused char **argv)
{
	uint32_t nb_queues = 4;
	uint16_t queues[] = {0, 1, 2, 3};
	create_gtp_u_inner_ip_rss_flow(0, nb_queues, queues);
	return 0;
}
