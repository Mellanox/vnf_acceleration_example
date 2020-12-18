/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright 2020 Mellanox Technologies, Ltd
 */
#ifndef RTE_VNF_EXAMPLES_H_
#define RTE_VNF_EXAMPLES_H_

#include <stdint.h>

struct rte_flow *
create_gtp_u_decap_rss_flow(uint16_t port, uint32_t nb_queues,
					     uint16_t *queues);

struct rte_flow *
create_gtp_u_inner_ip_rss_flow(uint16_t port, uint32_t nb_queues,
			       uint16_t *queues);

struct rte_flow *
create_gtp_u_encap_flow(uint16_t port);

int
sync_nic_tx_flows(uint16_t port);

int
sync_all_flows(uint16_t port);

int
hairpin_one_port_setup(uint16_t port, uint64_t nr_hairpin_queue);

int
hairpin_two_ports_setup(uint16_t nr_hairpin_queues);

int
hairpin_two_ports_bind();

int
hairpin_two_ports_unbind();

struct rte_flow *
hairpin_two_ports_flows_create(void);

struct rte_flow *
hairpin_one_port_flows_create(void);

struct rte_flow *
create_flow_with_tag(uint16_t port);

struct rte_flow *
create_flow_with_sampling(uint16_t port);

struct rte_flow *
create_flow_with_mirror(uint16_t port, uint16_t mirror2port, uint16_t fwd2port);

int
create_symmetric_rss_flow(uint16_t port, uint32_t nb_queues, uint16_t *queues);

int
create_flow_with_meter(uint16_t port);

int
create_gtp_u_qfi_flow(uint16_t port);

int
create_flow_with_age(uint16_t port);

int
register_aged_event(uint16_t port);
#endif
