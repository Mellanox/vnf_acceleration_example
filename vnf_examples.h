/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright 2020 Mellanox Technologies, Ltd
 */
#ifndef RTE_VNF_EXAMPLES_H_
#define RTE_VNF_EXAMPLES_H_


struct rte_flow *
create_gtp_u_decap_rss_flow(uint16_t port, uint32_t nb_queues,
					     uint16_t *queues);

struct rte_flow *
create_gtp_u_inner_ip_rss_flow(uint16_t port, uint32_t nb_queues,
			       uint16_t *queues);

struct rte_flow *
create_gtp_u_encap_flow(uint16_t port);
#endif
