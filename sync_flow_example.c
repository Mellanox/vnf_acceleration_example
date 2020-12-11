/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright 2020 Mellanox Technologies, Ltd
 */

#include <stdint.h>
#include <rte_compat.h>
#include <rte_pmd_mlx5.h>

#include "vnf_examples.h"

int
sync_nic_tx_flows(uint16_t port_id)
{
	return rte_pmd_mlx5_sync_flow(port_id, MLX5_DOMAIN_BIT_NIC_TX);
}

int
sync_all_flows(uint16_t port_id)
{
	return rte_pmd_mlx5_sync_flow(port_id,
			MLX5_DOMAIN_BIT_FDB |
			MLX5_DOMAIN_BIT_NIC_RX |
			MLX5_DOMAIN_BIT_NIC_TX);
}
