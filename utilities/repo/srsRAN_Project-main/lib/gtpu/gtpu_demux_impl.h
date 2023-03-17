/*
 *
 * Copyright 2021-2023 Software Radio Systems Limited
 *
 * This file is part of srsRAN.
 *
 * srsRAN is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as
 * published by the Free Software Foundation, either version 3 of
 * the License, or (at your option) any later version.
 *
 * srsRAN is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * A copy of the GNU Affero General Public License can be found in
 * the LICENSE file in the top-level directory of this distribution
 * and at http://www.gnu.org/licenses/.
 *
 */

#pragma once

#include "srsran/gtpu/gtpu_demux.h"
#include "srsran/support/executors/task_executor.h"
#include <memory>
#include <unordered_map>

namespace srsran {

class gtpu_demux_impl final : public gtpu_demux
{
public:
  explicit gtpu_demux_impl(task_executor& cu_up_exec);
  ~gtpu_demux_impl() = default;

  // gtpu_demux_rx_upper_layer_interface
  void handle_pdu(byte_buffer pdu) override; // Will be run from IO executor.

  // gtpu_demux_ctrl
  bool add_tunnel(uint32_t teid, gtpu_tunnel_rx_upper_layer_interface* tunnel) override;
  bool remove_tunnel(uint32_t teid) override;

private:
  // Actual demuxing, to be run in CU-UP executor.
  void handle_pdu_impl(uint32_t teid, byte_buffer pdu);

  task_executor& cu_up_exec;

  ///< TODO: revisit mapping of TEID to executors, one executor per UE should be doable.
  std::unordered_map<uint16_t, gtpu_tunnel_rx_upper_layer_interface*> teid_to_tunnel; ///< Map TEID on GTP-U entity.

  srslog::basic_logger& logger;
};

} // namespace srsran
