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

#include "ue_manager_interfaces.h"
#include "srsran/adt/slotted_array.h"
#include "srsran/f1u/cu_up/f1u_gateway.h"
#include "srsran/support/timers.h"

namespace srsran {

namespace srs_cu_up {

class ue_manager : public ue_manager_ctrl
{
public:
  explicit ue_manager(network_interface_config&            net_config_,
                      srslog::basic_logger&                logger_,
                      timer_manager&                       timers_,
                      f1u_cu_up_gateway&                   f1u_gw_,
                      gtpu_tunnel_tx_upper_layer_notifier& gtpu_tx_notifier_,
                      gtpu_demux_ctrl&                     gtpu_rx_demux_);

  using ue_db_t = slotted_array<std::unique_ptr<ue_context>, MAX_NOF_UES>;
  const ue_db_t& get_ues() const { return ue_db; }

  ue_context* add_ue() override;
  void        remove_ue(ue_index_t ue_index) override;
  ue_context* find_ue(ue_index_t ue_index) override;
  size_t      get_nof_ues() override;

private:
  /// \brief Get the next available UE index.
  /// \return The UE index.
  ue_index_t get_next_ue_index();

  network_interface_config&            net_config;
  srslog::basic_logger&                logger;
  timer_manager&                       timers;
  f1u_cu_up_gateway&                   f1u_gw;
  gtpu_tunnel_tx_upper_layer_notifier& gtpu_tx_notifier;
  gtpu_demux_ctrl&                     gtpu_rx_demux;
  ue_db_t                              ue_db;
};

} // namespace srs_cu_up

} // namespace srsran
