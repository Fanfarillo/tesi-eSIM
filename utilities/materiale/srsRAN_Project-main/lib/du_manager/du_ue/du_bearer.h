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

#include "../adapters/f1ap_adapters.h"
#include "../adapters/mac_adapters.h"
#include "../adapters/rlc_adapters.h"
#include "srsran/adt/optional.h"
#include "srsran/adt/slotted_array.h"
#include "srsran/ran/lcid.h"
#include "srsran/ran/up_transport_layer_info.h"
#include "srsran/rlc/rlc_config.h"
#include "srsran/rlc/rlc_entity.h"

namespace srsran {
namespace srs_du {

/// \brief Connector of the MAC, RLC and F1 for a given DU UE SRB bearer.
struct du_srb_connector {
  mac_sdu_rx_adapter              mac_rx_sdu_notifier;
  mac_sdu_tx_adapter              mac_tx_sdu_notifier;
  rlc_rx_rrc_sdu_adapter          rlc_rx_sdu_notif;
  rlc_tx_data_notifier            rlc_tx_data_notif;
  rlc_tx_control_notifier         rlc_tx_ctrl_notif;
  rlc_tx_mac_buffer_state_updater rlc_tx_buffer_state_notif;
  f1c_rx_sdu_rlc_adapter          f1c_rx_sdu_notif;

  /// \brief Connect bearers of MAC, RLC and F1AP layers.
  void connect(du_ue_index_t                       ue_index,
               srb_id_t                            srb_id,
               f1c_bearer&                         f1_bearer,
               rlc_entity&                         rlc_bearer,
               mac_ue_control_information_handler& mac_ue_info_handler);
};

/// \brief Connector of the MAC, RLC and F1 for a given DU UE DRB bearer.
struct du_drb_connector {
  mac_sdu_rx_adapter              mac_rx_sdu_notifier;
  mac_sdu_tx_adapter              mac_tx_sdu_notifier;
  rlc_f1u_tx_sdu_adapter          rlc_rx_sdu_notif;
  rlc_tx_data_notifier            rlc_tx_data_notif;
  rlc_tx_control_notifier         rlc_tx_ctrl_notif;
  rlc_tx_mac_buffer_state_updater rlc_tx_buffer_state_notif;
  f1u_rx_rlc_sdu_adapter          f1u_rx_sdu_notif;

  /// \brief Connect MAC, RLC and F1AP layers if bearer is a DRB.
  void connect(du_ue_index_t                       ue_index,
               drb_id_t                            drb_id,
               lcid_t                              lcid,
               f1u_bearer&                         f1_bearer,
               rlc_entity&                         rlc_bearer,
               mac_ue_control_information_handler& mac_ue_info_handler);
};

/// \brief SRB instance in DU manager. It contains SRB configuration information, RLC entity and adapters between
/// layers.
struct du_ue_srb {
  srb_id_t                    srb_id;
  rlc_config                  rlc_cfg;
  std::unique_ptr<rlc_entity> rlc_bearer;
  du_srb_connector            connector;

  lcid_t lcid() const { return srb_id_to_lcid(srb_id); }
};

/// \brief DRB instance in DU manager. It contains DRB configuration information, RLC entity and adapters between
/// layers.
struct du_ue_drb {
  drb_id_t                             drb_id;
  lcid_t                               lcid;
  std::vector<up_transport_layer_info> uluptnl_info_list;
  std::vector<up_transport_layer_info> dluptnl_info_list;
  rlc_config                           rlc_cfg;
  std::unique_ptr<rlc_entity>          rlc_bearer;
  f1u_bearer*                          drb_f1u;
  du_drb_connector                     connector;
};

/// \brief Bearer container for a UE object in the DU manager.
class du_ue_bearer_manager
{
  struct drb_id_to_index {
    constexpr size_t   get_index(drb_id_t drb_id) const { return static_cast<size_t>(drb_id) - 1; }
    constexpr drb_id_t get_id(size_t idx) const { return static_cast<drb_id_t>(idx + 1); }
  };

public:
  du_ue_srb& add_srb(srb_id_t srb_id, const rlc_config& rlc_cfg);
  du_ue_drb& add_drb(drb_id_t drb_id, lcid_t lcid, const rlc_config& rlc_cfg);

  void remove_drb(drb_id_t drb_id);

  const slotted_id_table<srb_id_t, du_ue_srb, MAX_NOF_SRBS>&                        srbs() const { return srbs_; }
  slotted_id_table<srb_id_t, du_ue_srb, MAX_NOF_SRBS>&                              srbs() { return srbs_; }
  const slotted_id_table<drb_id_t, du_ue_drb, MAX_NOF_DRBS, true, drb_id_to_index>& drbs() const { return drbs_; };
  slotted_id_table<drb_id_t, du_ue_drb, MAX_NOF_DRBS, true, drb_id_to_index>&       drbs() { return drbs_; };

  optional<lcid_t> allocate_lcid() const;

private:
  slotted_id_table<srb_id_t, du_ue_srb, MAX_NOF_SRBS>                        srbs_;
  slotted_id_table<drb_id_t, du_ue_drb, MAX_NOF_DRBS, true, drb_id_to_index> drbs_;
};

} // namespace srs_du
} // namespace srsran
