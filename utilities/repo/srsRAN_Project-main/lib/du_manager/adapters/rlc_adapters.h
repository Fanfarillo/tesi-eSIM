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

#include "srsran/f1ap/du/f1c_bearer.h"
#include "srsran/f1u/du/f1u_bearer.h"
#include "srsran/mac/mac_ue_control_information_handler.h"
#include "srsran/rlc/rlc_entity.h"

namespace srsran {
namespace srs_du {

class rlc_rx_rrc_sdu_adapter : public rlc_rx_upper_layer_data_notifier
{
public:
  void connect(f1c_bearer& bearer_) { f1bearer = &bearer_; }

  void on_new_sdu(byte_buffer_slice_chain pdu) override
  {
    srsran_assert(f1bearer != nullptr, "RLC Rx Bearer notifier is disconnected");
    f1bearer->handle_sdu(std::move(pdu));
  }

private:
  f1c_bearer* f1bearer = nullptr;
};

class rlc_f1u_tx_sdu_adapter : public rlc_rx_upper_layer_data_notifier
{
public:
  void connect(f1u_tx_sdu_handler& bearer_) { f1bearer = &bearer_; }

  void on_new_sdu(byte_buffer_slice_chain sdu) override
  {
    srsran_assert(f1bearer != nullptr, "RLC Rx bearer notifier is disconnected");
    f1bearer->handle_sdu(std::move(sdu));
  }

private:
  f1u_tx_sdu_handler* f1bearer = nullptr;
};

class rlc_tx_data_notifier : public rlc_tx_upper_layer_data_notifier
{
public:
  void on_transmitted_sdu(uint32_t max_deliv_pdcp_sn) override
  {
    // TODO
  }

  void on_delivered_sdu(uint32_t max_deliv_pdcp_sn) override
  {
    // TODO
  }
};

class rlc_tx_control_notifier : public rlc_tx_upper_layer_control_notifier
{
public:
  void on_protocol_failure() override
  {
    // TODO
  }

  void on_max_retx() override
  {
    // TODO
  }
};

class rlc_tx_mac_buffer_state_updater : public rlc_tx_lower_layer_notifier
{
public:
  void connect(du_ue_index_t ue_index_, lcid_t lcid_, mac_ue_control_information_handler& mac_)
  {
    ue_index = ue_index_;
    lcid     = lcid_;
    mac      = &mac_;
  }

  void on_buffer_state_update(unsigned bsr) override
  {
    srsran_assert(mac != nullptr, "RLC Tx Buffer State notifier is disconnected");
    mac_dl_buffer_state_indication_message bs{};
    bs.ue_index = ue_index;
    bs.lcid     = lcid;
    bs.bs       = bsr;
    mac->handle_dl_buffer_state_update_required(bs);
  }

private:
  du_ue_index_t                       ue_index = INVALID_DU_UE_INDEX;
  lcid_t                              lcid     = INVALID_LCID;
  mac_ue_control_information_handler* mac      = nullptr;
};

} // namespace srs_du
} // namespace srsran
