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

#include "srsran/f1ap/du/f1c_rx_sdu_notifier.h"
#include "srsran/f1u/du/f1u_rx_sdu_notifier.h"
#include "srsran/rlc/rlc_tx.h"

namespace srsran {
namespace srs_du {

class f1c_rx_sdu_rlc_adapter final : public f1c_rx_sdu_notifier
{
public:
  void connect(rlc_tx_upper_layer_data_interface& rlc_tx_) { rlc_tx = &rlc_tx_; }

  void on_new_sdu(byte_buffer pdu) override
  {
    srsran_assert(rlc_tx != nullptr, "RLC Tx PDU notifier is disconnected");
    rlc_tx->handle_sdu(rlc_sdu{std::move(pdu), {}});
  }

private:
  rlc_tx_upper_layer_data_interface* rlc_tx = nullptr;
};

class f1u_rx_rlc_sdu_adapter final : public f1u_rx_sdu_notifier
{
public:
  void connect(rlc_tx_upper_layer_data_interface& rlc_tx_) { rlc_tx = &rlc_tx_; }

  void on_new_sdu(pdcp_tx_pdu sdu) override
  {
    srsran_assert(rlc_tx != nullptr, "RLC Tx SDU notifier is disconnected");
    rlc_tx->handle_sdu(rlc_sdu{std::move(sdu.buf), sdu.pdcp_sn});
  }

  void on_discard_sdu(uint32_t pdcp_sn) override
  {
    // TODO.
  }

private:
  rlc_tx_upper_layer_data_interface* rlc_tx = nullptr;
};

} // namespace srs_du
} // namespace srsran
