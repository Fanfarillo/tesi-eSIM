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

#include "f1u_bearer_logger.h"
#include "srsran/f1u/du/f1u_bearer.h"
#include "srsran/f1u/du/f1u_rx_sdu_notifier.h"
#include "srsran/f1u/du/f1u_tx_pdu_notifier.h"
#include "srsran/ran/lcid.h"

namespace srsran {
namespace srs_du {

class f1u_bearer_impl final : public f1u_bearer,
                              public f1u_tx_sdu_handler,
                              public f1u_tx_delivery_handler,
                              public f1u_rx_pdu_handler
{
public:
  f1u_bearer_impl(uint32_t             ue_index,
                  drb_id_t             drb_id_,
                  f1u_rx_sdu_notifier& rx_sdu_notifier_,
                  f1u_tx_pdu_notifier& tx_pdu_notifier_);

  f1u_tx_sdu_handler&      get_tx_sdu_handler() override { return *this; }
  f1u_tx_delivery_handler& get_tx_delivery_handler() override { return *this; }
  f1u_rx_pdu_handler&      get_rx_pdu_handler() override { return *this; }

  void handle_sdu(byte_buffer_slice_chain sdu) override;
  void handle_transmit_notification(uint32_t highest_pdcp_sn) override;
  void handle_delivery_notification(uint32_t highest_pdcp_sn) override;
  void handle_pdu(nru_dl_message msg) override;

private:
  f1u_bearer_logger    logger;
  f1u_rx_sdu_notifier& rx_sdu_notifier;
  f1u_tx_pdu_notifier& tx_pdu_notifier;
};

} // namespace srs_du
} // namespace srsran
