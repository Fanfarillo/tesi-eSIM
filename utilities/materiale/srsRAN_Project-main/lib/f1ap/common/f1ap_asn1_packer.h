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

#include "srsran/adt/byte_buffer.h"
#include "srsran/f1ap/du/f1ap_du.h"
#include "srsran/gateways/sctp_network_gateway.h"
#include "srsran/srslog/srslog.h"
#include <cstdio>

namespace srsran {

class f1ap_asn1_packer : public f1ap_message_handler
{
public:
  explicit f1ap_asn1_packer(sctp_network_gateway_data_handler& gw, f1ap_message_handler& f1ap);

  void handle_packed_pdu(const byte_buffer& pdu);

  void handle_message(const f1ap_message& msg) override;

private:
  srslog::basic_logger&              logger;
  sctp_network_gateway_data_handler& gw;
  f1ap_message_handler&              f1ap;
};

} // namespace srsran
