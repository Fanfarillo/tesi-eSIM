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

#include "srsran/f1ap/common/f1ap_common.h"

namespace srsran {

/// \brief F1AP bridge between DU and CU-CP using fast-path message passing.
class f1ap_local_adapter : public f1ap_message_notifier
{
public:
  explicit f1ap_local_adapter(const std::string& log_name) : logger(srslog::fetch_basic_logger(log_name)) {}

  void attach_handler(f1ap_message_handler* handler_) { handler = handler_; }
  void on_new_message(const f1ap_message& msg) override
  {
    report_fatal_error_if_not(handler, "F1AP message handler not set");
    logger.debug("Received a PDU of type {}", msg.pdu.type().to_string());
    handler->handle_message(msg);
  }

private:
  srslog::basic_logger& logger;
  f1ap_message_handler* handler = nullptr;
};

}; // namespace srsran
