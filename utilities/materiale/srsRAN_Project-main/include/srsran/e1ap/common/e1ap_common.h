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

#include "srsran/asn1/e1ap/e1ap.h"

namespace srsran {

struct e1ap_message {
  asn1::e1ap::e1ap_pdu_c pdu;
};

/// This interface is used to push E1AP messages to the E1AP interface.
class e1ap_message_handler
{
public:
  virtual ~e1ap_message_handler() = default;

  /// Handle the incoming E1AP message.
  virtual void handle_message(const e1ap_message& msg) = 0;
};

/// Interface used by E1AP to inform about events.
class e1ap_event_handler
{
public:
  virtual ~e1ap_event_handler()         = default;
  virtual void handle_connection_loss() = 0;
};

/// This interface notifies the reception of new E1AP messages over the E1AP interface.
class e1ap_message_notifier
{
public:
  virtual ~e1ap_message_notifier() = default;

  /// This callback is invoked on each received E1AP message.
  virtual void on_new_message(const e1ap_message& msg) = 0;
};

} // namespace srsran
