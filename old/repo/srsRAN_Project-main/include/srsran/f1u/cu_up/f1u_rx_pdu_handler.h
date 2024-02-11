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

#include "srsran/f1u/common/nru_message.h"

namespace srsran {
namespace srs_cu_up {

/// \brief This interface represents the NR-U entry point of a F1-U bearer of the CU-UP.
/// The lower layer (e.g. GTP-U) will use this class to pass NR-U PDUs (from the DU) into the F1-U.
class f1u_rx_pdu_handler
{
public:
  virtual ~f1u_rx_pdu_handler() = default;

  virtual void handle_pdu(nru_ul_message msg) = 0;
};

} // namespace srs_cu_up
} // namespace srsran
