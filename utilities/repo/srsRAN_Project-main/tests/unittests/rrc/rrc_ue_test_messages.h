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

#include "srsran/e1ap/cu_cp/e1ap_cu_cp.h"

namespace srsran {
namespace srs_cu_cp {

/// Converts a hex string (e.g. 01FA02) to a sec_as_key.
security::sec_as_key make_sec_as_key(std::string hex_str);

/// Converts a hex string (e.g. 01FA02) to a sec_128_as_key.
security::sec_128_as_key make_sec_128_as_key(std::string hex_str);

/// \brief Constructs full RRC Reconfig request with radioBearerConfig, masterCellGroup and NAS PDU
cu_cp_rrc_reconfiguration_procedure_request generate_rrc_reconfiguration_procedure_request();

} // namespace srs_cu_cp
} // namespace srsran
