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

#include "srsran/mac/mac_cell_result.h"

namespace srsran {
namespace unittests {

/// Builds and returns a valid SIB1 information PDU.
sib_information build_valid_sib1_information_pdu();

/// Builds and returns a valid MAC SSB PDU.
dl_ssb_pdu build_valid_dl_ssb_pdu();

/// Builds and returns a valid MAC DL sched result.
mac_dl_sched_result build_valid_mac_dl_sched_result();

/// Builds and returns a valid PRACH occassion.
prach_occasion_info build_valid_prach_occassion();

/// Builds and returns a valid PUSCH PDU.
ul_sched_info build_valid_pusch_pdu();

/// Build and returns a valid PUCCH format 1 PDU.
pucch_info build_valid_pucch_format_1_pdu();

/// Build and returns a valid PUCCH format 2 PDU.
pucch_info build_valid_pucch_format_2_pdu();

} // namespace unittests
} // namespace srsran
