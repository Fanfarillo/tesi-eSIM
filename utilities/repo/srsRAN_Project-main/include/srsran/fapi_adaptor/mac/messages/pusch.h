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

#include "srsran/fapi/message_builders.h"

namespace srsran {

struct ul_sched_info;

namespace fapi_adaptor {

/// \brief Helper function that converts from a PUSCH MAC PDU to a PUSCH FAPI PDU.
///
/// \param[out] fapi_pdu PUSCH FAPI PDU that will store the converted data.
/// \param[in] mac_pdu MAC PDU that contains the PUSCH parameters.
void convert_pusch_mac_to_fapi(fapi::ul_pusch_pdu& fapi_pdu, const ul_sched_info& mac_pdu);

/// \brief Helper function that converts from a PUSCH MAC PDU to a PUSCH FAPI PDU.
///
/// \param[out] builder PUSCH FAPI builder that helps to fill the PDU.
/// \param[in] mac_pdu MAC PDU that contains the PUSCH parameters.
void convert_pusch_mac_to_fapi(fapi::ul_pusch_pdu_builder& builder, const ul_sched_info& mac_pdu);

} // namespace fapi_adaptor
} // namespace srsran
