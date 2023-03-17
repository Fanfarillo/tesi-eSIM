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

#include "srsran/ran/cyclic_prefix.h"
#include "srsran/scheduler/config/bwp_configuration.h"
#include "srsran/scheduler/config/dmrs.h"

namespace srsran {

/// \brief Collects the PDSCH default time-domain allocation parameters.
///
/// The parameters are provided by TS38.214 Tables 5.1.2.1.1-2, 5.1.2.1.1-3, 5.1.2.1.1-4 and 5.1.2.1.1-5.
///
/// A configuration is invalid if the duration is not zero.
struct pdsch_default_time_allocation_config {
  /// PDSCH mapping.
  sch_mapping_type mapping_type;
  /// PDCCH to PDSCH delay in slots, parameter \f$K_0\f$. The range is {0, 1}.
  uint8_t pdcch_to_pdsch_delay;
  /// Start symbol index within the slot, parameter \f$S\f$. The range is {0, ..., 10}.
  uint8_t start_symbol;
  /// Transmission duration in symbols, parameter \f$L\f$. The range is {2, ..., 12}
  uint8_t duration;
};

/// Reserved default PDSCH time-domain allocation. It indicates the configuration is invalid.
static constexpr pdsch_default_time_allocation_config PDSCH_DEFAULT_TIME_ALLOCATION_RESERVED = {};

/// \brief Determines the default PDSCH time-domain resource allocation A.
///
/// The time domain allocation configuration is described in TS38.214 Table 5.1.2.1.1-2 for normal cyclic prefix and
/// TS38.214 Table 5.1.2.1.1-3 for extended cyclic prefix.
///
/// \param[in] cp        Cyclic prefix.
/// \param[in] row_index Row index.
/// \param[in] dmrs_pos  DM-RS for mapping Type A position.
/// \return A valid PDSCH time-domain allocation configuration is the provided parameters are valid. Otherwise,
/// PDSCH_DEFAULT_TIME_ALLOCATION_RESERVED.
pdsch_default_time_allocation_config
pdsch_default_time_allocation_default_A_get(cyclic_prefix cp, unsigned row_index, dmrs_typeA_position dmrs_pos);

/// \brief Determines the table of default PDSCH time-domain resource allocation A.
///
/// \param[in] cp        Cyclic prefix.
/// \param[in] dmrs_pos  DM-RS for mapping Type A position.
/// \return A list of valid PDSCH time-domain allocation configurations to choose from.
span<const pdsch_time_domain_resource_allocation>
pdsch_default_time_allocations_default_A_table(cyclic_prefix cp, dmrs_typeA_position dmrs_pos);

} // namespace srsran
