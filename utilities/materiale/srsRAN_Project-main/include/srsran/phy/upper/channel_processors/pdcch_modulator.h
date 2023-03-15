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

#include "srsran/adt/bounded_bitset.h"
#include "srsran/adt/span.h"
#include "srsran/adt/static_vector.h"
#include "srsran/phy/constants.h"
#include "srsran/phy/support/mask_types.h"
#include "srsran/phy/support/resource_grid.h"

namespace srsran {

/// \brief Describes a PDCCH modulator interface.
///
/// \remark Defined in TS 38.211 section 7.3.2 Physical downlink control channel (PDCCH).
/// \note The configuration assumes the CCE-to-REG and REG-to-PRB mapping is included in \c rb_mask.
class pdcch_modulator
{
public:
  /// Describes the necessary parameters to modulate a PDCCH transmission.
  struct config_t {
    /// Indicates the RBs used for the PDCCH transmission.
    bounded_bitset<MAX_RB> rb_mask;
    /// CORESET start symbol index.
    unsigned start_symbol_index;
    /// CORESET duration in symbols.
    unsigned duration;
    /// Higher layer parameter PDCCH-DMRS-ScramblingID if it is given, otherwise the physical cell identifier.
    unsigned n_id;
    /// Parameter \f$n_{RNTI}\f$ used for PDCCH data scrambling according to TS 38.211 section 7.3.2.3.
    unsigned n_rnti;
    /// Scaling factor to apply to the resource elements according to PDCCH power allocation in TS 38.213.
    float scaling;
    /// Port indexes the PDSCH transmission is mapped onto.
    static_vector<uint8_t, MAX_PORTS> ports;
  };

  /// Default destructor.
  virtual ~pdcch_modulator() = default;

  /// \brief Modulates a PDCCH codeword according to TS 38.211 section 7.3.2 Physical downlink control channel.
  ///
  /// \param[out] grid Provides the destination resource grid.
  /// \param[in] data Provides the encoded and unpacked bits to modulate.
  /// \param[in] config Provides the configuration.
  /// \note The codeword length shall be consistent with the resource mapping.
  virtual void modulate(resource_grid_writer& grid, span<const uint8_t> data, const config_t& config) = 0;
};

} // namespace srsran
