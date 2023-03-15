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

#include "srsran/adt/complex.h"
#include "srsran/adt/span.h"
#include "srsran/ran/slot_point.h"

namespace srsran {

/// \brief Lower physical layer PRACH processor - Baseband interface.
///
/// Processes baseband samples with OFDM symbol granularity. The OFDM symbol size is inferred from the slot numerology.
class prach_processor_baseband
{
public:
  /// Default destructor.
  virtual ~prach_processor_baseband() = default;

  /// Collects the parameters that describe a symbol context.
  struct symbol_context {
    // Current slot.
    slot_point slot;
    // Current symbol index within the slot.
    unsigned symbol;
    // Sector identifier.
    unsigned sector;
    // Port identifier within the sector.
    unsigned port;
  };

  /// \brief Processes a baseband OFDM symbol.
  ///
  /// \param[in] samples Baseband samples to process.
  /// \param[in] context OFDM Symbol context.
  virtual void process_symbol(span<const cf_t> samples, const symbol_context& context) = 0;
};

} // namespace srsran
