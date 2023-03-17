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

#include "srsran/phy/upper/sequence_generators/pseudo_random_generator.h"
#include "srsran/phy/upper/signal_processors/dmrs_pdcch_processor.h"
#include <memory>

namespace srsran {

/// Describes a generic implementation of a DMRS for PDCCH processor.
class dmrs_pdcch_processor_impl : public dmrs_pdcch_processor
{
private:
  /// Defines the DMRS index increment in frequency domain.
  static constexpr unsigned STRIDE = 4;

  /// Defines the number of DMRS per active resource block.
  static constexpr unsigned NOF_DMRS_PER_RB = NRE / STRIDE;

  /// Defines the maximum number of DMRS for PDCCH that can be found in a symbol.
  static constexpr unsigned MAX_NOF_DMRS_PER_SYMBOL = MAX_RB * NOF_DMRS_PER_RB;

  /// Pseudo-random sequence generator instance.
  std::unique_ptr<pseudo_random_generator> prg;

  /// Temporary sequence storage.
  std::array<cf_t, MAX_NOF_DMRS_PER_SYMBOL> temp_sequence;

  /// \brief Computes the initial pseudo-random state.
  /// \param[in] symbol Denotes the symbol index.
  /// \param[in] config Provides the required parameters.
  /// \return The initial pseudo-random state.
  static unsigned c_init(unsigned symbol, const config_t& config);

  /// \brief Sequence generation as per TS 38.211 Section 7.4.1.3.1.
  ///
  /// This method generates the sequence described in TS 38.211 Section 7.4.1.3.1, considering the only values required
  /// to fill the resource blocks according to TS 38.211 Section 7.3.2.
  ///
  /// \param[out] sequence Provides the sequence destination.
  /// \param[in] symbol Denotes the symbol index.
  /// \param[in] config Provides the required parameters to calculate the sequences.
  void sequence_generation(span<cf_t> sequence, unsigned symbol, const config_t& config) const;

  /// \brief Mapping to physical resources as per TS 38.211 Section 7.4.1.3.2.
  ///
  /// This method implements the signal mapping as described in TS 38.211 Section 7.4.1.3.2.
  ///
  /// \param[out] grid            Destination resource grid.
  /// \param[in] sequence         Sequence to write in the resource grid.
  /// \param[in] rg_subc_mask     Indicates the subcarriers where \c sequence is mapped onto.
  /// \param[in] symbol           Denotes the OFDM symbol index within the slot.
  /// \param[in] ports            Port list.
  void mapping(resource_grid_writer&                    grid,
               span<const cf_t>                         sequence,
               const bounded_bitset<MAX_RB * NRE>&      rg_subc_mask,
               unsigned                                 symbol,
               const static_vector<uint8_t, MAX_PORTS>& ports);

public:
  explicit dmrs_pdcch_processor_impl(std::unique_ptr<pseudo_random_generator> prg_) : prg(std::move(prg_))
  {
    srsran_assert(prg, "Invalid PRG.");
  }

  void map(resource_grid_writer& grid, const config_t& config) override;
};

} // namespace srsran
