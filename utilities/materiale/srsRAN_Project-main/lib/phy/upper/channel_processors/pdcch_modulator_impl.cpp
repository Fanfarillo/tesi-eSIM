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

#include "pdcch_modulator_impl.h"
#include "srsran/srsvec/bit.h"
#include "srsran/srsvec/sc_prod.h"

using namespace srsran;

void pdcch_modulator_impl::scramble(span<uint8_t> b_hat, span<const uint8_t> b, const pdcch_modulator::config_t& config)
{
  // Calculate initial sequence state.
  unsigned c_init = ((config.n_rnti << 16U) + config.n_id) % (1U << 31U);

  // Initialize the scrambler with the initial state.
  scrambler->init(c_init);

  // Apply sequence as unpacked XOR.
  scrambler->apply_xor(b_hat, b);
}

void pdcch_modulator_impl::modulate(span<cf_t> d_pdcch, span<const uint8_t> b_hat, float scaling)
{
  // Adapt the bits for the modulator.
  static_bit_buffer<MAX_BITS> b_hat_packed(b_hat.size());
  srsvec::bit_pack(b_hat_packed, b_hat);

  // Modulate as QPSK.
  modulator->modulate(d_pdcch, b_hat_packed, modulation_scheme::QPSK);

  // Apply scaling to conform power.
  if (std::isnormal(scaling)) {
    srsvec::sc_prod(d_pdcch, scaling, d_pdcch);
  }
}

void pdcch_modulator_impl::map(resource_grid_writer& grid, span<const cf_t> d_pdcch, const config_t& config)
{
  // Resource element allocation within a resource block for PDCCH.
  static const re_prb_mask re_mask = {true, false, true, true, true, false, true, true, true, false, true, true};

  // Create RG OFDM symbol mask. Identical for all OFDM symbols.
  bounded_bitset<MAX_RB* NRE> rg_subc_mask = config.rb_mask.kronecker_product<NRE>(re_mask);

  // Repeat the same process for all ports.
  for (uint8_t port_idx : config.ports) {
    // As the resource element buffer advances for every symbol, it needs to be renewed for every port.
    span<const cf_t> d_buffer = d_pdcch;

    // For each symbol in the CORESET map the resource elements.
    for (unsigned symbol_idx       = config.start_symbol_index,
                  end_symbol_index = config.start_symbol_index + config.duration;
         symbol_idx != end_symbol_index;
         ++symbol_idx) {
      d_buffer = grid.put(port_idx, symbol_idx, 0, rg_subc_mask, d_buffer);
    }
  }
}

void pdcch_modulator_impl::modulate(srsran::resource_grid_writer&            grid,
                                    srsran::span<const uint8_t>              data,
                                    const srsran::pdcch_modulator::config_t& config)
{
  // Apply scrambling.
  span<uint8_t> b_hat = span<uint8_t>(temp_b_hat).first(data.size());
  scramble(b_hat, data, config);

  // Apply modulation mapping.
  span<cf_t> d_pdcch = span<cf_t>(temp_d_pdcch).first(data.size() / 2);
  modulate(d_pdcch, b_hat, config.scaling);

  // Map to resource elements.
  map(grid, d_pdcch, config);
}
