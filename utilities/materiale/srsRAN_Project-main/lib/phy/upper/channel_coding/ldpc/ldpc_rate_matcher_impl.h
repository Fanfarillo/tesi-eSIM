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

/// \file
/// \brief LDPC rate matcher declaration.

#pragma once

#include "ldpc_graph_impl.h"
#include "srsran/phy/upper/channel_coding/ldpc/ldpc_rate_matcher.h"

namespace srsran {

/// LDPC rate matching implementation, as per TS38.212 Section 5.4.2.
class ldpc_rate_matcher_impl : public ldpc_rate_matcher
{
public:
  // See interface for the documentation.
  void rate_match(span<uint8_t>                                 output,
                  span<const uint8_t>                           input,
                  const codeblock_metadata::tb_common_metadata& cfg) override;

private:
  /// Initializes the rate matcher internal state.
  void init(const codeblock_metadata::tb_common_metadata& cfg);

  /// \brief Carries out bit selection, as per TS38.212 Section 5.4.2.1.
  ///
  /// \param[out] out Sequence of selected bits.
  /// \param[in]  in  Input codeblock.
  void select_bits(span<uint8_t> out, span<const uint8_t> in) const;

  /// \brief Carries out bit interleaving, as per TS38.212 Section 5.4.2.2.
  ///
  /// \param[out] out Sequence of interleaved bits.
  /// \param[in]  in  Sequence of selected bits (see ldpc_rate_matcher_impl::select_bits).
  void interleave_bits(span<uint8_t> out, span<const uint8_t> in) const;

  // Data members

  /// Bit selection circular buffer.
  span<const uint8_t> buffer = {};
  /// Auxiliary buffer.
  std::array<uint8_t, ldpc::MAX_CODEBLOCK_RM_SIZE> auxiliary_buffer = {};
  /// Redundancy version, values in {0, 1, 2, 3}.
  unsigned rv = 0;
  /// Modulation scheme.
  unsigned modulation_order = 1;
  /// Buffer length.
  unsigned buffer_length = 0;
  /// Shift \f$ k_0 \f$ as defined in TS38.212 Table 5.4.2.1-2
  unsigned shift_k0 = 0;
};

} // namespace srsran
