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

#include "srsran/phy/upper/re_pattern.h"

using namespace srsran;

// Helper macro to assert the RB allocation of the pattern keeping the file and line for code tracing purposes.
#define re_pattern_assert()                                                                                            \
  do {                                                                                                                 \
    srsran_assert(rb_begin < MAX_RB, "RB begin ({}) is out-of-range", rb_begin);                                       \
    srsran_assert(rb_end > 0 && rb_end <= MAX_RB, "RB end ({}) is out-of-range", rb_end);                              \
    srsran_assert(rb_stride > 0, "RB stride ({}) is out-of-range", rb_stride);                                         \
  } while (false)

void re_pattern::get_inclusion_mask(bounded_bitset<MAX_RB * NRE>& mask, unsigned symbol) const
{
  // Verify attributes and inputs.
  re_pattern_assert();
  srsran_assert(
      mask.size() >= rb_end, "Provided mask size ({}) is too small. The minimum is {}.", (unsigned)mask.size(), rb_end);

  // Skip if the symbol is not set to true.
  if (!symbols.test(symbol)) {
    return;
  }

  // Create a mask for the maximum bandwidth.
  bounded_bitset<MAX_RB> rb_mask(mask.size() / NRE);

  // Fill RB mask.
  if (rb_stride == 1) {
    rb_mask.fill(rb_begin, rb_end);
  } else {
    for (unsigned i_rb = rb_begin; i_rb < rb_end; i_rb += rb_stride) {
      rb_mask.set(i_rb);
    }
  }

  // Apply the RE mask to all.
  bounded_bitset<MAX_RB* NRE> pattern_re_mask = rb_mask.kronecker_product<NRE>(re_mask);

  // The following logical operation shall result in:
  // - true if mask is true or re_mask is true,
  // - otherwise false.
  mask |= pattern_re_mask;
}

void re_pattern::get_exclusion_mask(bounded_bitset<MAX_RB * NRE>& mask, unsigned symbol) const
{
  // Verify attributes and inputs.
  re_pattern_assert();
  srsran_assert(
      mask.size() >= rb_end, "Provided mask size ({}) is too small. The minimum is {}.", (unsigned)mask.size(), rb_end);

  // Skip if the symbol is not used.
  if (!symbols.test(symbol)) {
    return;
  }

  // Create a mask for the maximum bandwidth.
  bounded_bitset<MAX_RB> rb_mask(mask.size() / NRE);

  // Fill RB mask.
  rb_mask.fill(rb_begin, rb_end);

  // Apply the RE mask to all.
  bounded_bitset<MAX_RB* NRE> pattern_re_mask = rb_mask.kronecker_product<NRE>(re_mask);

  // The following logical operation shall result in:
  // - true if mask is true and re_mask is false,
  // - otherwise false.
  mask &= (~pattern_re_mask);
}

void re_pattern_list::merge(const re_pattern& pattern)
{
  // Iterate all given patterns.
  for (re_pattern& p : list) {
    // Skip if RB allocation parameters do NOT match.
    if (p.rb_begin != pattern.rb_begin || p.rb_end != pattern.rb_end || p.rb_stride != pattern.rb_stride) {
      continue;
    }

    // Check if symbol mask matches.
    bool lmatch = (pattern.symbols == p.symbols);

    // Check if RE mask matches.
    bool kmatch = (pattern.re_mask == p.re_mask);

    // If OFDM symbols and subcarriers mask match, it means that the patterns are completely overlapped and no merging
    // is required.
    if (kmatch && lmatch) {
      return;
    }

    // If OFDM symbols mask matches, combine subcarrier mask.
    if (lmatch) {
      p.re_mask |= pattern.re_mask;
      return;
    }

    // If subcarriers mask matches, combine OFDM symbols mask.
    if (kmatch) {
      p.symbols |= pattern.symbols;
      return;
    }
  }

  // If reached here, no pattern was matched. Check if there is free space.
  srsran_assert(
      !list.full(), "RE pattern list is full. It seems {} maximum entries are not enough.", (unsigned)MAX_RE_PATTERN);

  // Append pattern.
  list.emplace_back(pattern);
}

bool re_pattern_list::operator==(const re_pattern_list& other) const
{
  // Generates the inclusion mask for each symbol and compare if they are equal.
  for (unsigned symbol = 0; symbol != MAX_NSYMB_PER_SLOT; ++symbol) {
    bounded_bitset<MAX_RB * NRE> inclusion_mask(MAX_RB * NRE);
    get_inclusion_mask(inclusion_mask, symbol);

    bounded_bitset<MAX_RB * NRE> inclusion_mask_other(MAX_RB * NRE);
    other.get_inclusion_mask(inclusion_mask_other, symbol);

    // Early return false if they are not equal for this symbol.
    if (inclusion_mask != inclusion_mask_other) {
      return false;
    }
  }

  return true;
}

void re_pattern_list::get_inclusion_mask(bounded_bitset<MAX_RB * NRE>& mask, unsigned symbol) const
{
  // Iterate all given patterns.
  for (const re_pattern& p : list) {
    p.get_inclusion_mask(mask, symbol);
  }
}

unsigned re_pattern_list::get_inclusion_count(unsigned                      start_symbol,
                                              unsigned                      nof_symbols,
                                              const bounded_bitset<MAX_RB>& rb_mask) const
{
  unsigned count = 0;

  re_prb_mask                 base_re_mask   = ~re_prb_mask();
  bounded_bitset<MAX_RB* NRE> active_re_mask = rb_mask.kronecker_product<NRE>(base_re_mask);

  for (unsigned symbol_idx = start_symbol; symbol_idx != start_symbol + nof_symbols; ++symbol_idx) {
    bounded_bitset<MAX_RB * NRE> inclusion_mask(active_re_mask.size());

    // Iterate all patterns to get a wideband inclusion mask.
    for (const re_pattern& p : list) {
      p.get_inclusion_mask(inclusion_mask, symbol_idx);
    }

    // Apply the mask to the active RE.
    inclusion_mask &= active_re_mask;

    // Count all the included elements.
    count += inclusion_mask.count();
  }

  return count;
}

void re_pattern_list::get_exclusion_mask(bounded_bitset<MAX_RB * NRE>& mask, unsigned symbol) const
{
  // Iterate all given patterns.
  for (const re_pattern& p : list) {
    p.get_exclusion_mask(mask, symbol);
  }
}
