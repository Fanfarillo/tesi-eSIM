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

#include "srsran/phy/support/prach_buffer.h"
#include "srsran/support/error_handling.h"

namespace srsran {

class prach_buffer_spy : public prach_buffer
{
public:
  unsigned   get_sequence_length() const override { return symbol_data.size(); }
  unsigned   get_max_nof_symbols() const override { return 1; }
  span<cf_t> get_symbol(unsigned symbol_index) override
  {
    report_fatal_error_if_not(
        symbol_index < nof_symbols, "The symbol index {} exceeds the number of symbols {}.", symbol_index, nof_symbols);
    get_symbol_entries.emplace_back(symbol_index);
    return span<cf_t>(symbol_data).subspan(symbol_size * symbol_index, symbol_size);
  }
  span<const cf_t> get_symbol(unsigned symbol_index) const override
  {
    report_fatal_error_if_not(
        symbol_index < nof_symbols, "The symbol index {} exceeds the number of symbols {}.", symbol_index, nof_symbols);
    get_symbol_const_entries.emplace_back(symbol_index);
    return span<const cf_t>(symbol_data).subspan(symbol_size * symbol_index, symbol_size);
  }

  unsigned get_total_count() const
  {
    return count_get_sequence_length + count_get_max_nof_symbols + get_symbol_entries.size() +
           get_symbol_const_entries.size();
  }

  void set_symbol_data(const std::vector<cf_t>& data, unsigned symbol_size_, unsigned nof_symbols_)
  {
    report_fatal_error_if_not(data.size() == symbol_size_ * nof_symbols_,
                              "The symbols data size is not consistent with the symbol size and number of symbols.");
    symbol_data = data;
    symbol_size = symbol_size_;
    nof_symbols = nof_symbols_;
  }

  const std::vector<unsigned>& get_get_symbol_entries() { return get_symbol_entries; };
  const std::vector<unsigned>& get_get_symbol_const_entries() { return get_symbol_const_entries; };

  void clear()
  {
    count_get_sequence_length = 0;
    count_get_max_nof_symbols = 0;
  }

private:
  unsigned                      symbol_size;
  unsigned                      nof_symbols;
  std::vector<cf_t>             symbol_data;
  unsigned                      count_get_sequence_length = 0;
  unsigned                      count_get_max_nof_symbols = 0;
  std::vector<unsigned>         get_symbol_entries;
  mutable std::vector<unsigned> get_symbol_const_entries;
};

} // namespace srsran
