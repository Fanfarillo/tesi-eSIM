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

#include "srsran/ran/prach/prach_configuration.h"

using namespace srsran;

static prach_configuration prach_configuration_get_fr1_paired(uint8_t prach_config_index)
{
  // TS38.211 Table 6.3.3.2-2.
  static const std::array<prach_configuration, 87> table = {{
      {preamble_format::FORMAT0, 16, 1, {1}, 0, 0, 0, 0},
      {preamble_format::FORMAT0, 16, 1, {4}, 0, 0, 0, 0},
      {preamble_format::FORMAT0, 16, 1, {7}, 0, 0, 0, 0},
      {preamble_format::FORMAT0, 16, 1, {9}, 0, 0, 0, 0},
      {preamble_format::FORMAT0, 8, 1, {1}, 0, 0, 0, 0},
      {preamble_format::FORMAT0, 8, 1, {4}, 0, 0, 0, 0},
      {preamble_format::FORMAT0, 8, 1, {7}, 0, 0, 0, 0},
      {preamble_format::FORMAT0, 8, 1, {9}, 0, 0, 0, 0},
      {preamble_format::FORMAT0, 4, 1, {1}, 0, 0, 0, 0},
      {preamble_format::FORMAT0, 4, 1, {4}, 0, 0, 0, 0},
      {preamble_format::FORMAT0, 4, 1, {7}, 0, 0, 0, 0},
      {preamble_format::FORMAT0, 4, 1, {9}, 0, 0, 0, 0},
      {preamble_format::FORMAT0, 2, 1, {1}, 0, 0, 0, 0},
      {preamble_format::FORMAT0, 2, 1, {4}, 0, 0, 0, 0},
      {preamble_format::FORMAT0, 2, 1, {7}, 0, 0, 0, 0},
      {preamble_format::FORMAT0, 2, 1, {9}, 0, 0, 0, 0},
      {preamble_format::FORMAT0, 1, 0, {1}, 0, 0, 0, 0},
      {preamble_format::FORMAT0, 1, 0, {4}, 0, 0, 0, 0},
      {preamble_format::FORMAT0, 1, 0, {7}, 0, 0, 0, 0},
      {preamble_format::FORMAT0, 1, 0, {1, 6}, 0, 0, 0, 0},
      {preamble_format::FORMAT0, 1, 0, {2, 7}, 0, 0, 0, 0},
      {preamble_format::FORMAT0, 1, 0, {3, 8}, 0, 0, 0, 0},
      {preamble_format::FORMAT0, 1, 0, {1, 4, 7}, 0, 0, 0, 0},
      {preamble_format::FORMAT0, 1, 0, {2, 5, 8}, 0, 0, 0, 0},
      {preamble_format::FORMAT0, 1, 0, {3, 6, 9}, 0, 0, 0, 0},
      {preamble_format::FORMAT0, 1, 0, {0, 2, 4, 6, 8}, 0, 0, 0, 0},
      {preamble_format::FORMAT0, 1, 0, {1, 3, 5, 7, 9}, 0, 0, 0, 0},
      {preamble_format::FORMAT0, 1, 0, {0, 1, 2, 3, 4, 5, 6, 7, 8, 9}, 0, 0, 0, 0},
      {preamble_format::FORMAT1, 16, 1, {1}, 0, 0, 0, 0},
      {preamble_format::FORMAT1, 16, 1, {4}, 0, 0, 0, 0},
      {preamble_format::FORMAT1, 16, 1, {7}, 0, 0, 0, 0},
      {preamble_format::FORMAT1, 16, 1, {9}, 0, 0, 0, 0},
      {preamble_format::FORMAT1, 8, 1, {1}, 0, 0, 0, 0},
      {preamble_format::FORMAT1, 8, 1, {4}, 0, 0, 0, 0},
      {preamble_format::FORMAT1, 8, 1, {7}, 0, 0, 0, 0},
      {preamble_format::FORMAT1, 8, 1, {9}, 0, 0, 0, 0},
      {preamble_format::FORMAT1, 4, 1, {1}, 0, 0, 0, 0},
      {preamble_format::FORMAT1, 4, 1, {4}, 0, 0, 0, 0},
      {preamble_format::FORMAT1, 4, 1, {7}, 0, 0, 0, 0},
      {preamble_format::FORMAT1, 4, 1, {9}, 0, 0, 0, 0},
      {preamble_format::FORMAT1, 2, 1, {1}, 0, 0, 0, 0},
      {preamble_format::FORMAT1, 2, 1, {4}, 0, 0, 0, 0},
      {preamble_format::FORMAT1, 2, 1, {7}, 0, 0, 0, 0},
      {preamble_format::FORMAT1, 2, 1, {9}, 0, 0, 0, 0},
      {preamble_format::FORMAT1, 1, 0, {1}, 0, 0, 0, 0},
      {preamble_format::FORMAT1, 1, 0, {4}, 0, 0, 0, 0},
      {preamble_format::FORMAT1, 1, 0, {7}, 0, 0, 0, 0},
      {preamble_format::FORMAT1, 1, 0, {1, 6}, 0, 0, 0, 0},
      {preamble_format::FORMAT1, 1, 0, {2, 7}, 0, 0, 0, 0},
      {preamble_format::FORMAT1, 1, 0, {3, 8}, 0, 0, 0, 0},
      {preamble_format::FORMAT1, 1, 0, {1, 4, 7}, 0, 0, 0, 0},
      {preamble_format::FORMAT1, 1, 0, {2, 5, 8}, 0, 0, 0, 0},
      {preamble_format::FORMAT1, 1, 0, {3, 6, 9}, 0, 0, 0, 0},
      {preamble_format::FORMAT2, 16, 1, {1}, 0, 0, 0, 0},
      {preamble_format::FORMAT2, 8, 1, {1}, 0, 0, 0, 0},
      {preamble_format::FORMAT2, 4, 0, {1}, 0, 0, 0, 0},
      {preamble_format::FORMAT2, 2, 0, {1}, 0, 0, 0, 0},
      {preamble_format::FORMAT2, 2, 0, {5}, 0, 0, 0, 0},
      {preamble_format::FORMAT2, 1, 0, {1}, 0, 0, 0, 0},
      {preamble_format::FORMAT2, 1, 0, {5}, 0, 0, 0, 0},
      {preamble_format::FORMAT3, 16, 1, {1}, 0, 0, 0, 0},
      {preamble_format::FORMAT3, 16, 1, {4}, 0, 0, 0, 0},
      {preamble_format::FORMAT3, 16, 1, {7}, 0, 0, 0, 0},
      {preamble_format::FORMAT3, 16, 1, {9}, 0, 0, 0, 0},
      {preamble_format::FORMAT3, 8, 1, {1}, 0, 0, 0, 0},
      {preamble_format::FORMAT3, 8, 1, {4}, 0, 0, 0, 0},
      {preamble_format::FORMAT3, 8, 1, {7}, 0, 0, 0, 0},
      {preamble_format::FORMAT3, 4, 1, {1}, 0, 0, 0, 0},
      {preamble_format::FORMAT3, 4, 1, {4}, 0, 0, 0, 0},
      {preamble_format::FORMAT3, 4, 1, {7}, 0, 0, 0, 0},
      {preamble_format::FORMAT3, 4, 1, {9}, 0, 0, 0, 0},
      {preamble_format::FORMAT3, 2, 1, {1}, 0, 0, 0, 0},
      {preamble_format::FORMAT3, 2, 1, {4}, 0, 0, 0, 0},
      {preamble_format::FORMAT3, 2, 1, {7}, 0, 0, 0, 0},
      {preamble_format::FORMAT3, 2, 1, {9}, 0, 0, 0, 0},
      {preamble_format::FORMAT3, 1, 0, {1}, 0, 0, 0, 0},
      {preamble_format::FORMAT3, 1, 0, {4}, 0, 0, 0, 0},
      {preamble_format::FORMAT3, 1, 0, {7}, 0, 0, 0, 0},
      {preamble_format::FORMAT3, 1, 0, {1, 6}, 0, 0, 0, 0},
      {preamble_format::FORMAT3, 1, 0, {2, 7}, 0, 0, 0, 0},
      {preamble_format::FORMAT3, 1, 0, {3, 8}, 0, 0, 0, 0},
      {preamble_format::FORMAT3, 1, 0, {1, 4, 7}, 0, 0, 0, 0},
      {preamble_format::FORMAT3, 1, 0, {2, 5, 8}, 0, 0, 0, 0},
      {preamble_format::FORMAT3, 1, 0, {3, 6, 9}, 0, 0, 0, 0},
      {preamble_format::FORMAT3, 1, 0, {0, 2, 4, 6, 8}, 0, 0, 0, 0},
      {preamble_format::FORMAT3, 1, 0, {1, 3, 5, 7, 9}, 0, 0, 0, 0},
      {preamble_format::FORMAT3, 1, 0, {0, 1, 2, 3, 4, 5, 6, 7, 8, 9}, 0, 0, 0, 0},
  }};

  if (prach_config_index < table.size()) {
    return table[prach_config_index];
  }

  return PRACH_CONFIG_RESERVED;
}

static prach_configuration prach_configuration_get_fr1_unpaired(uint8_t prach_config_index)
{
  // TS38.211 Table 6.3.3.2-2.
  static const std::array<prach_configuration, 67> table = {{
      {preamble_format::FORMAT0, 16, 1, {9}, 0, 0, 0, 0},
      {preamble_format::FORMAT0, 8, 1, {9}, 0, 0, 0, 0},
      {preamble_format::FORMAT0, 4, 1, {9}, 0, 0, 0, 0},
      {preamble_format::FORMAT0, 2, 0, {9}, 0, 0, 0, 0},
      {preamble_format::FORMAT0, 2, 1, {9}, 0, 0, 0, 0},
      {preamble_format::FORMAT0, 2, 0, {4}, 0, 0, 0, 0},
      {preamble_format::FORMAT0, 2, 1, {4}, 0, 0, 0, 0},
      {preamble_format::FORMAT0, 1, 0, {9}, 0, 0, 0, 0},
      {preamble_format::FORMAT0, 1, 0, {8}, 0, 0, 0, 0},
      {preamble_format::FORMAT0, 1, 0, {7}, 0, 0, 0, 0},
      {preamble_format::FORMAT0, 1, 0, {6}, 0, 0, 0, 0},
      {preamble_format::FORMAT0, 1, 0, {5}, 0, 0, 0, 0},
      {preamble_format::FORMAT0, 1, 0, {4}, 0, 0, 0, 0},
      {preamble_format::FORMAT0, 1, 0, {3}, 0, 0, 0, 0},
      {preamble_format::FORMAT0, 1, 0, {2}, 0, 0, 0, 0},
      {preamble_format::FORMAT0, 1, 0, {1, 6}, 0, 0, 0, 0},
      {preamble_format::FORMAT0, 1, 0, {1, 6}, 7, 0, 0, 0},
      {preamble_format::FORMAT0, 1, 0, {4, 9}, 0, 0, 0, 0},
      {preamble_format::FORMAT0, 1, 0, {3, 8}, 0, 0, 0, 0},
      {preamble_format::FORMAT0, 1, 0, {2, 7}, 0, 0, 0, 0},
      {preamble_format::FORMAT0, 1, 0, {8, 9}, 0, 0, 0, 0},
      {preamble_format::FORMAT0, 1, 0, {4, 8, 9}, 0, 0, 0, 0},
      {preamble_format::FORMAT0, 1, 0, {3, 4, 9}, 0, 0, 0, 0},
      {preamble_format::FORMAT0, 1, 0, {7, 8, 9}, 0, 0, 0, 0},
      {preamble_format::FORMAT0, 1, 0, {3, 4, 8, 9}, 0, 0, 0, 0},
      {preamble_format::FORMAT0, 1, 0, {6, 7, 8, 9}, 0, 0, 0, 0},
      {preamble_format::FORMAT0, 1, 0, {1, 4, 6, 9}, 0, 0, 0, 0},
      {preamble_format::FORMAT0, 1, 0, {1, 3, 5, 7, 9}, 0, 0, 0, 0},
      {preamble_format::FORMAT1, 16, 1, {7}, 0, 0, 0, 0},
      {preamble_format::FORMAT1, 8, 1, {7}, 0, 0, 0, 0},
      {preamble_format::FORMAT1, 4, 1, {7}, 0, 0, 0, 0},
      {preamble_format::FORMAT1, 2, 0, {7}, 0, 0, 0, 0},
      {preamble_format::FORMAT1, 2, 1, {7}, 0, 0, 0, 0},
      {preamble_format::FORMAT1, 1, 0, {7}, 0, 0, 0, 0},
      {preamble_format::FORMAT2, 16, 1, {6}, 0, 0, 0, 0},
      {preamble_format::FORMAT2, 8, 1, {6}, 0, 0, 0, 0},
      {preamble_format::FORMAT2, 4, 1, {6}, 0, 0, 0, 0},
      {preamble_format::FORMAT2, 2, 0, {6}, 7, 0, 0, 0},
      {preamble_format::FORMAT2, 2, 1, {6}, 7, 0, 0, 0},
      {preamble_format::FORMAT2, 1, 0, {6}, 7, 0, 0, 0},
      {preamble_format::FORMAT3, 16, 1, {9}, 0, 0, 0, 0},
      {preamble_format::FORMAT3, 8, 1, {9}, 0, 0, 0, 0},
      {preamble_format::FORMAT3, 4, 1, {9}, 0, 0, 0, 0},
      {preamble_format::FORMAT3, 2, 0, {9}, 0, 0, 0, 0},
      {preamble_format::FORMAT3, 2, 1, {9}, 0, 0, 0, 0},
      {preamble_format::FORMAT3, 2, 0, {4}, 0, 0, 0, 0},
      {preamble_format::FORMAT3, 2, 1, {4}, 0, 0, 0, 0},
      {preamble_format::FORMAT3, 1, 0, {9}, 0, 0, 0, 0},
      {preamble_format::FORMAT3, 1, 0, {8}, 0, 0, 0, 0},
      {preamble_format::FORMAT3, 1, 0, {7}, 0, 0, 0, 0},
      {preamble_format::FORMAT3, 1, 0, {6}, 0, 0, 0, 0},
      {preamble_format::FORMAT3, 1, 0, {5}, 0, 0, 0, 0},
      {preamble_format::FORMAT3, 1, 0, {4}, 0, 0, 0, 0},
      {preamble_format::FORMAT3, 1, 0, {3}, 0, 0, 0, 0},
      {preamble_format::FORMAT3, 1, 0, {2}, 0, 0, 0, 0},
      {preamble_format::FORMAT3, 1, 0, {1, 6}, 0, 0, 0, 0},
      {preamble_format::FORMAT3, 1, 0, {1, 6}, 7, 0, 0, 0},
      {preamble_format::FORMAT3, 1, 0, {4, 9}, 0, 0, 0, 0},
      {preamble_format::FORMAT3, 1, 0, {3, 8}, 0, 0, 0, 0},
      {preamble_format::FORMAT3, 1, 0, {2, 7}, 0, 0, 0, 0},
      {preamble_format::FORMAT3, 1, 0, {8, 9}, 0, 0, 0, 0},
      {preamble_format::FORMAT3, 1, 0, {4, 8, 9}, 0, 0, 0, 0},
      {preamble_format::FORMAT3, 1, 0, {3, 4, 9}, 0, 0, 0, 0},
      {preamble_format::FORMAT3, 1, 0, {7, 8, 9}, 0, 0, 0, 0},
      {preamble_format::FORMAT3, 1, 0, {3, 4, 8, 9}, 0, 0, 0, 0},
      {preamble_format::FORMAT3, 1, 0, {1, 4, 6, 9}, 0, 0, 0, 0},
      {preamble_format::FORMAT3, 1, 0, {1, 3, 5, 7, 9}, 0, 0, 0, 0},
  }};

  if (prach_config_index < table.size()) {
    return table[prach_config_index];
  }

  return PRACH_CONFIG_RESERVED;
}

prach_configuration srsran::prach_configuration_get(frequency_range fr, duplex_mode dm, uint8_t prach_config_index)
{
  if ((fr == frequency_range::FR1) && (dm == duplex_mode::FDD || dm == duplex_mode::SUL)) {
    return prach_configuration_get_fr1_paired(prach_config_index);
  }

  if ((fr == frequency_range::FR1) && (dm == duplex_mode::TDD)) {
    return prach_configuration_get_fr1_unpaired(prach_config_index);
  }

  return PRACH_CONFIG_RESERVED;
}