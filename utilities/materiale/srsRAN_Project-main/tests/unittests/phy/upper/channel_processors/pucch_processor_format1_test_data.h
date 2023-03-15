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

// This file was generated using the following MATLAB class on 10-02-2023:
//   + "srsPUCCHProcessorFormat1Unittest.m"

#include "../../support/resource_grid_test_doubles.h"
#include "srsran/phy/upper/channel_processors/pucch_processor.h"
#include "srsran/support/file_vector.h"

namespace srsran {

struct test_case_t {
  pucch_processor::format1_configuration                  config;
  std::vector<uint8_t>                                    ack_bits;
  file_vector<resource_grid_reader_spy::expected_entry_t> grid;
};

static const std::vector<test_case_t> pucch_processor_format1_test_data = {
    // clang-format off
  {{nullopt, {0, 1309}, 51, 1, cyclic_prefix::NORMAL, 32, {}, 821, 0, {0}, 10, 14, 0, 0}, {}, {"test_data/pucch_processor_format1_test_input_symbols0.dat"}},
  {{nullopt, {0, 7482}, 51, 1, cyclic_prefix::NORMAL, 49, {}, 304, 1, {0}, 7, 14, 0, 2}, {0}, {"test_data/pucch_processor_format1_test_input_symbols1.dat"}},
  {{nullopt, {0, 8339}, 51, 1, cyclic_prefix::NORMAL, 29, {}, 155, 2, {0}, 2, 14, 0, 0}, {1, 0}, {"test_data/pucch_processor_format1_test_input_symbols2.dat"}},
  {{nullopt, {0, 8504}, 51, 1, cyclic_prefix::NORMAL, 3, {}, 268, 0, {0}, 5, 13, 1, 4}, {}, {"test_data/pucch_processor_format1_test_input_symbols3.dat"}},
  {{nullopt, {0, 10131}, 51, 1, cyclic_prefix::NORMAL, 44, {}, 719, 1, {0}, 7, 13, 1, 0}, {1}, {"test_data/pucch_processor_format1_test_input_symbols4.dat"}},
  {{nullopt, {0, 9255}, 51, 1, cyclic_prefix::NORMAL, 3, {}, 229, 2, {0}, 6, 13, 1, 1}, {1, 1}, {"test_data/pucch_processor_format1_test_input_symbols5.dat"}},
  {{nullopt, {0, 2620}, 51, 1, cyclic_prefix::NORMAL, 44, {}, 789, 0, {0}, 5, 5, 5, 0}, {}, {"test_data/pucch_processor_format1_test_input_symbols6.dat"}},
  {{nullopt, {0, 3455}, 51, 1, cyclic_prefix::NORMAL, 17, {}, 479, 1, {0}, 1, 5, 5, 1}, {1}, {"test_data/pucch_processor_format1_test_input_symbols7.dat"}},
  {{nullopt, {0, 6081}, 51, 1, cyclic_prefix::NORMAL, 2, {}, 434, 2, {0}, 9, 5, 5, 0}, {0, 1}, {"test_data/pucch_processor_format1_test_input_symbols8.dat"}},
  {{nullopt, {0, 107}, 51, 1, cyclic_prefix::NORMAL, 42, {}, 312, 0, {0}, 11, 4, 10, 1}, {}, {"test_data/pucch_processor_format1_test_input_symbols9.dat"}},
  {{nullopt, {0, 102}, 51, 1, cyclic_prefix::NORMAL, 32, {}, 187, 1, {0}, 10, 4, 10, 0}, {1}, {"test_data/pucch_processor_format1_test_input_symbols10.dat"}},
  {{nullopt, {0, 10156}, 51, 1, cyclic_prefix::NORMAL, 16, {}, 174, 2, {0}, 9, 4, 10, 1}, {0, 0}, {"test_data/pucch_processor_format1_test_input_symbols11.dat"}},
  {{nullopt, {0, 5369}, 51, 1, cyclic_prefix::NORMAL, 10, {33}, 39, 0, {0}, 8, 14, 0, 2}, {}, {"test_data/pucch_processor_format1_test_input_symbols12.dat"}},
  {{nullopt, {0, 927}, 51, 1, cyclic_prefix::NORMAL, 28, {50}, 635, 1, {0}, 9, 14, 0, 1}, {1}, {"test_data/pucch_processor_format1_test_input_symbols13.dat"}},
  {{nullopt, {0, 2275}, 51, 1, cyclic_prefix::NORMAL, 17, {23}, 557, 2, {0}, 1, 14, 0, 0}, {0, 1}, {"test_data/pucch_processor_format1_test_input_symbols14.dat"}},
  {{nullopt, {0, 3707}, 51, 1, cyclic_prefix::NORMAL, 29, {3}, 849, 0, {0}, 7, 13, 1, 0}, {}, {"test_data/pucch_processor_format1_test_input_symbols15.dat"}},
  {{nullopt, {0, 7099}, 51, 1, cyclic_prefix::NORMAL, 37, {18}, 853, 1, {0}, 2, 13, 1, 0}, {1}, {"test_data/pucch_processor_format1_test_input_symbols16.dat"}},
  {{nullopt, {0, 9430}, 51, 1, cyclic_prefix::NORMAL, 25, {41}, 621, 2, {0}, 10, 13, 1, 1}, {1, 0}, {"test_data/pucch_processor_format1_test_input_symbols17.dat"}},
  {{nullopt, {0, 4640}, 51, 1, cyclic_prefix::NORMAL, 32, {3}, 386, 0, {0}, 7, 5, 5, 0}, {}, {"test_data/pucch_processor_format1_test_input_symbols18.dat"}},
  {{nullopt, {0, 6436}, 51, 1, cyclic_prefix::NORMAL, 50, {8}, 458, 1, {0}, 4, 5, 5, 0}, {0}, {"test_data/pucch_processor_format1_test_input_symbols19.dat"}},
  {{nullopt, {0, 750}, 51, 1, cyclic_prefix::NORMAL, 47, {1}, 350, 2, {0}, 11, 5, 5, 0}, {1, 1}, {"test_data/pucch_processor_format1_test_input_symbols20.dat"}},
  {{nullopt, {0, 3929}, 51, 1, cyclic_prefix::NORMAL, 44, {12}, 547, 0, {0}, 2, 4, 10, 0}, {}, {"test_data/pucch_processor_format1_test_input_symbols21.dat"}},
  {{nullopt, {0, 6011}, 51, 1, cyclic_prefix::NORMAL, 30, {34}, 798, 1, {0}, 8, 4, 10, 0}, {0}, {"test_data/pucch_processor_format1_test_input_symbols22.dat"}},
  {{nullopt, {0, 5182}, 51, 1, cyclic_prefix::NORMAL, 6, {32}, 190, 2, {0}, 1, 4, 10, 0}, {0, 0}, {"test_data/pucch_processor_format1_test_input_symbols23.dat"}},
  {{nullopt, {1, 8413}, 51, 1, cyclic_prefix::NORMAL, 6, {}, 16, 0, {0}, 10, 14, 0, 3}, {}, {"test_data/pucch_processor_format1_test_input_symbols24.dat"}},
  {{nullopt, {1, 9695}, 51, 1, cyclic_prefix::NORMAL, 45, {}, 593, 1, {0}, 11, 14, 0, 0}, {1}, {"test_data/pucch_processor_format1_test_input_symbols25.dat"}},
  {{nullopt, {1, 12958}, 51, 1, cyclic_prefix::NORMAL, 14, {}, 134, 2, {0}, 0, 14, 0, 0}, {1, 1}, {"test_data/pucch_processor_format1_test_input_symbols26.dat"}},
  {{nullopt, {1, 16472}, 51, 1, cyclic_prefix::NORMAL, 41, {}, 419, 0, {0}, 0, 13, 1, 0}, {}, {"test_data/pucch_processor_format1_test_input_symbols27.dat"}},
  {{nullopt, {1, 20460}, 51, 1, cyclic_prefix::NORMAL, 7, {}, 84, 1, {0}, 3, 13, 1, 1}, {1}, {"test_data/pucch_processor_format1_test_input_symbols28.dat"}},
  {{nullopt, {1, 9875}, 51, 1, cyclic_prefix::NORMAL, 22, {}, 617, 2, {0}, 8, 13, 1, 1}, {1, 1}, {"test_data/pucch_processor_format1_test_input_symbols29.dat"}},
  {{nullopt, {1, 20311}, 51, 1, cyclic_prefix::NORMAL, 30, {}, 349, 0, {0}, 2, 5, 5, 1}, {}, {"test_data/pucch_processor_format1_test_input_symbols30.dat"}},
  {{nullopt, {1, 2079}, 51, 1, cyclic_prefix::NORMAL, 13, {}, 634, 1, {0}, 11, 5, 5, 0}, {0}, {"test_data/pucch_processor_format1_test_input_symbols31.dat"}},
  {{nullopt, {1, 11471}, 51, 1, cyclic_prefix::NORMAL, 42, {}, 779, 2, {0}, 2, 5, 5, 1}, {0, 1}, {"test_data/pucch_processor_format1_test_input_symbols32.dat"}},
  {{nullopt, {1, 6540}, 51, 1, cyclic_prefix::NORMAL, 43, {}, 414, 0, {0}, 6, 4, 10, 1}, {}, {"test_data/pucch_processor_format1_test_input_symbols33.dat"}},
  {{nullopt, {1, 16068}, 51, 1, cyclic_prefix::NORMAL, 0, {}, 620, 1, {0}, 8, 4, 10, 0}, {0}, {"test_data/pucch_processor_format1_test_input_symbols34.dat"}},
  {{nullopt, {1, 20150}, 51, 1, cyclic_prefix::NORMAL, 16, {}, 981, 2, {0}, 11, 4, 10, 1}, {0, 1}, {"test_data/pucch_processor_format1_test_input_symbols35.dat"}},
  {{nullopt, {1, 7643}, 51, 1, cyclic_prefix::NORMAL, 2, {36}, 984, 0, {0}, 2, 14, 0, 1}, {}, {"test_data/pucch_processor_format1_test_input_symbols36.dat"}},
  {{nullopt, {1, 9421}, 51, 1, cyclic_prefix::NORMAL, 48, {10}, 318, 1, {0}, 8, 14, 0, 0}, {0}, {"test_data/pucch_processor_format1_test_input_symbols37.dat"}},
  {{nullopt, {1, 4590}, 51, 1, cyclic_prefix::NORMAL, 46, {5}, 189, 2, {0}, 0, 14, 0, 1}, {0, 0}, {"test_data/pucch_processor_format1_test_input_symbols38.dat"}},
  {{nullopt, {1, 13296}, 51, 1, cyclic_prefix::NORMAL, 19, {15}, 987, 0, {0}, 5, 13, 1, 0}, {}, {"test_data/pucch_processor_format1_test_input_symbols39.dat"}},
  {{nullopt, {1, 15999}, 51, 1, cyclic_prefix::NORMAL, 2, {1}, 16, 1, {0}, 2, 13, 1, 2}, {0}, {"test_data/pucch_processor_format1_test_input_symbols40.dat"}},
  {{nullopt, {1, 12636}, 51, 1, cyclic_prefix::NORMAL, 18, {29}, 756, 2, {0}, 3, 13, 1, 2}, {0, 0}, {"test_data/pucch_processor_format1_test_input_symbols41.dat"}},
  {{nullopt, {1, 8971}, 51, 1, cyclic_prefix::NORMAL, 17, {39}, 308, 0, {0}, 6, 5, 5, 0}, {}, {"test_data/pucch_processor_format1_test_input_symbols42.dat"}},
  {{nullopt, {1, 11059}, 51, 1, cyclic_prefix::NORMAL, 38, {3}, 987, 1, {0}, 7, 5, 5, 0}, {1}, {"test_data/pucch_processor_format1_test_input_symbols43.dat"}},
  {{nullopt, {1, 6974}, 51, 1, cyclic_prefix::NORMAL, 40, {28}, 538, 2, {0}, 8, 5, 5, 0}, {1, 1}, {"test_data/pucch_processor_format1_test_input_symbols44.dat"}},
  {{nullopt, {1, 17581}, 51, 1, cyclic_prefix::NORMAL, 12, {36}, 213, 0, {0}, 10, 4, 10, 0}, {}, {"test_data/pucch_processor_format1_test_input_symbols45.dat"}},
  {{nullopt, {1, 5353}, 51, 1, cyclic_prefix::NORMAL, 20, {44}, 716, 1, {0}, 8, 4, 10, 0}, {0}, {"test_data/pucch_processor_format1_test_input_symbols46.dat"}},
  {{nullopt, {1, 5644}, 51, 1, cyclic_prefix::NORMAL, 18, {42}, 112, 2, {0}, 11, 4, 10, 0}, {0, 1}, {"test_data/pucch_processor_format1_test_input_symbols47.dat"}},
    // clang-format on
};

} // namespace srsran
