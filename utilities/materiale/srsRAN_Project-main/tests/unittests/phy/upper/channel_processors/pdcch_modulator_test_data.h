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

// This file was generated using the following MATLAB class:
//   + "srsPDCCHModulatorUnittest.m"

#include "../../support/resource_grid_test_doubles.h"
#include "srsran/phy/upper/channel_processors/pdcch_modulator.h"
#include "srsran/support/file_vector.h"

namespace srsran {

struct test_case_t {
  pdcch_modulator::config_t                               config;
  file_vector<uint8_t>                                    data;
  file_vector<resource_grid_writer_spy::expected_entry_t> symbols;
};

static const std::vector<test_case_t> pdcch_modulator_test_data = {
    // clang-format off
  {{{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}, 11, 1, 905, 2068, 1, { 0}}, {"test_data/pdcch_modulator_test_input0.dat"}, {"test_data/pdcch_modulator_test_output0.dat"}},
  {{{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0, 0, 0, 0}, 4, 1, 680, 61014, 1, { 7}}, {"test_data/pdcch_modulator_test_input1.dat"}, {"test_data/pdcch_modulator_test_output1.dat"}},
  {{{1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}, 2, 1, 386, 35321, 1, { 7}}, {"test_data/pdcch_modulator_test_input2.dat"}, {"test_data/pdcch_modulator_test_output2.dat"}},
  {{{1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0, 0, 0, 0}, 2, 1, 92, 24605, 1, { 4}}, {"test_data/pdcch_modulator_test_input3.dat"}, {"test_data/pdcch_modulator_test_output3.dat"}},
  {{{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}, 10, 2, 681, 15497, 1, { 4}}, {"test_data/pdcch_modulator_test_input4.dat"}, {"test_data/pdcch_modulator_test_output4.dat"}},
  {{{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 1, 1, 0, 0, 0, 0}, 9, 2, 424, 58405, 1, { 0}}, {"test_data/pdcch_modulator_test_input5.dat"}, {"test_data/pdcch_modulator_test_output5.dat"}},
  {{{1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}, 6, 2, 78, 15490, 1, { 6}}, {"test_data/pdcch_modulator_test_input6.dat"}, {"test_data/pdcch_modulator_test_output6.dat"}},
  {{{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0, 0, 0, 0}, 8, 2, 328, 47139, 1, { 0}}, {"test_data/pdcch_modulator_test_input7.dat"}, {"test_data/pdcch_modulator_test_output7.dat"}},
  {{{1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0, 0, 0, 0}, 3, 2, 686, 58791, 1, { 6}}, {"test_data/pdcch_modulator_test_input8.dat"}, {"test_data/pdcch_modulator_test_output8.dat"}},
  {{{1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0, 0, 0, 0}, 10, 2, 346, 51849, 1, { 6}}, {"test_data/pdcch_modulator_test_input9.dat"}, {"test_data/pdcch_modulator_test_output9.dat"}},
  {{{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 0, 0, 0, 0}, 8, 3, 564, 4892, 1, { 6}}, {"test_data/pdcch_modulator_test_input10.dat"}, {"test_data/pdcch_modulator_test_output10.dat"}},
  {{{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}, 4, 3, 143, 23339, 1, { 4}}, {"test_data/pdcch_modulator_test_input11.dat"}, {"test_data/pdcch_modulator_test_output11.dat"}},
  {{{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 1, 1, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}, 1, 3, 896, 36031, 1, { 1}}, {"test_data/pdcch_modulator_test_input12.dat"}, {"test_data/pdcch_modulator_test_output12.dat"}},
  {{{1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}, 10, 3, 199, 62186, 1, { 1}}, {"test_data/pdcch_modulator_test_input13.dat"}, {"test_data/pdcch_modulator_test_output13.dat"}},
  {{{1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}, 1, 3, 602, 19514, 1, { 1}}, {"test_data/pdcch_modulator_test_input14.dat"}, {"test_data/pdcch_modulator_test_output14.dat"}},
  {{{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0}, 10, 3, 381, 5917, 1, { 2}}, {"test_data/pdcch_modulator_test_input15.dat"}, {"test_data/pdcch_modulator_test_output15.dat"}},
    // clang-format on
};

} // namespace srsran
