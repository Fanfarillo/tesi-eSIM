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

// This file was generated using the following MATLAB class on 13-01-2023:
//   + "srsPUSCHDemodulatorUnittest.m"

#include "../../support/resource_grid_test_doubles.h"
#include "srsran/phy/upper/channel_processors/pusch_demodulator.h"
#include "srsran/support/file_vector.h"

namespace srsran {

struct context_t {
  float                            noise_var;
  pusch_demodulator::configuration config;
};

struct test_case_t {
  context_t                                               context;
  file_vector<resource_grid_reader_spy::expected_entry_t> symbols;
  file_vector<cf_t>                                       estimates;
  file_vector<log_likelihood_ratio>                       sch_data;
};

static const std::vector<test_case_t> pusch_demodulator_test_data = {
    // clang-format off
  {{0.0084369, {8323, {1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}, modulation_scheme::PI_2_BPSK, 0, 14, {0, 0, 1, 0, 0, 1, 0, 0, 1, 0, 0, 1, 0, 0}, dmrs_type::TYPE1, 2, 821, 1, {}, {0}}}, {"test_data/pusch_demodulator_test_input_symbols0.dat"}, {"test_data/pusch_demodulator_test_input_estimates0.dat"}, {"test_data/pusch_demodulator_test_output0.dat"}},
  {{0.005109, {19406, {1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}, modulation_scheme::PI_2_BPSK, 0, 14, {0, 0, 1, 0, 0, 1, 0, 0, 1, 0, 0, 1, 0, 0}, dmrs_type::TYPE1, 1, 221, 1, {}, {0}}}, {"test_data/pusch_demodulator_test_input_symbols2.dat"}, {"test_data/pusch_demodulator_test_input_estimates2.dat"}, {"test_data/pusch_demodulator_test_output2.dat"}},
  {{0.0069524, {1612, {1, 1, 1, 1, 1, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}, modulation_scheme::PI_2_BPSK, 1, 13, {0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0}, dmrs_type::TYPE1, 1, 979, 1, {}, {0}}}, {"test_data/pusch_demodulator_test_input_symbols4.dat"}, {"test_data/pusch_demodulator_test_input_estimates4.dat"}, {"test_data/pusch_demodulator_test_output4.dat"}},
  {{0.0018122, {27688, {1, 1, 1, 1, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}, modulation_scheme::PI_2_BPSK, 1, 13, {0, 0, 1, 0, 0, 1, 0, 0, 1, 0, 0, 1, 0, 0}, dmrs_type::TYPE1, 1, 965, 1, {}, {0}}}, {"test_data/pusch_demodulator_test_input_symbols6.dat"}, {"test_data/pusch_demodulator_test_input_estimates6.dat"}, {"test_data/pusch_demodulator_test_output6.dat"}},
  {{0.0029571, {41625, {1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}, modulation_scheme::PI_2_BPSK, 2, 10, {0, 0, 1, 0, 0, 1, 0, 0, 1, 0, 0, 1, 0, 0}, dmrs_type::TYPE1, 2, 369, 1, {}, {0}}}, {"test_data/pusch_demodulator_test_input_symbols8.dat"}, {"test_data/pusch_demodulator_test_input_estimates8.dat"}, {"test_data/pusch_demodulator_test_output8.dat"}},
  {{0.0011173, {39792, {1, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}, modulation_scheme::PI_2_BPSK, 2, 10, {0, 0, 1, 0, 0, 0, 1, 0, 0, 1, 0, 0, 0, 0}, dmrs_type::TYPE1, 2, 164, 1, {}, {0}}}, {"test_data/pusch_demodulator_test_input_symbols10.dat"}, {"test_data/pusch_demodulator_test_input_estimates10.dat"}, {"test_data/pusch_demodulator_test_output10.dat"}},
  {{0.00087942, {63872, {1, 1, 1, 1, 1, 1, 1, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}, modulation_scheme::QPSK, 0, 14, {0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0}, dmrs_type::TYPE1, 1, 461, 1, {}, {0}}}, {"test_data/pusch_demodulator_test_input_symbols12.dat"}, {"test_data/pusch_demodulator_test_input_estimates12.dat"}, {"test_data/pusch_demodulator_test_output12.dat"}},
  {{0.0056346, {1458, {1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}, modulation_scheme::QPSK, 0, 14, {0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0}, dmrs_type::TYPE1, 1, 972, 1, {1,  101,  201,  301,  401,  501,  601,  701,  801,  901, 1001, 1101, 1201, 1301, 1401, 1501, 1601, 1701}, {0}}}, {"test_data/pusch_demodulator_test_input_symbols14.dat"}, {"test_data/pusch_demodulator_test_input_estimates14.dat"}, {"test_data/pusch_demodulator_test_output14.dat"}},
  {{0.0085591, {64691, {1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}, modulation_scheme::QPSK, 1, 13, {0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}, dmrs_type::TYPE1, 1, 761, 1, {}, {0}}}, {"test_data/pusch_demodulator_test_input_symbols16.dat"}, {"test_data/pusch_demodulator_test_input_estimates16.dat"}, {"test_data/pusch_demodulator_test_output16.dat"}},
  {{0.0051479, {17747, {1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}, modulation_scheme::QPSK, 1, 13, {0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}, dmrs_type::TYPE1, 1, 208, 1, {1,  101,  201,  301,  401,  501,  601,  701,  801,  901, 1001, 1101, 1201, 1301, 1401}, {0}}}, {"test_data/pusch_demodulator_test_input_symbols18.dat"}, {"test_data/pusch_demodulator_test_input_estimates18.dat"}, {"test_data/pusch_demodulator_test_output18.dat"}},
  {{0.00093791, {355, {1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}, modulation_scheme::QPSK, 2, 10, {0, 0, 1, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0}, dmrs_type::TYPE1, 2, 963, 1, {}, {0}}}, {"test_data/pusch_demodulator_test_input_symbols20.dat"}, {"test_data/pusch_demodulator_test_input_estimates20.dat"}, {"test_data/pusch_demodulator_test_output20.dat"}},
  {{0.009398, {1772, {1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}, modulation_scheme::QPSK, 2, 10, {0, 0, 1, 0, 0, 0, 1, 0, 0, 1, 0, 0, 0, 0}, dmrs_type::TYPE1, 1, 628, 1, {1, 101, 201, 301, 401, 501, 601, 701, 801, 901, 1001}, {0}}}, {"test_data/pusch_demodulator_test_input_symbols22.dat"}, {"test_data/pusch_demodulator_test_input_estimates22.dat"}, {"test_data/pusch_demodulator_test_output22.dat"}},
  {{0.0085039, {51848, {1, 1, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}, modulation_scheme::QAM16, 0, 14, {0, 0, 1, 0, 0, 0, 0, 1, 0, 0, 0, 1, 0, 0}, dmrs_type::TYPE1, 1, 962, 1, {}, {0}}}, {"test_data/pusch_demodulator_test_input_symbols24.dat"}, {"test_data/pusch_demodulator_test_input_estimates24.dat"}, {"test_data/pusch_demodulator_test_output24.dat"}},
  {{0.0067809, {18136, {1, 1, 1, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}, modulation_scheme::QAM16, 0, 14, {0, 0, 1, 0, 0, 0, 0, 1, 0, 0, 0, 1, 0, 0}, dmrs_type::TYPE1, 2, 810, 1, {1, 101, 201, 301, 401, 501, 601}, {0}}}, {"test_data/pusch_demodulator_test_input_symbols26.dat"}, {"test_data/pusch_demodulator_test_input_estimates26.dat"}, {"test_data/pusch_demodulator_test_output26.dat"}},
  {{0.0036239, {57638, {1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}, modulation_scheme::QAM16, 1, 13, {0, 0, 1, 0, 0, 1, 0, 0, 1, 0, 0, 1, 0, 0}, dmrs_type::TYPE1, 1, 121, 1, {}, {0}}}, {"test_data/pusch_demodulator_test_input_symbols28.dat"}, {"test_data/pusch_demodulator_test_input_estimates28.dat"}, {"test_data/pusch_demodulator_test_output28.dat"}},
  {{0.0080398, {15600, {1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}, modulation_scheme::QAM16, 1, 13, {0, 0, 1, 0, 0, 1, 0, 0, 1, 0, 0, 1, 0, 0}, dmrs_type::TYPE1, 2, 682, 1, {1, 101}, {0}}}, {"test_data/pusch_demodulator_test_input_symbols30.dat"}, {"test_data/pusch_demodulator_test_input_estimates30.dat"}, {"test_data/pusch_demodulator_test_output30.dat"}},
  {{0.0021066, {59401, {1, 1, 1, 1, 1, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}, modulation_scheme::QAM16, 2, 10, {0, 0, 1, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0}, dmrs_type::TYPE1, 1, 642, 1, {}, {0}}}, {"test_data/pusch_demodulator_test_input_symbols32.dat"}, {"test_data/pusch_demodulator_test_input_estimates32.dat"}, {"test_data/pusch_demodulator_test_output32.dat"}},
  {{0.0048092, {19521, {1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}, modulation_scheme::QAM16, 2, 10, {0, 0, 1, 0, 0, 1, 0, 0, 1, 0, 0, 1, 0, 0}, dmrs_type::TYPE1, 2, 62, 1, {1, 101, 201, 301, 401, 501, 601, 701}, {0}}}, {"test_data/pusch_demodulator_test_input_symbols34.dat"}, {"test_data/pusch_demodulator_test_input_estimates34.dat"}, {"test_data/pusch_demodulator_test_output34.dat"}},
  {{0.0076769, {9724, {1, 1, 1, 1, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}, modulation_scheme::QAM64, 0, 14, {0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0}, dmrs_type::TYPE1, 1, 318, 1, {}, {0}}}, {"test_data/pusch_demodulator_test_input_symbols36.dat"}, {"test_data/pusch_demodulator_test_input_estimates36.dat"}, {"test_data/pusch_demodulator_test_output36.dat"}},
  {{0.0080705, {57703, {1, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}, modulation_scheme::QAM64, 0, 14, {0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0}, dmrs_type::TYPE1, 1, 609, 1, {1, 101, 201, 301, 401}, {0}}}, {"test_data/pusch_demodulator_test_input_symbols38.dat"}, {"test_data/pusch_demodulator_test_input_estimates38.dat"}, {"test_data/pusch_demodulator_test_output38.dat"}},
  {{0.0086396, {50998, {1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}, modulation_scheme::QAM64, 1, 13, {0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0}, dmrs_type::TYPE1, 1, 501, 1, {}, {0}}}, {"test_data/pusch_demodulator_test_input_symbols40.dat"}, {"test_data/pusch_demodulator_test_input_estimates40.dat"}, {"test_data/pusch_demodulator_test_output40.dat"}},
  {{0.0080699, {23296, {1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}, modulation_scheme::QAM64, 1, 13, {0, 0, 1, 0, 0, 1, 0, 0, 1, 0, 0, 1, 0, 0}, dmrs_type::TYPE1, 1, 34, 1, {1,  101,  201,  301,  401,  501,  601,  701,  801,  901, 1001, 1101, 1201, 1301, 1401, 1501, 1601, 1701, 1801, 1901}, {0}}}, {"test_data/pusch_demodulator_test_input_symbols42.dat"}, {"test_data/pusch_demodulator_test_input_estimates42.dat"}, {"test_data/pusch_demodulator_test_output42.dat"}},
  {{0.0096938, {9146, {1, 1, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}, modulation_scheme::QAM64, 2, 10, {0, 0, 1, 0, 0, 0, 1, 0, 0, 1, 0, 0, 0, 0}, dmrs_type::TYPE1, 2, 73, 1, {}, {0}}}, {"test_data/pusch_demodulator_test_input_symbols44.dat"}, {"test_data/pusch_demodulator_test_input_estimates44.dat"}, {"test_data/pusch_demodulator_test_output44.dat"}},
  {{0.0086754, {27304, {1, 1, 1, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}, modulation_scheme::QAM64, 2, 10, {0, 0, 1, 0, 0, 1, 0, 0, 1, 0, 0, 1, 0, 0}, dmrs_type::TYPE1, 1, 327, 1, {1, 101, 201, 301, 401}, {0}}}, {"test_data/pusch_demodulator_test_input_symbols46.dat"}, {"test_data/pusch_demodulator_test_input_estimates46.dat"}, {"test_data/pusch_demodulator_test_output46.dat"}},
  {{0.00031866, {60427, {1, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}, modulation_scheme::QAM256, 0, 14, {0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0}, dmrs_type::TYPE1, 2, 5, 1, {}, {0}}}, {"test_data/pusch_demodulator_test_input_symbols48.dat"}, {"test_data/pusch_demodulator_test_input_estimates48.dat"}, {"test_data/pusch_demodulator_test_output48.dat"}},
  {{0.0012554, {1567, {1, 1, 1, 1, 1, 1, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}, modulation_scheme::QAM256, 0, 14, {0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0}, dmrs_type::TYPE1, 2, 444, 1, {1,  101,  201,  301,  401,  501,  601,  701,  801,  901, 1001, 1101}, {0}}}, {"test_data/pusch_demodulator_test_input_symbols50.dat"}, {"test_data/pusch_demodulator_test_input_estimates50.dat"}, {"test_data/pusch_demodulator_test_output50.dat"}},
  {{0.0046811, {43523, {1, 1, 1, 1, 1, 1, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}, modulation_scheme::QAM256, 1, 13, {0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}, dmrs_type::TYPE1, 1, 166, 1, {}, {0}}}, {"test_data/pusch_demodulator_test_input_symbols52.dat"}, {"test_data/pusch_demodulator_test_input_estimates52.dat"}, {"test_data/pusch_demodulator_test_output52.dat"}},
  {{0.003002, {65017, {1, 1, 1, 1, 1, 1, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}, modulation_scheme::QAM256, 1, 13, {0, 0, 1, 0, 0, 0, 0, 1, 0, 0, 0, 1, 0, 0}, dmrs_type::TYPE1, 2, 740, 1, {1, 101, 201, 301, 401, 501, 601, 701, 801, 901}, {0}}}, {"test_data/pusch_demodulator_test_input_symbols54.dat"}, {"test_data/pusch_demodulator_test_input_estimates54.dat"}, {"test_data/pusch_demodulator_test_output54.dat"}},
  {{0.001978, {50022, {1, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}, modulation_scheme::QAM256, 2, 10, {0, 0, 1, 0, 0, 1, 0, 0, 1, 0, 0, 1, 0, 0}, dmrs_type::TYPE1, 1, 168, 1, {}, {0}}}, {"test_data/pusch_demodulator_test_input_symbols56.dat"}, {"test_data/pusch_demodulator_test_input_estimates56.dat"}, {"test_data/pusch_demodulator_test_output56.dat"}},
  {{0.0073101, {58371, {1, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}, modulation_scheme::QAM256, 2, 10, {0, 0, 1, 0, 0, 0, 1, 0, 0, 1, 0, 0, 0, 0}, dmrs_type::TYPE1, 2, 275, 1, {1, 101, 201}, {0}}}, {"test_data/pusch_demodulator_test_input_symbols58.dat"}, {"test_data/pusch_demodulator_test_input_estimates58.dat"}, {"test_data/pusch_demodulator_test_output58.dat"}},
  {{0.0056444, {46930, {1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}, modulation_scheme::PI_2_BPSK, 0, 14, {0, 0, 1, 0, 0, 0, 0, 1, 0, 0, 0, 1, 0, 0}, dmrs_type::TYPE2, 1, 771, 1, {}, {0}}}, {"test_data/pusch_demodulator_test_input_symbols60.dat"}, {"test_data/pusch_demodulator_test_input_estimates60.dat"}, {"test_data/pusch_demodulator_test_output60.dat"}},
  {{0.0093894, {28989, {1, 1, 1, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}, modulation_scheme::PI_2_BPSK, 0, 14, {0, 0, 1, 0, 0, 0, 0, 1, 0, 0, 0, 1, 0, 0}, dmrs_type::TYPE2, 3, 748, 1, {}, {0}}}, {"test_data/pusch_demodulator_test_input_symbols62.dat"}, {"test_data/pusch_demodulator_test_input_estimates62.dat"}, {"test_data/pusch_demodulator_test_output62.dat"}},
  {{0.0063705, {7569, {1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}, modulation_scheme::PI_2_BPSK, 1, 13, {0, 0, 1, 0, 0, 1, 0, 0, 1, 0, 0, 1, 0, 0}, dmrs_type::TYPE2, 3, 972, 1, {}, {0}}}, {"test_data/pusch_demodulator_test_input_symbols64.dat"}, {"test_data/pusch_demodulator_test_input_estimates64.dat"}, {"test_data/pusch_demodulator_test_output64.dat"}},
  {{0.0057023, {44380, {1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}, modulation_scheme::PI_2_BPSK, 1, 13, {0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0}, dmrs_type::TYPE2, 1, 454, 1, {}, {0}}}, {"test_data/pusch_demodulator_test_input_symbols66.dat"}, {"test_data/pusch_demodulator_test_input_estimates66.dat"}, {"test_data/pusch_demodulator_test_output66.dat"}},
  {{0.0098559, {32982, {1, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}, modulation_scheme::PI_2_BPSK, 2, 10, {0, 0, 1, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0}, dmrs_type::TYPE2, 2, 640, 1, {}, {0}}}, {"test_data/pusch_demodulator_test_input_symbols68.dat"}, {"test_data/pusch_demodulator_test_input_estimates68.dat"}, {"test_data/pusch_demodulator_test_output68.dat"}},
  {{0.0071077, {2788, {1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}, modulation_scheme::PI_2_BPSK, 2, 10, {0, 0, 1, 0, 0, 1, 0, 0, 1, 0, 0, 1, 0, 0}, dmrs_type::TYPE2, 1, 151, 1, {}, {0}}}, {"test_data/pusch_demodulator_test_input_symbols70.dat"}, {"test_data/pusch_demodulator_test_input_estimates70.dat"}, {"test_data/pusch_demodulator_test_output70.dat"}},
  {{0.0052176, {11824, {1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}, modulation_scheme::QPSK, 0, 14, {0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}, dmrs_type::TYPE2, 1, 555, 1, {}, {0}}}, {"test_data/pusch_demodulator_test_input_symbols72.dat"}, {"test_data/pusch_demodulator_test_input_estimates72.dat"}, {"test_data/pusch_demodulator_test_output72.dat"}},
  {{0.0032342, {44996, {1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}, modulation_scheme::QPSK, 0, 14, {0, 0, 1, 0, 0, 0, 0, 1, 0, 0, 0, 1, 0, 0}, dmrs_type::TYPE2, 3, 378, 1, {1, 101, 201}, {0}}}, {"test_data/pusch_demodulator_test_input_symbols74.dat"}, {"test_data/pusch_demodulator_test_input_estimates74.dat"}, {"test_data/pusch_demodulator_test_output74.dat"}},
  {{0.0047457, {63207, {1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}, modulation_scheme::QPSK, 1, 13, {0, 0, 1, 0, 0, 1, 0, 0, 1, 0, 0, 1, 0, 0}, dmrs_type::TYPE2, 1, 79, 1, {}, {0}}}, {"test_data/pusch_demodulator_test_input_symbols76.dat"}, {"test_data/pusch_demodulator_test_input_estimates76.dat"}, {"test_data/pusch_demodulator_test_output76.dat"}},
  {{0.0072974, {13484, {1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}, modulation_scheme::QPSK, 1, 13, {0, 0, 1, 0, 0, 1, 0, 0, 1, 0, 0, 1, 0, 0}, dmrs_type::TYPE2, 1, 969, 1, {1,  101,  201,  301,  401,  501,  601,  701,  801,  901, 1001, 1101, 1201, 1301, 1401, 1501, 1601, 1701, 1801}, {0}}}, {"test_data/pusch_demodulator_test_input_symbols78.dat"}, {"test_data/pusch_demodulator_test_input_estimates78.dat"}, {"test_data/pusch_demodulator_test_output78.dat"}},
  {{0.0062897, {24274, {1, 1, 1, 1, 1, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}, modulation_scheme::QPSK, 2, 10, {0, 0, 1, 0, 0, 1, 0, 0, 1, 0, 0, 1, 0, 0}, dmrs_type::TYPE2, 3, 828, 1, {}, {0}}}, {"test_data/pusch_demodulator_test_input_symbols80.dat"}, {"test_data/pusch_demodulator_test_input_estimates80.dat"}, {"test_data/pusch_demodulator_test_output80.dat"}},
  {{0.0058552, {12112, {1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}, modulation_scheme::QPSK, 2, 10, {0, 0, 1, 0, 0, 1, 0, 0, 1, 0, 0, 1, 0, 0}, dmrs_type::TYPE2, 1, 640, 1, {1,  101,  201,  301,  401,  501,  601,  701,  801,  901, 1001, 1101, 1201, 1301}, {0}}}, {"test_data/pusch_demodulator_test_input_symbols82.dat"}, {"test_data/pusch_demodulator_test_input_estimates82.dat"}, {"test_data/pusch_demodulator_test_output82.dat"}},
  {{0.0054659, {1873, {1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}, modulation_scheme::QAM16, 0, 14, {0, 0, 1, 0, 0, 1, 0, 0, 1, 0, 0, 1, 0, 0}, dmrs_type::TYPE2, 2, 187, 1, {}, {0}}}, {"test_data/pusch_demodulator_test_input_symbols84.dat"}, {"test_data/pusch_demodulator_test_input_estimates84.dat"}, {"test_data/pusch_demodulator_test_output84.dat"}},
  {{0.0069343, {53140, {1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}, modulation_scheme::QAM16, 0, 14, {0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0}, dmrs_type::TYPE2, 1, 459, 1, {1,  101,  201,  301,  401,  501,  601,  701,  801,  901, 1001, 1101, 1201, 1301, 1401, 1501, 1601, 1701}, {0}}}, {"test_data/pusch_demodulator_test_input_symbols86.dat"}, {"test_data/pusch_demodulator_test_input_estimates86.dat"}, {"test_data/pusch_demodulator_test_output86.dat"}},
  {{0.0056199, {13240, {1, 1, 1, 1, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}, modulation_scheme::QAM16, 1, 13, {0, 0, 1, 0, 0, 0, 0, 1, 0, 0, 0, 1, 0, 0}, dmrs_type::TYPE2, 2, 540, 1, {}, {0}}}, {"test_data/pusch_demodulator_test_input_symbols88.dat"}, {"test_data/pusch_demodulator_test_input_estimates88.dat"}, {"test_data/pusch_demodulator_test_output88.dat"}},
  {{0.005261, {42724, {1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}, modulation_scheme::QAM16, 1, 13, {0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}, dmrs_type::TYPE2, 1, 215, 1, {1,  101,  201,  301,  401,  501,  601,  701,  801,  901, 1001, 1101, 1201, 1301, 1401, 1501, 1601, 1701, 1801}, {0}}}, {"test_data/pusch_demodulator_test_input_symbols90.dat"}, {"test_data/pusch_demodulator_test_input_estimates90.dat"}, {"test_data/pusch_demodulator_test_output90.dat"}},
  {{0.0025115, {37352, {1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}, modulation_scheme::QAM16, 2, 10, {0, 0, 1, 0, 0, 1, 0, 0, 1, 0, 0, 1, 0, 0}, dmrs_type::TYPE2, 2, 740, 1, {}, {0}}}, {"test_data/pusch_demodulator_test_input_symbols92.dat"}, {"test_data/pusch_demodulator_test_input_estimates92.dat"}, {"test_data/pusch_demodulator_test_output92.dat"}},
  {{0.0044474, {56096, {1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}, modulation_scheme::QAM16, 2, 10, {0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}, dmrs_type::TYPE2, 2, 309, 1, {1,  101,  201,  301,  401,  501,  601,  701,  801,  901, 1001, 1101, 1201, 1301}, {0}}}, {"test_data/pusch_demodulator_test_input_symbols94.dat"}, {"test_data/pusch_demodulator_test_input_estimates94.dat"}, {"test_data/pusch_demodulator_test_output94.dat"}},
  {{0.0078582, {23248, {1, 1, 1, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}, modulation_scheme::QAM64, 0, 14, {0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0}, dmrs_type::TYPE2, 1, 493, 1, {}, {0}}}, {"test_data/pusch_demodulator_test_input_symbols96.dat"}, {"test_data/pusch_demodulator_test_input_estimates96.dat"}, {"test_data/pusch_demodulator_test_output96.dat"}},
  {{0.00086927, {59128, {1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}, modulation_scheme::QAM64, 0, 14, {0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}, dmrs_type::TYPE2, 3, 24, 1, {1,  101,  201,  301,  401,  501,  601,  701,  801,  901, 1001, 1101, 1201, 1301, 1401, 1501, 1601, 1701, 1801, 1901, 2001, 2101, 2201, 2301}, {0}}}, {"test_data/pusch_demodulator_test_input_symbols98.dat"}, {"test_data/pusch_demodulator_test_input_estimates98.dat"}, {"test_data/pusch_demodulator_test_output98.dat"}},
  {{0.0060154, {19549, {1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}, modulation_scheme::QAM64, 1, 13, {0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0}, dmrs_type::TYPE2, 1, 651, 1, {}, {0}}}, {"test_data/pusch_demodulator_test_input_symbols100.dat"}, {"test_data/pusch_demodulator_test_input_estimates100.dat"}, {"test_data/pusch_demodulator_test_output100.dat"}},
  {{0.0089218, {25507, {1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}, modulation_scheme::QAM64, 1, 13, {0, 0, 1, 0, 0, 0, 0, 1, 0, 0, 0, 1, 0, 0}, dmrs_type::TYPE2, 3, 240, 1, {1,  101,  201,  301,  401,  501,  601,  701,  801,  901, 1001, 1101, 1201, 1301, 1401}, {0}}}, {"test_data/pusch_demodulator_test_input_symbols102.dat"}, {"test_data/pusch_demodulator_test_input_estimates102.dat"}, {"test_data/pusch_demodulator_test_output102.dat"}},
  {{0.0089728, {41828, {1, 1, 1, 1, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}, modulation_scheme::QAM64, 2, 10, {0, 0, 1, 0, 0, 0, 1, 0, 0, 1, 0, 0, 0, 0}, dmrs_type::TYPE2, 3, 550, 1, {}, {0}}}, {"test_data/pusch_demodulator_test_input_symbols104.dat"}, {"test_data/pusch_demodulator_test_input_estimates104.dat"}, {"test_data/pusch_demodulator_test_output104.dat"}},
  {{0.0063333, {57854, {1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}, modulation_scheme::QAM64, 2, 10, {0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}, dmrs_type::TYPE2, 1, 952, 1, {1, 101}, {0}}}, {"test_data/pusch_demodulator_test_input_symbols106.dat"}, {"test_data/pusch_demodulator_test_input_estimates106.dat"}, {"test_data/pusch_demodulator_test_output106.dat"}},
  {{0.0080034, {28333, {1, 1, 1, 1, 1, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}, modulation_scheme::QAM256, 0, 14, {0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0}, dmrs_type::TYPE2, 1, 833, 1, {}, {0}}}, {"test_data/pusch_demodulator_test_input_symbols108.dat"}, {"test_data/pusch_demodulator_test_input_estimates108.dat"}, {"test_data/pusch_demodulator_test_output108.dat"}},
  {{0.0015805, {53409, {1, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}, modulation_scheme::QAM256, 0, 14, {0, 0, 1, 0, 0, 0, 0, 1, 0, 0, 0, 1, 0, 0}, dmrs_type::TYPE2, 3, 848, 1, {1, 101, 201, 301}, {0}}}, {"test_data/pusch_demodulator_test_input_symbols110.dat"}, {"test_data/pusch_demodulator_test_input_estimates110.dat"}, {"test_data/pusch_demodulator_test_output110.dat"}},
  {{0.0047443, {57127, {1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}, modulation_scheme::QAM256, 1, 13, {0, 0, 1, 0, 0, 1, 0, 0, 1, 0, 0, 1, 0, 0}, dmrs_type::TYPE2, 3, 792, 1, {}, {0}}}, {"test_data/pusch_demodulator_test_input_symbols112.dat"}, {"test_data/pusch_demodulator_test_input_estimates112.dat"}, {"test_data/pusch_demodulator_test_output112.dat"}},
  {{0.0032103, {44203, {1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}, modulation_scheme::QAM256, 1, 13, {0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0}, dmrs_type::TYPE2, 1, 992, 1, {1,  101,  201,  301,  401,  501,  601,  701,  801,  901, 1001, 1101, 1201, 1301, 1401, 1501, 1601, 1701, 1801, 1901, 2001}, {0}}}, {"test_data/pusch_demodulator_test_input_symbols114.dat"}, {"test_data/pusch_demodulator_test_input_estimates114.dat"}, {"test_data/pusch_demodulator_test_output114.dat"}},
  {{0.0040816, {36226, {1, 1, 1, 1, 1, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}, modulation_scheme::QAM256, 2, 10, {0, 0, 1, 0, 0, 1, 0, 0, 1, 0, 0, 1, 0, 0}, dmrs_type::TYPE2, 1, 116, 1, {}, {0}}}, {"test_data/pusch_demodulator_test_input_symbols116.dat"}, {"test_data/pusch_demodulator_test_input_estimates116.dat"}, {"test_data/pusch_demodulator_test_output116.dat"}},
  {{0.0071118, {48326, {1, 1, 1, 1, 1, 1, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}, modulation_scheme::QAM256, 2, 10, {0, 0, 1, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0}, dmrs_type::TYPE2, 1, 215, 1, {1, 101, 201, 301, 401, 501, 601, 701, 801}, {0}}}, {"test_data/pusch_demodulator_test_input_symbols118.dat"}, {"test_data/pusch_demodulator_test_input_estimates118.dat"}, {"test_data/pusch_demodulator_test_output118.dat"}},
    // clang-format on
};

} // namespace srsran
