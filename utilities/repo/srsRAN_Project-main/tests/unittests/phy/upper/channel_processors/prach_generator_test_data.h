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

// This file was generated using the following MATLAB class on 05-Aug-2022:
//   + "srsPRACHGeneratorUnittest.m"

#include "srsran/phy/upper/channel_processors/prach_generator.h"
#include "srsran/support/file_vector.h"

namespace srsran {

struct test_case_t {
  prach_generator::configuration config;
  file_vector<cf_t>              sequence;
};

static const std::vector<test_case_t> prach_generator_test_data = {
    // clang-format off
  {{preamble_format::FORMAT0, 834, 57, restricted_set_config::UNRESTRICTED, 0}, {"test_data/prach_generator_test_output0.dat"}},
  {{preamble_format::FORMAT0, 130, 58, restricted_set_config::UNRESTRICTED, 5}, {"test_data/prach_generator_test_output1.dat"}},
  {{preamble_format::FORMAT0, 647, 6, restricted_set_config::UNRESTRICTED, 12}, {"test_data/prach_generator_test_output2.dat"}},
  {{preamble_format::FORMAT0, 285, 35, restricted_set_config::TYPE_A, 0}, {"test_data/prach_generator_test_output3.dat"}},
  {{preamble_format::FORMAT0, 980, 61, restricted_set_config::TYPE_A, 5}, {"test_data/prach_generator_test_output4.dat"}},
  {{preamble_format::FORMAT0, 161, 62, restricted_set_config::TYPE_A, 12}, {"test_data/prach_generator_test_output5.dat"}},
  {{preamble_format::FORMAT0, 980, 31, restricted_set_config::TYPE_B, 0}, {"test_data/prach_generator_test_output6.dat"}},
  {{preamble_format::FORMAT0, 819, 9, restricted_set_config::TYPE_B, 5}, {"test_data/prach_generator_test_output7.dat"}},
  {{preamble_format::FORMAT0, 431, 58, restricted_set_config::TYPE_B, 12}, {"test_data/prach_generator_test_output8.dat"}},
  {{preamble_format::FORMAT1, 811, 61, restricted_set_config::UNRESTRICTED, 0}, {"test_data/prach_generator_test_output9.dat"}},
  {{preamble_format::FORMAT1, 671, 2, restricted_set_config::UNRESTRICTED, 5}, {"test_data/prach_generator_test_output10.dat"}},
  {{preamble_format::FORMAT1, 869, 59, restricted_set_config::UNRESTRICTED, 12}, {"test_data/prach_generator_test_output11.dat"}},
  {{preamble_format::FORMAT1, 695, 48, restricted_set_config::TYPE_A, 0}, {"test_data/prach_generator_test_output12.dat"}},
  {{preamble_format::FORMAT1, 760, 25, restricted_set_config::TYPE_A, 5}, {"test_data/prach_generator_test_output13.dat"}},
  {{preamble_format::FORMAT1, 671, 10, restricted_set_config::TYPE_A, 12}, {"test_data/prach_generator_test_output14.dat"}},
  {{preamble_format::FORMAT1, 722, 2, restricted_set_config::TYPE_B, 0}, {"test_data/prach_generator_test_output15.dat"}},
  {{preamble_format::FORMAT1, 283, 2, restricted_set_config::TYPE_B, 5}, {"test_data/prach_generator_test_output16.dat"}},
  {{preamble_format::FORMAT1, 99, 52, restricted_set_config::TYPE_B, 12}, {"test_data/prach_generator_test_output17.dat"}},
  {{preamble_format::FORMAT2, 711, 20, restricted_set_config::UNRESTRICTED, 0}, {"test_data/prach_generator_test_output18.dat"}},
  {{preamble_format::FORMAT2, 973, 2, restricted_set_config::UNRESTRICTED, 5}, {"test_data/prach_generator_test_output19.dat"}},
  {{preamble_format::FORMAT2, 449, 24, restricted_set_config::UNRESTRICTED, 12}, {"test_data/prach_generator_test_output20.dat"}},
  {{preamble_format::FORMAT2, 783, 50, restricted_set_config::TYPE_A, 0}, {"test_data/prach_generator_test_output21.dat"}},
  {{preamble_format::FORMAT2, 191, 31, restricted_set_config::TYPE_A, 5}, {"test_data/prach_generator_test_output22.dat"}},
  {{preamble_format::FORMAT2, 456, 41, restricted_set_config::TYPE_A, 12}, {"test_data/prach_generator_test_output23.dat"}},
  {{preamble_format::FORMAT2, 726, 48, restricted_set_config::TYPE_B, 0}, {"test_data/prach_generator_test_output24.dat"}},
  {{preamble_format::FORMAT2, 282, 43, restricted_set_config::TYPE_B, 5}, {"test_data/prach_generator_test_output25.dat"}},
  {{preamble_format::FORMAT2, 670, 10, restricted_set_config::TYPE_B, 12}, {"test_data/prach_generator_test_output26.dat"}},
  {{preamble_format::FORMAT3, 121, 31, restricted_set_config::UNRESTRICTED, 0}, {"test_data/prach_generator_test_output27.dat"}},
  {{preamble_format::FORMAT3, 982, 21, restricted_set_config::UNRESTRICTED, 5}, {"test_data/prach_generator_test_output28.dat"}},
  {{preamble_format::FORMAT3, 599, 14, restricted_set_config::UNRESTRICTED, 12}, {"test_data/prach_generator_test_output29.dat"}},
  {{preamble_format::FORMAT3, 769, 16, restricted_set_config::TYPE_A, 0}, {"test_data/prach_generator_test_output30.dat"}},
  {{preamble_format::FORMAT3, 518, 44, restricted_set_config::TYPE_A, 5}, {"test_data/prach_generator_test_output31.dat"}},
  {{preamble_format::FORMAT3, 912, 61, restricted_set_config::TYPE_A, 12}, {"test_data/prach_generator_test_output32.dat"}},
  {{preamble_format::FORMAT3, 560, 8, restricted_set_config::TYPE_B, 0}, {"test_data/prach_generator_test_output33.dat"}},
  {{preamble_format::FORMAT3, 152, 16, restricted_set_config::TYPE_B, 5}, {"test_data/prach_generator_test_output34.dat"}},
  {{preamble_format::FORMAT3, 860, 16, restricted_set_config::TYPE_B, 12}, {"test_data/prach_generator_test_output35.dat"}},
  {{preamble_format::FORMAT0, 833, 15, restricted_set_config::UNRESTRICTED, 0}, {"test_data/prach_generator_test_output36.dat"}},
  {{preamble_format::FORMAT0, 951, 22, restricted_set_config::UNRESTRICTED, 5}, {"test_data/prach_generator_test_output37.dat"}},
  {{preamble_format::FORMAT0, 201, 16, restricted_set_config::UNRESTRICTED, 12}, {"test_data/prach_generator_test_output38.dat"}},
  {{preamble_format::FORMAT0, 630, 30, restricted_set_config::TYPE_A, 0}, {"test_data/prach_generator_test_output39.dat"}},
  {{preamble_format::FORMAT0, 360, 53, restricted_set_config::TYPE_A, 5}, {"test_data/prach_generator_test_output40.dat"}},
  {{preamble_format::FORMAT0, 599, 35, restricted_set_config::TYPE_A, 12}, {"test_data/prach_generator_test_output41.dat"}},
  {{preamble_format::FORMAT0, 939, 18, restricted_set_config::TYPE_B, 0}, {"test_data/prach_generator_test_output42.dat"}},
  {{preamble_format::FORMAT0, 775, 48, restricted_set_config::TYPE_B, 5}, {"test_data/prach_generator_test_output43.dat"}},
  {{preamble_format::FORMAT0, 389, 36, restricted_set_config::TYPE_B, 12}, {"test_data/prach_generator_test_output44.dat"}},
  {{preamble_format::FORMAT1, 77, 3, restricted_set_config::UNRESTRICTED, 0}, {"test_data/prach_generator_test_output45.dat"}},
  {{preamble_format::FORMAT1, 543, 49, restricted_set_config::UNRESTRICTED, 5}, {"test_data/prach_generator_test_output46.dat"}},
  {{preamble_format::FORMAT1, 956, 8, restricted_set_config::UNRESTRICTED, 12}, {"test_data/prach_generator_test_output47.dat"}},
  {{preamble_format::FORMAT1, 582, 30, restricted_set_config::TYPE_A, 0}, {"test_data/prach_generator_test_output48.dat"}},
  {{preamble_format::FORMAT1, 12, 21, restricted_set_config::TYPE_A, 5}, {"test_data/prach_generator_test_output49.dat"}},
  {{preamble_format::FORMAT1, 166, 50, restricted_set_config::TYPE_A, 12}, {"test_data/prach_generator_test_output50.dat"}},
  {{preamble_format::FORMAT1, 318, 33, restricted_set_config::TYPE_B, 0}, {"test_data/prach_generator_test_output51.dat"}},
  {{preamble_format::FORMAT1, 169, 38, restricted_set_config::TYPE_B, 5}, {"test_data/prach_generator_test_output52.dat"}},
  {{preamble_format::FORMAT1, 269, 41, restricted_set_config::TYPE_B, 12}, {"test_data/prach_generator_test_output53.dat"}},
  {{preamble_format::FORMAT2, 705, 47, restricted_set_config::UNRESTRICTED, 0}, {"test_data/prach_generator_test_output54.dat"}},
  {{preamble_format::FORMAT2, 461, 5, restricted_set_config::UNRESTRICTED, 5}, {"test_data/prach_generator_test_output55.dat"}},
  {{preamble_format::FORMAT2, 234, 58, restricted_set_config::UNRESTRICTED, 12}, {"test_data/prach_generator_test_output56.dat"}},
  {{preamble_format::FORMAT2, 156, 52, restricted_set_config::TYPE_A, 0}, {"test_data/prach_generator_test_output57.dat"}},
  {{preamble_format::FORMAT2, 551, 63, restricted_set_config::TYPE_A, 5}, {"test_data/prach_generator_test_output58.dat"}},
  {{preamble_format::FORMAT2, 80, 28, restricted_set_config::TYPE_A, 12}, {"test_data/prach_generator_test_output59.dat"}},
  {{preamble_format::FORMAT2, 109, 61, restricted_set_config::TYPE_B, 0}, {"test_data/prach_generator_test_output60.dat"}},
  {{preamble_format::FORMAT2, 4, 49, restricted_set_config::TYPE_B, 5}, {"test_data/prach_generator_test_output61.dat"}},
  {{preamble_format::FORMAT2, 836, 55, restricted_set_config::TYPE_B, 12}, {"test_data/prach_generator_test_output62.dat"}},
  {{preamble_format::FORMAT3, 86, 25, restricted_set_config::UNRESTRICTED, 0}, {"test_data/prach_generator_test_output63.dat"}},
  {{preamble_format::FORMAT3, 266, 51, restricted_set_config::UNRESTRICTED, 5}, {"test_data/prach_generator_test_output64.dat"}},
  {{preamble_format::FORMAT3, 441, 58, restricted_set_config::UNRESTRICTED, 12}, {"test_data/prach_generator_test_output65.dat"}},
  {{preamble_format::FORMAT3, 186, 16, restricted_set_config::TYPE_A, 0}, {"test_data/prach_generator_test_output66.dat"}},
  {{preamble_format::FORMAT3, 149, 8, restricted_set_config::TYPE_A, 5}, {"test_data/prach_generator_test_output67.dat"}},
  {{preamble_format::FORMAT3, 890, 37, restricted_set_config::TYPE_A, 12}, {"test_data/prach_generator_test_output68.dat"}},
  {{preamble_format::FORMAT3, 563, 9, restricted_set_config::TYPE_B, 0}, {"test_data/prach_generator_test_output69.dat"}},
  {{preamble_format::FORMAT3, 873, 39, restricted_set_config::TYPE_B, 5}, {"test_data/prach_generator_test_output70.dat"}},
  {{preamble_format::FORMAT3, 359, 32, restricted_set_config::TYPE_B, 12}, {"test_data/prach_generator_test_output71.dat"}},
  {{preamble_format::FORMAT0, 411, 4, restricted_set_config::UNRESTRICTED, 0}, {"test_data/prach_generator_test_output72.dat"}},
  {{preamble_format::FORMAT0, 245, 7, restricted_set_config::UNRESTRICTED, 5}, {"test_data/prach_generator_test_output73.dat"}},
  {{preamble_format::FORMAT0, 188, 15, restricted_set_config::UNRESTRICTED, 12}, {"test_data/prach_generator_test_output74.dat"}},
  {{preamble_format::FORMAT0, 427, 3, restricted_set_config::TYPE_A, 0}, {"test_data/prach_generator_test_output75.dat"}},
  {{preamble_format::FORMAT0, 924, 60, restricted_set_config::TYPE_A, 5}, {"test_data/prach_generator_test_output76.dat"}},
  {{preamble_format::FORMAT0, 502, 31, restricted_set_config::TYPE_A, 12}, {"test_data/prach_generator_test_output77.dat"}},
  {{preamble_format::FORMAT0, 345, 57, restricted_set_config::TYPE_B, 0}, {"test_data/prach_generator_test_output78.dat"}},
  {{preamble_format::FORMAT0, 378, 7, restricted_set_config::TYPE_B, 5}, {"test_data/prach_generator_test_output79.dat"}},
  {{preamble_format::FORMAT0, 798, 24, restricted_set_config::TYPE_B, 12}, {"test_data/prach_generator_test_output80.dat"}},
  {{preamble_format::FORMAT1, 247, 25, restricted_set_config::UNRESTRICTED, 0}, {"test_data/prach_generator_test_output81.dat"}},
  {{preamble_format::FORMAT1, 98, 8, restricted_set_config::UNRESTRICTED, 5}, {"test_data/prach_generator_test_output82.dat"}},
  {{preamble_format::FORMAT1, 964, 61, restricted_set_config::UNRESTRICTED, 12}, {"test_data/prach_generator_test_output83.dat"}},
  {{preamble_format::FORMAT1, 589, 3, restricted_set_config::TYPE_A, 0}, {"test_data/prach_generator_test_output84.dat"}},
  {{preamble_format::FORMAT1, 240, 22, restricted_set_config::TYPE_A, 5}, {"test_data/prach_generator_test_output85.dat"}},
  {{preamble_format::FORMAT1, 840, 0, restricted_set_config::TYPE_A, 12}, {"test_data/prach_generator_test_output86.dat"}},
  {{preamble_format::FORMAT1, 44, 10, restricted_set_config::TYPE_B, 0}, {"test_data/prach_generator_test_output87.dat"}},
  {{preamble_format::FORMAT1, 664, 46, restricted_set_config::TYPE_B, 5}, {"test_data/prach_generator_test_output88.dat"}},
  {{preamble_format::FORMAT1, 663, 28, restricted_set_config::TYPE_B, 12}, {"test_data/prach_generator_test_output89.dat"}},
  {{preamble_format::FORMAT2, 560, 18, restricted_set_config::UNRESTRICTED, 0}, {"test_data/prach_generator_test_output90.dat"}},
  {{preamble_format::FORMAT2, 762, 12, restricted_set_config::UNRESTRICTED, 5}, {"test_data/prach_generator_test_output91.dat"}},
  {{preamble_format::FORMAT2, 703, 11, restricted_set_config::UNRESTRICTED, 12}, {"test_data/prach_generator_test_output92.dat"}},
  {{preamble_format::FORMAT2, 377, 40, restricted_set_config::TYPE_A, 0}, {"test_data/prach_generator_test_output93.dat"}},
  {{preamble_format::FORMAT2, 798, 5, restricted_set_config::TYPE_A, 5}, {"test_data/prach_generator_test_output94.dat"}},
  {{preamble_format::FORMAT2, 951, 49, restricted_set_config::TYPE_A, 12}, {"test_data/prach_generator_test_output95.dat"}},
  {{preamble_format::FORMAT2, 498, 27, restricted_set_config::TYPE_B, 0}, {"test_data/prach_generator_test_output96.dat"}},
  {{preamble_format::FORMAT2, 457, 19, restricted_set_config::TYPE_B, 5}, {"test_data/prach_generator_test_output97.dat"}},
  {{preamble_format::FORMAT2, 520, 32, restricted_set_config::TYPE_B, 12}, {"test_data/prach_generator_test_output98.dat"}},
  {{preamble_format::FORMAT3, 837, 50, restricted_set_config::UNRESTRICTED, 0}, {"test_data/prach_generator_test_output99.dat"}},
  {{preamble_format::FORMAT3, 659, 24, restricted_set_config::UNRESTRICTED, 5}, {"test_data/prach_generator_test_output100.dat"}},
  {{preamble_format::FORMAT3, 831, 34, restricted_set_config::UNRESTRICTED, 12}, {"test_data/prach_generator_test_output101.dat"}},
  {{preamble_format::FORMAT3, 359, 60, restricted_set_config::TYPE_A, 0}, {"test_data/prach_generator_test_output102.dat"}},
  {{preamble_format::FORMAT3, 896, 35, restricted_set_config::TYPE_A, 5}, {"test_data/prach_generator_test_output103.dat"}},
  {{preamble_format::FORMAT3, 637, 37, restricted_set_config::TYPE_A, 12}, {"test_data/prach_generator_test_output104.dat"}},
  {{preamble_format::FORMAT3, 212, 19, restricted_set_config::TYPE_B, 0}, {"test_data/prach_generator_test_output105.dat"}},
  {{preamble_format::FORMAT3, 482, 14, restricted_set_config::TYPE_B, 5}, {"test_data/prach_generator_test_output106.dat"}},
  {{preamble_format::FORMAT3, 864, 12, restricted_set_config::TYPE_B, 12}, {"test_data/prach_generator_test_output107.dat"}},
  {{preamble_format::FORMAT0, 231, 10, restricted_set_config::UNRESTRICTED, 0}, {"test_data/prach_generator_test_output108.dat"}},
  {{preamble_format::FORMAT0, 233, 27, restricted_set_config::UNRESTRICTED, 5}, {"test_data/prach_generator_test_output109.dat"}},
  {{preamble_format::FORMAT0, 318, 59, restricted_set_config::UNRESTRICTED, 12}, {"test_data/prach_generator_test_output110.dat"}},
  {{preamble_format::FORMAT0, 440, 11, restricted_set_config::TYPE_A, 0}, {"test_data/prach_generator_test_output111.dat"}},
  {{preamble_format::FORMAT0, 926, 62, restricted_set_config::TYPE_A, 5}, {"test_data/prach_generator_test_output112.dat"}},
  {{preamble_format::FORMAT0, 449, 7, restricted_set_config::TYPE_A, 12}, {"test_data/prach_generator_test_output113.dat"}},
  {{preamble_format::FORMAT0, 264, 26, restricted_set_config::TYPE_B, 0}, {"test_data/prach_generator_test_output114.dat"}},
  {{preamble_format::FORMAT0, 609, 16, restricted_set_config::TYPE_B, 5}, {"test_data/prach_generator_test_output115.dat"}},
  {{preamble_format::FORMAT0, 617, 45, restricted_set_config::TYPE_B, 12}, {"test_data/prach_generator_test_output116.dat"}},
  {{preamble_format::FORMAT1, 227, 7, restricted_set_config::UNRESTRICTED, 0}, {"test_data/prach_generator_test_output117.dat"}},
  {{preamble_format::FORMAT1, 303, 20, restricted_set_config::UNRESTRICTED, 5}, {"test_data/prach_generator_test_output118.dat"}},
  {{preamble_format::FORMAT1, 434, 32, restricted_set_config::UNRESTRICTED, 12}, {"test_data/prach_generator_test_output119.dat"}},
  {{preamble_format::FORMAT1, 87, 16, restricted_set_config::TYPE_A, 0}, {"test_data/prach_generator_test_output120.dat"}},
  {{preamble_format::FORMAT1, 820, 1, restricted_set_config::TYPE_A, 5}, {"test_data/prach_generator_test_output121.dat"}},
  {{preamble_format::FORMAT1, 951, 46, restricted_set_config::TYPE_A, 12}, {"test_data/prach_generator_test_output122.dat"}},
  {{preamble_format::FORMAT1, 500, 37, restricted_set_config::TYPE_B, 0}, {"test_data/prach_generator_test_output123.dat"}},
  {{preamble_format::FORMAT1, 242, 29, restricted_set_config::TYPE_B, 5}, {"test_data/prach_generator_test_output124.dat"}},
  {{preamble_format::FORMAT1, 986, 34, restricted_set_config::TYPE_B, 12}, {"test_data/prach_generator_test_output125.dat"}},
  {{preamble_format::FORMAT2, 533, 14, restricted_set_config::UNRESTRICTED, 0}, {"test_data/prach_generator_test_output126.dat"}},
  {{preamble_format::FORMAT2, 500, 39, restricted_set_config::UNRESTRICTED, 5}, {"test_data/prach_generator_test_output127.dat"}},
  {{preamble_format::FORMAT2, 695, 25, restricted_set_config::UNRESTRICTED, 12}, {"test_data/prach_generator_test_output128.dat"}},
  {{preamble_format::FORMAT2, 376, 63, restricted_set_config::TYPE_A, 0}, {"test_data/prach_generator_test_output129.dat"}},
  {{preamble_format::FORMAT2, 38, 56, restricted_set_config::TYPE_A, 5}, {"test_data/prach_generator_test_output130.dat"}},
  {{preamble_format::FORMAT2, 935, 50, restricted_set_config::TYPE_A, 12}, {"test_data/prach_generator_test_output131.dat"}},
  {{preamble_format::FORMAT2, 101, 16, restricted_set_config::TYPE_B, 0}, {"test_data/prach_generator_test_output132.dat"}},
  {{preamble_format::FORMAT2, 343, 43, restricted_set_config::TYPE_B, 5}, {"test_data/prach_generator_test_output133.dat"}},
  {{preamble_format::FORMAT2, 139, 46, restricted_set_config::TYPE_B, 12}, {"test_data/prach_generator_test_output134.dat"}},
  {{preamble_format::FORMAT3, 109, 41, restricted_set_config::UNRESTRICTED, 0}, {"test_data/prach_generator_test_output135.dat"}},
  {{preamble_format::FORMAT3, 506, 49, restricted_set_config::UNRESTRICTED, 5}, {"test_data/prach_generator_test_output136.dat"}},
  {{preamble_format::FORMAT3, 732, 57, restricted_set_config::UNRESTRICTED, 12}, {"test_data/prach_generator_test_output137.dat"}},
  {{preamble_format::FORMAT3, 912, 21, restricted_set_config::TYPE_A, 0}, {"test_data/prach_generator_test_output138.dat"}},
  {{preamble_format::FORMAT3, 715, 12, restricted_set_config::TYPE_A, 5}, {"test_data/prach_generator_test_output139.dat"}},
  {{preamble_format::FORMAT3, 31, 47, restricted_set_config::TYPE_A, 12}, {"test_data/prach_generator_test_output140.dat"}},
  {{preamble_format::FORMAT3, 512, 30, restricted_set_config::TYPE_B, 0}, {"test_data/prach_generator_test_output141.dat"}},
  {{preamble_format::FORMAT3, 926, 39, restricted_set_config::TYPE_B, 5}, {"test_data/prach_generator_test_output142.dat"}},
  {{preamble_format::FORMAT3, 632, 55, restricted_set_config::TYPE_B, 12}, {"test_data/prach_generator_test_output143.dat"}},
    // clang-format on
};

} // namespace srsran
