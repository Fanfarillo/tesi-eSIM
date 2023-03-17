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

#include "lib/ran/ssb_freq_position_generator.h"
#include "ssb_coreset0_freq_pos_checker.h"
#include "srsran/ran/band_helper.h"
#include <gtest/gtest.h>

using namespace srsran;

// Define struct to pass parameters from test functions.
struct cfg_gen_input_params {
  unsigned           dl_arfcn;
  nr_band            band;
  unsigned           n_rbs;
  subcarrier_spacing scs_common;
  subcarrier_spacing scs_ssb;
  uint8_t            ss0_idx;

  optional<band_helper::ssb_coreset0_freq_location> generate_ssb_coreset0_location()
  {
    return band_helper::get_ssb_coreset0_freq_location(dl_arfcn, band, n_rbs, scs_common, scs_ssb, ss0_idx);
  }
};

// Helper that compares the SSB and Coreset0 parameters returned by du_config_generator.
static bool compare_ssb_freq_location(const ssb_freq_location& lhs, const ssb_freq_location& rhs)
{
  bool result = lhs.is_valid && rhs.is_valid && lhs.k_ssb.to_uint() == rhs.k_ssb.to_uint() &&
                lhs.offset_to_point_A.to_uint() == rhs.offset_to_point_A.to_uint();
  return result;
}

static bool verify_ssb_is_within_ch_band(unsigned           dl_arfcn,
                                         unsigned           n_rbs,
                                         subcarrier_spacing scs_common,
                                         double             ss_ref,
                                         subcarrier_spacing scs_ssb)
{
  double f_ssb_0_Hz  = ss_ref - static_cast<double>(scs_to_khz(scs_ssb) * KHZ_TO_HZ * NOF_SSB_SUBCARRIERS / 2);
  double f_ssb_ub_Hz = ss_ref + static_cast<double>(scs_to_khz(scs_ssb) * KHZ_TO_HZ * NOF_SSB_SUBCARRIERS / 2) - 1;

  double f_ref_hz   = band_helper::nr_arfcn_to_freq(dl_arfcn);
  double point_A_hz = band_helper::get_abs_freq_point_a_from_f_ref(f_ref_hz, n_rbs, scs_common);
  double bw_ub_hz   = point_A_hz + n_rbs * NOF_SUBCARRIERS_PER_RB * scs_to_khz(scs_common) * KHZ_TO_HZ - 1;

  return f_ssb_0_Hz >= point_A_hz and f_ssb_ub_Hz <= bw_ub_hz;
}

/*
 *      ===========    TEST GENERATION OF SSB POSITION WITHIN THE BAND    ===========
 */

// Test all possible SSB position within a given band returned by the config generator.
TEST(ssb_freq_position_generation_test, band_3)
{
  unsigned           dl_arfcn   = 365000;
  nr_band            nr_band    = nr_band::n3;
  unsigned           n_rbs      = 52;
  subcarrier_spacing scs_common = subcarrier_spacing::kHz15;
  subcarrier_spacing scs_ssb    = subcarrier_spacing::kHz15;

  ssb_freq_position_generator cfg_generator{dl_arfcn, nr_band, n_rbs, scs_common, scs_ssb};

  ssb_freq_location expected{true, 5, 2};
  ASSERT_TRUE(compare_ssb_freq_location(expected, cfg_generator.get_next_ssb_location()));

  // Get next SSB position and verify its position in terms of offsetToPointA and k_SSB.
  expected.offset_to_point_A = 11;
  expected.k_ssb             = 10;
  ssb_freq_location test     = cfg_generator.get_next_ssb_location();
  ASSERT_TRUE(compare_ssb_freq_location(expected, test));
  ASSERT_TRUE(verify_ssb_is_within_ch_band(dl_arfcn, n_rbs, scs_common, test.ss_ref, scs_ssb));

  expected.offset_to_point_A = 18;
  expected.k_ssb             = 6;
  test                       = cfg_generator.get_next_ssb_location();
  ASSERT_TRUE(compare_ssb_freq_location(expected, test));
  ASSERT_TRUE(verify_ssb_is_within_ch_band(dl_arfcn, n_rbs, scs_common, test.ss_ref, scs_ssb));

  expected.offset_to_point_A = 25;
  expected.k_ssb             = 2;
  test                       = cfg_generator.get_next_ssb_location();
  ASSERT_TRUE(compare_ssb_freq_location(expected, test));
  ASSERT_TRUE(verify_ssb_is_within_ch_band(dl_arfcn, n_rbs, scs_common, test.ss_ref, scs_ssb));

  expected.offset_to_point_A = 31;
  expected.k_ssb             = 10;
  test                       = cfg_generator.get_next_ssb_location();
  ASSERT_TRUE(compare_ssb_freq_location(expected, test));
  ASSERT_TRUE(verify_ssb_is_within_ch_band(dl_arfcn, n_rbs, scs_common, test.ss_ref, scs_ssb));

  // Verify there are no possible SSB positions within the band.
  ASSERT_TRUE(not cfg_generator.get_next_ssb_location().is_valid);
}

// Test all possible SSB position within a given band returned by the config generator.
TEST(ssb_freq_position_generation_test, band_7)
{
  unsigned           dl_arfcn   = 531720;
  nr_band            nr_band    = nr_band::n7;
  unsigned           n_rbs      = 25;
  subcarrier_spacing scs_common = subcarrier_spacing::kHz15;
  subcarrier_spacing scs_ssb    = subcarrier_spacing::kHz15;

  ssb_freq_position_generator cfg_generator{dl_arfcn, nr_band, n_rbs, scs_common, scs_ssb};

  ssb_freq_location expected{true, 0, 0};
  ssb_freq_location test = cfg_generator.get_next_ssb_location();
  ASSERT_TRUE(compare_ssb_freq_location(expected, test));
  ASSERT_TRUE(verify_ssb_is_within_ch_band(dl_arfcn, n_rbs, scs_common, test.ss_ref, scs_ssb));

  // Get next SSB position and verify its position in terms of offsetToPointA and k_SSB.
  ASSERT_FALSE(cfg_generator.get_next_ssb_location().is_valid);
}

// Test all possible SSB position within a given band returned by the config generator.
TEST(ssb_freq_position_generation_test, band_25)
{
  unsigned           dl_arfcn   = 391180;
  nr_band            nr_band    = nr_band::n25;
  unsigned           n_rbs      = 38;
  subcarrier_spacing scs_common = subcarrier_spacing::kHz30;
  subcarrier_spacing scs_ssb    = subcarrier_spacing::kHz15;

  ssb_freq_position_generator cfg_generator{dl_arfcn, nr_band, n_rbs, scs_common, scs_ssb};

  ssb_freq_location expected{true, 2, 2};
  ssb_freq_location test = cfg_generator.get_next_ssb_location();
  ASSERT_TRUE(compare_ssb_freq_location(expected, test));
  ASSERT_TRUE(verify_ssb_is_within_ch_band(dl_arfcn, n_rbs, scs_common, test.ss_ref, scs_ssb));

  // Get next SSB position and verify its position in terms of offsetToPointA and k_SSB.
  expected.offset_to_point_A = 8;
  expected.k_ssb             = 10;
  test                       = cfg_generator.get_next_ssb_location();
  ASSERT_TRUE(compare_ssb_freq_location(expected, test));
  ASSERT_TRUE(verify_ssb_is_within_ch_band(dl_arfcn, n_rbs, scs_common, test.ss_ref, scs_ssb));

  expected.offset_to_point_A = 14;
  expected.k_ssb             = 18;
  test                       = cfg_generator.get_next_ssb_location();
  ASSERT_TRUE(compare_ssb_freq_location(expected, test));
  ASSERT_TRUE(verify_ssb_is_within_ch_band(dl_arfcn, n_rbs, scs_common, test.ss_ref, scs_ssb));

  expected.offset_to_point_A = 22;
  expected.k_ssb             = 2;
  test                       = cfg_generator.get_next_ssb_location();
  ASSERT_TRUE(compare_ssb_freq_location(expected, test));
  ASSERT_TRUE(verify_ssb_is_within_ch_band(dl_arfcn, n_rbs, scs_common, test.ss_ref, scs_ssb));

  expected.offset_to_point_A = 28;
  expected.k_ssb             = 10;
  test                       = cfg_generator.get_next_ssb_location();
  ASSERT_TRUE(compare_ssb_freq_location(expected, test));
  ASSERT_TRUE(verify_ssb_is_within_ch_band(dl_arfcn, n_rbs, scs_common, test.ss_ref, scs_ssb));

  expected.offset_to_point_A = 34;
  expected.k_ssb             = 18;
  test                       = cfg_generator.get_next_ssb_location();
  ASSERT_TRUE(compare_ssb_freq_location(expected, test));
  ASSERT_TRUE(verify_ssb_is_within_ch_band(dl_arfcn, n_rbs, scs_common, test.ss_ref, scs_ssb));

  expected.offset_to_point_A = 42;
  expected.k_ssb             = 2;
  test                       = cfg_generator.get_next_ssb_location();
  ASSERT_TRUE(compare_ssb_freq_location(expected, test));
  ASSERT_TRUE(verify_ssb_is_within_ch_band(dl_arfcn, n_rbs, scs_common, test.ss_ref, scs_ssb));

  expected.offset_to_point_A = 48;
  expected.k_ssb             = 10;
  test                       = cfg_generator.get_next_ssb_location();
  ASSERT_TRUE(compare_ssb_freq_location(expected, test));
  ASSERT_TRUE(verify_ssb_is_within_ch_band(dl_arfcn, n_rbs, scs_common, test.ss_ref, scs_ssb));

  expected.offset_to_point_A = 54;
  expected.k_ssb             = 18;
  test                       = cfg_generator.get_next_ssb_location();
  ASSERT_TRUE(compare_ssb_freq_location(expected, test));
  ASSERT_TRUE(verify_ssb_is_within_ch_band(dl_arfcn, n_rbs, scs_common, test.ss_ref, scs_ssb));

  // Verify there are no possible SSB positions within the band.
  ASSERT_FALSE(cfg_generator.get_next_ssb_location().is_valid);
}

// Test all possible SSB position within a given band returned by the config generator.
TEST(ssb_freq_position_generation_test, band_41)
{
  unsigned           dl_arfcn   = 520002;
  nr_band            nr_band    = nr_band::n41;
  unsigned           n_rbs      = 52;
  subcarrier_spacing scs_common = subcarrier_spacing::kHz15;
  subcarrier_spacing scs_ssb    = subcarrier_spacing::kHz15;

  ssb_freq_position_generator cfg_generator{dl_arfcn, nr_band, n_rbs, scs_common, scs_ssb};

  ssb_freq_location expected{true, 5, 8};
  ssb_freq_location test = cfg_generator.get_next_ssb_location();
  ASSERT_TRUE(compare_ssb_freq_location(expected, test));
  ASSERT_TRUE(verify_ssb_is_within_ch_band(dl_arfcn, n_rbs, scs_common, test.ss_ref, scs_ssb));

  // Get next SSB position and verify its position in terms of offsetToPointA and k_SSB.
  expected.offset_to_point_A = 12;
  expected.k_ssb             = 4;
  test                       = cfg_generator.get_next_ssb_location();
  ASSERT_TRUE(compare_ssb_freq_location(expected, test));
  ASSERT_TRUE(verify_ssb_is_within_ch_band(dl_arfcn, n_rbs, scs_common, test.ss_ref, scs_ssb));

  expected.offset_to_point_A = 19;
  expected.k_ssb             = 0;
  test                       = cfg_generator.get_next_ssb_location();
  ASSERT_TRUE(compare_ssb_freq_location(expected, test));
  ASSERT_TRUE(verify_ssb_is_within_ch_band(dl_arfcn, n_rbs, scs_common, test.ss_ref, scs_ssb));

  expected.offset_to_point_A = 25;
  expected.k_ssb             = 8;
  test                       = cfg_generator.get_next_ssb_location();
  ASSERT_TRUE(compare_ssb_freq_location(expected, test));
  ASSERT_TRUE(verify_ssb_is_within_ch_band(dl_arfcn, n_rbs, scs_common, test.ss_ref, scs_ssb));

  // Verify there are no possible SSB positions within the band.
  ASSERT_FALSE(cfg_generator.get_next_ssb_location().is_valid);
}

// Test all possible SSB position within a given band returned by the config generator.
TEST(ssb_freq_position_generation_test, band_41_different_scs)
{
  unsigned           dl_arfcn   = 520008;
  nr_band            nr_band    = nr_band::n41;
  unsigned           n_rbs      = 38;
  subcarrier_spacing scs_common = subcarrier_spacing::kHz30;
  subcarrier_spacing scs_ssb    = subcarrier_spacing::kHz15;

  ssb_freq_position_generator cfg_generator{dl_arfcn, nr_band, n_rbs, scs_common, scs_ssb};

  ssb_freq_location expected{true, 4, 2};
  ssb_freq_location test = cfg_generator.get_next_ssb_location();
  ASSERT_TRUE(compare_ssb_freq_location(expected, test));
  ASSERT_TRUE(verify_ssb_is_within_ch_band(dl_arfcn, n_rbs, scs_common, test.ss_ref, scs_ssb));

  // Get next SSB position and verify its position in terms of offsetToPointA and k_SSB.
  expected.offset_to_point_A = 10;
  expected.k_ssb             = 10;
  test                       = cfg_generator.get_next_ssb_location();
  ASSERT_TRUE(compare_ssb_freq_location(expected, test));
  ASSERT_TRUE(verify_ssb_is_within_ch_band(dl_arfcn, n_rbs, scs_common, test.ss_ref, scs_ssb));

  expected.offset_to_point_A = 16;
  expected.k_ssb             = 18;
  test                       = cfg_generator.get_next_ssb_location();
  ASSERT_TRUE(compare_ssb_freq_location(expected, test));
  ASSERT_TRUE(verify_ssb_is_within_ch_band(dl_arfcn, n_rbs, scs_common, test.ss_ref, scs_ssb));

  expected.offset_to_point_A = 24;
  expected.k_ssb             = 2;
  test                       = cfg_generator.get_next_ssb_location();
  ASSERT_TRUE(compare_ssb_freq_location(expected, test));
  ASSERT_TRUE(verify_ssb_is_within_ch_band(dl_arfcn, n_rbs, scs_common, test.ss_ref, scs_ssb));

  expected.offset_to_point_A = 30;
  expected.k_ssb             = 10;
  test                       = cfg_generator.get_next_ssb_location();
  ASSERT_TRUE(compare_ssb_freq_location(expected, test));
  ASSERT_TRUE(verify_ssb_is_within_ch_band(dl_arfcn, n_rbs, scs_common, test.ss_ref, scs_ssb));

  expected.offset_to_point_A = 36;
  expected.k_ssb             = 18;
  test                       = cfg_generator.get_next_ssb_location();
  ASSERT_TRUE(compare_ssb_freq_location(expected, test));
  ASSERT_TRUE(verify_ssb_is_within_ch_band(dl_arfcn, n_rbs, scs_common, test.ss_ref, scs_ssb));

  expected.offset_to_point_A = 44;
  expected.k_ssb             = 2;
  test                       = cfg_generator.get_next_ssb_location();
  ASSERT_TRUE(compare_ssb_freq_location(expected, test));
  ASSERT_TRUE(verify_ssb_is_within_ch_band(dl_arfcn, n_rbs, scs_common, test.ss_ref, scs_ssb));

  expected.offset_to_point_A = 50;
  expected.k_ssb             = 10;
  test                       = cfg_generator.get_next_ssb_location();
  ASSERT_TRUE(compare_ssb_freq_location(expected, test));
  ASSERT_TRUE(verify_ssb_is_within_ch_band(dl_arfcn, n_rbs, scs_common, test.ss_ref, scs_ssb));

  // Verify there are no possible SSB positions within the band.
  ASSERT_FALSE(cfg_generator.get_next_ssb_location().is_valid);
}

// Test all possible SSB position within a given band returned by the config generator.
TEST(ssb_freq_position_generation_test, band_66)
{
  unsigned           dl_arfcn   = 435740;
  nr_band            nr_band    = nr_band::n66;
  unsigned           n_rbs      = 51;
  subcarrier_spacing scs_common = subcarrier_spacing::kHz30;
  subcarrier_spacing scs_ssb    = subcarrier_spacing::kHz30;

  ssb_freq_position_generator cfg_generator{dl_arfcn, nr_band, n_rbs, scs_common, scs_ssb};

  ssb_freq_location expected{true, 0, 22};
  ssb_freq_location test = cfg_generator.get_next_ssb_location();
  ASSERT_TRUE(compare_ssb_freq_location(expected, test));
  ASSERT_TRUE(verify_ssb_is_within_ch_band(dl_arfcn, n_rbs, scs_common, test.ss_ref, scs_ssb));

  // Get next SSB position(s) and verify its position in terms of offsetToPointA and k_SSB.
  expected.offset_to_point_A = 8;
  expected.k_ssb             = 6;
  test                       = cfg_generator.get_next_ssb_location();
  ASSERT_TRUE(compare_ssb_freq_location(expected, test));
  ASSERT_TRUE(verify_ssb_is_within_ch_band(dl_arfcn, n_rbs, scs_common, test.ss_ref, scs_ssb));

  expected.offset_to_point_A = 14;
  expected.k_ssb             = 14;
  test                       = cfg_generator.get_next_ssb_location();
  ASSERT_TRUE(compare_ssb_freq_location(expected, test));
  ASSERT_TRUE(verify_ssb_is_within_ch_band(dl_arfcn, n_rbs, scs_common, test.ss_ref, scs_ssb));

  expected.offset_to_point_A = 20;
  expected.k_ssb             = 22;
  test                       = cfg_generator.get_next_ssb_location();
  ASSERT_TRUE(compare_ssb_freq_location(expected, test));
  ASSERT_TRUE(verify_ssb_is_within_ch_band(dl_arfcn, n_rbs, scs_common, test.ss_ref, scs_ssb));

  expected.offset_to_point_A = 28;
  expected.k_ssb             = 6;
  test                       = cfg_generator.get_next_ssb_location();
  ASSERT_TRUE(compare_ssb_freq_location(expected, test));
  ASSERT_TRUE(verify_ssb_is_within_ch_band(dl_arfcn, n_rbs, scs_common, test.ss_ref, scs_ssb));

  expected.offset_to_point_A = 34;
  expected.k_ssb             = 14;
  test                       = cfg_generator.get_next_ssb_location();
  ASSERT_TRUE(compare_ssb_freq_location(expected, test));
  ASSERT_TRUE(verify_ssb_is_within_ch_band(dl_arfcn, n_rbs, scs_common, test.ss_ref, scs_ssb));

  expected.offset_to_point_A = 40;
  expected.k_ssb             = 22;
  test                       = cfg_generator.get_next_ssb_location();
  ASSERT_TRUE(compare_ssb_freq_location(expected, test));
  ASSERT_TRUE(verify_ssb_is_within_ch_band(dl_arfcn, n_rbs, scs_common, test.ss_ref, scs_ssb));

  expected.offset_to_point_A = 48;
  expected.k_ssb             = 6;
  test                       = cfg_generator.get_next_ssb_location();
  ASSERT_TRUE(compare_ssb_freq_location(expected, test));
  ASSERT_TRUE(verify_ssb_is_within_ch_band(dl_arfcn, n_rbs, scs_common, test.ss_ref, scs_ssb));

  expected.offset_to_point_A = 54;
  expected.k_ssb             = 14;
  test                       = cfg_generator.get_next_ssb_location();
  ASSERT_TRUE(compare_ssb_freq_location(expected, test));
  ASSERT_TRUE(verify_ssb_is_within_ch_band(dl_arfcn, n_rbs, scs_common, test.ss_ref, scs_ssb));

  expected.offset_to_point_A = 60;
  expected.k_ssb             = 22;
  test                       = cfg_generator.get_next_ssb_location();
  ASSERT_TRUE(compare_ssb_freq_location(expected, test));
  ASSERT_TRUE(verify_ssb_is_within_ch_band(dl_arfcn, n_rbs, scs_common, test.ss_ref, scs_ssb));

  // Verify there are no possible SSB positions within the band.
  ASSERT_FALSE(cfg_generator.get_next_ssb_location().is_valid);
}

// ============= Test Generation of CORESET#0 index based on SSB and SearchSpace#0 Index. ==============

struct cset0_test_params {
  optional<unsigned> expected_cset0_idx;

  nr_band               band;
  unsigned              n_rbs;
  subcarrier_spacing    scs_common;
  subcarrier_spacing    scs_ssb;
  ssb_offset_to_pointA  offset_to_point_A;
  ssb_subcarrier_offset k_ssb;
  uint8_t               ssb_first_symbol;
  uint8_t               ss0_idx;
  optional<unsigned>    nof_coreset0_symb;

  optional<unsigned> get_coreset0_index()
  {
    return band_helper::get_coreset0_index(
        band, n_rbs, scs_common, scs_ssb, offset_to_point_A, k_ssb, ssb_first_symbol, ss0_idx, nof_coreset0_symb);
  }
};

class coreset0_index_generation_test : public ::testing::TestWithParam<cset0_test_params>
{};

TEST_P(coreset0_index_generation_test, coreset0_params_are_valid)
{
  cset0_test_params  params    = GetParam();
  optional<unsigned> cset0_idx = params.get_coreset0_index();
  ASSERT_EQ(params.expected_cset0_idx, cset0_idx);
}

using scs_t = subcarrier_spacing;

INSTANTIATE_TEST_SUITE_P(
    coreset0_index_suite,
    coreset0_index_generation_test,
    testing::Values( // clang-format off
//            cset_idx0 |  band  | n_rb | scs_common |  scs_ssb   | OffPtA | k_ssb | ssb_symb | ss0_idx | cset0_nof_symb
  cset0_test_params{2,  nr_band::n3, 52, scs_t::kHz15, scs_t::kHz15,   5,      2,      2,         0,       {}},
  cset0_test_params{0,  nr_band::n7, 25, scs_t::kHz15, scs_t::kHz15,   0,      0,      2,         0,       {}},
  cset0_test_params{12, nr_band::n7, 106, scs_t::kHz15, scs_t::kHz15, 38,      6,      2,         0,       1}
)); // clang-format on

/*
 *      =====    TEST GENERATION OF SSB AND CORESET0 POSITIONS WITHIN THE BAND    =====
 */

struct test_params {
  optional<band_helper::ssb_coreset0_freq_location> expected_result;
  cfg_gen_input_params                              input_params;
};

class ssb_coreset0_param_generator_test : public ::testing::TestWithParam<test_params>
{
protected:
};

// Test whether the position of SSB and Coreset0/SS0 indices are correctly generated.
TEST_P(ssb_coreset0_param_generator_test, test_du_ssb_coreset0_idx)
{
  test_params                                       params = GetParam();
  optional<band_helper::ssb_coreset0_freq_location> ssb_coreset0_alloc =
      params.input_params.generate_ssb_coreset0_location();
  ASSERT_EQ(params.expected_result, ssb_coreset0_alloc);
}

INSTANTIATE_TEST_SUITE_P(
    du_ssb_coreset0_idx,
    ssb_coreset0_param_generator_test,
    testing::Values(
        test_params{
            band_helper::ssb_coreset0_freq_location{18, 6, 365090, 9, 0},
            cfg_gen_input_params{365000, nr_band::n3, 52, subcarrier_spacing::kHz15, subcarrier_spacing::kHz15}},
        test_params{
            band_helper::ssb_coreset0_freq_location{0, 0, 531630, 0, 0},
            cfg_gen_input_params{531720, nr_band::n7, 25, subcarrier_spacing::kHz15, subcarrier_spacing::kHz15}},
        test_params{
            band_helper::ssb_coreset0_freq_location{8, 7, 643296, 3, 0},
            cfg_gen_input_params{643265, nr_band::n78, 52, subcarrier_spacing::kHz15, subcarrier_spacing::kHz30}},
        test_params{
            band_helper::ssb_coreset0_freq_location{28, 6, 435650, 14, 0},
            cfg_gen_input_params{435740, nr_band::n66, 51, subcarrier_spacing::kHz30, subcarrier_spacing::kHz30}},
        test_params{
            band_helper::ssb_coreset0_freq_location{14, 18, 390730, 2, 0},
            cfg_gen_input_params{391180, nr_band::n25, 38, subcarrier_spacing::kHz30, subcarrier_spacing::kHz15}}));

/*
 *      =====    TEST SSB IS WITHIN SYNC RASTER AND CORESET0 IS WITHIN THE BAND    =====
 */

class ssb_coreset0_compatibility_with_raster_and_band : public ::testing::TestWithParam<cfg_gen_input_params>
{
protected:
};

// Test whether the SSB f_ref correspond to sync raster and Coreset0 is within the band.
TEST_P(ssb_coreset0_compatibility_with_raster_and_band, test_ssb_raster_and_cset0_band)
{
  cfg_gen_input_params                              input_params       = GetParam();
  optional<band_helper::ssb_coreset0_freq_location> ssb_coreset0_alloc = input_params.generate_ssb_coreset0_location();

  // This function test the SSB and CORESET0 allocation consitency.
  test_ssb_coreset0_allocation(input_params.dl_arfcn,
                               input_params.band,
                               input_params.n_rbs,
                               input_params.scs_common,
                               input_params.scs_ssb,
                               ssb_coreset0_alloc.value());
}

INSTANTIATE_TEST_SUITE_P(
    ssb_raster_and_cset0_band,
    ssb_coreset0_compatibility_with_raster_and_band,
    testing::Values(
        cfg_gen_input_params{365000, nr_band::n3, 52, subcarrier_spacing::kHz15, subcarrier_spacing::kHz15, 0},
        cfg_gen_input_params{531720, nr_band::n7, 25, subcarrier_spacing::kHz15, subcarrier_spacing::kHz15, 0},
        cfg_gen_input_params{643265, nr_band::n78, 52, subcarrier_spacing::kHz15, subcarrier_spacing::kHz30, 0},
        cfg_gen_input_params{435740, nr_band::n66, 51, subcarrier_spacing::kHz30, subcarrier_spacing::kHz30, 0},
        cfg_gen_input_params{391180, nr_band::n25, 38, subcarrier_spacing::kHz30, subcarrier_spacing::kHz15, 0}));