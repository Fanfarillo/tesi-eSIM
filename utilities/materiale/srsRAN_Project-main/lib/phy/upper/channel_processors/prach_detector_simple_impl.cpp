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

#include "prach_detector_simple_impl.h"
#include "srsran/ran/prach/prach_cyclic_shifts.h"
#include "srsran/ran/prach/prach_preamble_information.h"
#include "srsran/srsvec/compare.h"
#include "srsran/srsvec/dot_prod.h"
#include "srsran/srsvec/prod.h"
#include "srsran/srsvec/zero.h"
#include "srsran/support/error_handling.h"
#include "srsran/support/math_utils.h"

using namespace srsran;

prach_detection_result prach_detector_simple_impl::detect(const prach_buffer& input, const configuration& config)
{
  srsran_assert(config.start_preamble_index + config.nof_preamble_indices <= prach_constants::MAX_NUM_PREAMBLES,
                "The start preamble index {} and the number of preambles to detect {}, exceed the maximum of 64.",
                config.start_preamble_index,
                config.nof_preamble_indices);

  // Retrieve preamble configuration.
  prach_preamble_information preamble_info = get_prach_preamble_long_info(config.format);

  // Verify sequence lengths match.
  srsran_assert(input.get_sequence_length() == preamble_info.sequence_length,
                "The input buffer sequence length {} is not equal to the expected preamble sequence length {}.",
                input.get_sequence_length(),
                preamble_info.sequence_length);
  unsigned sequence_length_lower = preamble_info.sequence_length / 2;
  unsigned sequence_length_upper = preamble_info.sequence_length - sequence_length_lower;

  // Derive time domain sampling rate in Hz.
  unsigned sampling_rate_Hz = preamble_info.scs.to_Hz() * idft->get_size();

  // Get cyclic shift.
  unsigned N_cs = prach_cyclic_shifts_get(preamble_info.scs, config.restricted_set, config.zero_correlation_zone);
  srsran_assert(N_cs != PRACH_CYCLIC_SHIFTS_RESERVED, "Reserved cyclic shift.");

  // Calculate maximum delay due to the cyclic prefix.
  phy_time_unit time_advance_max = preamble_info.cp_length;

  // If the cyclic shift is not zero...
  if (N_cs != 0) {
    // Calculate the maximum time in advance limited by the number of cyclic shifts.
    phy_time_unit N_cs_time =
        phy_time_unit::from_seconds(static_cast<double>((N_cs * preamble_info.sequence_length) / idft->get_size()) /
                                    static_cast<double>(sampling_rate_Hz));
    // Select the most limiting value.
    time_advance_max = std::min(time_advance_max, N_cs_time);
  }
  unsigned delay_n_maximum = time_advance_max.to_samples(sampling_rate_Hz);

  // Segment the IDFT input into lower grid, upper grid and guard.
  span<cf_t> idft_lower_grid = idft->get_input().last(sequence_length_lower);
  span<cf_t> idft_upper_grid = idft->get_input().first(sequence_length_upper);
  span<cf_t> idft_guard =
      idft->get_input().subspan(sequence_length_upper, idft->get_size() - preamble_info.sequence_length);

  // Set the IDFT guard to zero.
  srsvec::zero(idft_guard);

  // Calculate RSSI.
  float rssi = srsvec::average_power(input.get_symbol(0));

  // Prepare results.
  prach_detection_result result;
  result.rssi_dB          = convert_power_to_dB(rssi);
  result.time_resolution  = phy_time_unit::from_seconds(1.0 / static_cast<double>(sampling_rate_Hz));
  result.time_advance_max = time_advance_max;
  result.preambles.clear();

  // Early stop if the RSSI is zero.
  if (!std::isnormal(rssi)) {
    return result;
  }

  // For each preamble to detect...
  for (unsigned preamble_index     = config.start_preamble_index,
                preamble_index_end = config.start_preamble_index + config.nof_preamble_indices;
       preamble_index != preamble_index_end;
       ++preamble_index) {
    // Generate preamble.
    prach_generator::configuration preamble_config;
    preamble_config.format                = config.format;
    preamble_config.root_sequence_index   = config.root_sequence_index;
    preamble_config.preamble_index        = preamble_index;
    preamble_config.restricted_set        = config.restricted_set;
    preamble_config.zero_correlation_zone = config.zero_correlation_zone;
    span<const cf_t> preamble_freq        = generator->generate(preamble_config);

    // Measure input signal power. Make sure an invalid power does not propagate.
    float preamble_power = srsvec::average_power(preamble_freq);
    report_fatal_error_if_not(std::isnormal(preamble_power), "Corrupted generated signal.");

    // Select first symbol in the buffer.
    span<const cf_t> signal_freq = input.get_symbol(0);

    // Perform correlation in frequency-domain and store the result in the IDFT input.
    srsvec::prod_conj(
        signal_freq.first(sequence_length_lower), preamble_freq.first(sequence_length_lower), idft_lower_grid);
    srsvec::prod_conj(
        signal_freq.last(sequence_length_upper), preamble_freq.last(sequence_length_upper), idft_upper_grid);

    // Convert the correlation to the time domain.
    span<const cf_t> correlation = idft->run();

    // Find delay and power of the maximum absolute value.
    std::pair<unsigned, float> max_abs   = srsvec::max_abs_element(correlation);
    unsigned                   delay_n   = max_abs.first;
    float                      max_power = max_abs.second;

    // Check if the maximum value gets over the threshold.
    float norm_corr = max_power / (rssi * preamble_power * preamble_freq.size() * preamble_freq.size());
    if (norm_corr < DETECTION_THRESHOLD) {
      continue;
    }

    // Detect delay sign.
    float sign = 1.0f;
    if (delay_n > idft->get_size() / 2) {
      sign    = -1.0f;
      delay_n = idft->get_size() - delay_n;
    }

    // Skip if the delay could be due to the cyclic shift.
    if (delay_n >= delay_n_maximum) {
      continue;
    }

    prach_detection_result::preamble_indication& info = result.preambles.emplace_back();
    info.preamble_index                               = preamble_index;
    info.time_advance =
        phy_time_unit::from_seconds(sign * static_cast<double>(delay_n) / static_cast<double>(sampling_rate_Hz));
    info.power_dB = convert_power_to_dB(max_power);
    info.snr_dB   = 0.0F;
  }

  return result;
}
