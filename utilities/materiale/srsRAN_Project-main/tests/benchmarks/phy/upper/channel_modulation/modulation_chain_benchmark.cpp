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

#include "srsran/phy/upper/channel_modulation/channel_modulation_factories.h"
#include "srsran/srsvec/bit.h"
#include "srsran/support/benchmark_utils.h"
#include "srsran/support/srsran_test.h"
#include <getopt.h>
#include <random>

// Random generator.
static std::mt19937 rgen(0);

static unsigned nof_repetitions = 1000;
static bool     silent          = false;

static void usage(const char* prog)
{
  fmt::print("Usage: {} [-R repetitions] [-s silent]\n", prog);
  fmt::print("\t-R Repetitions [Default {}]\n", nof_repetitions);
  fmt::print("\t-s Toggle silent operation [Default {}]\n", silent);
  fmt::print("\t-h Show this message\n");
}

static void parse_args(int argc, char** argv)
{
  int opt = 0;
  while ((opt = getopt(argc, argv, "R:sh")) != -1) {
    switch (opt) {
      case 'R':
        nof_repetitions = std::strtol(optarg, nullptr, 10);
        break;
      case 's':
        silent = (!silent);
        break;
      case 'h':
      default:
        usage(argv[0]);
        exit(0);
    }
  }
}

using namespace srsran;

int main(int argc, char** argv)
{
  parse_args(argc, argv);

  std::shared_ptr<channel_modulation_factory> factory = create_channel_modulation_sw_factory();
  TESTASSERT(factory);

  std::unique_ptr<modulation_mapper> modulator = factory->create_modulation_mapper();
  TESTASSERT(modulator);

  std::unique_ptr<demodulation_mapper> demodulator = factory->create_demodulation_mapper();
  TESTASSERT(demodulator);

  std::uniform_int_distribution<uint8_t> bit_dist(0, 1);

  for (modulation_scheme modulation : {modulation_scheme::PI_2_BPSK,
                                       modulation_scheme::BPSK,
                                       modulation_scheme::QPSK,
                                       modulation_scheme::QAM16,
                                       modulation_scheme::QAM64,
                                       modulation_scheme::QAM256}) {
    benchmarker perf_meas_modulator("Modulation mapper " + to_string(modulation), nof_repetitions);
    benchmarker perf_meas_demodulator("Demodulation mapper " + to_string(modulation), nof_repetitions);

    for (unsigned nof_symbols : {1, 123, 256, 512, 1024, 3300, 6600, 38880}) {
      // Calculate number of bytes.
      unsigned nof_bits = nof_symbols * get_bits_per_symbol(modulation);

      std::vector<uint8_t> data(nof_bits);
      std::generate(data.begin(), data.end(), [&]() { return bit_dist(rgen); });

      std::vector<float> noise_var(nof_symbols);
      std::generate(noise_var.begin(), noise_var.end(), [&]() { return 0.00001F; });

      std::vector<cf_t>                 symbols(nof_symbols);
      std::vector<log_likelihood_ratio> soft_bits(nof_bits);

      dynamic_bit_buffer packed_data(nof_bits);
      srsvec::bit_pack(packed_data, data);

      // Measure performance of the modulation mapper.
      perf_meas_modulator.new_measure(
          std::to_string(nof_symbols), nof_bits, [&]() { modulator->modulate(symbols, packed_data, modulation); });

      // Measure performance of the demodulation mapper.
      perf_meas_demodulator.new_measure(std::to_string(nof_symbols), nof_bits, [&]() {
        demodulator->demodulate_soft(soft_bits, symbols, noise_var, modulation);
      });
    }
    if (!silent) {
      perf_meas_modulator.print_percentiles_throughput("bits");
      perf_meas_demodulator.print_percentiles_throughput("bits");
    }
  }
}
