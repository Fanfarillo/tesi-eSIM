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

#include "../../support/resource_grid_test_doubles.h"
#include "srsran/phy/upper/channel_processors/channel_processor_factories.h"
#include "srsran/phy/upper/channel_processors/channel_processor_formatters.h"
#include "srsran/phy/upper/equalization/equalization_factories.h"
#include "srsran/ran/pucch/pucch_constants.h"
#include "fmt/ostream.h"
#include "gtest/gtest.h"

using namespace srsran;

namespace {

// Maximum channel dimensions used to construct the PUCCH processor.
channel_estimate::channel_estimate_dimensions max_dimensions = {MAX_RB,
                                                                MAX_NSYMB_PER_SLOT - 1,
                                                                1,
                                                                pucch_constants::MAX_LAYERS};

// Maximum number of UCI payload bits supported by the current PUCCH Format 2 implementation.
constexpr unsigned PUCCH_F2_IMPL_MAX_NBITS = 11;

// Valid PUCCH Format 2 configuration.
const pucch_processor::format2_configuration base_format_2_config = {
    // Context.
    nullopt,
    // Slot.
    {0, 9},
    // CP.
    cyclic_prefix::NORMAL,
    // Rx Ports.
    {0},
    // BWP size.
    50,
    // BWP start.
    10,
    // Starting PRB.
    1,
    // Second hop PRB.
    {},
    // Number of PRB.
    10,
    // Start symbol index.
    12,
    // Number of OFDM symbols.
    1,
    // RNTI.
    65535,
    // N_ID.
    0,
    // N_ID_0.
    0,
    // Number of HARQ-ACK bits.
    pucch_constants::FORMAT2_MIN_UCI_NBITS,
    // Number of SR bits.
    0,
    // Number of CSI Part 1 bits.
    0,
    // Number of CSI Part 2 bits.
    0};

// Test case parameters structure.
struct test_params {
  pucch_processor::format2_configuration config;
  std::string                            assert_message;
};

struct test_case_t {
  std::function<test_params()> get_test_params;
};

std::ostream& operator<<(std::ostream& os, const test_case_t& test_case)
{
  fmt::print(os, "{}", test_case.get_test_params().config);
  return os;
}

// Test cases are implemented as lambda functions that generate and return an invalid PUCCH Format 2 configuration,
// along with the expected assert message.
const std::vector<test_case_t> pucch_processor_validator_test_data = {
    {
        [] {
          test_params entry         = {};
          entry.config              = base_format_2_config;
          entry.config.bwp_start_rb = 10;
          entry.config.bwp_size_rb  = MAX_RB - entry.config.bwp_start_rb + 1;
          entry.assert_message      = fmt::format(
              R"(BWP allocation goes up to PRB {}\, exceeding the configured maximum grid RB size\, i\.e\.\, {}\.)",
              entry.config.bwp_start_rb + entry.config.bwp_size_rb,
              MAX_RB);
          return entry;
        },
    },
    {
        [] {
          test_params entry         = {};
          entry.config              = base_format_2_config;
          entry.config.starting_prb = entry.config.bwp_size_rb - entry.config.nof_prb + 1;
          entry.assert_message =
              fmt::format(R"(PRB allocation within the BWP goes up to PRB {}\, exceeding BWP size\, i\.e\.\, {}\.)",
                          entry.config.starting_prb + entry.config.nof_prb,
                          entry.config.bwp_size_rb);
          return entry;
        },
    },
    {
        [] {
          test_params entry               = {};
          entry.config                    = base_format_2_config;
          entry.config.start_symbol_index = get_nsymb_per_slot(entry.config.cp) - entry.config.nof_symbols + 1;
          entry.assert_message            = fmt::format(
              R"(OFDM symbol allocation goes up to symbol {}\, exceeding the number of symbols in the given slot with {} CP\, i\.e\.\, {}\.)",
              entry.config.start_symbol_index + entry.config.nof_symbols,
              entry.config.cp.to_string(),
              get_nsymb_per_slot(entry.config.cp));
          return entry;
        },
    },
    {
        [] {
          test_params entry               = {};
          entry.config                    = base_format_2_config;
          entry.config.cp                 = cyclic_prefix::NORMAL;
          entry.config.nof_symbols        = 1;
          entry.config.start_symbol_index = max_dimensions.nof_symbols;
          entry.assert_message            = fmt::format(
              R"(OFDM symbol allocation goes up to symbol {}\, exceeding the configured maximum number of slot symbols\, i\.e\.\, {}\.)",
              entry.config.start_symbol_index + entry.config.nof_symbols,
              max_dimensions.nof_symbols);
          return entry;
        },
    },
    {
        [] {
          test_params entry    = {};
          entry.config         = base_format_2_config;
          entry.config.ports   = {};
          entry.assert_message = fmt::format(R"(The number of receive ports cannot be zero\.)");
          return entry;
        },
    },
    {
        [] {
          test_params entry    = {};
          entry.config         = base_format_2_config;
          entry.config.ports   = {0, 1};
          entry.assert_message = fmt::format(
              R"(The number of receive ports\, i\.e\. {}\, exceeds the configured maximum number of receive ports\, i\.e\.\, {}\.)",
              entry.config.ports.size(),
              max_dimensions.nof_rx_ports);
          return entry;
        },
    },
    {
        [] {
          test_params entry          = {};
          entry.config               = base_format_2_config;
          entry.config.nof_csi_part2 = 1;
          entry.assert_message       = fmt::format(R"(CSI Part 2 is not currently supported\.)");
          return entry;
        },
    },
    {
        [] {
          test_params entry           = {};
          entry.config                = base_format_2_config;
          entry.config.second_hop_prb = 0;
          entry.assert_message        = fmt::format(R"(PUCCH Format 2 frequency hopping not supported\.)");
          return entry;
        },
    },
    {
        [] {
          test_params entry          = {};
          entry.config               = base_format_2_config;
          entry.config.nof_harq_ack  = pucch_constants::FORMAT2_MIN_UCI_NBITS - 1;
          entry.config.nof_sr        = 0;
          entry.config.nof_csi_part1 = 0;
          entry.config.nof_csi_part2 = 0;
          entry.assert_message       = fmt::format(
              R"(UCI Payload length\, i\.e\.\, {} is not supported\. Payload length must be {} to {} bits\.)",
              entry.config.nof_harq_ack + entry.config.nof_sr + entry.config.nof_csi_part1 + entry.config.nof_csi_part2,
              pucch_constants::FORMAT2_MIN_UCI_NBITS,
              PUCCH_F2_IMPL_MAX_NBITS);
          return entry;
        },
    },
    {
        [] {
          test_params entry         = {};
          entry.config              = base_format_2_config;
          entry.config.nof_harq_ack = uci_constants::MAX_NOF_HARQ_BITS;
          entry.assert_message =
              R"(The effective code rate \(i\.e\., [0-9]*\.[0-9]*) exceeds the maximum allowed 0\.8\.)";
          return entry;
        },
    },
    {
        [] {
          test_params entry          = {};
          entry.config               = base_format_2_config;
          entry.config.nof_harq_ack  = PUCCH_F2_IMPL_MAX_NBITS;
          entry.config.nof_sr        = 1;
          entry.config.nof_csi_part1 = 0;
          entry.config.nof_csi_part2 = 0;
          entry.assert_message       = fmt::format(
              R"(UCI Payload length\, i\.e\.\, {} is not supported\. Payload length must be {} to {} bits\.)",
              entry.config.nof_harq_ack + entry.config.nof_sr + entry.config.nof_csi_part1 + entry.config.nof_csi_part2,
              pucch_constants::FORMAT2_MIN_UCI_NBITS,
              PUCCH_F2_IMPL_MAX_NBITS);
          return entry;
        },
    }};

class PucchProcessorFixture : public ::testing::TestWithParam<test_case_t>
{
protected:
  static std::unique_ptr<pucch_processor>     pucch_proc;
  static std::unique_ptr<pucch_pdu_validator> pucch_validator;

  static void SetUpTestSuite()
  {
    if (!(pucch_proc && pucch_validator)) {
      // Create factories required by the PUCCH demodulator factory.
      std::shared_ptr<channel_equalizer_factory> equalizer_factory = create_channel_equalizer_factory_zf();
      ASSERT_NE(equalizer_factory, nullptr) << "Cannot create equalizer factory.";

      std::shared_ptr<channel_modulation_factory> demod_factory = create_channel_modulation_sw_factory();
      ASSERT_NE(demod_factory, nullptr) << "Cannot create channel modulation factory.";

      std::shared_ptr<pseudo_random_generator_factory> prg_factory = create_pseudo_random_generator_sw_factory();
      ASSERT_NE(prg_factory, nullptr) << "Cannot create pseudo-random generator factory.";

      // Create PUCCH demodulator factory.
      std::shared_ptr<pucch_demodulator_factory> pucch_demod_factory =
          create_pucch_demodulator_factory_sw(equalizer_factory, demod_factory, prg_factory);
      ASSERT_NE(pucch_demod_factory, nullptr) << "Cannot create PUCCH demodulator factory.";

      // Create factories required by the PUCCH channel estimator factory.
      std::shared_ptr<low_papr_sequence_generator_factory> lpg_factory =
          create_low_papr_sequence_generator_sw_factory();
      ASSERT_NE(lpg_factory, nullptr) << "Cannot create low PAPR sequence generator factory.";

      std::shared_ptr<low_papr_sequence_collection_factory> lpc_factory =
          create_low_papr_sequence_collection_sw_factory(lpg_factory);
      ASSERT_NE(lpc_factory, nullptr) << "Cannot create low PAPR sequence collection factory.";

      std::shared_ptr<dft_processor_factory> dft_factory = create_dft_processor_factory_fftw();
      if (!dft_factory) {
        dft_factory = create_dft_processor_factory_generic();
      }
      ASSERT_NE(dft_factory, nullptr) << "Cannot create DFT factory.";

      // Create channel estimator factory.
      std::shared_ptr<port_channel_estimator_factory> port_chan_estimator_factory =
          create_port_channel_estimator_factory_sw(dft_factory);
      ASSERT_NE(port_chan_estimator_factory, nullptr) << "Cannot create port channel estimator factory.";

      std::shared_ptr<dmrs_pucch_estimator_factory> estimator_factory =
          create_dmrs_pucch_estimator_factory_sw(prg_factory, lpc_factory, port_chan_estimator_factory);
      ASSERT_NE(estimator_factory, nullptr) << "Cannot create DM-RS PUCCH estimator factory.";

      // Create PUCCH detector factory.
      std::shared_ptr<pucch_detector_factory> detector_factory =
          create_pucch_detector_factory_sw(lpc_factory, prg_factory, equalizer_factory);
      ASSERT_NE(detector_factory, nullptr) << "Cannot create PUCCH detector factory.";

      // Create UCI decoder factory.
      std::shared_ptr<short_block_detector_factory> short_block_det_factory = create_short_block_detector_factory_sw();
      ASSERT_NE(short_block_det_factory, nullptr) << "Cannot create short block detector factory.";

      uci_decoder_factory_sw_configuration decoder_factory_config = {};
      decoder_factory_config.decoder_factory                      = short_block_det_factory;

      std::shared_ptr<uci_decoder_factory> decoder_factory = create_uci_decoder_factory_sw(decoder_factory_config);
      ASSERT_NE(decoder_factory, nullptr) << "Cannot create UCI decoder factory.";

      // Create PUCCH processor factory.
      std::shared_ptr<pucch_processor_factory> processor_factory = create_pucch_processor_factory_sw(
          estimator_factory, detector_factory, pucch_demod_factory, decoder_factory, max_dimensions);
      ASSERT_NE(processor_factory, nullptr) << "Cannot create PUCCH processor factory.";

      // Create PUCCH processor.
      pucch_proc = processor_factory->create();
      ASSERT_NE(pucch_proc, nullptr) << "Cannot create PUCCH processor.";

      // Create PUCCH processor validator.
      pucch_validator = processor_factory->create_validator();
      ASSERT_NE(pucch_validator, nullptr) << "Cannot create PUCCH validator.";
    }
  }
};

std::unique_ptr<pucch_processor>     PucchProcessorFixture::pucch_proc;
std::unique_ptr<pucch_pdu_validator> PucchProcessorFixture::pucch_validator;

TEST_P(PucchProcessorFixture, PucchProcessorValidatortest)
{
  ASSERT_NE(pucch_proc, nullptr) << "PUCCH processor not created.";
  ASSERT_NE(pucch_validator, nullptr) << "PUCCH validator not created.";

  const test_case_t& param = GetParam();

  // Make sure the configuration is invalid.
  ASSERT_FALSE(pucch_validator->is_valid(param.get_test_params().config));

  // Prepare resource grid.
  resource_grid_reader_spy grid;

  // Process PUCCH PDU.
#ifdef ASSERTS_ENABLED
  ASSERT_DEATH({ pucch_proc->process(grid, param.get_test_params().config); }, param.get_test_params().assert_message);
#endif // ASSERTS_ENABLED
}

// Creates test suite that combines all possible parameters.
INSTANTIATE_TEST_SUITE_P(PucchProcessorValidatortest,
                         PucchProcessorFixture,
                         ::testing::ValuesIn(pucch_processor_validator_test_data));

} // namespace
