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
#include "../signal_processors/dmrs_pdsch_processor_test_doubles.h"
#include "pdsch_encoder_test_doubles.h"
#include "pdsch_modulator_test_doubles.h"
#include "srsran/phy/upper/channel_processors/channel_processor_factories.h"
#include "srsran/phy/upper/channel_processors/pdsch_processor.h"
#include "srsran/srsvec/compare.h"
#include "srsran/support/srsran_test.h"
#include <random>

using namespace srsran;

int main()
{
  static const std::array<modulation_scheme, 5> modulations = {
      modulation_scheme::QPSK, modulation_scheme::QAM16, modulation_scheme::QAM64, modulation_scheme::QAM256};
  std::mt19937                            rgen(1234);
  std::uniform_int_distribution<uint8_t>  dist_payload(0, UINT8_MAX);
  std::uniform_int_distribution<uint8_t>  dist_bool(0, 1);
  std::uniform_int_distribution<unsigned> dist_u16(0, UINT16_MAX);
  std::uniform_int_distribution<unsigned> dist_start_symb(0, 1);
  std::uniform_int_distribution<unsigned> dist_rv(0, 3);
  std::uniform_int_distribution<unsigned> dist_mod(0, modulations.size() - 1);
  std::uniform_real_distribution<float>   dist_power(-6, 6);

  std::shared_ptr<pdsch_encoder_factory_spy>   encoder_factory_spy   = std::make_shared<pdsch_encoder_factory_spy>();
  std::shared_ptr<pdsch_modulator_factory_spy> modulator_factory_spy = std::make_shared<pdsch_modulator_factory_spy>();
  std::shared_ptr<dmrs_pdsch_processor_factory_spy> dmrs_factory_spy =
      std::make_shared<dmrs_pdsch_processor_factory_spy>();

  std::shared_ptr<pdsch_processor_factory> pdsch_proc_factory =
      create_pdsch_processor_factory_sw(std::shared_ptr<pdsch_encoder_factory>(encoder_factory_spy),
                                        std::shared_ptr<pdsch_modulator_factory>(modulator_factory_spy),
                                        std::shared_ptr<dmrs_pdsch_processor_factory>(dmrs_factory_spy));
  TESTASSERT(pdsch_proc_factory);

  std::unique_ptr<pdsch_processor> pdsch = pdsch_proc_factory->create();
  TESTASSERT(pdsch);

  pdsch_encoder_spy*        encoder_spy   = encoder_factory_spy->get_entries().front();
  pdsch_modulator_spy*      modulator_spy = modulator_factory_spy->get_entries().front();
  dmrs_pdsch_processor_spy* dmrs_spy      = dmrs_factory_spy->get_entries().front();

  for (unsigned nof_layers : {1}) {
    for (cyclic_prefix cp : {cyclic_prefix::NORMAL, cyclic_prefix::EXTENDED}) {
      for (dmrs_type dmrs_type_value : {dmrs_type::TYPE1}) {
        unsigned nof_codewords    = (nof_layers > 4) ? 2 : 1;
        unsigned nof_symbols_slot = get_nsymb_per_slot(cp);

        // Prepare PDSCH PDU.
        pdsch_processor::pdu_t pdu;
        pdu.slot         = {0, 0};
        pdu.rnti         = 0x1234;
        pdu.bwp_size_rb  = 52;
        pdu.bwp_start_rb = 1;
        pdu.cp           = cp;
        for (unsigned codeword = 0; codeword != nof_codewords; ++codeword) {
          pdu.codewords.emplace_back();
          pdu.codewords.back().modulation = modulations[dist_mod(rgen)];
          pdu.codewords.back().rv         = dist_rv(rgen);
        }
        pdu.n_id = 0;
        for (unsigned layer = 0; layer != nof_layers; ++layer) {
          pdu.ports.emplace_back(layer);
        }
        pdu.ref_point        = dist_bool(rgen) ? pdsch_processor::pdu_t::PRB0 : pdsch_processor::pdu_t::CRB0;
        pdu.dmrs_symbol_mask = symbol_slot_mask(nof_symbols_slot);
        pdu.dmrs_symbol_mask.set(2, static_cast<bool>(dist_bool(rgen)));
        pdu.dmrs_symbol_mask.set(7, static_cast<bool>(dist_bool(rgen)));
        pdu.dmrs_symbol_mask.set(11, static_cast<bool>(dist_bool(rgen)));
        pdu.dmrs                        = dmrs_type_value;
        pdu.scrambling_id               = dist_u16(rgen);
        pdu.n_scid                      = static_cast<bool>(dist_bool(rgen));
        pdu.nof_cdm_groups_without_data = 1;
        pdu.freq_alloc                  = rb_allocation::make_custom({1, 2, 3, 4});
        pdu.start_symbol_index          = dist_start_symb(rgen);
        pdu.nof_symbols                 = get_nsymb_per_slot(cp) - pdu.start_symbol_index;
        pdu.ldpc_base_graph             = static_cast<ldpc_base_graph_type>(dist_bool(rgen));
        pdu.tbs_lbrm_bytes              = ldpc::MAX_CODEBLOCK_SIZE / 8;
        pdu.reserved                    = {};
        pdu.ratio_pdsch_dmrs_to_sss_dB  = dist_power(rgen);
        pdu.ratio_pdsch_data_to_sss_dB  = dist_power(rgen);

        // Generate reserved element pattern for DMRS.
        re_pattern dmrs_reserved_pattern = pdu.dmrs.get_dmrs_pattern(
            pdu.bwp_start_rb, pdu.bwp_size_rb, pdu.nof_cdm_groups_without_data, pdu.dmrs_symbol_mask);

        // Create overall reserved pattern.
        re_pattern_list reserved = pdu.reserved;
        reserved.merge(dmrs_reserved_pattern);

        // Get physical RB allocation mask.
        bounded_bitset<MAX_RB> rb_mask = pdu.freq_alloc.get_prb_mask(pdu.bwp_start_rb, pdu.bwp_size_rb);

        // Count number of resource elements.
        unsigned Nre = pdu.freq_alloc.get_nof_rb() * NRE * pdu.nof_symbols -
                       reserved.get_inclusion_count(pdu.start_symbol_index, pdu.nof_symbols, rb_mask);

        static_vector<span<const uint8_t>, pdsch_processor::MAX_NOF_TRANSPORT_BLOCKS> data;

        // Generate random data and prepare TB.
        std::vector<uint8_t> data0(16);
        for (uint8_t& byte : data0) {
          byte = dist_payload(rgen);
        }
        data.emplace_back(data0);

        std::vector<uint8_t> data1(32);
        if (nof_codewords > 1) {
          for (uint8_t& byte : data1) {
            byte = dist_payload(rgen);
          }
          data.emplace_back(data1);
        }

        // Use resource grid dummy, the PDSCH processor must not call any method.
        resource_grid_dummy rg_dummy;

        // Reset spies.
        encoder_spy->reset();
        modulator_spy->reset();
        dmrs_spy->reset();

        // Process PDU.
        pdsch->process(rg_dummy, data, pdu);

        unsigned nof_layers_cw0 = nof_layers / nof_codewords;
        unsigned nof_layers_cw1 = nof_layers - nof_layers_cw0;

        // Validate encoder.
        {
          TESTASSERT_EQ(encoder_spy->get_nof_entries(), nof_codewords);
          const auto& entries = encoder_spy->get_entries();
          for (unsigned codeword = 0; codeword != nof_codewords; ++codeword) {
            const auto& entry = entries[codeword];
            TESTASSERT_EQ(entry.config.base_graph, pdu.ldpc_base_graph);
            TESTASSERT_EQ(entry.config.rv, pdu.codewords[codeword].rv);
            TESTASSERT_EQ(entry.config.mod, pdu.codewords[codeword].modulation);
            TESTASSERT_EQ(entry.config.Nref, pdu.tbs_lbrm_bytes * 8);
            TESTASSERT_EQ(entry.config.nof_layers, codeword == 0 ? nof_layers_cw0 : nof_layers_cw1);
            TESTASSERT_EQ(entry.config.nof_ch_symbols, Nre);
            TESTASSERT(srsvec::equal(entry.transport_block, data[codeword]));
          }
        }

        // Validate modulator.
        {
          TESTASSERT_EQ(modulator_spy->get_nof_entries(), 1);
          const auto& entries = modulator_spy->get_entries();
          const auto& entry   = entries.front();
          TESTASSERT_EQ(entry.config.rnti, pdu.rnti);
          TESTASSERT_EQ(entry.config.bwp_size_rb, pdu.bwp_size_rb);
          TESTASSERT_EQ(entry.config.bwp_start_rb, pdu.bwp_start_rb);
          TESTASSERT_EQ(entry.config.modulation1, pdu.codewords[0].modulation);
          if (nof_layers > 4) {
            TESTASSERT_EQ(entry.config.modulation2, pdu.codewords[1].modulation);
          }
          TESTASSERT(entry.config.freq_allocation == pdu.freq_alloc);
          TESTASSERT_EQ(entry.config.start_symbol_index, pdu.start_symbol_index);
          TESTASSERT_EQ(entry.config.nof_symbols, pdu.nof_symbols);
          TESTASSERT_EQ(entry.config.n_id, pdu.n_id);
          TESTASSERT(std::abs(entry.config.scaling - convert_dB_to_amplitude(-pdu.ratio_pdsch_data_to_sss_dB)) < 1e-6);
          TESTASSERT(entry.config.reserved == pdu.reserved);
          TESTASSERT(entry.config.ports == pdu.ports);
          TESTASSERT(entry.grid_ptr == &rg_dummy);
          for (unsigned codeword = 0; codeword != nof_codewords; ++codeword) {
            span<const uint8_t> codeword_encoder   = encoder_spy->get_entries()[codeword].codeword;
            const bit_buffer    codeword_modulator = entry.codewords[codeword];
            for (unsigned i_bit = 0, i_bit_end = codeword_encoder.size(); i_bit != i_bit_end; ++i_bit) {
              TESTASSERT(codeword_encoder[i_bit] == codeword_modulator.extract(i_bit, 1));
            }
          }
        }

        // Validate DMRS processor.
        {
          TESTASSERT_EQ(dmrs_spy->get_nof_entries(), 1);
          const auto& entries = dmrs_spy->get_entries();
          auto&       entry   = entries.front();
          TESTASSERT_EQ(entry.config.slot, pdu.slot);
          TESTASSERT_EQ(entry.config.reference_point_k_rb,
                        (pdu.ref_point == pdsch_processor::pdu_t::PRB0) ? pdu.bwp_start_rb : 0);
          TESTASSERT(entry.config.type == pdu.dmrs);
          TESTASSERT_EQ(entry.config.scrambling_id, pdu.scrambling_id);
          TESTASSERT_EQ(entry.config.n_scid, pdu.n_scid);
          TESTASSERT(std::abs(entry.config.amplitude - convert_dB_to_amplitude(-pdu.ratio_pdsch_dmrs_to_sss_dB)) <
                     1e-6);
          TESTASSERT(entry.config.symbols_mask == pdu.dmrs_symbol_mask);
          TESTASSERT(entry.config.rb_mask == rb_mask);
          TESTASSERT(srsvec::equal(entry.config.ports, pdu.ports));
          TESTASSERT(entry.grid == &rg_dummy);
          ;
        }
      }
    }
  }

  return 0;
}