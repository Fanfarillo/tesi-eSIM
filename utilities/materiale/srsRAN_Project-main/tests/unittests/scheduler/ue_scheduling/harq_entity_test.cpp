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

#include "lib/scheduler/ue_scheduling/harq_process.h"
#include "srsran/support/test_utils.h"
#include <gtest/gtest.h>

using namespace srsran;

TEST(harq_entity, when_harq_entity_is_created_all_harqs_are_empty)
{
  harq_entity harq_ent(to_rnti(0x4601), 16, 16, 4);

  ASSERT_EQ(harq_ent.nof_dl_harqs(), 16);
  ASSERT_EQ(harq_ent.nof_ul_harqs(), 16);
  ASSERT_NE(harq_ent.find_empty_dl_harq(), nullptr);
  ASSERT_TRUE(harq_ent.find_empty_dl_harq()->empty());
  ASSERT_NE(harq_ent.find_empty_ul_harq(), nullptr);
  ASSERT_TRUE(harq_ent.find_empty_ul_harq()->empty());
  ASSERT_EQ(harq_ent.find_pending_dl_retx(), nullptr);
  ASSERT_EQ(harq_ent.find_pending_ul_retx(), nullptr);
}

TEST(harq_entity, when_all_harqs_are_allocated_harq_entity_cannot_find_empty_harq)
{
  unsigned    nof_harqs = 8;
  harq_entity harq_ent(to_rnti(0x4601), nof_harqs, nof_harqs, 4);
  slot_point  sl_tx{0, 0};
  unsigned    ack_delay = 4;

  for (unsigned i = 0; i != nof_harqs; ++i) {
    harq_ent.find_empty_dl_harq()->new_tx(sl_tx, ack_delay, 4, 0);
    harq_ent.find_empty_ul_harq()->new_tx(sl_tx, 4);
  }
  ASSERT_EQ(harq_ent.find_empty_dl_harq(), nullptr);
  ASSERT_EQ(harq_ent.find_empty_ul_harq(), nullptr);
}

TEST(harq_entity, after_max_ack_wait_timeout_dl_harqs_are_available_for_retx)
{
  unsigned    nof_harqs = 8, max_ack_wait_slots = 4;
  harq_entity harq_ent(to_rnti(0x4601), nof_harqs, nof_harqs, max_ack_wait_slots);
  slot_point  sl_tx{0, 0};
  unsigned    ack_delay = 4;

  for (unsigned i = 0; i != nof_harqs; ++i) {
    harq_ent.find_empty_dl_harq()->new_tx(sl_tx, ack_delay, 4, 0);
  }
  for (unsigned i = 0; i != max_ack_wait_slots + ack_delay; ++i) {
    ASSERT_EQ(harq_ent.find_empty_dl_harq(), nullptr);
    ASSERT_EQ(harq_ent.find_pending_dl_retx(), nullptr);
    harq_ent.slot_indication(++sl_tx);
  }
  ASSERT_EQ(harq_ent.find_empty_dl_harq(), nullptr);
  ASSERT_NE(harq_ent.find_pending_dl_retx(), nullptr);
  ASSERT_TRUE(harq_ent.find_pending_dl_retx()->has_pending_retx());
}

class harq_entity_harq_1bit_tester : public ::testing::Test
{
protected:
  harq_entity_harq_1bit_tester()
  {
    logger.set_level(srslog::basic_levels::debug);
    srslog::init();
  }

  void run_slot()
  {
    logger.set_context(next_slot.sfn(), next_slot.slot_index());
    harq_ent.slot_indication(next_slot);
    ++next_slot;
  }

  const unsigned nof_harqs = 8, max_harq_retxs = 4, pucch_process_delay = 4;
  harq_entity    harq_ent{to_rnti(0x4601), nof_harqs};

  srslog::basic_logger& logger = srslog::fetch_basic_logger("SCHED");

  slot_point next_slot{0, test_rgen::uniform_int<unsigned>(0, 10239)};

  dl_harq_process& h_dl{*harq_ent.find_empty_dl_harq()};
};

TEST_F(harq_entity_harq_1bit_tester, when_dtx_received_after_ack_then_dtx_is_ignored)
{
  unsigned k1 = 4, dai = 0;

  this->h_dl.new_tx(next_slot, k1, max_harq_retxs, dai);
  slot_point pucch_slot = next_slot + k1;

  while (next_slot != pucch_slot) {
    run_slot();
  }

  // ACK received.
  ASSERT_NE(this->harq_ent.dl_ack_info(pucch_slot, srsran::mac_harq_ack_report_status::ack, dai), nullptr);

  // Reassignment of the HARQ.
  run_slot();
  this->h_dl.new_tx(next_slot, k1, max_harq_retxs, dai);

  // DTX received one slot late.
  this->harq_ent.dl_ack_info(pucch_slot, srsran::mac_harq_ack_report_status::dtx, dai);
}

enum harq_state_outcome { ACKed, NACKed, DTX_timeout };

struct test_2_harq_bits_params {
  std::vector<std::array<uint8_t, 2>> ack;
  std::array<harq_state_outcome, 2>   outcome;
};

/// \brief With this test suite, we intend to test the scenario where two HARQ bits arrive in a single PUCCH PDU to the
/// scheduler.
class harq_entity_2_harq_bits_tester : public ::testing::TestWithParam<test_2_harq_bits_params>
{
protected:
  harq_entity_2_harq_bits_tester()
  {
    logger.set_level(srslog::basic_levels::debug);
    srslog::init();

    // Allocate 2 HARQs with same PUCCH slot.
    // > First HARQ, DAI=0.
    run_slot();
    h_dls.push_back(harq_ent.find_empty_dl_harq());
    h_dls[0]->new_tx(next_slot, 5, max_harq_retxs, 0);
    // > Second HARQ, DAI=1.
    run_slot();
    h_dls.push_back(harq_ent.find_empty_dl_harq());
    h_dls[1]->new_tx(next_slot, 4, max_harq_retxs, 1);

    pucch_slot = next_slot + 4;

    while (next_slot <= pucch_slot + pucch_process_delay) {
      run_slot();
    }
  }

  ~harq_entity_2_harq_bits_tester() { srslog::flush(); }

  void run_slot()
  {
    logger.set_context(next_slot.sfn(), next_slot.slot_index());
    harq_ent.slot_indication(next_slot);
    ++next_slot;
  }

  const unsigned        nof_harqs = 8, max_harq_retxs = 4, pucch_process_delay = 4;
  harq_entity           harq_ent{to_rnti(0x4601), nof_harqs};
  srslog::basic_logger& logger = srslog::fetch_basic_logger("SCHED");

  slot_point next_slot{0, test_rgen::uniform_int<unsigned>(0, 10239)};
  slot_point pucch_slot;

  std::vector<dl_harq_process*> h_dls;
};

TEST_P(harq_entity_2_harq_bits_tester, handle_pucchs)
{
  auto params = GetParam();

  // First PUCCH, 2 HARQ bits, different DAIs.
  harq_ent.dl_ack_info(pucch_slot, (mac_harq_ack_report_status)params.ack[0][0], 0);
  harq_ent.dl_ack_info(pucch_slot, (mac_harq_ack_report_status)params.ack[0][1], 1);

  // Second PUCCH, 2 HARQ bits, different DAIs.
  if (params.ack.size() > 1) {
    harq_ent.dl_ack_info(pucch_slot, (mac_harq_ack_report_status)params.ack[1][0], 0);
    harq_ent.dl_ack_info(pucch_slot, (mac_harq_ack_report_status)params.ack[1][1], 1);
  }

  bool check_timeout = false;
  for (unsigned i = 0; i != params.outcome.size(); ++i) {
    if (params.outcome[i] == ACKed) {
      ASSERT_TRUE(h_dls[i]->empty());
    } else if (params.outcome[i] == NACKed) {
      ASSERT_TRUE(h_dls[i]->has_pending_retx());
    } else {
      // DTX_timeout
      ASSERT_FALSE(h_dls[i]->empty());
      ASSERT_FALSE(h_dls[i]->has_pending_retx());
      check_timeout = true;
    }
  }

  // Check if HARQs timeout in case of HARQ-ACK set to DTX.
  if (check_timeout) {
    for (unsigned i = 0; i != dl_harq_process::SHORT_ACK_TIMEOUT_DTX; ++i) {
      run_slot();
    }
    for (unsigned i = 0; i != params.outcome.size(); ++i) {
      if (params.outcome[i] == DTX_timeout) {
        ASSERT_TRUE(h_dls[i]->has_pending_retx());
      }
    }
  }
}

INSTANTIATE_TEST_SUITE_P(
    harq_entity_tester,
    harq_entity_2_harq_bits_tester,
    testing::Values(test_2_harq_bits_params{.ack = {{1, 1}}, .outcome = {ACKed, ACKed}},
                    test_2_harq_bits_params{.ack = {{0, 0}}, .outcome = {NACKed, NACKed}},
                    test_2_harq_bits_params{.ack = {{2, 2}}, .outcome = {DTX_timeout, DTX_timeout}},
                    test_2_harq_bits_params{.ack = {{2, 1}}, .outcome = {DTX_timeout, ACKed}},
                    test_2_harq_bits_params{.ack = {{1, 1}, {2, 2}}, .outcome = {ACKed, ACKed}},
                    test_2_harq_bits_params{.ack = {{0, 0}, {2, 2}}, .outcome = {NACKed, NACKed}},
                    test_2_harq_bits_params{.ack = {{2, 2}, {2, 1}}, .outcome = {DTX_timeout, ACKed}},
                    test_2_harq_bits_params{.ack = {{2, 2}, {2, 2}}, .outcome = {DTX_timeout, DTX_timeout}}));
