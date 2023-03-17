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

#include "ue_manager_test_helpers.h"
#include "srsran/rrc/rrc_ue.h"
#include <gtest/gtest.h>

using namespace srsran;
using namespace srs_cu_cp;

//////////////////////////////////////////////////////////////////////////////////////
/* DU UE                                                                            */
//////////////////////////////////////////////////////////////////////////////////////

/// Test creation of a DU UE with an invalid RNTI
TEST_F(ue_manager_test, when_rnti_invalid_then_ue_not_created)
{
  du_index_t du_index = uint_to_du_index(0);
  rnti_t     rnti     = rnti_t::INVALID_RNTI;

  auto* ue = ue_mng.add_ue(du_index, rnti);

  // check that the UE has not been added
  ASSERT_EQ(ue, nullptr);
  ASSERT_EQ(ue_mng.get_nof_du_ues(du_index), 0U);
  ASSERT_EQ(ue_mng.get_nof_du_ues(), 0U);
}

/// Test successful creation of a DU UE
TEST_F(ue_manager_test, when_rnti_valid_then_ue_added)
{
  du_index_t du_index = uint_to_du_index(0);
  rnti_t     rnti     = to_rnti(0x4601);

  auto* ue = ue_mng.add_ue(du_index, rnti);

  // check that the UE has been created
  ASSERT_NE(ue, nullptr);
  ASSERT_NE(ue_mng.find_du_ue(ue->get_ue_index()), nullptr);

  // check that the UE index is valid
  ASSERT_NE(ue->get_ue_index(), ue_index_t::invalid);

  // check that the RNTI has been set
  ASSERT_EQ(ue->get_c_rnti(), rnti);

  // check that the lookup by RNTI works
  ASSERT_EQ(ue->get_ue_index(), ue_mng.get_ue_index(ue->get_c_rnti()));

  // check that the number of DU UEs is 1
  ASSERT_EQ(ue_mng.get_nof_du_ues(), 1U);
}

/// Test finding invalid UE index
TEST_F(ue_manager_test, when_ue_index_invalid_then_ue_not_found)
{
  du_index_t du_index = uint_to_du_index(0);
  rnti_t     rnti     = to_rnti(0x4601);

  auto* ue = ue_mng.add_ue(du_index, rnti);

  // check that the UE has been created
  ASSERT_NE(ue, nullptr);

  // check that ue with invalid UE index is not found
  ASSERT_EQ(ue_mng.find_du_ue(ue_index_t::invalid), nullptr);
}

/// Test duplicate UE creation
TEST_F(ue_manager_test, when_rnti_already_exits_then_ue_not_added)
{
  du_index_t du_index = uint_to_du_index(0);
  rnti_t     rnti     = to_rnti(0x4601);

  ue_mng.add_ue(du_index, rnti);

  // check that the number of DU UEs is 1
  ASSERT_EQ(ue_mng.get_nof_du_ues(), 1U);

  auto* ue2 = ue_mng.add_ue(du_index, rnti);

  // check that the UE has not been added
  ASSERT_EQ(ue2, nullptr);
  ASSERT_EQ(ue_mng.get_nof_du_ues(), 1U);
}

/// Test successful removal of a DU UE
TEST_F(ue_manager_test, when_ue_exists_then_removal_successful)
{
  du_index_t du_index = uint_to_du_index(0);
  rnti_t     rnti     = to_rnti(0x4601);

  auto* ue = ue_mng.add_ue(du_index, rnti);

  ue_mng.remove_du_ue(ue->get_ue_index());

  // check that the UE has been removed
  ASSERT_EQ(ue_mng.get_nof_du_ues(du_index), 0U);
  ASSERT_EQ(ue_mng.get_nof_du_ues(), 0U);

  // No NGAP context has been added, so the UE should be completely removed
  ASSERT_EQ(ue_mng.get_nof_ngap_ues(), 0U);
}

/// Test successful removal of a DU UE
TEST_F(ue_manager_test, when_ngap_ue_context_exists_then_du_ue_removal_successful)
{
  du_index_t du_index = uint_to_du_index(0);
  rnti_t     rnti     = to_rnti(0x4601);

  auto* ue = ue_mng.add_ue(du_index, rnti);

  // add a NGAP context
  auto* ue_ngap =
      ue_mng.add_ue(ue->get_ue_index(), rrc_ue_pdu_notifier, rrc_ue_pdu_notifier, du_processor_ctrl_notifier);
  // check that the UE has been created
  ASSERT_NE(ue_ngap, nullptr);

  ue_mng.remove_du_ue(ue->get_ue_index());

  // check that the UE has been removed
  ASSERT_EQ(ue_mng.get_nof_du_ues(du_index), 0U);
  ASSERT_EQ(ue_mng.get_nof_du_ues(), 0U);

  // NGAP context has been added, so the UE should not be completely removed
  ASSERT_EQ(ue_mng.get_nof_ngap_ues(), 1U);
}

/// Test creation of multiple DU UEs
TEST_F(ue_manager_test, when_multiple_ues_added_then_ues_exist)
{
  du_index_t du_index = uint_to_du_index(0);

  // reduce log level to avoid flooding the log
  ue_mng_logger.set_level(srslog::basic_levels::warning);
  test_logger.set_level(srslog::basic_levels::warning);

  for (unsigned it = rnti_t::MIN_CRNTI; it < rnti_t::MIN_CRNTI + MAX_NOF_UES_PER_DU; it++) {
    rnti_t rnti = to_rnti(it);

    auto* ue = ue_mng.add_ue(du_index, rnti);

    // check that the UE has been created
    ASSERT_NE(ue, nullptr);
    ASSERT_NE(ue_mng.find_du_ue(ue->get_ue_index()), nullptr);

    // check that the UE index is valid
    ASSERT_NE(ue->get_ue_index(), ue_index_t::invalid);

    // check that the RNTI has been set
    ASSERT_EQ(ue->get_c_rnti(), rnti);

    // check that the lookup by RNTI works
    ASSERT_EQ(ue->get_ue_index(), ue_mng.get_ue_index(ue->get_c_rnti()));

    // check that the number of DU UEs is increased
    ASSERT_EQ(ue_mng.get_nof_du_ues(du_index), it - rnti_t::MIN_CRNTI + 1);
    ASSERT_EQ(ue_mng.get_nof_du_ues(), it - rnti_t::MIN_CRNTI + 1);
  }

  // reset log level
  ue_mng_logger.set_level(srslog::basic_levels::debug);

  // check that the maximum number of DU UEs has been reached
  ASSERT_EQ(ue_mng.get_nof_du_ues(du_index), MAX_NOF_UES_PER_DU);
  ASSERT_EQ(ue_mng.get_nof_du_ues(), MAX_NOF_UES_PER_DU);
}

/// Test creation of unsupported number of DU UEs
TEST_F(ue_manager_test, when_more_than_max_ues_added_then_ue_not_created)
{
  du_index_t du_index = uint_to_du_index(0);

  // reduce log level to avoid flooding the log
  ue_mng_logger.set_level(srslog::basic_levels::warning);
  test_logger.set_level(srslog::basic_levels::warning);

  for (unsigned it = rnti_t::MIN_CRNTI; it < rnti_t::MIN_CRNTI + MAX_NOF_UES_PER_DU; it++) {
    rnti_t rnti = to_rnti(it);

    auto* ue = ue_mng.add_ue(du_index, rnti);

    // check that the UE has been created
    ASSERT_NE(ue, nullptr);
    ASSERT_NE(ue_mng.find_du_ue(ue->get_ue_index()), nullptr);

    // check that the UE index is valid
    ASSERT_NE(ue->get_ue_index(), ue_index_t::invalid);

    // check that the RNTI has been set
    ASSERT_EQ(ue->get_c_rnti(), rnti);

    // check that the lookup by RNTI works
    ASSERT_EQ(ue->get_ue_index(), ue_mng.get_ue_index(ue->get_c_rnti()));

    // check that the number of DU UEs is increased
    ASSERT_EQ(ue_mng.get_nof_du_ues(du_index), it - rnti_t::MIN_CRNTI + 1);
    ASSERT_EQ(ue_mng.get_nof_du_ues(), it - rnti_t::MIN_CRNTI + 1);
  }

  // reset log level
  ue_mng_logger.set_level(srslog::basic_levels::debug);
  test_logger.set_level(srslog::basic_levels::debug);

  // check that the maximum number of DU UEs has been reached
  ASSERT_EQ(ue_mng.get_nof_du_ues(du_index), MAX_NOF_UES_PER_DU);
  ASSERT_EQ(ue_mng.get_nof_du_ues(), MAX_NOF_UES_PER_DU);

  auto* ue = ue_mng.add_ue(du_index, rnti_t::MAX_CRNTI);

  // check that the UE has not been added
  ASSERT_EQ(ue, nullptr);
  ASSERT_EQ(ue_mng.get_nof_du_ues(du_index), MAX_NOF_UES_PER_DU);
  ASSERT_EQ(ue_mng.get_nof_du_ues(), MAX_NOF_UES_PER_DU);
}

//////////////////////////////////////////////////////////////////////////////////////
/* NGAP UE                                                                          */
//////////////////////////////////////////////////////////////////////////////////////

/// Test creation of NGAP UE before creation of a DU UE
TEST_F(ue_manager_test, when_ue_not_created_then_ngap_ue_not_added)
{
  auto* ue = ue_mng.add_ue(uint_to_ue_index(0), rrc_ue_pdu_notifier, rrc_ue_pdu_notifier, du_processor_ctrl_notifier);

  // check that the UE has not been added
  ASSERT_EQ(ue, nullptr);
  ASSERT_EQ(ue_mng.get_nof_ngap_ues(), 0U);
}

/// Test successful creation of a NGAP UE
TEST_F(ue_manager_test, when_ue_created_then_then_ngap_ue_added)
{
  ue_index_t ue_index = create_ue(uint_to_du_index(0), to_rnti(0x4601));

  auto* ue = ue_mng.add_ue(ue_index, rrc_ue_pdu_notifier, rrc_ue_pdu_notifier, du_processor_ctrl_notifier);

  // check that the NGAP UE has been added
  ASSERT_NE(ue, nullptr);
  ASSERT_NE(ue_mng.find_ngap_ue(ue->get_ue_index()), nullptr);

  // check that the UE index is valid
  ASSERT_NE(ue->get_ue_index(), ue_index_t::invalid);

  // check that a RAN UE ID has been set
  ASSERT_NE(ue->get_ran_ue_id(), ran_ue_id_t::invalid);

  // check that the lookup by RAN UE ID works
  ASSERT_EQ(ue->get_ue_index(), ue_mng.get_ue_index(ue->get_ran_ue_id()));

  // check that the number of NGAP UEs is 1
  ASSERT_EQ(ue_mng.get_nof_ngap_ues(), 1U);
}

/// Test finding invalid UE index
TEST_F(ue_manager_test, when_ue_index_invalid_then_ngap_ue_not_found)
{
  ue_index_t ue_index = create_ue(uint_to_du_index(0), to_rnti(0x4601));

  auto* ue = ue_mng.add_ue(ue_index, rrc_ue_pdu_notifier, rrc_ue_pdu_notifier, du_processor_ctrl_notifier);

  // check that the NGAP UE has been created
  ASSERT_NE(ue, nullptr);

  // check that ue with invalid UE index is not found
  ASSERT_EQ(ue_mng.find_ngap_ue(ue_index_t::invalid), nullptr);
}

/// Test duplicate UE creation
TEST_F(ue_manager_test, when_ngap_context_already_exits_then_ue_not_added)
{
  ue_index_t ue_index = create_ue(uint_to_du_index(0), to_rnti(0x4601));

  auto* ue = ue_mng.add_ue(ue_index, rrc_ue_pdu_notifier, rrc_ue_pdu_notifier, du_processor_ctrl_notifier);

  // check that the NGAP UE has been created
  ASSERT_NE(ue, nullptr);

  // check that the number of NGAP UEs is 1
  ASSERT_EQ(ue_mng.get_nof_ngap_ues(), 1U);

  auto* ue2 = ue_mng.add_ue(ue_index, rrc_ue_pdu_notifier, rrc_ue_pdu_notifier, du_processor_ctrl_notifier);

  // check that the UE has not been added
  ASSERT_EQ(ue2, nullptr);
  ASSERT_EQ(ue_mng.get_nof_ngap_ues(), 1U);
}

/// Test successful removal of a NGAP UE
TEST_F(ue_manager_test, when_du_ue_context_exists_then_ngap_ue_removal_successful)
{
  ue_index_t ue_index = create_ue(uint_to_du_index(0), to_rnti(0x4601));

  auto* ue = ue_mng.add_ue(ue_index, rrc_ue_pdu_notifier, rrc_ue_pdu_notifier, du_processor_ctrl_notifier);

  ue_mng.remove_ngap_ue(ue->get_ue_index());

  // check that the NGAP UE has been removed
  ASSERT_EQ(ue_mng.get_nof_ngap_ues(), 0U);

  // check that the DU UE has not been removed
  ASSERT_EQ(ue_mng.get_nof_du_ues(), 1U);
}

/// Test successful removal of a NGAP UE
TEST_F(ue_manager_test, when_ngap_ue_exists_then_removal_successful)
{
  du_index_t du_index = uint_to_du_index(0);

  ue_index_t ue_index = create_ue(du_index, to_rnti(0x4601));

  auto* ue = ue_mng.add_ue(ue_index, rrc_ue_pdu_notifier, rrc_ue_pdu_notifier, du_processor_ctrl_notifier);

  ue_mng.remove_du_ue(ue->get_ue_index());

  // check that the DU UE has been removed
  ASSERT_EQ(ue_mng.get_nof_du_ues(du_index), 0U);
  ASSERT_EQ(ue_mng.get_nof_du_ues(), 0U);

  ue_mng.remove_ngap_ue(ue->get_ue_index());

  // check that the NGAP UE has been removed
  ASSERT_EQ(ue_mng.get_nof_ngap_ues(), 0U);
}

/// Test creation of multiple DU UEs
TEST_F(ue_manager_test, when_multiple_ngap_ues_added_then_ues_exist)
{
  // reduce log level to avoid flooding the log
  ue_mng_logger.set_level(srslog::basic_levels::warning);
  test_logger.set_level(srslog::basic_levels::warning);

  for (unsigned du_idx = du_index_to_uint(du_index_t::min); du_idx <= du_index_to_uint(du_index_t::max); du_idx++) {
    unsigned du_offset = du_idx * MAX_NOF_UES_PER_DU;

    for (unsigned it = rnti_t::MIN_CRNTI; it < rnti_t::MIN_CRNTI + MAX_NOF_UES_PER_DU; it++) {
      ue_index_t ue_index = create_ue(uint_to_du_index(du_idx), to_rnti(du_offset + it));
      auto*      ue = ue_mng.add_ue(ue_index, rrc_ue_pdu_notifier, rrc_ue_pdu_notifier, du_processor_ctrl_notifier);

      // check that the UE has been created
      ASSERT_NE(ue, nullptr);
      ASSERT_NE(ue_mng.find_ngap_ue(ue->get_ue_index()), nullptr);

      // check that the UE index is valid
      ASSERT_NE(ue->get_ue_index(), ue_index_t::invalid);

      // check that the RAN UE ID has been set
      ASSERT_NE(ue->get_ran_ue_id(), ran_ue_id_t::invalid);

      // check that the lookup by RAN UE ID works
      ASSERT_EQ(ue->get_ue_index(), ue_mng.get_ue_index(ue->get_ran_ue_id()));

      // check that the number of NGAP UEs is increased
      ASSERT_EQ(ue_mng.get_nof_ngap_ues(), du_offset + it - rnti_t::MIN_CRNTI + 1);
    }
  }

  // reset log level
  ue_mng_logger.set_level(srslog::basic_levels::debug);
  test_logger.set_level(srslog::basic_levels::debug);

  // check that the maximum number of NGAP UEs has been reached
  ASSERT_EQ(ue_mng.get_nof_ngap_ues(), (du_index_to_uint(du_index_t::max) + 1) * MAX_NOF_UES_PER_DU);
}

/// Test creation of unsupported number of NGAP UEs
TEST_F(ue_manager_test, when_more_than_max_ues_added_then_ngap_ue_not_created)
{
  // reduce log level to avoid flooding the log
  ue_mng_logger.set_level(srslog::basic_levels::warning);
  test_logger.set_level(srslog::basic_levels::warning);

  for (unsigned du_idx = du_index_to_uint(du_index_t::min); du_idx <= du_index_to_uint(du_index_t::max); du_idx++) {
    unsigned du_offset = du_idx * MAX_NOF_UES_PER_DU;

    for (unsigned it = rnti_t::MIN_CRNTI; it < rnti_t::MIN_CRNTI + MAX_NOF_UES_PER_DU; it++) {
      ue_index_t ue_index = create_ue(uint_to_du_index(du_idx), to_rnti(du_offset + it));
      auto*      ue = ue_mng.add_ue(ue_index, rrc_ue_pdu_notifier, rrc_ue_pdu_notifier, du_processor_ctrl_notifier);

      // check that the UE has been created
      ASSERT_NE(ue, nullptr);
      ASSERT_NE(ue_mng.find_ngap_ue(ue->get_ue_index()), nullptr);

      // check that the UE index is valid
      ASSERT_NE(ue->get_ue_index(), ue_index_t::invalid);

      // check that the RAN UE ID has been set
      ASSERT_NE(ue->get_ran_ue_id(), ran_ue_id_t::invalid);

      // check that the lookup by RAN UE ID works
      ASSERT_EQ(ue->get_ue_index(), ue_mng.get_ue_index(ue->get_ran_ue_id()));

      // check that the number of NGAP UEs is increased
      ASSERT_EQ(ue_mng.get_nof_ngap_ues(), du_offset + it - rnti_t::MIN_CRNTI + 1);
    }
  }

  // reset log level
  ue_mng_logger.set_level(srslog::basic_levels::debug);
  test_logger.set_level(srslog::basic_levels::debug);

  // check that the maximum number of NGAP UEs has been reached
  ASSERT_EQ(ue_mng.get_nof_ngap_ues(), (du_index_to_uint(du_index_t::max) + 1) * MAX_NOF_UES_PER_DU);

  ue_index_t ue_index = create_ue(du_index_t::max, rnti_t::MAX_CRNTI);
  ASSERT_EQ(ue_index, ue_index_t::invalid);
  auto* ue = ue_mng.add_ue(ue_index, rrc_ue_pdu_notifier, rrc_ue_pdu_notifier, du_processor_ctrl_notifier);

  // check that the UE has not been added
  ASSERT_EQ(ue, nullptr);
  ASSERT_EQ(ue_mng.get_nof_ngap_ues(), (du_index_to_uint(du_index_t::max) + 1) * MAX_NOF_UES_PER_DU);
}
