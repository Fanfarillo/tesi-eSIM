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

#include "du_manager_test_helpers.h"
#include "lib/du_manager/du_ue/du_ue_manager.h"
#include "srsran/du/du_cell_config_helpers.h"
#include "srsran/support/executors/manual_task_worker.h"
#include "srsran/support/test_utils.h"
#include <gtest/gtest.h>

/// \file
/// \brief In this file, we unit test the interaction between DU UE procedures in the DU UE Manager. For unit tests
/// addressing the specific details of each DU UE manager procedure, please check procedures/ directory.

using namespace srsran;
using namespace srs_du;

class du_ue_manager_tester : public ::testing::Test
{
protected:
  du_ue_manager_tester()
  {
    srslog::fetch_basic_logger("DU-MNG").set_level(srslog::basic_levels::debug);
    srslog::fetch_basic_logger("TEST").set_level(srslog::basic_levels::debug);
    srslog::init();

    // By default F1AP creates two F1-C bearers.
    f1ap_dummy.next_ue_create_response.result = true;
    f1ap_dummy.next_ue_create_response.f1c_bearers_added.resize(2);
  }
  ~du_ue_manager_tester() { srslog::flush(); }

  ul_ccch_indication_message create_ul_ccch_message(rnti_t rnti)
  {
    ul_ccch_indication_message ccch_ind{};
    ccch_ind.cell_index = to_du_cell_index(0);
    ccch_ind.crnti      = rnti;
    ccch_ind.subpdu     = {0, 1, 2, 3, 4, 5};
    return ccch_ind;
  }

  void push_ul_ccch_message(ul_ccch_indication_message ccch_ind)
  {
    test_logger.info("TEST: Pushing UL CCCH indication for RNTI={:#x}...", ccch_ind.crnti);
    ue_mng.handle_ue_create_request(ccch_ind);
  }

  void push_f1ap_ue_delete_request(du_ue_index_t ue_index)
  {
    f1ap_ue_delete_request ue_del_req{};
    ue_del_req.ue_index = ue_index;
    test_logger.info("TEST: Starting UE deletion with UE index={}...", ue_del_req.ue_index);
    ue_mng.schedule_async_task(ue_del_req.ue_index, ue_mng.handle_ue_delete_request(ue_del_req));
  }

  void mac_completes_ue_creation(bool result)
  {
    mac_dummy.wait_ue_create.result.ue_index   = get_last_ue_index();
    mac_dummy.wait_ue_create.result.cell_index = to_du_cell_index(0);
    mac_dummy.wait_ue_create.result.result     = result;
    mac_dummy.wait_ue_create.ready_ev.set();
  }

  void mac_completes_ue_deletion()
  {
    mac_dummy.wait_ue_delete.result.result = true;
    mac_dummy.wait_ue_delete.ready_ev.set();
  }

  bool is_ue_creation_complete() const { return not mac_dummy.last_pushed_ul_ccch_msg.empty(); }

  du_ue_index_t get_last_ue_index() const
  {
    srsran_assert(f1ap_dummy.last_ue_create.has_value(), "No UE creation request was provided");
    return f1ap_dummy.last_ue_create.value().ue_index;
  }

  srslog::basic_logger&      test_logger = srslog::fetch_basic_logger("TEST");
  timer_manager              timers;
  manual_task_worker         worker{128};
  dummy_ue_executor_mapper   ue_execs{worker};
  dummy_cell_executor_mapper cell_execs{worker};

  std::vector<du_cell_config>            cells = {config_helpers::make_default_du_cell_config()};
  f1ap_test_dummy                        f1ap_dummy;
  f1u_gateway_dummy                      f1u_dummy;
  mac_test_dummy                         mac_dummy;
  dummy_ue_resource_configurator_factory cell_res_alloc;

  du_manager_params params{{"srsgnb", 1, 1, cells},
                           {timers, worker, ue_execs, cell_execs},
                           {f1ap_dummy, f1ap_dummy},
                           {f1u_dummy},
                           {mac_dummy, f1ap_dummy, f1ap_dummy},
                           {mac_dummy, mac_dummy}};

  du_ue_manager ue_mng{params, cell_res_alloc};
};

TEST_F(du_ue_manager_tester, when_ue_create_request_is_received_du_manager_requests_f1ap_and_mac_to_create_ue)
{
  // Action: UL CCCH Message received.
  ul_ccch_indication_message ccch_ind = create_ul_ccch_message(to_rnti(0x4601));
  push_ul_ccch_message(ccch_ind);

  // TEST: F1AP received request to create UE.
  TESTASSERT(f1ap_dummy.last_ue_create.has_value());
  du_ue_index_t ue_index = f1ap_dummy.last_ue_create.value().ue_index;
  TESTASSERT(ue_index < MAX_NOF_DU_UES);

  // TEST: MAC received UE creation request.
  TESTASSERT(mac_dummy.last_ue_create_msg.has_value());
  TESTASSERT_EQ(ccch_ind.crnti, mac_dummy.last_ue_create_msg->crnti);

  // TEST: DU UE manager registers UE being created.
  ASSERT_TRUE(ue_mng.get_ues().contains(ue_index));
  ASSERT_EQ(ue_mng.get_ues()[ue_index].rnti, 0x4601);
}

TEST_F(du_ue_manager_tester,
       when_ue_create_request_is_received_du_manager_requests_mac_to_create_ue_and_awaits_response)
{
  // Action 1: UL CCCH Message received.
  ul_ccch_indication_message ccch_ind = create_ul_ccch_message(to_rnti(0x4601));
  push_ul_ccch_message(ccch_ind);

  // TEST: While MAC does not respond, UE creation is not complete.
  ASSERT_FALSE(is_ue_creation_complete());

  // Action 2: MAC UE creation completed.
  mac_completes_ue_creation(true);

  // TEST: DU manager completes DU UE creation procedure with success.
  ASSERT_TRUE(is_ue_creation_complete());
}

TEST_F(du_ue_manager_tester, when_mac_fails_to_create_ue_then_no_ue_is_created_in_du)
{
  // Action: UL CCCH Message received and MAC UE creation fails.
  ul_ccch_indication_message ccch_ind = create_ul_ccch_message(to_rnti(0x4601));
  push_ul_ccch_message(ccch_ind);
  mac_completes_ue_creation(false);

  // TEST: DU manager completes DU UE creation procedure with failure.
  ASSERT_TRUE(ue_mng.get_ues().empty());
  ASSERT_FALSE(is_ue_creation_complete());
}

TEST_F(du_ue_manager_tester, inexistent_ue_index_removal_is_handled)
{
  // Action: Request UE deletion for inexistent UE Index.
  push_f1ap_ue_delete_request(to_du_ue_index(test_rgen::uniform_int<unsigned>(0, MAX_NOF_DU_UES - 1)));

  // There should not be any reply from MAC and F1AP should receive failure signal
  ASSERT_TRUE(ue_mng.get_ues().empty());
  ASSERT_FALSE(mac_dummy.last_ue_delete_msg.has_value());
  // TODO: F1AP check
}

TEST_F(du_ue_manager_tester,
       when_request_for_ue_creation_and_removal_are_received_concurrently_then_the_procedures_run_in_sequence)
{
  // Action 1: UL CCCH Message and UE deletion request received concurrently.
  push_ul_ccch_message(create_ul_ccch_message(to_rnti(0x4601)));
  push_f1ap_ue_delete_request(get_last_ue_index());

  // MAC and F1AP receive request to create UE.
  ASSERT_TRUE(mac_dummy.last_ue_create_msg.has_value());
  ASSERT_TRUE(f1ap_dummy.last_ue_create.has_value());

  // Until MAC completes UE creation, F1AP and MAC should not receive request to delete UE.
  ASSERT_FALSE(mac_dummy.last_ue_delete_msg.has_value());
  ASSERT_FALSE(f1ap_dummy.last_ue_release.has_value());
  mac_completes_ue_creation(true);
  ASSERT_TRUE(mac_dummy.last_ue_delete_msg.has_value());
  ASSERT_EQ(get_last_ue_index(), mac_dummy.last_ue_delete_msg->ue_index);

  // Action 2: MAC finishes UE deletion.
  ASSERT_FALSE(ue_mng.get_ues().empty());
  mac_completes_ue_deletion();

  // UE deleted from the DU.
  TESTASSERT(ue_mng.get_ues().empty());
}

TEST_F(du_ue_manager_tester,
       when_requests_for_ue_creation_are_received_sequentially_then_the_created_ues_have_different_indexes)
{
  // Action 1: UL CCCH Message received and UE creation completes.
  push_ul_ccch_message(create_ul_ccch_message(to_rnti(0x4601)));
  du_ue_index_t ue_index1 = get_last_ue_index();
  ASSERT_TRUE(mac_dummy.last_ue_create_msg.has_value());
  ASSERT_EQ(mac_dummy.last_ue_create_msg.value().ue_index, ue_index1);
  ASSERT_EQ(mac_dummy.last_ue_create_msg.value().crnti, 0x4601);
  mac_completes_ue_creation(true);

  // Action 2: UL CCCH Message received concurrently.
  push_ul_ccch_message(create_ul_ccch_message(to_rnti(0x4602)));
  du_ue_index_t ue_index2 = get_last_ue_index();
  ASSERT_TRUE(mac_dummy.last_ue_create_msg.has_value());
  ASSERT_EQ(mac_dummy.last_ue_create_msg.value().ue_index, ue_index2);
  ASSERT_EQ(mac_dummy.last_ue_create_msg.value().crnti, 0x4602);
  mac_completes_ue_creation(true);

  // TEST: UEs should have different UE indexes.
  ASSERT_NE(ue_index1, ue_index2);
  ASSERT_EQ(ue_mng.get_ues().size(), 2);
}

TEST_F(du_ue_manager_tester,
       when_requests_for_ue_creation_are_received_concurrently_then_the_created_ues_have_different_indexes)
{
  // Action 1: UL CCCH Message received.
  push_ul_ccch_message(create_ul_ccch_message(to_rnti(0x4601)));
  du_ue_index_t ue_index1 = get_last_ue_index();
  ASSERT_TRUE(mac_dummy.last_ue_create_msg.has_value());
  ASSERT_EQ(mac_dummy.last_ue_create_msg.value().ue_index, ue_index1);
  ASSERT_EQ(mac_dummy.last_ue_create_msg.value().crnti, 0x4601);

  // Action 2: UL CCCH Message received concurrently.
  push_ul_ccch_message(create_ul_ccch_message(to_rnti(0x4602)));
  du_ue_index_t ue_index2 = get_last_ue_index();
  ASSERT_TRUE(mac_dummy.last_ue_create_msg.has_value());
  ASSERT_EQ(mac_dummy.last_ue_create_msg.value().ue_index, ue_index2);
  ASSERT_EQ(mac_dummy.last_ue_create_msg.value().crnti, 0x4602);

  // TEST: UEs should have different UE indexes.
  ASSERT_NE(ue_index1, ue_index2);
}

TEST_F(du_ue_manager_tester,
       when_requests_for_ue_creation_are_received_with_duplicate_crnti_then_only_one_request_is_handled)
{
  // Action: Two UL CCCH Messages with the same TC-RNTI received.
  push_ul_ccch_message(create_ul_ccch_message(to_rnti(0x4601)));
  du_ue_index_t ue_index1 = get_last_ue_index();
  push_ul_ccch_message(create_ul_ccch_message(to_rnti(0x4601)));
  mac_completes_ue_creation(true);

  // TEST: MAC only processes the first request.
  ASSERT_TRUE(mac_dummy.last_ue_create_msg.has_value());
  ASSERT_EQ(mac_dummy.last_ue_create_msg.value().ue_index, ue_index1);
  ASSERT_EQ(mac_dummy.last_ue_create_msg.value().crnti, 0x4601);
  ASSERT_TRUE(is_ue_creation_complete());
  ASSERT_EQ(ue_mng.get_ues().size(), 1);
}
