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

#include "f1ap_cu_test_helpers.h"
#include "srsran/f1ap/cu_cp/f1ap_cu.h"
#include "srsran/support/test_utils.h"
#include <gtest/gtest.h>

using namespace srsran;
using namespace srs_cu_cp;
using namespace asn1::f1ap;

//////////////////////////////////////////////////////////////////////////////////////
/* Handling of unsupported messages                                                 */
//////////////////////////////////////////////////////////////////////////////////////

TEST_F(f1ap_cu_test, when_unsupported_f1ap_pdu_received_then_message_ignored)
{
  // Set last message of PDU notifier to init_msg
  f1ap_pdu_notifier.last_f1ap_msg.pdu.set_init_msg();

  // Generate unsupported F1AP PDU
  f1ap_message unsupported_msg = {};
  unsupported_msg.pdu.set_choice_ext();

  f1ap->handle_message(unsupported_msg);

  // Check that PDU has not been forwarded (last PDU is still init_msg)
  EXPECT_EQ(f1ap_pdu_notifier.last_f1ap_msg.pdu.type(), asn1::f1ap::f1ap_pdu_c::types_opts::options::init_msg);
}

TEST_F(f1ap_cu_test, when_unsupported_init_msg_received_then_message_ignored)
{
  // Set last message of PDU notifier to successful outcome
  f1ap_pdu_notifier.last_f1ap_msg.pdu.set_successful_outcome();

  // Generate unupported F1AP PDU
  f1ap_message unsupported_msg = {};
  unsupported_msg.pdu.set_init_msg();

  f1ap->handle_message(unsupported_msg);

  // Check that PDU has not been forwarded (last PDU is still successful_outcome)
  EXPECT_EQ(f1ap_pdu_notifier.last_f1ap_msg.pdu.type(),
            asn1::f1ap::f1ap_pdu_c::types_opts::options::successful_outcome);
}

TEST_F(f1ap_cu_test, when_unsupported_successful_outcome_received_then_message_ignored)
{
  // Set last message of PDU notifier to init_msg
  f1ap_pdu_notifier.last_f1ap_msg.pdu.set_init_msg();

  // Generate unupported F1AP PDU
  f1ap_message unsupported_msg = {};
  unsupported_msg.pdu.set_successful_outcome();

  f1ap->handle_message(unsupported_msg);

  // Check that PDU has not been forwarded (last PDU is still init_msg)
  EXPECT_EQ(f1ap_pdu_notifier.last_f1ap_msg.pdu.type(), asn1::f1ap::f1ap_pdu_c::types_opts::options::init_msg);
}

TEST_F(f1ap_cu_test, when_unsupported_unsuccessful_outcome_received_then_message_ignored)
{
  // Set last message of PDU notifier to init_msg
  f1ap_pdu_notifier.last_f1ap_msg.pdu.set_init_msg();

  // Generate unupported F1AP PDU
  f1ap_message unsupported_msg = {};
  unsupported_msg.pdu.set_unsuccessful_outcome();

  f1ap->handle_message(unsupported_msg);

  // Check that PDU has not been forwarded (last PDU is still init_msg)
  EXPECT_EQ(f1ap_pdu_notifier.last_f1ap_msg.pdu.type(), asn1::f1ap::f1ap_pdu_c::types_opts::options::init_msg);
}

//////////////////////////////////////////////////////////////////////////////////////
/* F1 Setup handling                                                                */
//////////////////////////////////////////////////////////////////////////////////////

/// Test the successful f1 setup procedure
TEST_F(f1ap_cu_test, when_f1_setup_request_valid_then_connect_du)
{
  // Action 1: Receive F1SetupRequest message
  test_logger.info("TEST: Receive F1SetupRequest message...");

  // Generate F1SetupRequest
  f1ap_message f1setup_msg = generate_f1_setup_request();

  f1ap->handle_message(f1setup_msg);

  // Action 2: Check if F1SetupRequest was forwarded to DU processor
  ASSERT_EQ(du_processor_notifier.last_f1_setup_request_msg.request->gnb_du_id.value, 0x11U);

  // Action 3: Transmit F1SetupResponse message
  test_logger.info("TEST: Transmit F1SetupResponse message...");
  f1_setup_response_message msg = {};
  msg.success                   = true;
  f1ap->handle_f1_setup_response(msg);

  // Check the generated PDU is indeed the F1 Setup response
  ASSERT_EQ(asn1::f1ap::f1ap_pdu_c::types_opts::options::successful_outcome,
            f1ap_pdu_notifier.last_f1ap_msg.pdu.type());
  ASSERT_EQ(asn1::f1ap::f1ap_elem_procs_o::successful_outcome_c::types_opts::options::f1_setup_resp,
            f1ap_pdu_notifier.last_f1ap_msg.pdu.successful_outcome().value.type());
}

/// Test the f1 setup failure
TEST_F(f1ap_cu_test, when_f1_setup_request_invalid_then_reject_du)
{
  // Generate Invalid F1SetupRequest
  f1ap_message f1setup_msg                    = generate_f1_setup_request();
  auto&        setup_req                      = f1setup_msg.pdu.init_msg().value.f1_setup_request();
  setup_req->gnb_du_served_cells_list_present = false;
  setup_req->gnb_du_served_cells_list.value.clear();

  f1ap->handle_message(f1setup_msg);

  // Action 2: Check if F1SetupRequest was forwarded to DU processor
  ASSERT_EQ(du_processor_notifier.last_f1_setup_request_msg.request->gnb_du_id.value, 0x11U);

  // Action 3: Transmit F1SetupFailure message
  test_logger.info("TEST: Transmit F1SetupFailure message...");
  f1_setup_response_message msg = {};
  msg.success                   = false;
  f1ap->handle_f1_setup_response(msg);

  // Check the generated PDU is indeed the F1 Setup failure
  ASSERT_EQ(asn1::f1ap::f1ap_pdu_c::types_opts::options::unsuccessful_outcome,
            f1ap_pdu_notifier.last_f1ap_msg.pdu.type());
  ASSERT_EQ(asn1::f1ap::f1ap_elem_procs_o::unsuccessful_outcome_c::types_opts::f1_setup_fail,
            f1ap_pdu_notifier.last_f1ap_msg.pdu.unsuccessful_outcome().value.type());
}

//////////////////////////////////////////////////////////////////////////////////////
/* Initial UL RRC Message handling                                                  */
//////////////////////////////////////////////////////////////////////////////////////

TEST_F(f1ap_cu_test, when_init_ul_rrc_correct_then_ue_added)
{
  // Generate F1 Initial UL RRC Message
  f1ap_message init_ul_rrc_msg = generate_init_ul_rrc_message_transfer(int_to_gnb_du_ue_f1ap_id(41255));

  // Pass message to F1AP
  f1ap->handle_message(init_ul_rrc_msg);

  EXPECT_EQ(f1ap->get_nof_ues(), 1);
}

TEST_F(f1ap_cu_test, when_du_to_cu_rrc_container_missing_then_ue_not_added)
{
  // Generate F1 Initial UL RRC Message without DU to CU RRC Container
  f1ap_message init_ul_rrc_msg = generate_init_ul_rrc_message_transfer(int_to_gnb_du_ue_f1ap_id(41255));
  init_ul_rrc_msg.pdu.init_msg().value.init_ul_rrc_msg_transfer()->du_to_cu_rrc_container_present = false;
  init_ul_rrc_msg.pdu.init_msg().value.init_ul_rrc_msg_transfer()->du_to_cu_rrc_container->clear();

  // Pass message to F1AP
  f1ap->handle_message(init_ul_rrc_msg);

  EXPECT_EQ(f1ap->get_nof_ues(), 0);
}

TEST_F(f1ap_cu_test, when_max_nof_ues_PER_DU_exceeded_then_ue_not_added)
{
  // Reduce F1AP and TEST logger loglevel to warning to reduce console output
  srslog::fetch_basic_logger("CU-CP-F1").set_level(srslog::basic_levels::warning);
  srslog::fetch_basic_logger("TEST").set_level(srslog::basic_levels::warning);

  // Add the maximum number of UEs
  for (int ue_index = 0; ue_index < MAX_NOF_UES_PER_DU; ue_index++) {
    // Generate ue_creation message
    f1ap_message init_ul_rrc_msg = generate_init_ul_rrc_message_transfer(int_to_gnb_du_ue_f1ap_id(ue_index));

    // Pass message to F1AP
    f1ap->handle_message(init_ul_rrc_msg);
  }

  // Reset F1AP and TEST logger loglevel
  srslog::fetch_basic_logger("CU-CP-F1").set_level(srslog::basic_levels::debug);
  srslog::fetch_basic_logger("TEST").set_level(srslog::basic_levels::debug);

  EXPECT_EQ(f1ap->get_nof_ues(), MAX_NOF_UES_PER_DU);

  // Add one more UE to F1AP
  // Generate ue_creation message
  f1ap_message init_ul_rrc_msg =
      generate_init_ul_rrc_message_transfer(int_to_gnb_du_ue_f1ap_id(MAX_NOF_UES_PER_DU + 1));

  // Pass message to F1AP
  f1ap->handle_message(init_ul_rrc_msg);

  EXPECT_EQ(f1ap->get_nof_ues(), MAX_NOF_UES_PER_DU);
}

TEST_F(f1ap_cu_test, when_ue_creation_fails_then_ue_not_added)
{
  // Add maximum number of UEs to dummy DU processor
  du_processor_notifier.set_ue_id(MAX_NOF_UES_PER_DU);

  // Add one more UE to F1AP
  // Generate F1 Initial UL RRC Message
  f1ap_message init_ul_rrc_msg = generate_init_ul_rrc_message_transfer(int_to_gnb_du_ue_f1ap_id(41255));

  // Pass message to F1AP
  f1ap->handle_message(init_ul_rrc_msg);

  EXPECT_EQ(f1ap->get_nof_ues(), 0);
}

TEST_F(f1ap_cu_test, when_rrc_setup_complete_present_then_forward_over_srb1)
{
  // Generate F1 Initial UL RRC Message with RRC Setup Complete present
  f1ap_message init_ul_rrc_msg = generate_init_ul_rrc_message_transfer(int_to_gnb_du_ue_f1ap_id(41255));
  auto&        init_ul_rrc     = init_ul_rrc_msg.pdu.init_msg().value.init_ul_rrc_msg_transfer();
  init_ul_rrc->rrc_container_rrc_setup_complete_present = true;

  // Pass message to F1AP
  f1ap->handle_message(init_ul_rrc_msg);

  EXPECT_EQ(du_processor_notifier.rx_notifier->last_rrc_container.to_string(),
            init_ul_rrc->rrc_container_rrc_setup_complete.value.to_string());
}

//////////////////////////////////////////////////////////////////////////////////////
/* F1 Removal Request handling                                                      */
//////////////////////////////////////////////////////////////////////////////////////

TEST_F(f1ap_cu_test, when_f1_removal_request_received_then_du_deleted)
{
  // Generate F1 Removal Request Message
  f1ap_message removal_request = {};
  removal_request.pdu.set_init_msg();
  removal_request.pdu.init_msg().load_info_obj(ASN1_F1AP_ID_F1_REMOVAL);

  // Pass message to F1AP
  f1ap->handle_message(removal_request);

  EXPECT_EQ(f1ap_du_mgmt_notifier.last_du_idx, du_index_t::min);
}
