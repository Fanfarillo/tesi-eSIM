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

#include "f1ap_du_test_helpers.h"
#include "srsran/support/async/async_test_utils.h"
#include <gtest/gtest.h>

using namespace srsran;
using namespace srs_du;

/// Test successful f1 setup procedure
TEST_F(f1ap_du_test, when_f1_setup_response_received_then_du_connected)
{
  // Action 1: Launch F1 setup procedure
  f1_setup_request_message request_msg = generate_f1_setup_request_message();
  test_logger.info("Launch f1 setup request procedure...");
  async_task<f1_setup_response_message>         t = f1ap->handle_f1_setup_request(request_msg);
  lazy_task_launcher<f1_setup_response_message> t_launcher(t);

  // Status: CU received F1 Setup Request.
  ASSERT_EQ(msg_notifier.last_f1ap_msg.pdu.type().value, asn1::f1ap::f1ap_pdu_c::types_opts::init_msg);
  ASSERT_EQ(msg_notifier.last_f1ap_msg.pdu.init_msg().value.type().value,
            asn1::f1ap::f1ap_elem_procs_o::init_msg_c::types_opts::f1_setup_request);

  // Status: Procedure not yet ready.
  ASSERT_FALSE(t.ready());

  // Action 2: F1 setup response received.
  unsigned     transaction_id    = get_transaction_id(msg_notifier.last_f1ap_msg.pdu).value();
  f1ap_message f1_setup_response = generate_f1_setup_response_message(transaction_id);
  test_logger.info("Injecting F1SetupResponse");
  f1ap->handle_message(f1_setup_response);

  ASSERT_TRUE(t.ready());
  ASSERT_TRUE(t.get().success);
  ASSERT_EQ(t.get().msg->gnb_cu_rrc_version.value.latest_rrc_version.to_number(), 2U);
}

/// Test unsuccessful f1 setup procedure with time to wait and successful retry
TEST_F(f1ap_du_test, when_f1_setup_failure_with_time_to_wait_received_then_retry_with_success)
{
  // Action 1: Launch F1 setup procedure
  f1_setup_request_message request_msg = generate_f1_setup_request_message();
  test_logger.info("Launch f1 setup request procedure...");
  async_task<f1_setup_response_message>         t = f1ap->handle_f1_setup_request(request_msg);
  lazy_task_launcher<f1_setup_response_message> t_launcher(t);

  // Status: CU received F1 Setup Request.
  ASSERT_EQ(msg_notifier.last_f1ap_msg.pdu.type().value, asn1::f1ap::f1ap_pdu_c::types_opts::init_msg);
  ASSERT_EQ(msg_notifier.last_f1ap_msg.pdu.init_msg().value.type().value,
            asn1::f1ap::f1ap_elem_procs_o::init_msg_c::types_opts::f1_setup_request);

  // Status: Procedure not yet ready.
  ASSERT_FALSE(t.ready());

  // Action 2: F1 setup failure with time to wait received.
  unsigned     transaction_id = get_transaction_id(msg_notifier.last_f1ap_msg.pdu).value();
  f1ap_message f1_setup_failure =
      generate_f1_setup_failure_message(transaction_id, asn1::f1ap::time_to_wait_opts::v10s);
  test_logger.info("Injecting F1SetupFailure with time to wait");
  msg_notifier.last_f1ap_msg = {};
  f1ap->handle_message(f1_setup_failure);

  // Status: CU does not receive new F1 Setup Request until time-to-wait has ended.
  for (unsigned msec_elapsed = 0; msec_elapsed < 10000; ++msec_elapsed) {
    ASSERT_FALSE(t.ready());
    ASSERT_EQ(msg_notifier.last_f1ap_msg.pdu.type().value, asn1::f1ap::f1ap_pdu_c::types_opts::nulltype);

    this->timers.tick_all();
  }

  // Status: CU received F1 Setup Request again.
  ASSERT_EQ(msg_notifier.last_f1ap_msg.pdu.type().value, asn1::f1ap::f1ap_pdu_c::types_opts::init_msg);
  ASSERT_EQ(msg_notifier.last_f1ap_msg.pdu.init_msg().value.type().value,
            asn1::f1ap::f1ap_elem_procs_o::init_msg_c::types_opts::f1_setup_request);

  unsigned transaction_id2 = get_transaction_id(msg_notifier.last_f1ap_msg.pdu).value();
  EXPECT_NE(transaction_id, transaction_id2);

  // Successful outcome after reinitiated F1 Setup
  f1ap_message f1_setup_response = generate_f1_setup_response_message(transaction_id2);
  test_logger.info("Injecting F1SetupResponse");
  f1ap->handle_message(f1_setup_response);

  ASSERT_TRUE(t.ready());
  ASSERT_TRUE(t.get().success);
  ASSERT_EQ(t.get().msg->gnb_cu_rrc_version.value.latest_rrc_version.to_number(), 2U);
}

/// Test unsuccessful f1 setup procedure with time to wait and unsuccessful retry
TEST_F(f1ap_du_test, when_f1_setup_failure_with_time_to_wait_received_then_retry_without_success)
{
  // Action 1: Launch F1 setup procedure
  f1_setup_request_message request_msg = generate_f1_setup_request_message();
  test_logger.info("Launch f1 setup request procedure...");
  async_task<f1_setup_response_message>         t = f1ap->handle_f1_setup_request(request_msg);
  lazy_task_launcher<f1_setup_response_message> t_launcher(t);

  // Status: CU received F1 Setup Request.
  ASSERT_EQ(msg_notifier.last_f1ap_msg.pdu.type().value, asn1::f1ap::f1ap_pdu_c::types_opts::init_msg);
  ASSERT_EQ(msg_notifier.last_f1ap_msg.pdu.init_msg().value.type().value,
            asn1::f1ap::f1ap_elem_procs_o::init_msg_c::types_opts::f1_setup_request);

  // Status: Procedure not yet ready.
  EXPECT_FALSE(t.ready());

  // Action 2: F1 setup failure with time to wait received.
  unsigned     transaction_id = get_transaction_id(msg_notifier.last_f1ap_msg.pdu).value();
  f1ap_message f1_setup_failure =
      generate_f1_setup_failure_message(transaction_id, asn1::f1ap::time_to_wait_opts::v10s);
  test_logger.info("Injecting F1SetupFailure with time to wait");
  msg_notifier.last_f1ap_msg = {};
  f1ap->handle_message(f1_setup_failure);

  // Status: CU does not receive new F1 Setup Request until time-to-wait has ended.
  for (unsigned msec_elapsed = 0; msec_elapsed < 10000; ++msec_elapsed) {
    ASSERT_FALSE(t.ready());
    ASSERT_EQ(msg_notifier.last_f1ap_msg.pdu.type().value, asn1::f1ap::f1ap_pdu_c::types_opts::nulltype);

    this->timers.tick_all();
  }

  // Status: CU received F1 Setup Request again.
  ASSERT_EQ(msg_notifier.last_f1ap_msg.pdu.type().value, asn1::f1ap::f1ap_pdu_c::types_opts::init_msg);
  ASSERT_EQ(msg_notifier.last_f1ap_msg.pdu.init_msg().value.type().value,
            asn1::f1ap::f1ap_elem_procs_o::init_msg_c::types_opts::f1_setup_request);

  unsigned transaction_id2 = get_transaction_id(msg_notifier.last_f1ap_msg.pdu).value();
  EXPECT_NE(transaction_id, transaction_id2);

  // Unsuccessful outcome after reinitiated F1 Setup
  f1_setup_failure = generate_f1_setup_failure_message(transaction_id2);
  test_logger.info("Injecting F1SetupFailure");
  f1ap->handle_message(f1_setup_failure);

  ASSERT_TRUE(t.ready());
  EXPECT_FALSE(t.get().success);
}

/// Test the f1 setup procedure
TEST_F(f1ap_du_test, when_retry_limit_reached_then_du_not_connected)
{
  // Action 1: Launch F1 setup procedure
  f1_setup_request_message request_msg = generate_f1_setup_request_message();
  test_logger.info("Launch f1 setup request procedure...");
  async_task<f1_setup_response_message>         t = f1ap->handle_f1_setup_request(request_msg);
  lazy_task_launcher<f1_setup_response_message> t_launcher(t);

  // Status: CU received F1 Setup Request.
  ASSERT_EQ(msg_notifier.last_f1ap_msg.pdu.type().value, asn1::f1ap::f1ap_pdu_c::types_opts::init_msg);
  ASSERT_EQ(msg_notifier.last_f1ap_msg.pdu.init_msg().value.type().value,
            asn1::f1ap::f1ap_elem_procs_o::init_msg_c::types_opts::f1_setup_request);

  // Status: Procedure not yet ready.
  ASSERT_FALSE(t.ready());

  for (unsigned i = 0; i < request_msg.max_setup_retries; i++) {
    // Status: F1 setup failure received.
    unsigned     transaction_id = get_transaction_id(msg_notifier.last_f1ap_msg.pdu).value();
    f1ap_message f1_setup_response_msg =
        generate_f1_setup_failure_message(transaction_id, asn1::f1ap::time_to_wait_opts::v10s);
    msg_notifier.last_f1ap_msg = {};
    f1ap->handle_message(f1_setup_response_msg);

    // Status: CU does not receive new F1 Setup Request until time-to-wait has ended.
    for (unsigned msec_elapsed = 0; msec_elapsed < 10000; ++msec_elapsed) {
      ASSERT_FALSE(t.ready());
      ASSERT_EQ(msg_notifier.last_f1ap_msg.pdu.type().value, asn1::f1ap::f1ap_pdu_c::types_opts::nulltype);

      this->timers.tick_all();
    }
  }

  // Status: F1 setup failure received.
  unsigned     transaction_id = get_transaction_id(msg_notifier.last_f1ap_msg.pdu).value();
  f1ap_message f1_setup_response_msg =
      generate_f1_setup_failure_message(transaction_id, asn1::f1ap::time_to_wait_opts::v10s);
  msg_notifier.last_f1ap_msg = {};
  f1ap->handle_message(f1_setup_response_msg);

  ASSERT_TRUE(t.ready());
  ASSERT_FALSE(t.get().success);
  ASSERT_EQ(msg_notifier.last_f1ap_msg.pdu.type().value, asn1::f1ap::f1ap_pdu_c::types_opts::nulltype);
}
