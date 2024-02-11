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
#include "srsran/support/async/async_test_utils.h"
#include "srsran/support/test_utils.h"
#include <gtest/gtest.h>

using namespace srsran;
using namespace srs_cu_cp;
using namespace asn1::f1ap;

class f1ap_cu_ue_context_setup_test : public f1ap_cu_test
{
protected:
  void start_procedure(const f1ap_ue_context_setup_request& req)
  {
    t = f1ap->handle_ue_context_setup_request(req);
    t_launcher.emplace(t);

    EXPECT_EQ(this->f1ap_pdu_notifier.last_f1ap_msg.pdu.init_msg().value.type().value,
              f1ap_elem_procs_o::init_msg_c::types::ue_context_setup_request);

    test_ues[req.ue_index].cu_ue_id = int_to_gnb_cu_ue_f1ap_id(
        this->f1ap_pdu_notifier.last_f1ap_msg.pdu.init_msg().value.ue_context_setup_request()->gnb_cu_ue_f1ap_id.value);
  }

  bool was_ue_context_setup_request_sent(gnb_du_ue_f1ap_id_t du_ue_id) const
  {
    if (this->f1ap_pdu_notifier.last_f1ap_msg.pdu.type().value != f1ap_pdu_c::types::init_msg) {
      return false;
    }
    if (this->f1ap_pdu_notifier.last_f1ap_msg.pdu.init_msg().value.type().value !=
        asn1::f1ap::f1ap_elem_procs_o::init_msg_c::types_opts::ue_context_setup_request) {
      return false;
    }
    auto& req = this->f1ap_pdu_notifier.last_f1ap_msg.pdu.init_msg().value.ue_context_setup_request();

    return req->gnb_du_ue_f1ap_id.value == (unsigned)du_ue_id;
  }

  bool was_ue_context_setup_response_received(gnb_du_ue_f1ap_id_t du_ue_id, gnb_cu_ue_f1ap_id_t cu_ue_id) const
  {
    if (not t.ready() or not t.get().success) {
      return false;
    }
    return int_to_gnb_du_ue_f1ap_id(t.get().response->gnb_du_ue_f1ap_id.value) == du_ue_id and
           int_to_gnb_cu_ue_f1ap_id(t.get().response->gnb_cu_ue_f1ap_id->value) == cu_ue_id;
  }

  bool was_ue_context_setup_failure_received(gnb_du_ue_f1ap_id_t du_ue_id, gnb_cu_ue_f1ap_id_t cu_ue_id) const
  {
    if (not t.ready() or t.get().success) {
      return false;
    }
    return int_to_gnb_du_ue_f1ap_id(t.get().failure->gnb_du_ue_f1ap_id.value) == du_ue_id and
           int_to_gnb_cu_ue_f1ap_id(t.get().failure->gnb_cu_ue_f1ap_id->value) == cu_ue_id;
  }

  async_task<f1ap_ue_context_setup_response>                   t;
  optional<lazy_task_launcher<f1ap_ue_context_setup_response>> t_launcher;
};

TEST_F(f1ap_cu_ue_context_setup_test, when_request_sent_then_procedure_waits_for_response)
{
  // Test Preamble.
  test_ue& u = create_ue(int_to_gnb_du_ue_f1ap_id(test_rgen::uniform_int<uint32_t>()));

  // Start UE CONTEXT SETUP procedure.
  this->start_procedure(create_ue_context_setup_request(u.ue_index, {drb_id_t::drb1}));

  // The UE CONTEXT SETUP was sent to DU and F1AP-CU is waiting for response.
  ASSERT_TRUE(was_ue_context_setup_request_sent(*u.du_ue_id));
  ASSERT_FALSE(t.ready());
}

TEST_F(f1ap_cu_ue_context_setup_test, when_response_received_then_procedure_successful)
{
  // Test Preamble.
  test_ue& u = create_ue(int_to_gnb_du_ue_f1ap_id(test_rgen::uniform_int<uint32_t>()));

  // Start UE CONTEXT SETUP procedure and return back the response from the DU.
  this->start_procedure(create_ue_context_setup_request(u.ue_index, {drb_id_t::drb1}));
  f1ap_message response = generate_ue_context_setup_response(*u.cu_ue_id, *u.du_ue_id);
  f1ap->handle_message(response);

  // The UE CONTEXT SETUP RESPONSE was received and the F1AP-CU completed the procedure.
  ASSERT_TRUE(was_ue_context_setup_response_received(*u.du_ue_id, *u.cu_ue_id));
}

TEST_F(f1ap_cu_ue_context_setup_test, when_ue_setup_failure_received_then_procedure_unsuccessful)
{
  // Test Preamble.
  test_ue& u = create_ue(int_to_gnb_du_ue_f1ap_id(test_rgen::uniform_int<uint32_t>()));

  // Start UE CONTEXT SETUP procedure and return back the failure response from the DU.
  this->start_procedure(create_ue_context_setup_request(u.ue_index, {drb_id_t::drb1}));
  f1ap_message response = generate_ue_context_setup_failure(*u.cu_ue_id, *u.du_ue_id);
  f1ap->handle_message(response);

  // The UE CONTEXT SETUP FAILURE was received and the F1AP-CU completed the procedure with failure.
  ASSERT_TRUE(was_ue_context_setup_failure_received(*u.du_ue_id, *u.cu_ue_id));
}
