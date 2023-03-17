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

#include "f1ap_du_setup_procedure.h"
#include "../f1ap_du_context.h"
#include "srsran/support/async/async_timer.h"

using namespace srsran;
using namespace srsran::srs_du;
using namespace asn1::f1ap;

f1ap_du_setup_procedure::f1ap_du_setup_procedure(const f1_setup_request_message& request_,
                                                 f1ap_message_notifier&          cu_notif_,
                                                 f1ap_event_manager&             ev_mng_,
                                                 timer_manager&                  timers,
                                                 f1ap_du_context&                du_ctxt_) :
  request(request_),
  cu_notifier(cu_notif_),
  ev_mng(ev_mng_),
  logger(srslog::fetch_basic_logger("DU-F1")),
  du_ctxt(du_ctxt_),
  f1_setup_wait_timer(timers.create_unique_timer())
{
}

void f1ap_du_setup_procedure::operator()(coro_context<async_task<f1_setup_response_message>>& ctx)
{
  CORO_BEGIN(ctx);

  while (true) {
    transaction = ev_mng.transactions.create_transaction();

    // Send request to CU.
    send_f1_setup_request();

    // Await CU response.
    CORO_AWAIT(transaction);

    if (not retry_required()) {
      // No more attempts. Exit loop.
      break;
    }

    // Await timer.
    logger.debug("Received F1SetupFailure with Time to Wait IE - reinitiating F1 setup in {}s (retry={}/{})",
                 time_to_wait,
                 f1_setup_retry_no,
                 request.max_setup_retries);
    CORO_AWAIT(async_wait_for(f1_setup_wait_timer, time_to_wait * 1000));
  }

  // Forward procedure result to DU manager.
  CORO_RETURN(create_f1_setup_result());
}

void f1ap_du_setup_procedure::send_f1_setup_request()
{
  f1ap_message msg = {};
  // set F1AP PDU contents
  msg.pdu.set_init_msg();
  msg.pdu.init_msg().load_info_obj(ASN1_F1AP_ID_F1_SETUP);
  msg.pdu.init_msg().value.f1_setup_request() = request.msg;

  // set values handled by F1
  auto& setup_req                 = msg.pdu.init_msg().value.f1_setup_request();
  setup_req->transaction_id.value = transaction.id();

  // send request
  cu_notifier.on_new_message(msg);
}

bool f1ap_du_setup_procedure::retry_required()
{
  const f1ap_outcome& cu_pdu_response = transaction.result();
  if (cu_pdu_response.has_value()) {
    // Success case.
    return false;
  }

  if (cu_pdu_response.error().value.type().value !=
      f1ap_elem_procs_o::unsuccessful_outcome_c::types_opts::f1_setup_fail) {
    // Invalid response type.
    return false;
  }

  const f1_setup_fail_ies_container& f1_setup_fail = *cu_pdu_response.error().value.f1_setup_fail();
  if (not f1_setup_fail.time_to_wait_present) {
    // CU didn't command a waiting time.
    logger.error("CU-CP did not set any retry waiting time");
    return false;
  }
  if (f1_setup_retry_no++ >= request.max_setup_retries) {
    // Number of retries exceeded, or there is no time to wait.
    logger.error("Reached maximum number of F1 Setup connection retries ({})", request.max_setup_retries);
    return false;
  }

  time_to_wait = f1_setup_fail.time_to_wait->to_number();
  return true;
}

f1_setup_response_message f1ap_du_setup_procedure::create_f1_setup_result()
{
  const f1ap_outcome&       cu_pdu_response = transaction.result();
  f1_setup_response_message res{};

  if (cu_pdu_response.has_value() and cu_pdu_response.value().value.type().value ==
                                          f1ap_elem_procs_o::successful_outcome_c::types_opts::f1_setup_resp) {
    logger.debug("Received PDU with successful outcome");
    res.msg     = cu_pdu_response.value().value.f1_setup_resp();
    res.success = true;

    // Update F1 DU Context (taking values from request).
    du_ctxt.gnb_du_id   = request.msg->gnb_du_id->value;
    du_ctxt.gnb_du_name = request.msg->gnb_du_name->to_string();
    du_ctxt.served_cells.resize(request.msg->gnb_du_served_cells_list.value.size());
    for (unsigned i = 0; i != du_ctxt.served_cells.size(); ++i) {
      du_ctxt.served_cells[i] = request.msg->gnb_du_served_cells_list.value[i]->gnb_du_served_cells_item();
    }

  } else if (cu_pdu_response.has_value() or cu_pdu_response.error().value.type().value !=
                                                f1ap_elem_procs_o::unsuccessful_outcome_c::types_opts::f1_setup_fail) {
    logger.error("Received PDU with unexpected PDU type {}", cu_pdu_response.value().value.type().to_string());
    res.success = false;
  } else {
    logger.debug("Received PDU with unsuccessful outcome cause={}",
                 get_cause_str(cu_pdu_response.error().value.f1_setup_fail()->cause.value));
    res.success = false;
  }
  return res;
}
