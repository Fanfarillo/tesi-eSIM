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

#include "e1ap_cu_cp_impl.h"
#include "../../ran/gnb_format.h"
#include "../common/e1ap_asn1_helpers.h"
#include "e1ap_cu_cp_asn1_helpers.h"
#include "srsran/asn1/e1ap/e1ap.h"

using namespace srsran;
using namespace asn1::e1ap;
using namespace srs_cu_cp;

e1ap_cu_cp_impl::e1ap_cu_cp_impl(timer_manager&                 timers_,
                                 e1ap_message_notifier&         e1ap_pdu_notifier_,
                                 e1ap_cu_up_processor_notifier& e1ap_cu_up_processor_notifier_,
                                 task_executor&                 ctrl_exec_) :
  logger(srslog::fetch_basic_logger("CU-CP-E1")),
  timers(timers_),
  ue_ctxt_list(timers),
  ev_mng(timers),
  pdu_notifier(e1ap_pdu_notifier_),
  cu_up_processor_notifier(e1ap_cu_up_processor_notifier_),
  ctrl_exec(ctrl_exec_)
{
}

// Note: For fwd declaration of member types, dtor cannot be trivial.
e1ap_cu_cp_impl::~e1ap_cu_cp_impl() {}

void e1ap_cu_cp_impl::handle_cu_up_e1_setup_response(const cu_up_e1_setup_response& msg)
{
  // Pack message into PDU
  e1ap_message e1ap_msg;
  if (msg.success) {
    logger.debug("Sending CuUpE1SetupResponse");

    e1ap_msg.pdu.set_successful_outcome();
    e1ap_msg.pdu.successful_outcome().load_info_obj(ASN1_E1AP_ID_GNB_CU_UP_E1_SETUP);
    auto& setup_resp = e1ap_msg.pdu.successful_outcome().value.gnb_cu_up_e1_setup_resp();

    if (msg.gnb_cu_cp_name.has_value()) {
      setup_resp->gnb_cu_cp_name.value.from_string(msg.gnb_cu_cp_name.value());
    }

    // set values handled by E1AP
    e1ap_msg.pdu.successful_outcome().value.gnb_cu_up_e1_setup_resp()->transaction_id.value = current_transaction_id;

    // send response
    pdu_notifier.on_new_message(e1ap_msg);
  } else {
    logger.debug("Sending CuUpE1SetupFailure");
    e1ap_msg.pdu.set_unsuccessful_outcome();
    e1ap_msg.pdu.unsuccessful_outcome().load_info_obj(ASN1_E1AP_ID_GNB_CU_UP_E1_SETUP);
    e1ap_msg.pdu.unsuccessful_outcome().value.gnb_cu_up_e1_setup_fail();
    auto& setup_fail        = e1ap_msg.pdu.unsuccessful_outcome().value.gnb_cu_up_e1_setup_fail();
    setup_fail->cause.value = cause_to_e1ap_cause(msg.cause.value());

    // set values handled by E1
    setup_fail->transaction_id.value = current_transaction_id;
    setup_fail->cause.value.set_radio_network();
    setup_fail->cause.value.radio_network() = asn1::e1ap::cause_radio_network_opts::options::no_radio_res_available;

    // send response
    pdu_notifier.on_new_message(e1ap_msg);
  }
}

async_task<cu_cp_e1_setup_response>
e1ap_cu_cp_impl::handle_cu_cp_e1_setup_request(const cu_cp_e1_setup_request& request)
{
  return launch_async<cu_cp_e1_setup_procedure>(request, pdu_notifier, ev_mng, timers, logger);
}

async_task<e1ap_bearer_context_setup_response>
e1ap_cu_cp_impl::handle_bearer_context_setup_request(const e1ap_bearer_context_setup_request& request)
{
  gnb_cu_cp_ue_e1ap_id_t cu_cp_ue_e1ap_id = ue_ctxt_list.next_gnb_cu_cp_ue_e1ap_id();
  if (cu_cp_ue_e1ap_id == gnb_cu_cp_ue_e1ap_id_t::invalid) {
    logger.error("No CU-CP UE E1AP ID available");
    return launch_async([](coro_context<async_task<e1ap_bearer_context_setup_response>>& ctx) mutable {
      CORO_BEGIN(ctx);
      e1ap_bearer_context_setup_response res;
      res.success = false;
      CORO_RETURN(res);
    });
  }

  // add new e1ap_ue_context
  ue_ctxt_list.add_ue(request.ue_index, cu_cp_ue_e1ap_id);
  e1ap_ue_context& ue_ctxt = ue_ctxt_list[cu_cp_ue_e1ap_id];

  logger.debug("ue={} Added UE (cu_cp_ue_e1ap_id={})", request.ue_index, cu_cp_ue_e1ap_id);

  e1ap_message e1ap_msg;
  e1ap_msg.pdu.set_init_msg();
  e1ap_msg.pdu.init_msg().load_info_obj(ASN1_E1AP_ID_BEARER_CONTEXT_SETUP);

  auto& bearer_context_setup_request = e1ap_msg.pdu.init_msg().value.bearer_context_setup_request();

  fill_asn1_bearer_context_setup_request(bearer_context_setup_request, request);
  bearer_context_setup_request->gnb_cu_cp_ue_e1ap_id.value = gnb_cu_cp_ue_e1ap_id_to_uint(ue_ctxt.cu_cp_ue_e1ap_id);

  return launch_async<bearer_context_setup_procedure>(e1ap_msg, ue_ctxt, pdu_notifier, logger);
}

async_task<e1ap_bearer_context_modification_response>
e1ap_cu_cp_impl::handle_bearer_context_modification_request(const e1ap_bearer_context_modification_request& request)
{
  // Get UE context
  e1ap_ue_context& ue_ctxt = ue_ctxt_list[request.ue_index];

  e1ap_message e1ap_msg;
  e1ap_msg.pdu.set_init_msg();
  e1ap_msg.pdu.init_msg().load_info_obj(ASN1_E1AP_ID_BEARER_CONTEXT_MOD);

  auto& bearer_context_mod_request                       = e1ap_msg.pdu.init_msg().value.bearer_context_mod_request();
  bearer_context_mod_request->gnb_cu_cp_ue_e1ap_id.value = gnb_cu_cp_ue_e1ap_id_to_uint(ue_ctxt.cu_cp_ue_e1ap_id);
  bearer_context_mod_request->gnb_cu_up_ue_e1ap_id.value = gnb_cu_up_ue_e1ap_id_to_uint(ue_ctxt.cu_up_ue_e1ap_id);

  fill_asn1_bearer_context_modification_request(bearer_context_mod_request, request);

  return launch_async<bearer_context_modification_procedure>(e1ap_msg, ue_ctxt, pdu_notifier, logger);
}

async_task<void>
e1ap_cu_cp_impl::handle_bearer_context_release_command(const e1ap_bearer_context_release_command& command)
{
  if (!ue_ctxt_list.contains(command.ue_index)) {
    logger.error("ue={} Can't find bearer to release", command.ue_index);
    return launch_async([](coro_context<async_task<void>>& ctx) mutable {
      CORO_BEGIN(ctx);
      CORO_RETURN();
    });
  }

  // Get UE context
  e1ap_ue_context& ue_ctxt = ue_ctxt_list[command.ue_index];

  e1ap_message e1ap_msg;
  e1ap_msg.pdu.set_init_msg();
  e1ap_msg.pdu.init_msg().load_info_obj(ASN1_E1AP_ID_BEARER_CONTEXT_RELEASE);
  auto& bearer_context_release_cmd                       = e1ap_msg.pdu.init_msg().value.bearer_context_release_cmd();
  bearer_context_release_cmd->gnb_cu_cp_ue_e1ap_id.value = gnb_cu_cp_ue_e1ap_id_to_uint(ue_ctxt.cu_cp_ue_e1ap_id);
  bearer_context_release_cmd->gnb_cu_up_ue_e1ap_id.value = gnb_cu_up_ue_e1ap_id_to_uint(ue_ctxt.cu_up_ue_e1ap_id);

  fill_asn1_bearer_context_release_command(bearer_context_release_cmd, command);

  return launch_async<bearer_context_release_procedure>(command.ue_index, e1ap_msg, ue_ctxt_list, pdu_notifier, logger);
}

void e1ap_cu_cp_impl::handle_message(const e1ap_message& msg)
{
  logger.debug("Handling PDU of type {}", msg.pdu.type().to_string());

  // Log message.
  expected<gnb_cu_cp_ue_e1ap_id_t> gnb_cu_cp_ue_e1ap_id = get_gnb_cu_cp_ue_e1ap_id(msg.pdu);
  expected<uint8_t>                transaction_id       = get_transaction_id(msg.pdu);
  if (transaction_id.has_value()) {
    logger.debug("SDU \"{}.{}\" transaction id={}",
                 msg.pdu.type().to_string(),
                 get_message_type_str(msg.pdu),
                 transaction_id.value());
  } else if (gnb_cu_cp_ue_e1ap_id.has_value()) {
    logger.debug("SDU \"{}.{}\" GNB-CU-CP-UE-E1AP-ID={}",
                 msg.pdu.type().to_string(),
                 get_message_type_str(msg.pdu),
                 gnb_cu_cp_ue_e1ap_id.value());
  } else {
    logger.debug("SDU \"{}.{}\"", msg.pdu.type().to_string(), get_message_type_str(msg.pdu));
  }

  // Run E1AP protocols in Control executor.
  ctrl_exec.execute([this, msg]() {
    switch (msg.pdu.type().value) {
      case asn1::e1ap::e1ap_pdu_c::types_opts::init_msg:
        handle_initiating_message(msg.pdu.init_msg());
        break;
      case asn1::e1ap::e1ap_pdu_c::types_opts::successful_outcome:
        handle_successful_outcome(msg.pdu.successful_outcome());
        break;
      case asn1::e1ap::e1ap_pdu_c::types_opts::unsuccessful_outcome:
        handle_unsuccessful_outcome(msg.pdu.unsuccessful_outcome());
        break;
      default:
        logger.error("Invalid PDU type");
        break;
    }
  });
}

void e1ap_cu_cp_impl::handle_initiating_message(const asn1::e1ap::init_msg_s& msg)
{
  switch (msg.value.type().value) {
    case asn1::e1ap::e1ap_elem_procs_o::init_msg_c::types_opts::options::gnb_cu_up_e1_setup_request: {
      current_transaction_id     = msg.value.gnb_cu_up_e1_setup_request()->transaction_id.value;
      cu_up_e1_setup_request req = {};
      fill_e1ap_cu_up_e1_setup_request(req, msg.value.gnb_cu_up_e1_setup_request());
      cu_up_processor_notifier.on_cu_up_e1_setup_request_received(req);
    } break;
    default:
      logger.error("Initiating message of type {} is not supported", msg.value.type().to_string());
  }
}

void e1ap_cu_cp_impl::handle_successful_outcome(const asn1::e1ap::successful_outcome_s& outcome)
{
  switch (outcome.value.type().value) {
    case asn1::e1ap::e1ap_elem_procs_o::successful_outcome_c::types_opts::bearer_context_setup_resp: {
      ue_ctxt_list[int_to_gnb_cu_cp_ue_e1ap_id(outcome.value.bearer_context_setup_resp()->gnb_cu_cp_ue_e1ap_id->value)]
          .bearer_ev_mng.context_setup_outcome.set(outcome.value.bearer_context_setup_resp());
    } break;
    case asn1::e1ap::e1ap_elem_procs_o::successful_outcome_c::types_opts::bearer_context_mod_resp: {
      ue_ctxt_list[int_to_gnb_cu_cp_ue_e1ap_id(outcome.value.bearer_context_mod_resp()->gnb_cu_cp_ue_e1ap_id->value)]
          .bearer_ev_mng.context_modification_outcome.set(outcome.value.bearer_context_mod_resp());
    } break;
    case asn1::e1ap::e1ap_elem_procs_o::successful_outcome_c::types_opts::bearer_context_release_complete: {
      ue_ctxt_list[int_to_gnb_cu_cp_ue_e1ap_id(
                       outcome.value.bearer_context_release_complete()->gnb_cu_cp_ue_e1ap_id->value)]
          .bearer_ev_mng.context_release_complete.set(outcome.value.bearer_context_release_complete());
    } break;
    default:
      // Handle successful outcomes with transaction id
      expected<uint8_t> transaction_id = get_transaction_id(outcome);
      if (transaction_id.is_error()) {
        logger.error("Successful outcome of type {} is not supported", outcome.value.type().to_string());
        return;
      }

      // Set transaction result and resume suspended procedure.
      if (not ev_mng.transactions.set(transaction_id.value(), outcome)) {
        logger.warning("Ignoring message. Cause: Transaction with id={} has already completed.",
                       transaction_id.value());
      }
  }
}

void e1ap_cu_cp_impl::handle_unsuccessful_outcome(const asn1::e1ap::unsuccessful_outcome_s& outcome)
{
  switch (outcome.value.type().value) {
    case asn1::e1ap::e1ap_elem_procs_o::unsuccessful_outcome_c::types_opts::bearer_context_setup_fail: {
      ue_ctxt_list[int_to_gnb_cu_cp_ue_e1ap_id(outcome.value.bearer_context_setup_fail()->gnb_cu_cp_ue_e1ap_id->value)]
          .bearer_ev_mng.context_setup_outcome.set(outcome.value.bearer_context_setup_fail());
    } break;
    case asn1::e1ap::e1ap_elem_procs_o::unsuccessful_outcome_c::types_opts::bearer_context_mod_fail: {
      ue_ctxt_list[int_to_gnb_cu_cp_ue_e1ap_id(outcome.value.bearer_context_mod_fail()->gnb_cu_cp_ue_e1ap_id->value)]
          .bearer_ev_mng.context_modification_outcome.set(outcome.value.bearer_context_mod_fail());
    } break;
    default:
      // Handle unsuccessful outcomes with transaction id
      expected<uint8_t> transaction_id = get_transaction_id(outcome);
      if (transaction_id.is_error()) {
        logger.error("Unsuccessful outcome of type {} is not supported", outcome.value.type().to_string());
        return;
      }

      // Set transaction result and resume suspended procedure.
      if (not ev_mng.transactions.set(transaction_id.value(), outcome)) {
        logger.warning("Ignoring message. Cause: Transaction with id={} has already completed.",
                       transaction_id.value());
      }
  }
}
