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

#include "e1ap_cu_up_impl.h"
#include "../../ran/gnb_format.h"
#include "e1ap_cu_up_asn1_helpers.h"
#include "srsran/asn1/e1ap/e1ap.h"
#include "srsran/ran/bcd_helpers.h"

using namespace srsran;
using namespace asn1::e1ap;
using namespace srs_cu_up;

e1ap_cu_up_impl::e1ap_cu_up_impl(e1ap_message_notifier& e1ap_pdu_notifier_,
                                 e1ap_cu_up_notifier&   cu_up_notifier_,
                                 task_executor&         cu_up_exec_) :
  cu_up_exec(cu_up_exec_),
  logger(srslog::fetch_basic_logger("CU-UP-E1")),
  pdu_notifier(e1ap_pdu_notifier_),
  cu_up_notifier(cu_up_notifier_)
{
}

// Note: For fwd declaration of member types, dtor cannot be trivial.
e1ap_cu_up_impl::~e1ap_cu_up_impl() {}

void e1ap_cu_up_impl::handle_cu_cp_e1_setup_response(const cu_cp_e1_setup_response& msg)
{
  // Pack message into PDU
  e1ap_message e1ap_msg;
  if (msg.success) {
    logger.debug("Sending CuCpE1SetupResponse message");

    e1ap_msg.pdu.set_successful_outcome();
    e1ap_msg.pdu.successful_outcome().load_info_obj(ASN1_E1AP_ID_GNB_CU_CP_E1_SETUP);
    auto& setup_resp = e1ap_msg.pdu.successful_outcome().value.gnb_cu_cp_e1_setup_resp();

    setup_resp->gnb_cu_up_id.value = msg.gnb_cu_up_id.value();
    if (msg.gnb_cu_up_name.has_value()) {
      setup_resp->gnb_cu_up_name_present = true;
      setup_resp->gnb_cu_up_name.value.from_string(msg.gnb_cu_up_name.value());
    }

    // TODO: Add missing values

    // set values handled by E1
    setup_resp->transaction_id.value = current_transaction_id;

    // send response
    pdu_notifier.on_new_message(e1ap_msg);
  } else {
    logger.debug("Sending CuCpE1SetupFailure message");
    e1ap_msg.pdu.set_unsuccessful_outcome();
    e1ap_msg.pdu.unsuccessful_outcome().load_info_obj(ASN1_E1AP_ID_GNB_CU_CP_E1_SETUP);
    auto& setup_fail        = e1ap_msg.pdu.unsuccessful_outcome().value.gnb_cu_cp_e1_setup_fail();
    setup_fail->cause.value = cause_to_e1ap_cause(msg.cause.value());

    // set values handled by E1
    setup_fail->transaction_id.value = current_transaction_id;
    setup_fail->cause.value.set_radio_network();
    setup_fail->cause.value.radio_network() = asn1::e1ap::cause_radio_network_opts::options::no_radio_res_available;

    // send response
    pdu_notifier.on_new_message(e1ap_msg);
  }
}

void e1ap_cu_up_impl::handle_message(const e1ap_message& msg)
{
  // Run E1AP protocols in CU-UP executor.
  cu_up_exec.execute([this, msg]() {
    logger.debug("Handling PDU of type {}", msg.pdu.type().to_string());

    // Log message.
    expected<gnb_cu_up_ue_e1ap_id_t> gnb_cu_up_ue_e1ap_id = get_gnb_cu_up_ue_e1ap_id(msg.pdu);
    expected<uint8_t>                transaction_id       = get_transaction_id(msg.pdu);
    if (transaction_id.has_value()) {
      logger.debug("SDU \"{}.{}\" transaction id={}",
                   msg.pdu.type().to_string(),
                   get_message_type_str(msg.pdu),
                   transaction_id.value());
    } else if (gnb_cu_up_ue_e1ap_id.has_value()) {
      logger.debug("SDU \"{}.{}\" GNB-CU-UP-UE-E1AP-ID={}",
                   msg.pdu.type().to_string(),
                   get_message_type_str(msg.pdu),
                   gnb_cu_up_ue_e1ap_id.value());
    } else {
      logger.debug("SDU \"{}.{}\"", msg.pdu.type().to_string(), get_message_type_str(msg.pdu));
    }

    if (logger.debug.enabled()) {
      asn1::json_writer js;
      msg.pdu.to_json(js);
      logger.debug("Rx E1AP SDU: {}", js.to_string());
    }

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

void e1ap_cu_up_impl::handle_initiating_message(const asn1::e1ap::init_msg_s& msg)
{
  switch (msg.value.type().value) {
    case asn1::e1ap::e1ap_elem_procs_o::init_msg_c::types_opts::options::gnb_cu_cp_e1_setup_request: {
      current_transaction_id = msg.value.gnb_cu_cp_e1_setup_request()->transaction_id.value;
      handle_cu_cp_e1_setup_request(msg.value.gnb_cu_cp_e1_setup_request());
    } break;
    case asn1::e1ap::e1ap_elem_procs_o::init_msg_c::types_opts::options::bearer_context_setup_request: {
      handle_bearer_context_setup_request(msg.value.bearer_context_setup_request());
    } break;
    case asn1::e1ap::e1ap_elem_procs_o::init_msg_c::types_opts::options::bearer_context_mod_request: {
      handle_bearer_context_modification_request(msg.value.bearer_context_mod_request());
    } break;
    case asn1::e1ap::e1ap_elem_procs_o::init_msg_c::types_opts::options::bearer_context_release_cmd: {
      handle_bearer_context_release_command(msg.value.bearer_context_release_cmd());
    } break;
    default:
      logger.error("Initiating message of type {} is not supported", msg.value.type().to_string());
  }
}

void e1ap_cu_up_impl::handle_cu_cp_e1_setup_request(const asn1::e1ap::gnb_cu_cp_e1_setup_request_s& msg)
{
  cu_cp_e1_setup_request req_msg = {};

  if (msg->gnb_cu_cp_name_present) {
    req_msg.gnb_cu_cp_name = msg->gnb_cu_cp_name.value.to_string();
  }

  cu_up_notifier.on_cu_cp_e1_setup_request_received(req_msg);
}

void e1ap_cu_up_impl::handle_bearer_context_setup_request(const asn1::e1ap::bearer_context_setup_request_s& msg)
{
  // create failure message for early returns
  e1ap_message e1ap_msg;
  e1ap_msg.pdu.set_unsuccessful_outcome();
  e1ap_msg.pdu.unsuccessful_outcome().load_info_obj(ASN1_E1AP_ID_BEARER_CONTEXT_SETUP);
  e1ap_msg.pdu.unsuccessful_outcome().value.bearer_context_setup_fail()->gnb_cu_cp_ue_e1ap_id =
      msg->gnb_cu_cp_ue_e1ap_id;
  e1ap_msg.pdu.unsuccessful_outcome().value.bearer_context_setup_fail()->cause.value.set_protocol();

  // We only support NG-RAN Bearer
  if (msg->sys_bearer_context_setup_request.value.type() !=
      asn1::e1ap::sys_bearer_context_setup_request_c::types::ng_ran_bearer_context_setup_request) {
    logger.error("Not handling E-UTRAN Bearers");

    // send response
    logger.debug("Sending BearerContextSetupFailure message");
    pdu_notifier.on_new_message(e1ap_msg);
    return;
  }

  logger.debug("Received BearerContextSetupRequest (plmn={})", plmn_bcd_to_string(msg->serving_plmn.value.to_number()));

  gnb_cu_up_ue_e1ap_id_t cu_up_ue_e1ap_id = ue_ctxt_list.next_gnb_cu_up_ue_e1ap_id();
  if (cu_up_ue_e1ap_id == gnb_cu_up_ue_e1ap_id_t::invalid) {
    logger.error("No CU-UP UE E1AP ID available.");

    // send response
    logger.debug("Sending BearerContextSetupFailure message");
    pdu_notifier.on_new_message(e1ap_msg);
    return;
  }

  // Add gnb_cu_up_ue_e1ap_id to failure message
  e1ap_msg.pdu.unsuccessful_outcome().value.bearer_context_setup_fail()->gnb_cu_up_ue_e1ap_id.value =
      gnb_cu_up_ue_e1ap_id_to_uint(cu_up_ue_e1ap_id);

  // Forward message to CU-UP
  e1ap_bearer_context_setup_request bearer_context_setup = {};
  fill_e1ap_bearer_context_setup_request(bearer_context_setup, msg);

  e1ap_bearer_context_setup_response bearer_context_setup_response_msg =
      cu_up_notifier.on_bearer_context_setup_request_received(bearer_context_setup);

  if (bearer_context_setup_response_msg.ue_index == INVALID_UE_INDEX) {
    logger.error("Invalid UE index");

    // send response
    logger.debug("Sending BearerContextSetupFailure message");
    pdu_notifier.on_new_message(e1ap_msg);
    return;
  }

  // Create UE context and store it
  ue_ctxt_list.add_ue(bearer_context_setup_response_msg.ue_index,
                      cu_up_ue_e1ap_id,
                      int_to_gnb_cu_cp_ue_e1ap_id(msg->gnb_cu_cp_ue_e1ap_id.value));
  e1ap_ue_context& ue_ctxt = ue_ctxt_list[cu_up_ue_e1ap_id];

  logger.debug("ue={} Added UE context (gnb_cu_up_ue_e1ap_id={}, gnb_cu_cp_e1ap_ue_id={}).",
               ue_ctxt.ue_index,
               ue_ctxt.cu_up_ue_e1ap_id,
               ue_ctxt.cu_cp_ue_e1ap_id);

  if (bearer_context_setup_response_msg.success) {
    e1ap_msg.pdu.set_successful_outcome();
    e1ap_msg.pdu.successful_outcome().load_info_obj(ASN1_E1AP_ID_BEARER_CONTEXT_SETUP);
    e1ap_msg.pdu.successful_outcome().value.bearer_context_setup_resp()->gnb_cu_cp_ue_e1ap_id =
        msg->gnb_cu_cp_ue_e1ap_id;
    e1ap_msg.pdu.successful_outcome().value.bearer_context_setup_resp()->gnb_cu_up_ue_e1ap_id.value =
        gnb_cu_up_ue_e1ap_id_to_uint(cu_up_ue_e1ap_id);

    fill_asn1_bearer_context_setup_response(
        e1ap_msg.pdu.successful_outcome().value.bearer_context_setup_resp()->sys_bearer_context_setup_resp.value,
        bearer_context_setup_response_msg);

    // send response
    logger.debug("ue={} Sending BearerContextSetupResponse", ue_ctxt.ue_index);
    pdu_notifier.on_new_message(e1ap_msg);
  } else {
    e1ap_msg.pdu.unsuccessful_outcome().value.bearer_context_setup_fail()->cause.value =
        cause_to_e1ap_cause(bearer_context_setup_response_msg.cause.value());

    // send response
    logger.debug("ue={} Sending BearerContextSetupFailure", ue_ctxt.ue_index);
    pdu_notifier.on_new_message(e1ap_msg);
  }
}

void e1ap_cu_up_impl::handle_bearer_context_modification_request(const asn1::e1ap::bearer_context_mod_request_s& msg)
{
  // create failure message for early returns
  e1ap_message e1ap_msg;
  e1ap_msg.pdu.set_unsuccessful_outcome();
  e1ap_msg.pdu.unsuccessful_outcome().load_info_obj(ASN1_E1AP_ID_BEARER_CONTEXT_MOD);
  e1ap_msg.pdu.unsuccessful_outcome().value.bearer_context_mod_fail()->gnb_cu_cp_ue_e1ap_id = msg->gnb_cu_cp_ue_e1ap_id;
  e1ap_msg.pdu.unsuccessful_outcome().value.bearer_context_mod_fail()->gnb_cu_up_ue_e1ap_id = msg->gnb_cu_up_ue_e1ap_id;
  e1ap_msg.pdu.unsuccessful_outcome().value.bearer_context_mod_fail()->cause.value.set_protocol();

  e1ap_bearer_context_modification_request bearer_context_mod = {};

  e1ap_ue_context& ue_ctxt = ue_ctxt_list[int_to_gnb_cu_up_ue_e1ap_id(msg->gnb_cu_up_ue_e1ap_id.value)];
  if (ue_ctxt.cu_up_ue_e1ap_id == gnb_cu_up_ue_e1ap_id_t::invalid) {
    logger.error("No UE context for the received gnb_cu_up_ue_e1ap_id={} available.", msg->gnb_cu_up_ue_e1ap_id.value);

    // send response
    logger.debug("Sending BearerContextModificationFailure");
    pdu_notifier.on_new_message(e1ap_msg);
    return;
  }

  // sys bearer context mod request
  if (msg->sys_bearer_context_mod_request_present) {
    // We only support NG-RAN Bearer
    if (msg->sys_bearer_context_mod_request.value.type() !=
        asn1::e1ap::sys_bearer_context_mod_request_c::types::ng_ran_bearer_context_mod_request) {
      logger.error("ue={} Not handling E-UTRAN Bearers", ue_ctxt.ue_index);

      // send response
      logger.debug("ue={} Sending BearerContextModificationFailure", ue_ctxt.ue_index);
      pdu_notifier.on_new_message(e1ap_msg);
      return;
    }

    bearer_context_mod.ue_index = ue_ctxt.ue_index;
    bearer_context_mod.request  = msg->sys_bearer_context_mod_request.value;
  }

  // Forward message to CU-UP
  e1ap_bearer_context_modification_response ue_context_mod_response_msg =
      cu_up_notifier.on_bearer_context_modification_request_received(bearer_context_mod);

  if (ue_context_mod_response_msg.ue_index == INVALID_UE_INDEX) {
    logger.error("Invalid UE index");

    // send response
    logger.debug("Sending BearerContextModificationFailure");
    pdu_notifier.on_new_message(e1ap_msg);
    return;
  }

  if (ue_context_mod_response_msg.success) {
    e1ap_msg.pdu.set_successful_outcome();
    e1ap_msg.pdu.successful_outcome().load_info_obj(ASN1_E1AP_ID_BEARER_CONTEXT_MOD);
    e1ap_msg.pdu.successful_outcome().value.bearer_context_mod_resp()->gnb_cu_cp_ue_e1ap_id = msg->gnb_cu_cp_ue_e1ap_id;
    e1ap_msg.pdu.successful_outcome().value.bearer_context_mod_resp()->gnb_cu_up_ue_e1ap_id = msg->gnb_cu_up_ue_e1ap_id;
    e1ap_msg.pdu.successful_outcome().value.bearer_context_mod_resp()->sys_bearer_context_mod_resp.value =
        ue_context_mod_response_msg.sys_bearer_context_modification_resp;

    // send response
    logger.debug("ue={} Sending BearerContextModificationResponse", ue_ctxt.ue_index);
    pdu_notifier.on_new_message(e1ap_msg);
  } else {
    e1ap_msg.pdu.unsuccessful_outcome().value.bearer_context_mod_fail()->cause.value =
        ue_context_mod_response_msg.cause;

    // send response
    logger.debug("ue={} Sending BearerContextModificationFailure", ue_ctxt.ue_index);
    pdu_notifier.on_new_message(e1ap_msg);
  }
}

void e1ap_cu_up_impl::handle_bearer_context_release_command(const asn1::e1ap::bearer_context_release_cmd_s& msg)
{
  e1ap_bearer_context_release_command bearer_context_release_cmd = {};

  e1ap_ue_context& ue_ctxt = ue_ctxt_list[int_to_gnb_cu_up_ue_e1ap_id(msg->gnb_cu_up_ue_e1ap_id.value)];
  if (ue_ctxt.cu_up_ue_e1ap_id == gnb_cu_up_ue_e1ap_id_t::invalid) {
    logger.error("No UE context for the received gnb_cu_up_ue_e1ap_id={} available", msg->gnb_cu_up_ue_e1ap_id.value);
    return;
  }

  bearer_context_release_cmd.ue_index = ue_ctxt.ue_index;
  bearer_context_release_cmd.cause    = msg->cause.value;

  // Forward message to CU-UP
  cu_up_notifier.on_bearer_context_release_command_received(bearer_context_release_cmd);

  // Remove UE context
  ue_ctxt_list.remove_ue(ue_ctxt.ue_index);

  e1ap_message e1ap_msg;
  e1ap_msg.pdu.set_successful_outcome();
  e1ap_msg.pdu.successful_outcome().load_info_obj(ASN1_E1AP_ID_BEARER_CONTEXT_RELEASE);
  e1ap_msg.pdu.successful_outcome().value.bearer_context_release_complete()->gnb_cu_cp_ue_e1ap_id =
      msg->gnb_cu_cp_ue_e1ap_id;
  e1ap_msg.pdu.successful_outcome().value.bearer_context_release_complete()->gnb_cu_up_ue_e1ap_id =
      msg->gnb_cu_up_ue_e1ap_id;

  // send response
  logger.debug("ue={} Sending BearerContextReleaseComplete", bearer_context_release_cmd.ue_index);
  pdu_notifier.on_new_message(e1ap_msg);
}

void e1ap_cu_up_impl::handle_successful_outcome(const asn1::e1ap::successful_outcome_s& outcome)
{
  switch (outcome.value.type().value) {
    default:
      // Handle successful outcomes with transaction id
      expected<uint8_t> transaction_id = get_transaction_id(outcome);
      if (transaction_id.is_error()) {
        logger.error("Successful outcome of type {} is not supported", outcome.value.type().to_string());
        return;
      }
  }
}

void e1ap_cu_up_impl::handle_unsuccessful_outcome(const asn1::e1ap::unsuccessful_outcome_s& outcome)
{
  switch (outcome.value.type().value) {
    default:
      // Handle unsuccessful outcomes with transaction id
      expected<uint8_t> transaction_id = get_transaction_id(outcome);
      if (transaction_id.is_error()) {
        logger.error("Unsuccessful outcome of type {} is not supported", outcome.value.type().to_string());
        return;
      }
  }
}
