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

#include "ue_context_modification_procedure.h"
#include "../../common/asn1_helpers.h"
#include "../f1ap_asn1_helpers.h"

using namespace srsran;
using namespace srsran::srs_cu_cp;
using namespace asn1::f1ap;

ue_context_modification_procedure::ue_context_modification_procedure(
    const cu_cp_ue_context_modification_request& request_,
    f1ap_ue_context&                             ue_ctx_,
    f1ap_message_notifier&                       f1ap_notif_,
    srslog::basic_logger&                        logger_) :
  request(request_), ue_ctx(ue_ctx_), f1ap_notifier(f1ap_notif_), logger(logger_)
{
}

void ue_context_modification_procedure::operator()(
    coro_context<async_task<cu_cp_ue_context_modification_response>>& ctx)
{
  CORO_BEGIN(ctx);

  // Subscribe to respective publisher to receive UE CONTEXT MODIFICATION RESPONSE/FAILURE message.
  transaction_sink.subscribe_to(ue_ctx.ev_mng.context_modification_outcome);

  // Send command to DU.
  send_ue_context_modification_request();

  // Await CU response.
  CORO_AWAIT(transaction_sink);

  // Handle response from DU and return UE index
  CORO_RETURN(create_ue_context_modification_result());
}

void ue_context_modification_procedure::send_ue_context_modification_request()
{
  // Pack message into PDU
  f1ap_message f1ap_ue_ctxt_mod_request_msg;
  f1ap_ue_ctxt_mod_request_msg.pdu.set_init_msg().load_info_obj(ASN1_F1AP_ID_UE_CONTEXT_MOD);
  ue_context_mod_request_s& ctx_mod = f1ap_ue_ctxt_mod_request_msg.pdu.init_msg().value.ue_context_mod_request();

  fill_f1ap_ue_context_modification_request(ctx_mod, request);

  ctx_mod->gnb_du_ue_f1ap_id->value = gnb_du_ue_f1ap_id_to_uint(ue_ctx.du_ue_f1ap_id);
  ctx_mod->gnb_cu_ue_f1ap_id->value = gnb_cu_ue_f1ap_id_to_uint(ue_ctx.cu_ue_f1ap_id);

  if (logger.debug.enabled()) {
    asn1::json_writer js;
    f1ap_ue_ctxt_mod_request_msg.pdu.to_json(js);
    logger.debug("Containerized UeContextModificationRequest: {}", js.to_string());
  }

  // send UE context modification request message
  f1ap_notifier.on_new_message(f1ap_ue_ctxt_mod_request_msg);
}

cu_cp_ue_context_modification_response ue_context_modification_procedure::create_ue_context_modification_result()
{
  cu_cp_ue_context_modification_response res{};

  if (transaction_sink.successful()) {
    const asn1::f1ap::ue_context_mod_resp_s& resp = transaction_sink.response();
    logger.debug("Received UeContextModificationResponse");
    if (logger.debug.enabled()) {
      asn1::json_writer js;
      resp.to_json(js);
      logger.debug("Containerized UeContextModificationResponse: {}", js.to_string());
    }
    fill_f1ap_ue_context_modification_response_message(res, resp);
  } else if (transaction_sink.failed()) {
    const asn1::f1ap::ue_context_mod_fail_s& fail = transaction_sink.failure();
    logger.debug("Received UeContextModificationFailure cause={}", get_cause_str(fail->cause.value));
    if (logger.debug.enabled()) {
      asn1::json_writer js;
      (*transaction_sink.failure()).to_json(js);
      logger.debug("Containerized UeContextModificationFailure: {}", js.to_string());
    }
    fill_f1ap_ue_context_modification_response_message(res, fail);
  } else {
    logger.warning("UeContextModificationResponse timeout");
    res.success = false;
    res.cause   = cause_t::misc;
  }

  return res;
}
