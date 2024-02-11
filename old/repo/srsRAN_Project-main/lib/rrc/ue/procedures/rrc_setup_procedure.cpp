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

#include "rrc_setup_procedure.h"
#include "../rrc_asn1_helpers.h"

using namespace srsran;
using namespace srsran::srs_cu_cp;
using namespace asn1::rrc_nr;

rrc_setup_procedure::rrc_setup_procedure(rrc_ue_context_t&                        context_,
                                         const asn1::rrc_nr::rrc_setup_request_s& request_,
                                         const byte_buffer&                       du_to_cu_container_,
                                         rrc_ue_setup_proc_notifier&              rrc_ue_notifier_,
                                         rrc_ue_du_processor_notifier&            du_processor_notifier_,
                                         rrc_ue_nas_notifier&                     nas_notifier_,
                                         rrc_ue_event_manager&                    event_mng_,
                                         srslog::basic_logger&                    logger_) :
  context(context_),
  request(request_),
  du_to_cu_container(du_to_cu_container_),
  rrc_ue(rrc_ue_notifier_),
  du_processor_notifier(du_processor_notifier_),
  nas_notifier(nas_notifier_),
  event_mng(event_mng_),
  logger(logger_)
{
}

void rrc_setup_procedure::operator()(coro_context<async_task<void>>& ctx)
{
  CORO_BEGIN(ctx);

  // create SRB1
  create_srb1();

  // create new transaction for RRCSetup
  transaction = event_mng.transactions.create_transaction(rrc_setup_timeout_ms);

  // send RRC setup to UE
  send_rrc_setup();

  // Await UE response
  CORO_AWAIT(transaction);

  auto coro_res = transaction.result();
  if (coro_res.has_value()) {
    logger.debug("ue={} \"{}\" finished successfully", context.ue_index, name());
    context.state = rrc_state::connected;
    send_initial_ue_msg(coro_res.value().msg.c1().rrc_setup_complete());
  } else {
    logger.debug("ue={} \"{}\" timed out", context.ue_index, name());
    rrc_ue.on_ue_delete_request();
  }

  CORO_RETURN();
}

void rrc_setup_procedure::create_srb1()
{
  // create SRB1
  srb_creation_message srb1_msg{};
  srb1_msg.ue_index = context.ue_index;
  srb1_msg.srb_id   = srb_id_t::srb1;
  srb1_msg.pdcp_cfg = srb1_pdcp_cfg;
  du_processor_notifier.on_create_srb(srb1_msg);
}

void rrc_setup_procedure::send_rrc_setup()
{
  dl_ccch_msg_s dl_ccch_msg;
  dl_ccch_msg.msg.set_c1().set_rrc_setup();
  rrc_setup_s& rrc_setup = dl_ccch_msg.msg.c1().rrc_setup();
  fill_asn1_rrc_setup_msg(rrc_setup, du_to_cu_container, transaction.id());
  rrc_ue.on_new_dl_ccch(dl_ccch_msg);
}

void rrc_setup_procedure::send_initial_ue_msg(const asn1::rrc_nr::rrc_setup_complete_s& rrc_setup_complete_msg)
{
  initial_ue_message init_ue_msg = {};
  init_ue_msg.ue_index           = context.ue_index;

  auto& ded_nas_msg = rrc_setup_complete_msg.crit_exts.rrc_setup_complete().ded_nas_msg;
  init_ue_msg.nas_pdu.resize(ded_nas_msg.size());
  std::copy(ded_nas_msg.begin(), ded_nas_msg.end(), init_ue_msg.nas_pdu.begin());

  init_ue_msg.establishment_cause = request.rrc_setup_request.establishment_cause;
  init_ue_msg.cell                = context.cell;

  nas_notifier.on_initial_ue_message(init_ue_msg);
}
