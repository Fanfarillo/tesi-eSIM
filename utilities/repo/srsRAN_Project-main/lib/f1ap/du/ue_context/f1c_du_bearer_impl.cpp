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

#include "f1c_du_bearer_impl.h"
#include "../../../ran/gnb_format.h"
#include "du/procedures/f1ap_du_event_manager.h"

using namespace srsran::srs_du;

f1c_srb0_du_bearer::f1c_srb0_du_bearer(f1ap_ue_context&            ue_ctxt_,
                                       const asn1::f1ap::nr_cgi_s& nr_cgi_,
                                       const byte_buffer&          du_cu_rrc_container_,
                                       f1ap_message_notifier&      f1ap_notifier_,
                                       f1c_rx_sdu_notifier&        f1c_rx_sdu_notifier_,
                                       f1ap_event_manager&         ev_manager_) :
  ue_ctxt(ue_ctxt_),
  nr_cgi(nr_cgi_),
  du_cu_rrc_container(du_cu_rrc_container_.copy()),
  f1ap_notifier(f1ap_notifier_),
  sdu_notifier(f1c_rx_sdu_notifier_),
  ev_manager(ev_manager_),
  logger(srslog::fetch_basic_logger("DU-F1"))
{
}

void f1c_srb0_du_bearer::handle_sdu(byte_buffer_slice_chain sdu)
{
  protocol_transaction<f1ap_outcome> transaction = ev_manager.transactions.create_transaction();

  // Pack Initial UL RRC Message Transfer as per TS38.473, Section 8.4.1.
  f1ap_message msg;
  msg.pdu.set_init_msg().load_info_obj(ASN1_F1AP_ID_INIT_UL_RRC_MSG_TRANSFER);
  asn1::f1ap::init_ul_rrc_msg_transfer_s& init_msg = msg.pdu.init_msg().value.init_ul_rrc_msg_transfer();
  init_msg->gnb_du_ue_f1ap_id->value               = gnb_du_ue_f1ap_id_to_uint(ue_ctxt.gnb_du_ue_f1ap_id);
  init_msg->nr_cgi.value                           = nr_cgi;
  init_msg->c_rnti->value                          = ue_ctxt.rnti;
  init_msg->rrc_container.value.resize(sdu.length());
  std::copy(sdu.begin(), sdu.end(), init_msg->rrc_container->begin());
  init_msg->du_to_cu_rrc_container_present = true;
  init_msg->du_to_cu_rrc_container->resize(du_cu_rrc_container.length());
  std::copy(du_cu_rrc_container.begin(), du_cu_rrc_container.end(), init_msg->du_to_cu_rrc_container->begin());
  init_msg->sul_access_ind_present                   = false;
  init_msg->transaction_id->value                    = transaction.id();
  init_msg->ran_ue_id_present                        = false;
  init_msg->rrc_container_rrc_setup_complete_present = false;

  // Notify upper layers of the initial UL RRC Message Transfer.
  f1ap_notifier.on_new_message(msg);

  // Signal that the transaction has completed and the DU does not expect a response.
  if (not ev_manager.transactions.set(transaction.id(), f1ap_outcome{})) {
    logger.warning("Unexpected transaction id={}", transaction.id());
  }

  log_ue_event(logger,
               ue_event_prefix{"UL", ue_ctxt.ue_index}.set_channel("SRB0") | ue_ctxt.rnti,
               "InitialUlRrcMessageTransfer");
}

void f1c_srb0_du_bearer::handle_pdu(byte_buffer pdu)
{
  sdu_notifier.on_new_sdu(std::move(pdu));

  log_ue_event(
      logger, ue_event_prefix{"DL", ue_ctxt.ue_index}.set_channel("SRB0") | ue_ctxt.rnti, "DlRrcMessageTransfer");
}

f1c_other_srb_du_bearer::f1c_other_srb_du_bearer(f1ap_ue_context&       ue_ctxt_,
                                                 srb_id_t               srb_id_,
                                                 f1ap_message_notifier& f1ap_notifier_,
                                                 f1c_rx_sdu_notifier&   f1c_sdu_notifier_) :
  ue_ctxt(ue_ctxt_),
  srb_id(srb_id_),
  f1ap_notifier(f1ap_notifier_),
  sdu_notifier(f1c_sdu_notifier_),
  logger(srslog::fetch_basic_logger("DU-F1"))
{
}

void f1c_other_srb_du_bearer::handle_sdu(byte_buffer_slice_chain sdu)
{
  f1ap_message msg;

  // Fill F1AP UL RRC Message Transfer.
  msg.pdu.set_init_msg().load_info_obj(ASN1_F1AP_ID_UL_RRC_MSG_TRANSFER);
  asn1::f1ap::ul_rrc_msg_transfer_s& ul_msg = msg.pdu.init_msg().value.ul_rrc_msg_transfer();
  ul_msg->gnb_du_ue_f1ap_id->value          = gnb_du_ue_f1ap_id_to_uint(ue_ctxt.gnb_du_ue_f1ap_id);
  ul_msg->gnb_cu_ue_f1ap_id->value          = gnb_cu_ue_f1ap_id_to_uint(ue_ctxt.gnb_cu_ue_f1ap_id);
  ul_msg->srb_id->value                     = srb_id_to_uint(srb_id);
  ul_msg->rrc_container->resize(sdu.length());
  std::copy(sdu.begin(), sdu.end(), ul_msg->rrc_container->begin());
  ul_msg->sel_plmn_id_present           = false;
  ul_msg->new_gnb_du_ue_f1ap_id_present = false;

  f1ap_notifier.on_new_message(msg);

  log_ue_event(logger,
               ue_event_prefix{"UL", ue_ctxt.ue_index}.set_channel(srb_id_to_string(srb_id)) | ue_ctxt.rnti,
               "UL RRC Message Transfer.");
}

void f1c_other_srb_du_bearer::handle_pdu(srsran::byte_buffer sdu)
{
  sdu_notifier.on_new_sdu(std::move(sdu));

  log_ue_event(logger,
               ue_event_prefix{"DL", ue_ctxt.ue_index}.set_channel(srb_id_to_string(srb_id)) | ue_ctxt.rnti,
               "DL RRC Message Transfer.");
}