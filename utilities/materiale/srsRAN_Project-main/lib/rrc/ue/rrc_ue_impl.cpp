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

#include "rrc_ue_impl.h"
#include "../../ran/gnb_format.h"
#include "srsran/support/srsran_assert.h"

using namespace srsran;
using namespace srs_cu_cp;
using namespace asn1::rrc_nr;

rrc_ue_impl::rrc_ue_impl(rrc_ue_du_processor_notifier&          du_proc_notif_,
                         rrc_ue_nas_notifier&                   nas_notif_,
                         rrc_ue_control_notifier&               ngap_ctrl_notif_,
                         const ue_index_t                       ue_index_,
                         const rnti_t                           c_rnti_,
                         const rrc_cell_context                 cell_,
                         const rrc_ue_cfg_t&                    cfg_,
                         const srb_notifiers_array&             srbs_,
                         const asn1::unbounded_octstring<true>& du_to_cu_container_,
                         rrc_ue_task_scheduler&                 task_sched_,
                         bool&                                  reject_users_) :
  context(ue_index_, c_rnti_, cell_, cfg_),
  du_processor_notifier(du_proc_notif_),
  nas_notifier(nas_notif_),
  ngap_ctrl_notifier(ngap_ctrl_notif_),
  srbs(srbs_),
  du_to_cu_container(du_to_cu_container_),
  task_sched(task_sched_),
  reject_users(reject_users_),
  logger(cfg_.logger),
  event_mng(std::make_unique<rrc_ue_event_manager>(task_sched_.get_timer_manager()))
{
  // TODO: Use task_sched to schedule RRC procedures.
  (void)task_sched;
}

void rrc_ue_impl::connect_srb_notifier(srb_id_t                  srb_id,
                                       rrc_pdu_notifier&         notifier,
                                       rrc_tx_security_notifier* tx_sec,
                                       rrc_rx_security_notifier* rx_sec)
{
  if (srb_id_to_uint(srb_id) >= MAX_NOF_SRBS) {
    logger.error("Couldn't connect notifier for SRB{}", srb_id);
  }
  srbs[srb_id_to_uint(srb_id)].pdu_notifier    = &notifier;
  srbs[srb_id_to_uint(srb_id)].tx_sec_notifier = tx_sec;
  srbs[srb_id_to_uint(srb_id)].rx_sec_notifier = rx_sec;
}

void rrc_ue_impl::on_new_dl_ccch(const asn1::rrc_nr::dl_ccch_msg_s& dl_ccch_msg)
{
  send_dl_ccch(dl_ccch_msg);
}

void rrc_ue_impl::on_new_dl_dcch(const asn1::rrc_nr::dl_dcch_msg_s& dl_dcch_msg)
{
  send_dl_dcch(dl_dcch_msg);
}

void rrc_ue_impl::on_new_security_config(security::sec_as_config sec_cfg)
{
  srsran_sanity_check(srbs[srb_id_to_uint(srb_id_t::srb1)].tx_sec_notifier != nullptr,
                      "Attempted to configure security, but there is no interface to PDCP TX");
  srsran_sanity_check(srbs[srb_id_to_uint(srb_id_t::srb1)].rx_sec_notifier != nullptr,
                      "Attempted to configure security, but there is no interface to PDCP RX");

  // store in rrc ue context
  context.sec_cfg = sec_cfg;

  srbs[srb_id_to_uint(srb_id_t::srb1)].tx_sec_notifier->enable_security(security::truncate_config(sec_cfg));
  srbs[srb_id_to_uint(srb_id_t::srb1)].rx_sec_notifier->enable_security(security::truncate_config(sec_cfg));
}

async_task<bool> rrc_ue_impl::handle_init_security_context(const rrc_init_security_context& sec_ctx)
{
  //  Launch RRC security mode procedure
  return launch_async<rrc_security_mode_command_procedure>(context, sec_ctx, *this, *event_mng, logger);
}

async_task<bool> rrc_ue_impl::start_rrc_reconfiguration(const cu_cp_rrc_reconfiguration_procedure_request& msg)
{
  //  Launch RRC Reconfiguration procedure
  return launch_async<rrc_reconfiguration_procedure>(context, msg, *this, *event_mng, logger);
}

template <class T>
void rrc_ue_impl::log_rrc_message(const char*       source,
                                  const direction_t dir,
                                  byte_buffer_view  pdu,
                                  const T&          msg,
                                  const char*       msg_type)
{
  if (logger.debug.enabled()) {
    asn1::json_writer json_writer;
    msg.to_json(json_writer);
    // TODO: remove serialization
    std::vector<uint8_t> bytes{pdu.begin(), pdu.end()};
    logger.debug(
        bytes.data(), bytes.size(), "{} - {} {} ({} B)", source, (dir == Rx) ? "Rx" : "Tx", msg_type, pdu.length());
    logger.debug("Content: {}", json_writer.to_string().c_str());
  } else if (logger.info.enabled()) {
    std::vector<uint8_t> bytes{pdu.begin(), pdu.end()};
    logger.info(bytes.data(), bytes.size(), "{} {}", source, msg_type);
  }
}
template void rrc_ue_impl::log_rrc_message<ul_ccch_msg_s>(const char*          source,
                                                          const direction_t    dir,
                                                          byte_buffer_view     pdu,
                                                          const ul_ccch_msg_s& msg,
                                                          const char*          msg_type);
template void rrc_ue_impl::log_rrc_message<ul_dcch_msg_s>(const char*          source,
                                                          const direction_t    dir,
                                                          byte_buffer_view     pdu,
                                                          const ul_dcch_msg_s& msg,
                                                          const char*          msg_type);
template void rrc_ue_impl::log_rrc_message<dl_ccch_msg_s>(const char*          source,
                                                          const direction_t    dir,
                                                          byte_buffer_view     pdu,
                                                          const dl_ccch_msg_s& msg,
                                                          const char*          msg_type);
template void rrc_ue_impl::log_rrc_message<dl_dcch_msg_s>(const char*          source,
                                                          const direction_t    dir,
                                                          byte_buffer_view     pdu,
                                                          const dl_dcch_msg_s& msg,
                                                          const char*          msg_type);
template void rrc_ue_impl::log_rrc_message<cell_group_cfg_s>(const char*             source,
                                                             const direction_t       dir,
                                                             byte_buffer_view        pdu,
                                                             const cell_group_cfg_s& msg,
                                                             const char*             msg_type);
template void rrc_ue_impl::log_rrc_message<radio_bearer_cfg_s>(const char*               source,
                                                               const direction_t         dir,
                                                               byte_buffer_view          pdu,
                                                               const radio_bearer_cfg_s& msg,
                                                               const char*               msg_type);

void rrc_ue_impl::log_rx_pdu_fail(ue_index_t       ue_index,
                                  const char*      source,
                                  byte_buffer_view pdu,
                                  const char*      cause_str,
                                  bool             log_hex)
{
  if (log_hex) {
    std::vector<uint8_t> bytes{pdu.begin(), pdu.end()};
    logger.error(bytes.data(), bytes.size(), "ue={} Rx {} PDU - discarding cause={}", ue_index, source, cause_str);
  } else {
    logger.error("ue={} Rx {} PDU - discarding cause={}", ue_index, source, cause_str);
  }
}
