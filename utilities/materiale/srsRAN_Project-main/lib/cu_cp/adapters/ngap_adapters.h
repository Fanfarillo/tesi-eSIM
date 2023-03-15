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

#pragma once

#include "../task_schedulers/ue_task_scheduler.h"
#include "srsran/asn1/ngap/ngap.h"
#include "srsran/cu_cp/cu_cp.h"
#include "srsran/cu_cp/du_processor.h"
#include "srsran/e1ap/cu_cp/e1ap_cu_cp.h"
#include "srsran/ngap/ngap.h"
#include "srsran/ran/bcd_helpers.h"
#include "srsran/rrc/rrc_ue.h"
#include "srsran/srslog/srslog.h"

#include "../../ngap/ngap_asn1_utils.h"

namespace srsran {
namespace srs_cu_cp {

/// Adapter between NGAP and Task Scheduler
class ngap_to_cu_cp_task_scheduler : public ngap_ue_task_scheduler
{
public:
  ngap_to_cu_cp_task_scheduler() = default;

  void connect_cu_cp(ue_task_scheduler& cu_cp_task_sched_) { cu_cp_task_sched = &cu_cp_task_sched_; }

  void schedule_async_task(ue_index_t ue_index, async_task<void>&& task) override
  {
    srsran_assert(cu_cp_task_sched != nullptr, "CU-CP task scheduler handler must not be nullptr");
    cu_cp_task_sched->handle_ue_async_task(ue_index, std::move(task));
  }

  unique_timer make_unique_timer() override
  {
    srsran_assert(cu_cp_task_sched != nullptr, "CU-CP task scheduler handler must not be nullptr");
    return cu_cp_task_sched->make_unique_timer();
  }
  timer_manager& get_timer_manager() override
  {
    srsran_assert(cu_cp_task_sched != nullptr, "CU-CP task scheduler handler must not be nullptr");
    return cu_cp_task_sched->get_timer_manager();
  }

private:
  ue_task_scheduler* cu_cp_task_sched = nullptr;
};

/// Adapter between NGAP and CU-CP
class ngap_cu_cp_adapter : public ngap_cu_cp_connection_notifier
{
public:
  explicit ngap_cu_cp_adapter() = default;

  void connect_cu_cp(cu_cp_ngap_connection_handler& cu_cp_handler_) { cu_cp_handler = &cu_cp_handler_; }

  void on_amf_connection() override
  {
    srsran_assert(cu_cp_handler != nullptr, "CU-CP handler must not be nullptr");
    cu_cp_handler->handle_amf_connection();
  }

  void on_amf_connection_drop() override
  {
    srsran_assert(cu_cp_handler != nullptr, "CU-CP handler must not be nullptr");
    cu_cp_handler->handle_amf_connection_drop();
  }

private:
  cu_cp_ngap_connection_handler* cu_cp_handler = nullptr;
};

/// Adapter between NGAP and RRC UE
class ngap_rrc_ue_adapter : public ngap_rrc_ue_pdu_notifier, public ngap_rrc_ue_control_notifier
{
public:
  ngap_rrc_ue_adapter() = default;

  void connect_rrc_ue(rrc_ue_dl_nas_message_handler*        rrc_ue_msg_handler_,
                      rrc_ue_control_message_handler*       rrc_ue_ctrl_handler_,
                      rrc_ue_init_security_context_handler* rrc_ue_security_handler_)
  {
    rrc_ue_msg_handler      = rrc_ue_msg_handler_;
    rrc_ue_ctrl_handler     = rrc_ue_ctrl_handler_;
    rrc_ue_security_handler = rrc_ue_security_handler_;
  }

  void on_new_pdu(byte_buffer nas_pdu) override
  {
    srsran_assert(rrc_ue_msg_handler != nullptr, "RRC UE message handler must not be nullptr");

    dl_nas_transport_message dl_nas_msg = {};
    dl_nas_msg.nas_pdu                  = std::move(nas_pdu);

    rrc_ue_msg_handler->handle_dl_nas_transport_message(dl_nas_msg);
  }

  async_task<bool> on_new_security_context(const asn1::ngap::ue_security_cap_s&           caps,
                                           const asn1::fixed_bitstring<256, false, true>& key) override
  {
    srsran_assert(rrc_ue_security_handler != nullptr, "RRC UE security handler must not be nullptr");

    rrc_init_security_context sec_ctxt;
    copy_asn1_key(sec_ctxt.k, key);
    fill_supported_algorithms(sec_ctxt.supported_int_algos, caps.nr_integrity_protection_algorithms);
    fill_supported_algorithms(sec_ctxt.supported_enc_algos, caps.nr_encryption_algorithms);
    logger.debug(key.data(), 32, "K_gnb");
    logger.debug("Supported integrity algorithms: {}", sec_ctxt.supported_int_algos);
    logger.debug("Supported ciphering algorithms: {}", sec_ctxt.supported_enc_algos);

    return rrc_ue_security_handler->handle_init_security_context(sec_ctxt);
  }

private:
  rrc_ue_dl_nas_message_handler*        rrc_ue_msg_handler      = nullptr;
  rrc_ue_control_message_handler*       rrc_ue_ctrl_handler     = nullptr;
  rrc_ue_init_security_context_handler* rrc_ue_security_handler = nullptr;
  srslog::basic_logger&                 logger                  = srslog::fetch_basic_logger("NGAP");
};

/// Adapter between NGAP and DU Processor
class ngap_du_processor_adapter : public ngap_du_processor_control_notifier
{
public:
  ngap_du_processor_adapter() = default;

  void connect_du_processor(du_processor_ngap_interface* du_processor_ngap_handler_)
  {
    du_processor_ngap_handler = du_processor_ngap_handler_;
  }

  async_task<cu_cp_pdu_session_resource_setup_response>
  on_new_pdu_session_resource_setup_request(cu_cp_pdu_session_resource_setup_request& request) override
  {
    srsran_assert(du_processor_ngap_handler != nullptr, "DU Processor handler must not be nullptr");

    return du_processor_ngap_handler->handle_new_pdu_session_resource_setup_request(request);
  }

  void on_new_ue_context_release_command(cu_cp_ue_context_release_command& command) override
  {
    srsran_assert(du_processor_ngap_handler != nullptr, "DU Processor handler must not be nullptr");

    du_processor_ngap_handler->handle_new_ue_context_release_command(command);
  }

private:
  du_processor_ngap_interface* du_processor_ngap_handler = nullptr;
};

} // namespace srs_cu_cp
} // namespace srsran
