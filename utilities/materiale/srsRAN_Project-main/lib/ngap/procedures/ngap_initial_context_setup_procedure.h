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

#include "../ngap_asn1_utils.h"
#include "srsran/cu_cp/ue_manager.h" // for ngap_ue
#include "srsran/ngap/ngap.h"
#include "srsran/support/async/async_task.h"

namespace srsran {
namespace srs_cu_cp {

struct initial_context_failure_message {
  asn1::ngap::cause_c                      cause;
  ngap_pdu_session_res_list                failed_to_setup;
  optional<asn1::ngap::crit_diagnostics_s> crit_diagnostics;
};

struct initial_context_response_message {
  ngap_pdu_session_res_list                succeed_to_setup;
  ngap_pdu_session_res_list                failed_to_setup;
  optional<asn1::ngap::crit_diagnostics_s> crit_diagnostics;
};

class ngap_initial_context_setup_procedure
{
public:
  ngap_initial_context_setup_procedure(const ue_index_t                                ue_index_,
                                       const asn1::ngap::init_context_setup_request_s& request_,
                                       ngap_ue_manager&                                ue_manager_,
                                       ngap_message_notifier&                          amf_notif_,
                                       srslog::basic_logger&                           logger_);

  void operator()(coro_context<async_task<void>>& ctx);

private:
  // results senders
  void send_initial_context_setup_response(const initial_context_response_message& msg,
                                           const amf_ue_id_t&                      amf_ue_id,
                                           const ran_ue_id_t&                      ran_ue_id);
  void send_initial_context_setup_failure(const initial_context_failure_message& msg,
                                          const amf_ue_id_t&                     amf_ue_id,
                                          const ran_ue_id_t&                     ran_ue_id);

  const ue_index_t                               ue_index;
  const asn1::ngap::init_context_setup_request_s request;
  ngap_ue_manager&                               ue_manager;
  ngap_message_notifier&                         amf_notifier;
  srslog::basic_logger&                          logger;

  ngap_ue* ue = nullptr;

  bool success = false;
};

} // namespace srs_cu_cp
} // namespace srsran
