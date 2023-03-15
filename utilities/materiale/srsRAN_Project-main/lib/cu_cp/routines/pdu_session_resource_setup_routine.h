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

#include "srsran/cu_cp/du_processor.h"
#include "srsran/support/async/async_task.h"
#include "srsran/support/async/eager_async_task.h"

namespace srsran {
namespace srs_cu_cp {

/// \brief Handles the setup of PDU session resources from the RRC viewpoint.
/// TODO Add seqdiag
class pdu_session_resource_setup_routine
{
public:
  pdu_session_resource_setup_routine(const cu_cp_pdu_session_resource_setup_request& setup_msg_,
                                     const srsran::security::sec_as_config&          security_cfg_,
                                     du_processor_e1ap_control_notifier&             e1ap_ctrl_notif_,
                                     du_processor_f1ap_ue_context_notifier&          f1ap_ue_ctxt_notif_,
                                     du_processor_rrc_ue_control_message_notifier&   rrc_ue_notifier_,
                                     drb_manager&                                    rrc_ue_drb_manager_,
                                     srslog::basic_logger&                           logger_);

  void operator()(coro_context<async_task<cu_cp_pdu_session_resource_setup_response>>& ctx);

  static const char* name() { return "PDU Session Creation Routine"; }

private:
  void fill_e1ap_bearer_context_setup_request(e1ap_bearer_context_setup_request& e1ap_request);
  void fill_e1ap_bearer_context_modification_request(e1ap_bearer_context_modification_request& e1ap_request);
  bool valid_5qi(const qos_flow_setup_request_item& flow);

  cu_cp_pdu_session_resource_setup_response handle_pdu_session_resource_setup_result(bool success);

  const cu_cp_pdu_session_resource_setup_request setup_msg;
  const srsran::security::sec_as_config          security_cfg;

  std::vector<drb_id_t> drb_to_add_list; // list of DRBs to be added

  du_processor_e1ap_control_notifier&           e1ap_ctrl_notifier;    // to trigger bearer context setup at CU-UP
  du_processor_f1ap_ue_context_notifier&        f1ap_ue_ctxt_notifier; // to trigger UE context modification at DU
  du_processor_rrc_ue_control_message_notifier& rrc_ue_notifier;       // to trigger RRC Reconfiguration at UE
  drb_manager&                                  rrc_ue_drb_manager;    // to get RRC DRB config
  srslog::basic_logger&                         logger;

  // (sub-)routine requests
  e1ap_bearer_context_setup_request           bearer_context_setup_request;
  cu_cp_ue_context_modification_request       ue_context_mod_request;
  e1ap_bearer_context_modification_request    bearer_context_modification_request;
  cu_cp_rrc_reconfiguration_procedure_request rrc_reconfig_args;

  // (sub-)routine results
  cu_cp_pdu_session_resource_setup_response response_msg;
  e1ap_bearer_context_setup_response        bearer_context_setup_response; // to initially setup the DRBs at the CU-UP
  cu_cp_ue_context_modification_response    ue_context_modification_response; // to inform DU about the new DRBs
  e1ap_bearer_context_modification_response
       bearer_context_modification_response; // to inform CU-UP about the new TEID for UL F1u traffic
  bool rrc_reconfig_result = false;          // the final UE reconfiguration
};

} // namespace srs_cu_cp
} // namespace srsran
