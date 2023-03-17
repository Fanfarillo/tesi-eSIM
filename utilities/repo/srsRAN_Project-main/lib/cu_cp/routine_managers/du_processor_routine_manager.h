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

#include "../ue_manager_impl.h"
#include "srsran/cu_cp/du_processor.h"
#include "srsran/support/async/async_task.h"
#include "srsran/support/async/async_task_loop.h"

namespace srsran {
namespace srs_cu_cp {

/// \brief Service provided by DU Processor to handle routines.
class du_processor_routine_manager
{
public:
  explicit du_processor_routine_manager(du_processor_e1ap_control_notifier&    e1ap_ctrl_notifier_,
                                        du_processor_f1ap_ue_context_notifier& f1ap_ue_ctxt_notifier_,
                                        du_processor_rrc_du_ue_notifier&       rrc_du_notifier_,
                                        du_processor_ue_manager&               ue_manager_,
                                        srslog::basic_logger&                  logger_);
  ~du_processor_routine_manager() = default;

  async_task<cu_cp_pdu_session_resource_setup_response>
  start_pdu_session_resource_setup_routine(const cu_cp_pdu_session_resource_setup_request& setup_msg,
                                           const srsran::security::sec_as_config&          security_cfg,
                                           du_processor_rrc_ue_control_message_notifier&   rrc_ue_ctrl_notifier,
                                           drb_manager&                                    rrc_ue_drb_manager);

  async_task<void> start_ue_context_release_routine(const cu_cp_ue_context_release_command& command);

private:
  du_processor_e1ap_control_notifier&    e1ap_ctrl_notifier;
  du_processor_f1ap_ue_context_notifier& f1ap_ue_ctxt_notifier;
  du_processor_rrc_du_ue_notifier&       rrc_du_notifier;
  du_processor_ue_manager&               ue_manager;
  srslog::basic_logger&                  logger;
};

} // namespace srs_cu_cp
} // namespace srsran
