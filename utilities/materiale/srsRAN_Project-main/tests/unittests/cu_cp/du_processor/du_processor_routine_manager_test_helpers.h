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

#include "../common/du_processor_test_messages.h"
#include "../common/test_helpers.h"
#include "lib/cu_cp/routine_managers/du_processor_routine_manager.h"
#include "lib/cu_cp/ue_manager_impl.h"
#include "lib/rrc/ue/drb_manager_impl.h"
#include "tests/unittests/rrc/rrc_ue_test_messages.h"
#include "srsran/support/test_utils.h"
#include <gtest/gtest.h>

namespace srsran {
namespace srs_cu_cp {

/// Fixture class for DU processor creation
class du_processor_routine_manager_test : public ::testing::Test
{
protected:
  du_processor_routine_manager_test();
  ~du_processor_routine_manager_test() override;

  void init_security_config();

  srslog::basic_logger& test_logger  = srslog::fetch_basic_logger("TEST");
  srslog::basic_logger& cu_cp_logger = srslog::fetch_basic_logger("CU-CP");

  srsran::security::sec_as_config security_cfg;

  dummy_du_processor_e1ap_control_notifier           e1ap_ctrl_notifier;
  dummy_du_processor_f1ap_ue_context_notifier        f1ap_ue_ctxt_notifier;
  dummy_du_processor_rrc_du_ue_notifier              rrc_du_notifier;
  ue_manager                                         ue_mng;
  dummy_du_processor_rrc_ue_control_message_notifier rrc_ue_ctrl_notifier;
  drb_manager_impl                                   rrc_ue_drb_manager{drb_manager_cfg{}};
  std::unique_ptr<du_processor_routine_manager>      routine_mng;
};

} // namespace srs_cu_cp
} // namespace srsran
