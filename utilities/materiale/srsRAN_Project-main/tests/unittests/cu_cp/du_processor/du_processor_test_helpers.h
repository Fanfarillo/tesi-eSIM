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
#include "du_processor_test_helpers.h"
#include "lib/cu_cp/ue_manager_impl.h"
#include "lib/f1ap/common/asn1_helpers.h"
#include "tests/unittests/f1ap/common/test_helpers.h"
#include "tests/unittests/f1ap/cu_cp/f1ap_cu_test_helpers.h"
#include "tests/unittests/rrc/test_helpers.h"
#include "srsran/cu_cp/cu_cp_types.h"
#include "srsran/cu_cp/du_processor.h"
#include "srsran/cu_cp/du_processor_factory.h"
#include "srsran/rrc/rrc.h"
#include "srsran/support/executors/manual_task_worker.h"
#include "srsran/support/test_utils.h"
#include <gtest/gtest.h>

namespace srsran {
namespace srs_cu_cp {

/// Fixture class for DU processor creation
class du_processor_test : public ::testing::Test
{
protected:
  du_processor_test();
  ~du_processor_test() override;

  void attach_ue();

  void receive_rrc_reconfig_complete();

  srslog::basic_logger& test_logger  = srslog::fetch_basic_logger("TEST");
  srslog::basic_logger& cu_cp_logger = srslog::fetch_basic_logger("CU-CP");

  timer_manager                                         timers;
  ue_manager                                            ue_mng;
  dummy_du_processor_cu_cp_notifier                     cu_cp_notifier;
  dummy_f1ap_pdu_notifier                               f1ap_pdu_notifier;
  dummy_f1ap_du_management_notifier                     f1ap_du_mgmt_notifier;
  dummy_du_processor_e1ap_control_notifier              e1ap_ctrl_notifier;
  dummy_rrc_ue_ngap_adapter                             rrc_ue_ngap_notifier;
  std::unique_ptr<dummy_du_processor_ue_task_scheduler> ue_task_sched;
  manual_task_worker                                    ctrl_worker{128};
  std::unique_ptr<du_processor_interface>               du_processor_obj;
};

} // namespace srs_cu_cp
} // namespace srsran
