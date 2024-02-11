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

#include "../common/f1ap_cu_test_messages.h"
#include "../common/test_helpers.h"
#include "srsran/cu_cp/cu_cp_types.h"
#include "srsran/f1ap/common/f1ap_common.h"
#include "srsran/f1ap/cu_cp/f1ap_cu.h"
#include "srsran/f1ap/cu_cp/f1ap_cu_factory.h"
#include "srsran/support/executors/manual_task_worker.h"
#include <gtest/gtest.h>

namespace srsran {
namespace srs_cu_cp {

/// Reusable notifier class that a) stores the received du_index for test inspection and b)
/// calls the registered DU handler (if any). The handler can be added upon construction
/// or later via the attach_handler() method.
class dummy_f1ap_du_management_notifier : public f1ap_du_management_notifier
{
public:
  void attach_handler(cu_cp_du_handler* handler_) { handler = handler_; };
  void on_du_remove_request_received(du_index_t idx) override
  {
    logger.info("Received a du remove request for du {}", idx);
    last_du_idx = idx; // store idx

    if (handler != nullptr) {
      logger.info("Forwarding remove request");
      handler->handle_du_remove_request(idx);
    }
  }

  du_index_t last_du_idx;

private:
  srslog::basic_logger& logger  = srslog::fetch_basic_logger("TEST");
  cu_cp_du_handler*     handler = nullptr;
};

/// \brief Creates a dummy UE CONTEXT SETUP REQUEST.
f1ap_ue_context_setup_request create_ue_context_setup_request(ue_index_t                             ue_index,
                                                              const std::initializer_list<drb_id_t>& drbs_to_add);

/// Fixture class for F1AP
class f1ap_cu_test : public ::testing::Test
{
protected:
  struct test_ue {
    ue_index_t                    ue_index;
    optional<gnb_cu_ue_f1ap_id_t> cu_ue_id;
    optional<gnb_du_ue_f1ap_id_t> du_ue_id;
  };

  f1ap_cu_test();
  ~f1ap_cu_test() override;

  /// \brief Helper method to successfully create UE instance in F1AP.
  test_ue& create_ue(gnb_du_ue_f1ap_id_t du_ue_id);

  /// \brief Helper method to run F1AP CU UE Context Setup procedure to completion for a given UE.
  void run_ue_context_setup(ue_index_t ue_index);

  srslog::basic_logger& f1ap_logger = srslog::fetch_basic_logger("F1AP");
  srslog::basic_logger& test_logger = srslog::fetch_basic_logger("TEST");

  slotted_id_table<ue_index_t, test_ue, MAX_NOF_UES_PER_DU> test_ues;

  dummy_f1ap_pdu_notifier           f1ap_pdu_notifier;
  dummy_f1ap_du_processor_notifier  du_processor_notifier;
  dummy_f1ap_du_management_notifier f1ap_du_mgmt_notifier;
  manual_task_worker                ctrl_worker{128};
  std::unique_ptr<f1ap_cu>          f1ap;
};

} // namespace srs_cu_cp
} // namespace srsran
