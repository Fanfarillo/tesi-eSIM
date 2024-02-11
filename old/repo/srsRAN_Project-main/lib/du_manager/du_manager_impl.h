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

#include "du_cell_manager.h"
#include "du_ue/du_ue_manager.h"
#include "ran_resource_management/du_ran_resource_manager_impl.h"
#include "srsran/du_manager/du_manager.h"
#include "srsran/du_manager/du_manager_params.h"

namespace srsran {
namespace srs_du {

class du_manager_impl final : public du_manager_interface
{
public:
  explicit du_manager_impl(const du_manager_params& params_);

  // Controller interface.
  void start() override;
  void stop() override;

  // MAC interface
  void handle_ul_ccch_indication(const ul_ccch_indication_message& msg) override;

  // Task scheduling interface.
  void schedule_async_task(async_task<void>&& task) override { main_ctrl_loop.schedule(std::move(task)); }
  void schedule_async_task(du_ue_index_t ue_index, async_task<void>&& task) override
  {
    ue_mng.schedule_async_task(ue_index, std::move(task));
  }

  async_task<f1ap_ue_context_update_response>
  handle_ue_context_update(const f1ap_ue_context_update_request& request) override;

  async_task<void> handle_ue_delete_request(const f1ap_ue_delete_request& request) override;

  size_t nof_ues() override;

private:
  // DU manager configuration that will be visible to all running procedures
  du_manager_params params;

  // Components
  du_cell_manager              cell_mng;
  du_ran_resource_manager_impl cell_res_alloc;
  du_ue_manager                ue_mng;

  // Handler for DU tasks.
  async_task_sequencer main_ctrl_loop;
};

} // namespace srs_du
} // namespace srsran
