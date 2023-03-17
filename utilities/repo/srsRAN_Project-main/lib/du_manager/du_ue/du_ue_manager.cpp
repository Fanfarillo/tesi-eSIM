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

#include "du_ue_manager.h"
#include "../procedures/ue_configuration_procedure.h"
#include "../procedures/ue_creation_procedure.h"
#include "../procedures/ue_deletion_procedure.h"

using namespace srsran;
using namespace srs_du;

du_ue_manager::du_ue_manager(du_manager_params& cfg_, du_ran_resource_manager& cell_res_alloc_) :
  cfg(cfg_), cell_res_alloc(cell_res_alloc_), logger(srslog::fetch_basic_logger("DU-MNG"))
{
  std::fill(rnti_to_ue_index.begin(), rnti_to_ue_index.end(), du_ue_index_t::INVALID_DU_UE_INDEX);

  const size_t number_of_pending_procedures = 16;
  for (size_t i = 0; i < MAX_NOF_DU_UES; ++i) {
    ue_ctrl_loop.emplace(i, number_of_pending_procedures);
  }
}

void du_ue_manager::handle_ue_create_request(const ul_ccch_indication_message& msg)
{
  // Search unallocated UE index with no pending events.
  du_ue_index_t ue_idx_candidate = MAX_NOF_DU_UES;
  for (size_t i = 0; i < ue_ctrl_loop.size(); ++i) {
    du_ue_index_t ue_index = to_du_ue_index(i);
    if (not ue_db.contains(ue_index) and ue_ctrl_loop[ue_index].empty()) {
      ue_idx_candidate = ue_index;
      break;
    }
  }

  // Enqueue UE creation procedure
  ue_ctrl_loop[ue_idx_candidate].schedule<ue_creation_procedure>(
      ue_idx_candidate, msg, *this, cfg.services, cfg.mac, cfg.rlc, cfg.f1ap, cell_res_alloc);
}

async_task<f1ap_ue_context_update_response>
du_ue_manager::handle_ue_config_request(const f1ap_ue_context_update_request& msg)
{
  return launch_async<ue_configuration_procedure>(msg, *this, cfg);
}

async_task<void> du_ue_manager::handle_ue_delete_request(const f1ap_ue_delete_request& msg)
{
  // Enqueue UE deletion procedure
  return launch_async<ue_deletion_procedure>(msg, cfg.mac.ue_cfg, *this);
}

du_ue* du_ue_manager::find_ue(du_ue_index_t ue_index)
{
  srsran_assert(ue_index < MAX_NOF_DU_UES, "Invalid ue_index={}", ue_index);
  return ue_db.contains(ue_index) ? &ue_db[ue_index] : nullptr;
}

du_ue* du_ue_manager::find_rnti(rnti_t rnti)
{
  if (rnti_to_ue_index[rnti % MAX_NOF_DU_UES] == INVALID_DU_UE_INDEX) {
    return nullptr;
  }
  return &ue_db[rnti_to_ue_index[rnti % MAX_NOF_DU_UES]];
}

du_ue* du_ue_manager::add_ue(std::unique_ptr<du_ue> ue_ctx)
{
  if (ue_ctx->ue_index >= INVALID_DU_UE_INDEX or ue_ctx->rnti == INVALID_RNTI) {
    // UE identifiers are invalid.
    return nullptr;
  }

  if (ue_db.contains(ue_ctx->ue_index) or rnti_to_ue_index[ue_ctx->rnti % MAX_NOF_DU_UES] != INVALID_DU_UE_INDEX) {
    // UE already existed with same ue_index
    return nullptr;
  }

  // Create UE object
  du_ue_index_t ue_index = ue_ctx->ue_index;
  ue_db.insert(ue_index, std::move(ue_ctx));
  auto& u = ue_db[ue_index];

  // Update RNTI -> UE index map
  srsran_sanity_check(rnti_to_ue_index[u.rnti % MAX_NOF_DU_UES] == INVALID_DU_UE_INDEX, "Invalid RNTI={:#x}", u.rnti);
  rnti_to_ue_index[u.rnti % MAX_NOF_DU_UES] = ue_index;

  return &u;
}

void du_ue_manager::remove_ue(du_ue_index_t ue_index)
{
  // Note: The caller of this function can be a UE procedure. Thus, we have to wait for the procedure to finish
  // before safely removing the UE. This achieved via a scheduled async task

  srsran_assert(ue_index < MAX_NOF_DU_UES, "Invalid ueId={}", ue_index);
  logger.debug("Scheduling ueId={} deletion", ue_index);

  // Schedule UE removal task
  ue_ctrl_loop[ue_index].schedule([this, ue_index](coro_context<async_task<void>>& ctx) {
    CORO_BEGIN(ctx);
    srsran_assert(ue_db.contains(ue_index), "Remove UE called for inexistent ueId={}", ue_index);
    rnti_to_ue_index[ue_db[ue_index].rnti % MAX_NOF_DU_UES] = INVALID_DU_UE_INDEX;
    ue_db.erase(ue_index);
    logger.debug("Removed ueId={}", ue_index);
    CORO_RETURN();
  });
}
