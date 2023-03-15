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

#include "../du_manager_test_helpers.h"
#include "srsran/mac/config/mac_cell_group_config_factory.h"

namespace srsran {
namespace srs_du {

class ue_manager_dummy : public ue_manager_ctrl_configurator
{
public:
  slotted_array<std::unique_ptr<du_ue>, MAX_NOF_DU_UES> ues;

  du_ue* add_ue(std::unique_ptr<du_ue> u) override
  {
    du_ue* ret = u.get();
    ues.emplace(u->ue_index, std::move(u));
    return ret;
  }
  void   remove_ue(du_ue_index_t ue_index) override { ues.erase(ue_index); }
  du_ue* find_ue(du_ue_index_t ue_index) override { return ues.contains(ue_index) ? ues[ue_index].get() : nullptr; }
  du_ue* find_rnti(rnti_t rnti) override
  {
    for (auto& u : ues) {
      if (u->rnti == rnti) {
        return u.get();
      }
    }
    return nullptr;
  }
};

ul_ccch_indication_message create_test_ul_ccch_message(rnti_t rnti);

class du_manager_proc_tester : public du_manager_test_bench
{
public:
  du_manager_proc_tester(span<const du_cell_config> cells_) : du_manager_test_bench(cells_) {}

  du_ue& create_ue(du_ue_index_t ue_index);

  f1ap_ue_context_update_response configure_ue(const f1ap_ue_context_update_request& req);

  ue_manager_dummy ue_mng;
};

} // namespace srs_du
} // namespace srsran