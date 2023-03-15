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

#include "csi_rs_scheduler.h"

using namespace srsran;

static csi_rs_info build_csi_rs_info(const bwp_configuration& bwp_cfg, const nzp_csi_rs_resource& nzp_csi_rs_res)
{
  csi_rs_info csi_rs;

  csi_rs.bwp_cfg = &bwp_cfg;
  csi_rs.crbs    = {nzp_csi_rs_res.res_mapping.freq_band_start_rb,
                    nzp_csi_rs_res.res_mapping.freq_band_start_rb + nzp_csi_rs_res.res_mapping.freq_band_nof_rb};
  csi_rs.type    = srsran::csi_rs_type::CSI_RS_NZP;

  csi_rs.freq_domain = nzp_csi_rs_res.res_mapping.fd_alloc;
  switch (csi_rs.freq_domain.size()) {
    case 4:
      csi_rs.row = 1;
      break;
    case 12:
      csi_rs.row = 2;
      break;
    case 3:
      csi_rs.row = 4;
      break;
    case 6:
    default:
      report_fatal_error("Not supported");
  }
  csi_rs.symbol0                      = nzp_csi_rs_res.res_mapping.first_ofdm_symbol_in_td;
  csi_rs.symbol1                      = nzp_csi_rs_res.res_mapping.first_ofdm_symbol_in_td2.has_value()
                                            ? *nzp_csi_rs_res.res_mapping.first_ofdm_symbol_in_td2
                                            : 2;
  csi_rs.cdm_type                     = nzp_csi_rs_res.res_mapping.cdm;
  csi_rs.freq_density                 = nzp_csi_rs_res.res_mapping.freq_density;
  csi_rs.scrambling_id                = nzp_csi_rs_res.scrambling_id;
  csi_rs.power_ctrl_offset_profile_nr = nzp_csi_rs_res.pwr_ctrl_offset;
  csi_rs.power_ctrl_offset_ss_profile_nr =
      nzp_csi_rs_res.pwr_ctrl_offset_ss_db.has_value() ? *nzp_csi_rs_res.pwr_ctrl_offset_ss_db : 0;

  return csi_rs;
}

csi_rs_scheduler::csi_rs_scheduler(const cell_configuration& cell_cfg_) : cell_cfg(cell_cfg_)
{
  if (cell_cfg.csi_meas_cfg.has_value()) {
    for (const auto& nzp_csi : cell_cfg.csi_meas_cfg->nzp_csi_rs_res_list) {
      cached_csi_rs.push_back(build_csi_rs_info(cell_cfg.dl_cfg_common.init_dl_bwp.generic_params, nzp_csi));
    }
  }
}

void csi_rs_scheduler::run_slot(cell_slot_resource_allocator& res_grid)
{
  if (cached_csi_rs.empty()) {
    return;
  }
  if (not cell_cfg.is_dl_enabled(res_grid.slot)) {
    return;
  }

  for (unsigned i = 0; i != cached_csi_rs.size(); ++i) {
    const nzp_csi_rs_resource& nzp_csi = cell_cfg.csi_meas_cfg->nzp_csi_rs_res_list[i];
    if ((res_grid.slot - *nzp_csi.csi_res_offset).to_uint() % (unsigned)*nzp_csi.csi_res_period == 0) {
      res_grid.result.dl.csi_rs.push_back(cached_csi_rs[i]);
    }
  }
}
