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

#include "scheduler_time_rr.h"
#include "../support/config_helpers.h"

using namespace srsran;

/// \brief Algorithm to select next UE to allocate in a time-domain RR fashion
/// \param[in] ue_db map of "slot_ue"
/// \param[in] next_ue_index UE index with the highest priority to be allocated.
/// \param[in] alloc_ue callable with signature "bool(ue&)" that returns true if UE allocation was successful.
/// \param[in] stop_cond callable with signature "bool()" that verifies if the conditions are present for the
/// round-robin to early-stop the iteration.
/// \return Index of next UE to allocate.
template <typename AllocUEFunc, typename StopIterationFunc>
du_ue_index_t round_robin_apply(const ue_list&           ue_db,
                                du_ue_index_t            next_ue_index,
                                const AllocUEFunc&       alloc_ue,
                                const StopIterationFunc& stop_cond)
{
  if (ue_db.empty()) {
    return next_ue_index;
  }
  auto it          = ue_db.lower_bound(next_ue_index);
  bool first_alloc = true;
  for (unsigned count = 0; count < ue_db.size(); ++count, ++it) {
    if (it == ue_db.end()) {
      // wrap-around
      it = ue_db.begin();
    }
    if (alloc_ue(*it)) {
      if (first_alloc) {
        next_ue_index = to_du_ue_index((unsigned)it->ue_index + 1U);
        first_alloc   = false;
      }
      if (stop_cond()) {
        break;
      }
    }
  }
  return next_ue_index;
}

/// \brief Gets SearchSpace configurations prioritized based on nof. candidates for a given aggregation level in a UE
/// cell.
/// \param[in] ue_cc UE's cell context.
/// \param[in] agg_lvl Aggregation level.
/// \return List of SearchSpace configuration.
static static_vector<const search_space_configuration*, MAX_NOF_SEARCH_SPACE_PER_BWP>
get_ue_cell_prioritized_ss_for_agg_lvl(const ue_cell& ue_cc, aggregation_level agg_lvl)
{
  auto search_spaces = ue_cc.cfg().get_search_spaces(ue_cc.active_bwp_id());
  std::sort(search_spaces.begin(),
            search_spaces.end(),
            [agg_lvl](const search_space_configuration* lhs, const search_space_configuration* rhs) -> bool {
              if (lhs->nof_candidates[to_aggregation_level_index(agg_lvl)] ==
                  rhs->nof_candidates[to_aggregation_level_index(agg_lvl)]) {
                // In case nof. candidates are equal, choose the SS with higher CORESET Id (i.e. try to use CORESET#0 as
                // less as possible).
                return lhs->cs_id > rhs->cs_id;
              }
              return lhs->nof_candidates[to_aggregation_level_index(agg_lvl)] >
                     rhs->nof_candidates[to_aggregation_level_index(agg_lvl)];
            });
  return search_spaces;
}

/// \brief Gets SearchSpace configuration of Type-1 PDCCH CSS for a UE.
/// \param[in] ue_cc UE's cell context.
/// \return List containing Type-1 PDCCH CSS configuration.
static static_vector<const search_space_configuration*, MAX_NOF_SEARCH_SPACE_PER_BWP>
get_type1_pdcch_css(const ue_cell& ue_cc)
{
  return {ue_cc.cfg().find_search_space(
      ue_cc.cfg().cell_cfg_common.dl_cfg_common.init_dl_bwp.pdcch_common.ra_search_space_id)};
}

/// Allocate UE PDSCH grant.
static bool alloc_dl_ue(const ue&                    u,
                        const ue_resource_grid_view& res_grid,
                        ue_pdsch_allocator&          pdsch_alloc,
                        bool                         is_retx,
                        srslog::basic_logger&        logger)
{
  if (not is_retx and not u.has_pending_dl_newtx_bytes()) {
    return false;
  }
  // TODO: Set aggregation level based on link quality.
  const aggregation_level agg_lvl    = srsran::aggregation_level::n4;
  slot_point              pdcch_slot = res_grid.get_pdcch_slot();

  // Prioritize PCell over SCells.
  for (unsigned i = 0; i != u.nof_cells(); ++i) {
    const ue_cell& ue_cc = u.get_cell(to_ue_cell_index(i));
    if (not res_grid.get_cell_cfg_common(ue_cc.cell_index).is_dl_enabled(pdcch_slot)) {
      // DL needs to be active for PDCCH in this slot.
      continue;
    }

    // Search available HARQ.
    const dl_harq_process* h = is_retx ? ue_cc.harqs.find_pending_dl_retx() : ue_cc.harqs.find_empty_dl_harq();
    if (h == nullptr) {
      if (not is_retx) {
        logger.debug(
            "ue={} rnti={:#x} PDSCH allocation skipped. Cause: No available HARQs", ue_cc.ue_index, ue_cc.rnti());
      }
      continue;
    }

    // Search for available symbolxRB resources in different SearchSpaces.
    const cell_configuration& cell_cfg_cmn = ue_cc.cfg().cell_cfg_common;
    static_vector<const search_space_configuration*, MAX_NOF_SEARCH_SPACE_PER_BWP> search_spaces;
    // See 3GPP TS 38.213, clause 10.1,
    // A UE monitors PDCCH candidates in one or more of the following search spaces sets
    //  - a Type1-PDCCH CSS set configured by ra-SearchSpace in PDCCH-ConfigCommon for a DCI format with
    //    CRC scrambled by a RA-RNTI, a MsgB-RNTI, or a TC-RNTI on the primary cell.
    if (is_retx && h->last_alloc_params().dci_cfg_type == srsran::dci_dl_rnti_config_type::tc_rnti_f1_0) {
      search_spaces = get_type1_pdcch_css(ue_cc);
    } else {
      search_spaces = get_ue_cell_prioritized_ss_for_agg_lvl(ue_cc, agg_lvl);
    }

    for (const search_space_configuration* ss_cfg : search_spaces) {
      const span<const pdsch_time_domain_resource_allocation> pdsch_list =
          ue_cc.cfg().get_pdsch_time_domain_list(ss_cfg->id);

      bwp_configuration bwp_cfg = ue_cc.cfg().dl_bwp_common(ue_cc.active_bwp_id()).generic_params;
      if (ss_cfg->type == search_space_configuration::type_t::common) {
        // See TS 38.214, 5.1.2.2.2, Downlink resource allocation type 1.
        bwp_cfg = ue_cc.cfg().dl_bwp_common(to_bwp_id(0)).generic_params;
        if (cell_cfg_cmn.dl_cfg_common.init_dl_bwp.pdcch_common.coreset0.has_value()) {
          bwp_cfg.crbs = get_coreset0_crbs(cell_cfg_cmn.dl_cfg_common.init_dl_bwp.pdcch_common);
        }
      }

      for (unsigned time_res = 0; time_res != pdsch_list.size(); ++time_res) {
        const pdsch_time_domain_resource_allocation& pdsch = pdsch_list[time_res];
        if (not res_grid.get_cell_cfg_common(ue_cc.cell_index).is_dl_enabled(pdcch_slot + pdsch.k0)) {
          // DL needs to be active for PDSCH in this slot.
          continue;
        }
        const cell_slot_resource_grid& grid      = res_grid.get_pdsch_grid(ue_cc.cell_index, pdsch.k0);
        const prb_bitmap               used_crbs = grid.used_crbs(bwp_cfg, pdsch.symbols);

        // TODO verify the there is at least 1 TB.
        const grant_prbs_mcs mcs_prbs = is_retx ? grant_prbs_mcs{h->last_alloc_params().tb.front().value().mcs,
                                                                 h->last_alloc_params().prbs.prbs().length()}
                                                : ue_cc.required_dl_prbs(time_res, u.pending_dl_newtx_bytes());

        if (mcs_prbs.n_prbs == 0) {
          logger.debug("ue={} rnti={:#x} PDSCH allocation skipped. Cause: UE's CQI=0 ", ue_cc.ue_index, ue_cc.rnti());
          return false;
        }

        const crb_interval ue_grant_crbs  = find_empty_interval_of_length(used_crbs, mcs_prbs.n_prbs, 0);
        bool               are_crbs_valid = not ue_grant_crbs.empty(); // Cannot be empty.
        if (is_retx) {
          // In case of Retx, the #CRBs need to stay the same.
          are_crbs_valid = ue_grant_crbs.length() == h->last_alloc_params().prbs.prbs().length();
        }
        if (are_crbs_valid) {
          const bool res_allocated = pdsch_alloc.allocate_dl_grant(ue_pdsch_grant{&u,
                                                                                  ue_cc.cell_index,
                                                                                  h->id,
                                                                                  ss_cfg->id,
                                                                                  time_res,
                                                                                  ue_grant_crbs,
                                                                                  dci_dl_format::f1_0,
                                                                                  agg_lvl,
                                                                                  mcs_prbs.mcs});
          if (res_allocated) {
            return true;
          }
        }
      }
    }
  }
  return false;
}

/// Allocate UE PUSCH grant.
static bool alloc_ul_ue(const ue&                    u,
                        const ue_resource_grid_view& res_grid,
                        ue_pusch_allocator&          pusch_alloc,
                        bool                         is_retx,
                        srslog::basic_logger&        logger)
{
  unsigned pending_newtx_bytes = 0;
  if (not is_retx) {
    pending_newtx_bytes = u.pending_ul_newtx_bytes();
    if (pending_newtx_bytes == 0) {
      return false;
    }
  }
  // TODO: Set aggregation level based on link quality.
  const aggregation_level agg_lvl    = srsran::aggregation_level::n4;
  slot_point              pdcch_slot = res_grid.get_pdcch_slot();

  // Prioritize PCell over SCells.
  for (unsigned i = 0; i != u.nof_cells(); ++i) {
    const ue_cell&            ue_cc           = u.get_cell(to_ue_cell_index(i));
    const cell_configuration& cell_cfg_common = res_grid.get_cell_cfg_common(ue_cc.cell_index);
    if (not cell_cfg_common.is_dl_enabled(res_grid.get_pdcch_slot())) {
      // DL needs to be active for PDCCH in this slot.
      continue;
    }

    const ul_harq_process* h = nullptr;
    h                        = is_retx ? ue_cc.harqs.find_pending_ul_retx() : ue_cc.harqs.find_empty_ul_harq();
    if (h == nullptr) {
      // No HARQs available.
      if (not is_retx) {
        logger.debug(
            "ue={} rnti={:#x} PUSCH allocation skipped. Cause: No available HARQs", ue_cc.ue_index, ue_cc.rnti());
      }
      continue;
    }

    for (const search_space_configuration* ss_cfg : get_ue_cell_prioritized_ss_for_agg_lvl(ue_cc, agg_lvl)) {
      const span<const pusch_time_domain_resource_allocation> pusch_list =
          ue_cc.cfg().get_pusch_time_domain_list(ss_cfg->id);
      bwp_configuration bwp_lims = ue_cc.alloc_type1_bwp_limits(dci_ul_format::f0_0, ss_cfg->type);

      // Search minimum k2 that corresponds to a UL slot.
      unsigned time_res = 0;
      for (; time_res != pusch_list.size(); ++time_res) {
        if (cell_cfg_common.is_ul_enabled(pdcch_slot + pusch_list[time_res].k2)) {
          // UL needs to be active for PUSCH in this slot.
          break;
        }
      }
      if (time_res == pusch_list.size()) {
        // no valid k2 found.
        continue;
      }

      const unsigned                 k2   = pusch_list[time_res].k2;
      const cell_slot_resource_grid& grid = res_grid.get_pusch_grid(ue_cc.cell_index, k2);
      if (res_grid.has_ue_ul_grant(ue_cc.cell_index, ue_cc.rnti(), k2)) {
        // only one PUSCH per UE per slot.
        continue;
      }
      // TODO: Get correct DCI format.
      const dci_ul_rnti_config_type dci_type      = dci_ul_rnti_config_type::c_rnti_f0_0;
      const ofdm_symbol_range       pusch_symbols = pusch_list[time_res].symbols;
      const prb_bitmap              used_crbs     = grid.used_crbs(bwp_lims, pusch_symbols);

      // Compute the MCS and the number of PRBs, depending on the pending bytes to transmit.
      const grant_prbs_mcs mcs_prbs =
          is_retx ? grant_prbs_mcs{h->last_tx_params().mcs, h->last_tx_params().prbs.prbs().length()}
                  : ue_cc.required_ul_prbs(time_res, pending_newtx_bytes, dci_type);

      const crb_interval ue_grant_crbs  = find_empty_interval_of_length(used_crbs, mcs_prbs.n_prbs, 0);
      bool               are_crbs_valid = not ue_grant_crbs.empty(); // Cannot be empty.
      if (is_retx) {
        // In case of Retx, the #CRBs need to stay the same.
        are_crbs_valid = ue_grant_crbs.length() == h->last_tx_params().prbs.prbs().length();
      }
      if (are_crbs_valid) {
        const bool res_allocated = pusch_alloc.allocate_ul_grant(ue_pusch_grant{
            &u, ue_cc.cell_index, h->id, ue_grant_crbs, pusch_symbols, time_res, ss_cfg->id, agg_lvl, mcs_prbs.mcs});
        if (res_allocated) {
          return true;
        }
      }
    }
  }
  return false;
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

scheduler_time_rr::scheduler_time_rr() :
  logger(srslog::fetch_basic_logger("SCHED")),
  next_dl_ue_index(INVALID_DU_UE_INDEX),
  next_ul_ue_index(INVALID_DU_UE_INDEX)
{
}

void scheduler_time_rr::dl_sched(ue_pdsch_allocator&          pdsch_alloc,
                                 const ue_resource_grid_view& res_grid,
                                 const ue_list&               ues,
                                 bool                         is_retx)
{
  auto tx_ue_function = [this, &res_grid, &pdsch_alloc, is_retx](const ue& u) {
    return alloc_dl_ue(u, res_grid, pdsch_alloc, is_retx, logger);
  };
  auto stop_iter = [&res_grid]() {
    // TODO: Account for different BWPs and cells.
    du_cell_index_t cell_idx    = to_du_cell_index(0);
    auto&           init_dl_bwp = res_grid.get_cell_cfg_common(cell_idx).dl_cfg_common.init_dl_bwp;
    // If all RBs are occupied, stop iteration.
    return res_grid.get_pdsch_grid(cell_idx, init_dl_bwp.pdsch_common.pdsch_td_alloc_list[0].k0)
        .used_crbs(init_dl_bwp.generic_params, init_dl_bwp.pdsch_common.pdsch_td_alloc_list[0].symbols)
        .all();
  };
  next_dl_ue_index = round_robin_apply(ues, next_dl_ue_index, tx_ue_function, stop_iter);
}

void scheduler_time_rr::ul_sched(ue_pusch_allocator&          pusch_alloc,
                                 const ue_resource_grid_view& res_grid,
                                 const ue_list&               ues,
                                 bool                         is_retx)
{
  auto tx_ue_function = [this, &res_grid, &pusch_alloc, is_retx](const ue& u) {
    return alloc_ul_ue(u, res_grid, pusch_alloc, is_retx, logger);
  };
  auto stop_iter = [&res_grid]() {
    // TODO: Account for different BWPs and cells.
    du_cell_index_t cell_idx    = to_du_cell_index(0);
    auto&           init_ul_bwp = res_grid.get_cell_cfg_common(cell_idx).ul_cfg_common.init_ul_bwp;
    // If all RBs are occupied, stop iteration.
    return res_grid.get_pusch_grid(cell_idx, init_ul_bwp.pusch_cfg_common->pusch_td_alloc_list[0].k2)
        .used_crbs(init_ul_bwp.generic_params, init_ul_bwp.pusch_cfg_common->pusch_td_alloc_list[0].symbols)
        .all();
  };
  next_ul_ue_index = round_robin_apply(ues, next_ul_ue_index, tx_ue_function, stop_iter);
}
