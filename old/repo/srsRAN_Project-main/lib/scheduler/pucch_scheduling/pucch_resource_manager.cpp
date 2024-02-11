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

#include "../support/pucch/pucch_default_resource.h"
#include "pucch_allocator_impl.h"

using namespace srsran;

/////////////    RESOURCE MANAGER     /////////////

/////////////   Public methods   /////////////

int get_pucch_res_idx_for_csi(const ue_cell_configuration& ue_cell_cfg)
{
  // We assume we use only 1 CSI report.
  const unsigned csi_report_cfg_idx = 0;
  // We assume we use the First BWP.
  // TODO: extend by passing the BWP id.
  const bwp_id_t bwp_id      = srsran::MIN_BWP_ID;
  const auto& csi_report_cfg = ue_cell_cfg.cfg_dedicated().csi_meas_cfg.value().csi_report_cfg_list[csi_report_cfg_idx];
  auto&       csi_pucch_res_list =
      variant_get<csi_report_config::periodic_or_semi_persistent_report_on_pucch>(csi_report_cfg.report_cfg_type)
          .pucch_csi_res_list;

  const auto& it = std::find_if(csi_pucch_res_list.begin(),
                                csi_pucch_res_list.end(),
                                [](const csi_report_config::pucch_csi_resource& csi) { return csi.ul_bwp == bwp_id; });

  if (it != csi_pucch_res_list.end()) {
    return static_cast<int>(it->pucch_res_id);
  }

  return -1;
}

/////////////   Public methods   /////////////

pucch_resource_manager::pucch_resource_manager()
{
  auto reset_slot_record = [](rnti_pucch_res_id_slot_record& res_counter) {
    res_counter.ue_using_csi_resource = INVALID_RNTI;
    for (auto& ue_rec : res_counter.ues_using_format1_res) {
      ue_rec = INVALID_RNTI;
    }
    for (auto& ue_rec : res_counter.ues_using_format2_res) {
      ue_rec = INVALID_RNTI;
    }
    for (auto& ue_rec : res_counter.ues_using_sr_resources) {
      ue_rec.pucch_res_id = -1;
      ue_rec.allocated_ue = INVALID_RNTI;
    }
  };

  std::for_each(resource_slots.begin(), resource_slots.end(), reset_slot_record);
}

void pucch_resource_manager::slot_indication(slot_point slot_tx)
{
  // Update Slot.
  last_sl_ind = slot_tx;

  rnti_pucch_res_id_slot_record& res_counter = get_slot_resource_counter(last_sl_ind - 1);

  res_counter.ue_using_csi_resource = INVALID_RNTI;
  for (auto& ue_rec : res_counter.ues_using_format1_res) {
    ue_rec = INVALID_RNTI;
  }
  for (auto& ue_rec : res_counter.ues_using_format2_res) {
    ue_rec = INVALID_RNTI;
  }
  for (auto& ue_rec : res_counter.ues_using_sr_resources) {
    ue_rec.pucch_res_id = -1;
    ue_rec.allocated_ue = INVALID_RNTI;
  }
}

pucch_harq_resource_alloc_record pucch_resource_manager::reserve_next_harq_res_available(slot_point          slot_harq,
                                                                                         rnti_t              crnti,
                                                                                         const pucch_config& pucch_cfg)
{
  srsran_sanity_check(slot_harq < last_sl_ind + RES_MANAGER_RING_BUFFER_SIZE,
                      "PUCCH being allocated to far into the future");

  // Get resource list of wanted slot.
  rnti_pucch_res_id_slot_record& res_counter = get_slot_resource_counter(slot_harq);

  const auto available_resource = std::find_if(res_counter.ues_using_format1_res.begin(),
                                               res_counter.ues_using_format1_res.end(),
                                               [](const rnti_t rnti) { return rnti == INVALID_RNTI; });

  const auto& pucch_res_list = pucch_cfg.pucch_res_list;

  const unsigned pucch_resource_set_format1_idx = 0;

  if (available_resource != res_counter.ues_using_format1_res.end() and
      static_cast<unsigned>(available_resource - res_counter.ues_using_format1_res.begin()) <
          pucch_cfg.pucch_res_set[pucch_resource_set_format1_idx].pucch_res_id_list.size()) {
    const unsigned pucch_res_indicator =
        static_cast<unsigned>(available_resource - res_counter.ues_using_format1_res.begin());
    *available_resource = crnti;
    const unsigned pucch_res_idx_from_list =
        pucch_cfg.pucch_res_set[pucch_resource_set_format1_idx].pucch_res_id_list[pucch_res_indicator];
    return pucch_harq_resource_alloc_record{.pucch_res           = &pucch_res_list[pucch_res_idx_from_list],
                                            .pucch_res_indicator = pucch_res_indicator};
  }
  return pucch_harq_resource_alloc_record{.pucch_res = nullptr};
};

pucch_harq_resource_alloc_record
pucch_resource_manager::reserve_next_format2_res_available(slot_point          slot_harq,
                                                           rnti_t              crnti,
                                                           const pucch_config& pucch_cfg)
{
  srsran_sanity_check(slot_harq < last_sl_ind + RES_MANAGER_RING_BUFFER_SIZE,
                      "PUCCH being allocated to far into the future");

  // Get resource list of wanted slot.
  rnti_pucch_res_id_slot_record& res_counter = get_slot_resource_counter(slot_harq);

  auto available_resource = std::find_if(res_counter.ues_using_format2_res.begin(),
                                         res_counter.ues_using_format2_res.end(),
                                         [](const rnti_t rnti) { return rnti == INVALID_RNTI; });

  const auto& pucch_res_list = pucch_cfg.pucch_res_list;

  const unsigned PUCCH_RESOURCE_SET_FORMAT2_IDX = 1;

  if (available_resource != res_counter.ues_using_format2_res.end() and
      static_cast<unsigned>(available_resource - res_counter.ues_using_format2_res.begin()) <
          pucch_cfg.pucch_res_set[PUCCH_RESOURCE_SET_FORMAT2_IDX].pucch_res_id_list.size()) {
    unsigned pucch_res_indicator =
        static_cast<unsigned>(available_resource - res_counter.ues_using_format2_res.begin());
    *available_resource = crnti;
    unsigned pucch_res_idx_from_list =
        pucch_cfg.pucch_res_set[PUCCH_RESOURCE_SET_FORMAT2_IDX].pucch_res_id_list[pucch_res_indicator];

    return pucch_harq_resource_alloc_record{.pucch_res           = &pucch_res_list[pucch_res_idx_from_list],
                                            .pucch_res_indicator = pucch_res_indicator};
  }
  return pucch_harq_resource_alloc_record{.pucch_res = nullptr};
};

const pucch_resource* pucch_resource_manager::reserve_specific_format2_res(slot_point          slot_harq,
                                                                           rnti_t              crnti,
                                                                           unsigned            res_indicator,
                                                                           const pucch_config& pucch_cfg)
{
  srsran_sanity_check(slot_harq < last_sl_ind + RES_MANAGER_RING_BUFFER_SIZE,
                      "PUCCH being allocated to far into the future");

  // Get resource list of wanted slot.
  rnti_pucch_res_id_slot_record& res_counter = get_slot_resource_counter(slot_harq);

  const unsigned PUCCH_RESOURCE_SET_FORMAT2_IDX = 1;
  if (res_indicator >= std::min(res_counter.ues_using_format2_res.size(),
                                pucch_cfg.pucch_res_set[PUCCH_RESOURCE_SET_FORMAT2_IDX].pucch_res_id_list.size())) {
    // PUCCH resource indicator exceeds the PUCCH resource set list.
    return nullptr;
  }

  const auto& pucch_res_list = pucch_cfg.pucch_res_list;

  if (res_counter.ues_using_format2_res[res_indicator] == INVALID_RNTI) {
    res_counter.ues_using_format2_res[res_indicator] = crnti;
    unsigned pucch_res_idx_from_list =
        pucch_cfg.pucch_res_set[PUCCH_RESOURCE_SET_FORMAT2_IDX].pucch_res_id_list[res_indicator];
    return &pucch_res_list[pucch_res_idx_from_list];
  }
  return nullptr;
}

const pucch_resource* pucch_resource_manager::reserve_csi_resource(slot_point                   slot_csi,
                                                                   rnti_t                       crnti,
                                                                   const ue_cell_configuration& ue_cell_cfg)
{
  srsran_sanity_check(slot_csi < last_sl_ind + RES_MANAGER_RING_BUFFER_SIZE,
                      "PUCCH being allocated to far into the future");

  auto& slot_record = get_slot_resource_counter(slot_csi);

  const pucch_config& pucch_cfg = ue_cell_cfg.cfg_dedicated().ul_config.value().init_ul_bwp.pucch_cfg.value();

  const int csi_pucch_res_idx = get_pucch_res_idx_for_csi(ue_cell_cfg);
  if (csi_pucch_res_idx < 0) {
    return nullptr;
  }

  // Check if the list of PUCCH resources contains the resource indexed to be used for CSI.
  if (slot_record.ue_using_csi_resource == INVALID_RNTI) {
    const auto& pucch_res_list         = pucch_cfg.pucch_res_list;
    const auto* csi_pucch_resource_cfg = std::find_if(
        pucch_res_list.begin(), pucch_res_list.end(), [csi_pucch_res_idx](const pucch_resource& pucch_res) {
          return static_cast<unsigned>(csi_pucch_res_idx) == pucch_res.res_id;
        });

    // If there is no such PUCCH resource, return \c nullptr.
    if (csi_pucch_resource_cfg == pucch_res_list.end()) {
      return nullptr;
    }

    slot_record.ue_using_csi_resource = crnti;
    return &pucch_cfg.pucch_res_list[csi_pucch_res_idx];
  }
  return nullptr;
};

const pucch_resource*
pucch_resource_manager::reserve_sr_res_available(slot_point slot_sr, rnti_t crnti, const pucch_config& pucch_cfg)
{
  srsran_sanity_check(slot_sr < last_sl_ind + RES_MANAGER_RING_BUFFER_SIZE,
                      "PUCCH being allocated to far into the future");
  srsran_sanity_check(pucch_cfg.sr_res_list.size() == 1, "UE SR resource list must have size 1.");

  auto& slot_record = get_slot_resource_counter(slot_sr);

  // We assume each UE only has 1 SR Resource Config configured.
  const unsigned sr_pucch_res_id = pucch_cfg.sr_res_list[0].pucch_res_id;
  auto*          it              = std::find_if(slot_record.ues_using_sr_resources.begin(),
                          slot_record.ues_using_sr_resources.end(),
                          [sr_res_idx = pucch_cfg.sr_res_list[0].pucch_res_id](const sr_record& sr_rec) {
                            return static_cast<int>(sr_res_idx) == sr_rec.pucch_res_id;
                          });

  // If there is already a record for this pucch_res_id, it means it is used by another UE.
  if (it != slot_record.ues_using_sr_resources.end()) {
    return nullptr;
  }

  // Check the first available slot in the record list.
  it = std::find_if(slot_record.ues_using_sr_resources.begin(),
                    slot_record.ues_using_sr_resources.end(),
                    [](const sr_record& sr_rec) { return sr_rec.allocated_ue == INVALID_RNTI; });

  // There are no available records for the SR.
  if (it == slot_record.ues_using_sr_resources.end()) {
    return nullptr;
  }

  it->pucch_res_id = static_cast<int>(sr_pucch_res_id);
  it->allocated_ue = crnti;
  return &pucch_cfg.pucch_res_list[sr_pucch_res_id];
};

bool pucch_resource_manager::release_harq_resource(slot_point slot_harq, rnti_t crnti, const pucch_config& pucch_cfg)
{
  auto& allocated_ues = get_slot_resource_counter(slot_harq).ues_using_format1_res;
  auto  target_res = std::find_if(allocated_ues.begin(), allocated_ues.end(), [target_rnti = crnti](const rnti_t rnti) {
    return rnti == target_rnti;
  });

  // If the resources was found, then release it (i.e., remove the C-RNTI of the user allocated to it).
  if (target_res != allocated_ues.end()) {
    *target_res = INVALID_RNTI;
    return true;
  }

  return false;
}

bool pucch_resource_manager::release_format2_resource(slot_point slot_harq, rnti_t crnti, const pucch_config& pucch_cfg)
{
  auto& allocated_ues = get_slot_resource_counter(slot_harq).ues_using_format2_res;
  auto  target_res = std::find_if(allocated_ues.begin(), allocated_ues.end(), [target_rnti = crnti](const rnti_t rnti) {
    return rnti == target_rnti;
  });

  // If the resources was found, then release it (i.e., remove the C-RNTI of the user allocated to it).
  if (target_res != allocated_ues.end()) {
    *target_res = INVALID_RNTI;
    return true;
  }

  return false;
}

bool pucch_resource_manager::release_sr_resource(slot_point slot_sr, rnti_t crnti)
{
  auto& slot_record = get_slot_resource_counter(slot_sr);

  auto* it = std::find_if(slot_record.ues_using_sr_resources.begin(),
                          slot_record.ues_using_sr_resources.end(),
                          [crnti](const sr_record& sr_rec) { return crnti == sr_rec.allocated_ue; });

  // If the UE allocated to the SR PUCCH resource matches the given CRNTI, release the resource.
  if (it == slot_record.ues_using_sr_resources.end()) {
    return false;
  }

  it->allocated_ue = INVALID_RNTI;
  it->pucch_res_id = -1;
  return true;
}

bool pucch_resource_manager::release_csi_resource(slot_point slot_sr, rnti_t crnti)
{
  auto& allocated_ue = get_slot_resource_counter(slot_sr).ue_using_csi_resource;

  // If the UE allocated to the SR PUCCH resource matches the given CRNTI, release the resource.
  if (allocated_ue == crnti) {
    allocated_ue = INVALID_RNTI;
    return true;
  }

  return false;
}

int pucch_resource_manager::fetch_f1_pucch_res_indic(slot_point slot_tx, rnti_t crnti)
{
  const auto& ue_recs = get_slot_resource_counter(slot_tx).ues_using_format1_res;

  auto ue_resource = std::find_if(
      ue_recs.begin(), ue_recs.end(), [target_rnti = crnti](const rnti_t rnti) { return rnti == target_rnti; });

  // -1 indicates that the there is no UE record for given RNTI.
  return ue_resource != ue_recs.end() ? static_cast<int>(ue_resource - ue_recs.begin()) : -1;
}

int pucch_resource_manager::fetch_f2_pucch_res_indic(slot_point slot_tx, rnti_t crnti)
{
  const auto& ue_recs = get_slot_resource_counter(slot_tx).ues_using_format2_res;

  auto ue_resource = std::find_if(
      ue_recs.begin(), ue_recs.end(), [target_rnti = crnti](const rnti_t rnti) { return rnti == target_rnti; });

  // -1 indicates that the there is no UE record for given RNTI.
  return ue_resource != ue_recs.end() ? static_cast<int>(ue_resource - ue_recs.begin()) : -1;
}

const pucch_resource* pucch_resource_manager::fetch_csi_pucch_res_config(slot_point                   slot_tx,
                                                                         rnti_t                       crnti,
                                                                         const ue_cell_configuration& ue_cell_cfg)
{
  srsran_sanity_check(slot_tx < last_sl_ind + RES_MANAGER_RING_BUFFER_SIZE,
                      "PUCCH being allocated to far into the future");

  rnti_pucch_res_id_slot_record& slot_record = get_slot_resource_counter(slot_tx);

  if (slot_record.ue_using_csi_resource != crnti) {
    return nullptr;
  }

  const pucch_config& pucch_cfg = ue_cell_cfg.cfg_dedicated().ul_config.value().init_ul_bwp.pucch_cfg.value();

  const int csi_pucch_res_idx = get_pucch_res_idx_for_csi(ue_cell_cfg);
  if (csi_pucch_res_idx < 0) {
    return nullptr;
  }

  // Check if the list of PUCCH resources contains the resource indexed to be used for CSI.
  const auto& pucch_res_list = pucch_cfg.pucch_res_list;
  const auto* csi_pucch_resource_cfg =
      std::find_if(pucch_res_list.begin(), pucch_res_list.end(), [csi_pucch_res_idx](const pucch_resource& pucch_res) {
        return static_cast<unsigned>(csi_pucch_res_idx) == pucch_res.res_id;
      });

  return csi_pucch_resource_cfg != pucch_res_list.end() ? &pucch_cfg.pucch_res_list[csi_pucch_res_idx] : nullptr;
}

pucch_resource_manager::rnti_pucch_res_id_slot_record& pucch_resource_manager::get_slot_resource_counter(slot_point sl)
{
  srsran_sanity_check(sl < last_sl_ind + RES_MANAGER_RING_BUFFER_SIZE,
                      "PUCCH resource ring-buffer accessed too far into the future");
  return resource_slots[sl.to_uint() % RES_MANAGER_RING_BUFFER_SIZE];
}
