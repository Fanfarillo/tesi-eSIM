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

#include "../cell/cell_configuration.h"
#include "ue_configuration.h"
#include "srsran/scheduler/harq_id.h"
#include "srsran/scheduler/scheduler_slot_handler.h"

namespace srsran {

struct pdsch_config_params {
  pdsch_mcs_table   mcs_table;
  ofdm_symbol_range symbols;
  unsigned          nof_oh_prb;
  unsigned          tb_scaling_field;
  unsigned          nof_layers;
  dmrs_information  dmrs;
};

/// Contains some of the PUSCH parameters needed to compute the MCS, the number of PRBs, the TBS and to build the PUSCH
/// PDU.
struct pusch_config_params {
  pusch_mcs_table   mcs_table;
  ofdm_symbol_range symbols;
  unsigned          nof_oh_prb;
  unsigned          tb_scaling_field;
  unsigned          nof_layers;
  bool              tp_pi2bpsk_present;
  dmrs_information  dmrs;
  unsigned          nof_harq_ack_bits{0};
  unsigned          nof_csi_part1_bits{0};
  unsigned          nof_csi_part2_bits{0};
};

/// \brief Fetches the PUSCH parameters needed for PUSCH PDU for DCI format 0_0, scrambled by TC-RNTI.
///
/// The parameters returned by this function are needed to compute the number of PRBs, MCS and TBS.
pdsch_config_params get_pdsch_config_f1_0_tc_rnti(const cell_configuration& cell_cfg, unsigned time_resource);

/// \brief Fetches the PUSCH parameters needed for PUSCH PDU for DCI format 0_0, scrambled by TC-RNTI.
///
/// The parameters returned by this function are needed to compute the number of PRBs, MCS and TBS.
pdsch_config_params get_pdsch_config_f1_0_c_rnti(const cell_configuration&    cell_cfg,
                                                 const ue_cell_configuration& ue_cell_cfg,
                                                 unsigned                     time_resource);

/// \brief Fetches the PUSCH parameters needed for PUSCH PDU for DCI format 0_0, scrambled by TC-RNTI.
///
/// The parameters returned by this function are needed to compute the number of PRBs, MCS and TBS.
pusch_config_params get_pusch_config_f0_0_tc_rnti(const cell_configuration& cell_cfg, unsigned time_resource);

/// \brief Fetches the PUSCH parameters needed for PUSCH PDU for DCI format 0_0, scrambled by C-RNTI.
///
/// The parameters returned by this function are needed to compute the number of PRBs, MCS and TBS.
pusch_config_params get_pusch_config_f0_0_c_rnti(const cell_configuration&    cell_cfg,
                                                 const ue_cell_configuration& ue_cell_cfg,
                                                 const bwp_uplink_common&     ul_bwp,
                                                 unsigned                     time_resource);

/// \brief Builds PDSCH PDU for DCI format 1_0, scrambled by TC-RNTI.
void build_pdsch_f1_0_tc_rnti(pdsch_information&                   pdsch,
                              const pdsch_config_params&           pdsch_cfg,
                              unsigned                             tbs_bytes,
                              rnti_t                               rnti,
                              const cell_configuration&            cell_cfg,
                              const dci_1_0_tc_rnti_configuration& dci_cfg,
                              bool                                 is_new_data);

/// \brief Builds PDSCH PDU for DCI format 1_0, scrambled by C-RNTI.
void build_pdsch_f1_0_c_rnti(pdsch_information&                  pdsch,
                             const pdsch_config_params&          pdsch_cfg,
                             unsigned                            tbs_bytes,
                             rnti_t                              rnti,
                             const ue_cell_configuration&        ue_cell_cfg,
                             bwp_id_t                            active_bwp_id,
                             const search_space_configuration&   ss_cfg,
                             const dci_1_0_c_rnti_configuration& dci_cfg,
                             bool                                is_new_data);

/// \brief Builds PUSCH PDU for DCI format 0_0, scrambled by TC-RNTI.
void build_pusch_f0_0_tc_rnti(pusch_information&                   pusch,
                              const pusch_config_params&           pusch_cfg,
                              unsigned                             tbs_bytes,
                              rnti_t                               rnti,
                              const cell_configuration&            cell_cfg,
                              const dci_0_0_tc_rnti_configuration& dci_cfg,
                              bool                                 is_new_data);

/// \brief Builds PUSCH PDU for DCI format 0_0, scrambled by C-RNTI.
void build_pusch_f0_0_c_rnti(pusch_information&                  pusch,
                             rnti_t                              rnti,
                             const pusch_config_params&          pusch_cfg,
                             unsigned                            tbs_bytes,
                             const cell_configuration&           cell_cfg,
                             const bwp_uplink_common&            ul_bwp,
                             const dci_0_0_c_rnti_configuration& dci_cfg,
                             bool                                is_new_data);

} // namespace srsran
