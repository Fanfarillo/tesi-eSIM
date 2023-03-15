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

#include "srsran/adt/byte_buffer.h"
#include "srsran/adt/optional.h"
#include "srsran/ran/du_types.h"
#include "srsran/ran/lcid.h"
#include "srsran/ran/up_transport_layer_info.h"

namespace srsran {
namespace srs_du {

/// \brief Possible modes for an DRB RLC entity.
enum class drb_rlc_mode { am = 0, um_bidir, um_unidir_ul, um_unidir_dl };

/// \brief DRB to be setup in the UE context.
struct f1ap_drb_to_setup {
  drb_id_t                             drb_id;
  optional<lcid_t>                     lcid;
  drb_rlc_mode                         mode;
  uint8_t                              five_qi;
  std::vector<up_transport_layer_info> uluptnl_info_list;
};

/// \brief SCell to be setup in the UE context.
struct f1ap_scell_to_setup {
  serv_cell_index_t serv_cell_index;
  du_cell_index_t   cell_index;
};

/// \brief DRB that was setup successfully in the F1AP UE context.
struct f1ap_drb_setup {
  drb_id_t                             drb_id;
  optional<lcid_t>                     lcid;
  std::vector<up_transport_layer_info> dluptnl_info_list;
};

/// \brief Request from DU F1AP to DU manager to modify existing UE configuration.
struct f1ap_ue_context_update_request {
  du_ue_index_t                    ue_index;
  std::vector<srb_id_t>            srbs_to_setup;
  std::vector<f1ap_drb_to_setup>   drbs_to_setup;
  std::vector<drb_id_t>            drbs_to_rem;
  std::vector<f1ap_scell_to_setup> scells_to_setup;
  std::vector<serv_cell_index_t>   scells_to_rem;
};

/// \brief Response from DU manager to DU F1AP with the result of the UE context update.
struct f1ap_ue_context_update_response {
  bool                        result;
  std::vector<f1ap_drb_setup> drbs_setup;
  std::vector<drb_id_t>       drbs_failed_to_setup;
  byte_buffer                 du_to_cu_rrc_container;
};

} // namespace srs_du
} // namespace srsran
