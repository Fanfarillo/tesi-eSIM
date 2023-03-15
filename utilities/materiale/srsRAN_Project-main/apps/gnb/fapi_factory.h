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

#include "srsran/fapi_adaptor/mac/mac_fapi_adaptor_factory.h"
#include "srsran/fapi_adaptor/phy/phy_fapi_adaptor_factory.h"

namespace srsran {

std::unique_ptr<fapi_adaptor::phy_fapi_adaptor> build_phy_fapi_adaptor(unsigned                    sector_id,
                                                                       subcarrier_spacing          scs,
                                                                       subcarrier_spacing          scs_common,
                                                                       downlink_processor_pool&    dl_processor_pool,
                                                                       resource_grid_pool&         dl_rg_pool,
                                                                       uplink_request_processor&   ul_request_processor,
                                                                       resource_grid_pool&         ul_rg_pool,
                                                                       uplink_slot_pdu_repository& ul_pdu_repository,
                                                                       const downlink_pdu_validator& dl_pdu_validator,
                                                                       const uplink_pdu_validator&   ul_pdu_validator,
                                                                       const fapi::prach_config&     prach_cfg,
                                                                       const fapi::carrier_config&   carrier_cfg);

std::unique_ptr<fapi_adaptor::mac_fapi_adaptor>
build_mac_fapi_adaptor(unsigned                          sector_id,
                       subcarrier_spacing                scs,
                       fapi::slot_message_gateway&       gateway,
                       fapi::slot_last_message_notifier& last_msg_notifier);

} // namespace srsran
