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

#include "srsran/fapi_adaptor/phy/messages/prach.h"
#include "srsran/phy/support/prach_buffer_context.h"

using namespace srsran;
using namespace fapi_adaptor;

static preamble_format convert_fapi_format_to_phy(fapi::prach_format_type format)
{
  switch (format) {
    case fapi::prach_format_type::zero:
      return preamble_format::values::FORMAT0;
    case fapi::prach_format_type::one:
      return preamble_format::values::FORMAT1;
    case fapi::prach_format_type::two:
      return preamble_format::values::FORMAT2;
    case fapi::prach_format_type::three:
      return preamble_format::values::FORMAT3;
    default:
      srsran_assert(0, "Invalid PRACH format type ({})", static_cast<unsigned>(format));
      break;
  }

  return preamble_format::values::FORMAT1;
}

void srsran::fapi_adaptor::convert_prach_fapi_to_phy(prach_buffer_context&       context,
                                                     const fapi::ul_prach_pdu&   fapi_pdu,
                                                     const fapi::prach_config&   prach_cfg,
                                                     const fapi::carrier_config& carrier_cfg,
                                                     unsigned                    sfn,
                                                     unsigned                    slot,
                                                     unsigned                    sector_id)
{
  srsran_assert(fapi_pdu.maintenance_v3.prach_config_scope == fapi::prach_config_scope_type::phy_context,
                "Common context not supported.");
  srsran_assert(fapi_pdu.maintenance_v3.prach_res_config_index == 0,
                "Only PRACH resource configuration index 0 supported.");
  srsran_assert(fapi_pdu.index_fd_ra == 0, "Only one FD occasion supported.");
  srsran_assert(fapi_pdu.num_prach_ocas == 1, "Only one PRACH occasion supported.");

  context.slot                 = slot_point(prach_cfg.prach_ul_bwp_pusch_scs, sfn, slot);
  context.sector               = sector_id;
  context.format               = convert_fapi_format_to_phy(fapi_pdu.prach_format);
  context.start_symbol         = fapi_pdu.prach_start_symbol;
  context.start_preamble_index = fapi_pdu.maintenance_v3.start_preamble_index;
  context.nof_preamble_indices = fapi_pdu.maintenance_v3.num_preamble_indices;

  context.pusch_scs       = prach_cfg.prach_ul_bwp_pusch_scs;
  context.restricted_set  = prach_cfg.restricted_set;
  context.nof_prb_ul_grid = carrier_cfg.ul_grid_size[to_numerology_value(context.pusch_scs)];

  srsran_assert(fapi_pdu.index_fd_ra < prach_cfg.fd_occasions.size(), "Index FD RA out of bounds");
  const fapi::prach_fd_occasion_config& fd_occas = prach_cfg.fd_occasions[fapi_pdu.index_fd_ra];
  context.rb_offset                              = fd_occas.prach_freq_offset;
  context.root_sequence_index                    = fd_occas.prach_root_sequence_index;
  context.zero_correlation_zone                  = fd_occas.prach_zero_corr_conf;

  // NOTE: set the port to 0 for now.
  context.port = 0;
}
