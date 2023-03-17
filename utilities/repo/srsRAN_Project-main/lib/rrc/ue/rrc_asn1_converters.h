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
#include "srsran/asn1/rrc_nr/rrc_nr.h"
#include "srsran/cu_cp/cu_cp_types.h"
#include <string>
#include <vector>

namespace srsran {
namespace srs_cu_cp {

/// \brief Converts type \c pdcp_config_t to an RRC NR ASN.1 type.
/// \param pdcp_cfg pdcp config object.
/// \return The RRC NR ASN.1 object where the result of the conversion is stored.
inline asn1::rrc_nr::pdcp_cfg_s pdcp_config_to_rrc_nr_asn1(pdcp_config_t pdcp_cfg)
{
  asn1::rrc_nr::pdcp_cfg_s rrc_pdcp_cfg;

  // drb
  if (pdcp_cfg.drb.has_value()) {
    rrc_pdcp_cfg.drb_present = true;

    // hdr compress
    if (pdcp_cfg.drb.value().hdr_compress.rohc.has_value()) {
      rrc_pdcp_cfg.drb.hdr_compress.set_rohc();
      auto& rrc_rohc = rrc_pdcp_cfg.drb.hdr_compress.rohc();

      // profiles
      rrc_rohc.profiles.profile0x0001 = pdcp_cfg.drb.value().hdr_compress.rohc.value().profiles.profile0x0001;
      rrc_rohc.profiles.profile0x0002 = pdcp_cfg.drb.value().hdr_compress.rohc.value().profiles.profile0x0002;
      rrc_rohc.profiles.profile0x0003 = pdcp_cfg.drb.value().hdr_compress.rohc.value().profiles.profile0x0003;
      rrc_rohc.profiles.profile0x0004 = pdcp_cfg.drb.value().hdr_compress.rohc.value().profiles.profile0x0004;
      rrc_rohc.profiles.profile0x0006 = pdcp_cfg.drb.value().hdr_compress.rohc.value().profiles.profile0x0006;
      rrc_rohc.profiles.profile0x0101 = pdcp_cfg.drb.value().hdr_compress.rohc.value().profiles.profile0x0101;
      rrc_rohc.profiles.profile0x0102 = pdcp_cfg.drb.value().hdr_compress.rohc.value().profiles.profile0x0102;
      rrc_rohc.profiles.profile0x0103 = pdcp_cfg.drb.value().hdr_compress.rohc.value().profiles.profile0x0103;
      rrc_rohc.profiles.profile0x0104 = pdcp_cfg.drb.value().hdr_compress.rohc.value().profiles.profile0x0104;

      // drb continue rohc
      rrc_rohc.drb_continue_rohc_present = pdcp_cfg.drb.value().hdr_compress.rohc.value().drb_continue_rohc_present;

      // max c id
      if (pdcp_cfg.drb.value().hdr_compress.rohc.value().max_cid.has_value()) {
        rrc_rohc.max_c_id_present = true;
        rrc_rohc.max_c_id         = pdcp_cfg.drb.value().hdr_compress.rohc.value().max_cid.value();
      }
    } else if (pdcp_cfg.drb.value().hdr_compress.ul_only_rohc.has_value()) {
      rrc_pdcp_cfg.drb.hdr_compress.set_ul_only_rohc();
      auto& rrc_ul_only_rohc = rrc_pdcp_cfg.drb.hdr_compress.ul_only_rohc();

      // profiles
      rrc_ul_only_rohc.profiles.profile0x0006 =
          pdcp_cfg.drb.value().hdr_compress.ul_only_rohc.value().profiles.profile0x0006;

      // drb continue rohc

      rrc_ul_only_rohc.drb_continue_rohc_present =
          pdcp_cfg.drb.value().hdr_compress.ul_only_rohc.value().drb_continue_rohc_present;

      // max c id
      if (pdcp_cfg.drb.value().hdr_compress.ul_only_rohc.value().max_cid.has_value()) {
        rrc_ul_only_rohc.max_c_id_present = true;
        rrc_ul_only_rohc.max_c_id         = pdcp_cfg.drb.value().hdr_compress.ul_only_rohc.value().max_cid.value();
      }
    } else {
      rrc_pdcp_cfg.drb.hdr_compress.set_not_used();
    }

    // discard timer
    if (pdcp_cfg.drb.value().discard_timer.has_value()) {
      rrc_pdcp_cfg.drb.discard_timer_present = true;
      asn1::number_to_enum(rrc_pdcp_cfg.drb.discard_timer, pdcp_cfg.drb.value().discard_timer.value());
    }

    // pdcp sn size ul
    if (pdcp_cfg.drb.value().pdcp_sn_size_ul.has_value()) {
      rrc_pdcp_cfg.drb.pdcp_sn_size_ul_present = true;
      asn1::number_to_enum(rrc_pdcp_cfg.drb.pdcp_sn_size_ul,
                           pdcp_sn_size_to_uint(pdcp_cfg.drb.value().pdcp_sn_size_ul.value()));
    }

    // pdcp sn size dl
    if (pdcp_cfg.drb.value().pdcp_sn_size_dl.has_value()) {
      rrc_pdcp_cfg.drb.pdcp_sn_size_dl_present = true;
      asn1::number_to_enum(rrc_pdcp_cfg.drb.pdcp_sn_size_dl,
                           pdcp_sn_size_to_uint(pdcp_cfg.drb.value().pdcp_sn_size_dl.value()));
    }

    // integrity protection present
    rrc_pdcp_cfg.drb.integrity_protection_present = pdcp_cfg.drb.value().integrity_protection_present;

    // status report required present
    rrc_pdcp_cfg.drb.status_report_required_present = pdcp_cfg.drb.value().status_report_required_present;

    // out of order delivery present
    rrc_pdcp_cfg.drb.out_of_order_delivery_present = pdcp_cfg.drb.value().out_of_order_delivery_present;
  }

  // more than one rlc
  if (pdcp_cfg.more_than_one_rlc.has_value()) {
    rrc_pdcp_cfg.more_than_one_rlc_present = true;

    // primary path
    // cell group
    if (pdcp_cfg.more_than_one_rlc.value().primary_path.cell_group.has_value()) {
      rrc_pdcp_cfg.more_than_one_rlc.primary_path.cell_group_present = true;
      rrc_pdcp_cfg.more_than_one_rlc.primary_path.cell_group =
          pdcp_cfg.more_than_one_rlc.value().primary_path.cell_group.value();
    }
    // lc ch
    if (pdcp_cfg.more_than_one_rlc.value().primary_path.lc_ch.has_value()) {
      rrc_pdcp_cfg.more_than_one_rlc.primary_path.lc_ch_present = true;
      rrc_pdcp_cfg.more_than_one_rlc.primary_path.lc_ch = pdcp_cfg.more_than_one_rlc.value().primary_path.lc_ch.value();
    }
    // ul data split thres
    if (pdcp_cfg.more_than_one_rlc.value().ul_data_split_thres.has_value()) {
      rrc_pdcp_cfg.more_than_one_rlc.ul_data_split_thres_present = true;
      asn1::number_to_enum(rrc_pdcp_cfg.more_than_one_rlc.ul_data_split_thres,
                           pdcp_cfg.more_than_one_rlc.value().ul_data_split_thres.value());
    }
    // pdcp dupl
    if (pdcp_cfg.more_than_one_rlc.value().pdcp_dupl.has_value()) {
      rrc_pdcp_cfg.more_than_one_rlc.pdcp_dupl_present = true;
      rrc_pdcp_cfg.more_than_one_rlc.pdcp_dupl         = pdcp_cfg.more_than_one_rlc.value().pdcp_dupl.value();
    }
  }

  // t reordering
  if (pdcp_cfg.t_reordering.has_value()) {
    rrc_pdcp_cfg.t_reordering_present = true;
    asn1::number_to_enum(rrc_pdcp_cfg.t_reordering, pdcp_cfg.t_reordering.value());
  }

  // ciphering disabled present
  rrc_pdcp_cfg.ciphering_disabled_present = pdcp_cfg.ciphering_disabled_present;

  return rrc_pdcp_cfg;
}

/// \brief Converts type \c sdap_config to an RRC NR ASN.1 type.
/// \param sdap_cfg sdap config object.
/// \return The RRC NR ASN.1 object where the result of the conversion is stored.
inline asn1::rrc_nr::sdap_cfg_s sdap_config_to_rrc_asn1(sdap_config_t sdap_cfg)
{
  asn1::rrc_nr::sdap_cfg_s asn1_sdap_cfg;

  // pdu session
  asn1_sdap_cfg.pdu_session = pdu_session_id_to_uint(sdap_cfg.pdu_session);

  // sdap hdr dl
  asn1::string_to_enum(asn1_sdap_cfg.sdap_hdr_dl, sdap_cfg.sdap_hdr_dl);

  // sdap hdr ul
  asn1::string_to_enum(asn1_sdap_cfg.sdap_hdr_ul, sdap_cfg.sdap_hdr_ul);

  // default drb
  asn1_sdap_cfg.default_drb = sdap_cfg.default_drb;

  // mapped qos flow to add
  for (const auto& mapped_qps_flow_to_add : sdap_cfg.mapped_qos_flows_to_add) {
    asn1_sdap_cfg.mapped_qos_flows_to_add.push_back(qos_flow_id_to_uint(mapped_qps_flow_to_add));
  }

  // mapped qos flow to release
  for (const auto& mapped_qps_flow_to_release : sdap_cfg.mapped_qos_flows_to_release) {
    asn1_sdap_cfg.mapped_qos_flows_to_release.push_back(qos_flow_id_to_uint(mapped_qps_flow_to_release));
  }

  return asn1_sdap_cfg;
}

} // namespace srs_cu_cp
} // namespace srsran
