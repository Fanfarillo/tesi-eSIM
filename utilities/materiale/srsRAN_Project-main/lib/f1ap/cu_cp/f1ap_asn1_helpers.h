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

#include "f1ap_asn1_converters.h"
#include "srsran/f1ap/cu_cp/f1ap_cu.h"
#include "srsran/ran/lcid.h"

namespace srsran {
namespace srs_cu_cp {

/// \brief Convert the UE Context Modification Request from common type to ASN.1.
/// \param[out] asn1_request The ASN.1 struct to store the result.
/// \param[in] msg The common type UE Context Modification Request.
inline void fill_f1ap_ue_context_modification_request(asn1::f1ap::ue_context_mod_request_s&        asn1_request,
                                                      const cu_cp_ue_context_modification_request& msg)
{
  // drb to be setup mod list
  asn1_request->drbs_to_be_setup_mod_list_present = msg.cu_cp_drb_setup_msgs.size() > 0;
  for (const auto& drb_to_be_setup : msg.cu_cp_drb_setup_msgs) {
    asn1::protocol_ie_single_container_s<asn1::f1ap::drbs_to_be_setup_mod_item_ies_o> asn1_setup_item;
    auto& asn1_drb_to_setup_item = asn1_setup_item->drbs_to_be_setup_mod_item();

    asn1_drb_to_setup_item.drb_id = drb_id_to_uint(drb_to_be_setup.drb_id);
    switch (drb_to_be_setup.rlc) {
      case rlc_mode::am:
        asn1_drb_to_setup_item.rlc_mode.value = asn1::f1ap::rlc_mode_opts::rlc_am;
        break;
      case rlc_mode::um_bidir:
        asn1_drb_to_setup_item.rlc_mode.value = asn1::f1ap::rlc_mode_opts::rlc_um_bidirectional;
        break;
      case rlc_mode::um_unidir_dl:
        asn1_drb_to_setup_item.rlc_mode.value = asn1::f1ap::rlc_mode_opts::rlc_um_unidirectional_dl;
        break;
      case rlc_mode::um_unidir_ul:
        asn1_drb_to_setup_item.rlc_mode.value = asn1::f1ap::rlc_mode_opts::rlc_um_unidirectional_ul;
        break;
      case rlc_mode::tm:
        // TM not supported for DRBs
        report_fatal_error("Invalid RLC mode {}", drb_to_be_setup.rlc);
        break;
    }

    // Add uLUPTNLInformation_ToBeSetup
    for (const auto& gtp_tunnel_item : drb_to_be_setup.gtp_tunnels) {
      asn1::f1ap::ul_up_tnl_info_to_be_setup_item_s item;
      up_transport_layer_info_to_asn1(item.ul_up_tnl_info, gtp_tunnel_item);
      asn1_drb_to_setup_item.ul_up_tnl_info_to_be_setup_list.push_back(item);
    }

    // Add qos information
    asn1_drb_to_setup_item.qos_info.set_choice_ext();
    auto& choice_ext = asn1_drb_to_setup_item.qos_info.choice_ext();
    choice_ext.load_info_obj(ASN1_F1AP_ID_DRB_INFO);

    auto& drb_info = choice_ext.value().drb_info();
    drb_info.drb_qos.qos_characteristics.set_non_dyn_5qi();
    drb_info.drb_qos.qos_characteristics.non_dyn_5qi().five_qi = drb_to_be_setup.qos_info.five_qi;
    drb_info.drb_qos.ngra_nalloc_retention_prio.prio_level     = drb_to_be_setup.qos_info.prio_level_arp;
    drb_info.drb_qos.ngra_nalloc_retention_prio.pre_emption_cap =
        asn1::f1ap::pre_emption_cap_opts::shall_not_trigger_pre_emption;
    drb_info.drb_qos.ngra_nalloc_retention_prio.pre_emption_vulnerability.value =
        asn1::f1ap::pre_emption_vulnerability_opts::not_pre_emptable;
    drb_info.snssai.sst.from_number(drb_to_be_setup.s_nssai.sst);
    if (drb_to_be_setup.s_nssai.sd.has_value()) {
      drb_info.snssai.sd.from_number(drb_to_be_setup.s_nssai.sd.value());
    }

    for (const auto& qos_flow : drb_to_be_setup.qos_flows_mapped_to_drb) {
      asn1::f1ap::flows_mapped_to_drb_item_s asn1_flow;
      asn1_flow.qos_flow_id               = qos_flow_id_to_uint(qos_flow.qos_flow_id);
      asn1_flow.qos_flow_level_qos_params = drb_info.drb_qos;

      drb_info.flows_mapped_to_drb_list.push_back(asn1_flow);
    }

    asn1_request->drbs_to_be_setup_mod_list.value.push_back(asn1_setup_item);
  }

  // Add ue aggregate maximum bit rate
  if (msg.ue_aggregate_maximum_bit_rate_ul.has_value()) {
    asn1_request->gnb_du_ue_ambr_ul_present = true;
    asn1_request->gnb_du_ue_ambr_ul.value   = msg.ue_aggregate_maximum_bit_rate_ul.value();
  }
}

/// \brief Convert the UE Context Modification Response from ASN.1 to common type.
/// \param[out] res The common type struct to store the result.
/// \param[in] asn1_response The ASN.1 type UE Context Modification Response.
inline void fill_f1ap_ue_context_modification_response_message(cu_cp_ue_context_modification_response&  res,
                                                               const asn1::f1ap::ue_context_mod_resp_s& asn1_response)
{
  res.success = true;

  // DUtoCURRCInformation
  if (asn1_response->du_to_cu_rrc_info_present) {
    res.du_to_cu_rrc_info.cell_group_cfg      = asn1_response->du_to_cu_rrc_info->cell_group_cfg.copy();
    res.du_to_cu_rrc_info.meas_gap_cfg        = asn1_response->du_to_cu_rrc_info->meas_gap_cfg.copy();
    res.du_to_cu_rrc_info.requested_p_max_fr1 = asn1_response->du_to_cu_rrc_info->requested_p_max_fr1.copy();
  }

  // Add DRBs setup mod list
  if (asn1_response->drbs_setup_mod_list_present) {
    for (auto asn1_drb_setup_mod_list_item : asn1_response->drbs_setup_mod_list.value) {
      auto& asn1_drb_mod_item = asn1_drb_setup_mod_list_item.value().drbs_setup_mod_item();

      cu_cp_drbs_setup_modified_item drb_setup_mod_item;
      drb_setup_mod_item.drb_id = uint_to_drb_id(asn1_drb_mod_item.drb_id);

      // Add DL UP TNL to be setup list
      for (auto asn1_dl_up_tnl_info_to_be_setup_item : asn1_drb_mod_item.dl_up_tnl_info_to_be_setup_list) {
        cu_cp_dl_up_tnl_info_to_be_setup_item dl_up_tnl_info_to_be_setup_item;
        dl_up_tnl_info_to_be_setup_item.dl_up_tnl_info =
            asn1_to_up_transport_layer_info(asn1_dl_up_tnl_info_to_be_setup_item.dl_up_tnl_info);
        drb_setup_mod_item.dl_up_tnl_info_to_be_setup_list.push_back(dl_up_tnl_info_to_be_setup_item);
      }

      if (asn1_drb_mod_item.lcid_present) {
        drb_setup_mod_item.lcid = uint_to_lcid(asn1_drb_mod_item.lcid);
      }

      res.drbs_setup_mod_list.emplace(drb_setup_mod_item.drb_id, drb_setup_mod_item);
    }
  }

  // Add DRBs modified list
  if (asn1_response->drbs_modified_list_present) {
    for (auto asn1_drbs_modified_list_item : asn1_response->drbs_modified_list.value) {
      auto& asn1_drb_mod_item = asn1_drbs_modified_list_item.value().drbs_modified_item();

      cu_cp_drbs_setup_modified_item drb_setup_mod_item;
      drb_setup_mod_item.drb_id = uint_to_drb_id(asn1_drb_mod_item.drb_id);

      // Add DL UP TNL to be setup list
      for (auto asn1_dl_up_tnl_info_to_be_setup_item : asn1_drb_mod_item.dl_up_tnl_info_to_be_setup_list) {
        cu_cp_dl_up_tnl_info_to_be_setup_item dl_up_tnl_info_to_be_setup_item;
        dl_up_tnl_info_to_be_setup_item.dl_up_tnl_info =
            asn1_to_up_transport_layer_info(asn1_dl_up_tnl_info_to_be_setup_item.dl_up_tnl_info);
        drb_setup_mod_item.dl_up_tnl_info_to_be_setup_list.push_back(dl_up_tnl_info_to_be_setup_item);
      }

      if (asn1_drb_mod_item.lcid_present) {
        drb_setup_mod_item.lcid = uint_to_lcid(asn1_drb_mod_item.lcid);
      }

      res.drbs_modified_list.emplace(drb_setup_mod_item.drb_id, drb_setup_mod_item);
    }
  }

  // Add SRBs failed to be setup mod list
  if (asn1_response->srbs_failed_to_be_setup_mod_list_present) {
    for (auto asn1_srbs_failed_setup_mod_list_item : asn1_response->srbs_failed_to_be_setup_mod_list.value) {
      auto& asn1_srb_failed_item = asn1_srbs_failed_setup_mod_list_item.value().srbs_failed_to_be_setup_mod_item();

      cu_cp_srbs_failed_to_be_setup_mod_item srb_failed_item;
      srb_failed_item.srb_id = int_to_srb_id(asn1_srb_failed_item.srb_id);
      if (asn1_srb_failed_item.cause_present) {
        srb_failed_item.cause = f1ap_cause_to_cause(asn1_srb_failed_item.cause);
      }
      res.srbs_failed_to_be_setup_mod_list.emplace(srb_failed_item.srb_id, srb_failed_item);
    }
  }

  // Add DRBs failed to be setup mod list
  if (asn1_response->drbs_failed_to_be_setup_mod_list_present) {
    for (auto asn1_drbs_failed_setup_mod_list_item : asn1_response->drbs_failed_to_be_setup_mod_list.value) {
      auto& asn1_drb_failed_item = asn1_drbs_failed_setup_mod_list_item.value().drbs_failed_to_be_setup_mod_item();

      cu_cp_drbs_failed_to_be_setup_modified_item drb_failed_item;
      drb_failed_item.drb_id = uint_to_drb_id(asn1_drb_failed_item.drb_id);
      if (asn1_drb_failed_item.cause_present) {
        drb_failed_item.cause = f1ap_cause_to_cause(asn1_drb_failed_item.cause);
      }
      res.drbs_failed_to_be_setup_mod_list.emplace(drb_failed_item.drb_id, drb_failed_item);
    }
  }

  // Add SCell failed to be setup mod list
  if (asn1_response->scell_failedto_setup_mod_list_present) {
    for (auto asn1_scell_failed_setup_mod_list_item : asn1_response->scell_failedto_setup_mod_list.value) {
      auto& asn1_scell_failed_item = asn1_scell_failed_setup_mod_list_item.value().scell_failedto_setup_mod_item();

      cu_cp_scell_failed_to_setup_mod_item scell_failed_item;
      scell_failed_item.scell_id = f1ap_nrcgi_to_nr_cell_identity(asn1_scell_failed_item.scell_id);
      if (asn1_scell_failed_item.cause_present) {
        scell_failed_item.cause = f1ap_cause_to_cause(asn1_scell_failed_item.cause);
      }
      res.scell_failed_to_setup_mod_list.push_back(scell_failed_item);
    }
  }

  // Add DRBs failed to be modified list
  if (asn1_response->drbs_failed_to_be_modified_list_present) {
    for (auto asn1_drbs_failed_modified_list_item : asn1_response->drbs_failed_to_be_modified_list.value) {
      auto& asn1_drb_failed_item = asn1_drbs_failed_modified_list_item.value().drbs_failed_to_be_modified_item();

      cu_cp_drbs_failed_to_be_setup_modified_item drb_failed_item;
      drb_failed_item.drb_id = uint_to_drb_id(asn1_drb_failed_item.drb_id);
      if (asn1_drb_failed_item.cause_present) {
        drb_failed_item.cause = f1ap_cause_to_cause(asn1_drb_failed_item.cause);
      }
      res.drbs_failed_to_be_modified_list.emplace(drb_failed_item.drb_id, drb_failed_item);
    }
  }

  // Add inactivity monitoring response
  if (asn1_response->inactivity_monitoring_resp_present) {
    res.inactivity_monitoring_resp = asn1_response->inactivity_monitoring_resp.value.to_string();
  }

  // Add C-RNTI
  if (asn1_response->c_rnti_present) {
    res.c_rnti = to_rnti(asn1_response->c_rnti.value);
  }

  // Add associated SCell list
  if (asn1_response->associated_scell_list_present) {
    for (auto asn1_associated_scell_list_item : asn1_response->associated_scell_list.value) {
      auto& asn1_associated_scell_item = asn1_associated_scell_list_item.value().associated_scell_item();

      cu_cp_associated_scell_item associated_scell_item;
      associated_scell_item.scell_id = f1ap_nrcgi_to_nr_cell_identity(asn1_associated_scell_item.scell_id);

      res.associated_scell_list.push_back(associated_scell_item);
    }
  }

  // Add SRBs setup mod list
  if (asn1_response->srbs_setup_mod_list_present) {
    for (auto asn1_srbs_setup_mod_list_item : asn1_response->srbs_setup_mod_list.value) {
      auto& asn1_srbs_setup_mod_item = asn1_srbs_setup_mod_list_item.value().srbs_setup_mod_item();

      cu_cp_srbs_setup_modified_item srbs_setup_mod_item;
      srbs_setup_mod_item.srb_id = int_to_srb_id(asn1_srbs_setup_mod_item.srb_id);
      srbs_setup_mod_item.lcid   = uint_to_lcid(asn1_srbs_setup_mod_item.lcid);

      res.srbs_setup_mod_list.emplace(srbs_setup_mod_item.srb_id, srbs_setup_mod_item);
    }
  }

  // Add SRBs modified list
  if (asn1_response->srbs_modified_list_present) {
    for (auto asn1_srbs_modified_list_item : asn1_response->srbs_modified_list.value) {
      auto& asn1_srbs_modified_item = asn1_srbs_modified_list_item.value().srbs_modified_item();

      cu_cp_srbs_setup_modified_item srbs_modified_item;
      srbs_modified_item.srb_id = int_to_srb_id(asn1_srbs_modified_item.srb_id);
      srbs_modified_item.lcid   = uint_to_lcid(asn1_srbs_modified_item.lcid);

      res.srbs_modified_list.emplace(srbs_modified_item.srb_id, srbs_modified_item);
    }
  }

  // Add full configuration
  if (asn1_response->full_cfg_present) {
    res.full_cfg = asn1_response->full_cfg.value.to_string();
  }
}

/// \brief Convert the UE Context Modification Failure from ASN.1 to common type.
/// \param[out] res The common type struct to store the result.
/// \param[in] asn1_fail The ASN.1 type UE Context Modification Failure.
inline void fill_f1ap_ue_context_modification_response_message(cu_cp_ue_context_modification_response&  res,
                                                               const asn1::f1ap::ue_context_mod_fail_s& asn1_fail)
{
  res.success = false;
  res.cause   = f1ap_cause_to_cause(asn1_fail->cause.value);
  if (asn1_fail->crit_diagnostics_present) {
    // TODO: Add crit diagnostics
  }
}

} // namespace srs_cu_cp
} // namespace srsran
