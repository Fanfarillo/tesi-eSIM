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
#include "srsran/adt/slotted_array.h"
#include "srsran/ran/cause.h"
#include "srsran/ran/crit_diagnostics.h"
#include "srsran/ran/cu_types.h"
#include "srsran/ran/lcid.h"
#include "srsran/ran/nr_cgi.h"
#include "srsran/ran/rnti.h"
#include "srsran/ran/s_nssai.h"
#include "srsran/ran/subcarrier_spacing.h"
#include "srsran/ran/up_transport_layer_info.h"
#include "srsran/rlc/rlc_config.h"
#include "srsran/security/security.h"
#include <cstdint>
#include <map>
#include <string>
#include <type_traits>
#include <vector>

namespace srsran {
namespace srs_cu_cp {

/// Maximum number of UEs per DU (implementation-defined).
const uint16_t MAX_NOF_UES_PER_DU = 1024;
/// Maximum number of DUs supported by CU-CP (implementation-defined).
const uint16_t MAX_NOF_DUS = 2;
/// Maximum number of UEs supported by CU-CP (implementation-defined).
#define MAX_NOF_CU_UES (MAX_NOF_DUS * MAX_NOF_UES_PER_DU)
/// Maximum number of CU-UPs supported by CU-CP (implementation-defined).
const uint16_t MAX_NOF_CU_UPS = 2;
/// Maximum number of cells per DU supported by CU-CP (implementation-defined).
const uint16_t MAX_NOF_DU_CELLS = 16;

/// \brief ue_index internally used to identify the UE CU-CP-wide.
/// \remark The ue_index is derived from the DU index and the maximum number of UEs per DU.
enum class ue_index_t : uint64_t { min = 0, max = MAX_NOF_CU_UES - 1, invalid = MAX_NOF_CU_UES };

/// Convert ue_index  type to integer.
inline uint64_t ue_index_to_uint(ue_index_t index)
{
  return static_cast<uint64_t>(index);
}

/// Convert integer to ue_index type.
inline ue_index_t uint_to_ue_index(std::underlying_type_t<ue_index_t> index)
{
  return static_cast<ue_index_t>(index);
}

/// Maximum number of DUs supported by CU-CP (implementation-defined).
enum class du_index_t : uint16_t { min = 0, max = MAX_NOF_DUS - 1, invalid = MAX_NOF_DUS };

/// Convert integer to DU index type.
constexpr inline du_index_t uint_to_du_index(std::underlying_type_t<du_index_t> index)
{
  return static_cast<du_index_t>(index);
}

/// Convert DU index type to integer.
constexpr inline std::underlying_type_t<du_index_t> du_index_to_uint(du_index_t du_index)
{
  return static_cast<std::underlying_type_t<du_index_t>>(du_index);
}

/// Get DU index from UE index.
inline du_index_t get_du_index_from_ue_index(ue_index_t index)
{
  if (index == ue_index_t::invalid) {
    return du_index_t::invalid;
  }
  return uint_to_du_index((ue_index_to_uint(index) / MAX_NOF_UES_PER_DU));
}

/// Generate a UE index from DU index and an index.
inline ue_index_t generate_ue_index(du_index_t du_index, uint16_t index)
{
  return uint_to_ue_index(du_index_to_uint(du_index) * MAX_NOF_UES_PER_DU + index);
}

/// Maximum number of CU-UPs supported by CU-CP (implementation-defined).
enum class cu_up_index_t : uint16_t { min = 0, max = MAX_NOF_CU_UPS - 1, invalid = MAX_NOF_CU_UPS };

/// Convert integer to CU-UP index type.
constexpr inline cu_up_index_t uint_to_cu_up_index(std::underlying_type_t<cu_up_index_t> index)
{
  return static_cast<cu_up_index_t>(index);
}

/// Convert CU-UP index type to integer.
constexpr inline std::underlying_type_t<cu_up_index_t> cu_up_index_to_uint(cu_up_index_t cu_up_index)
{
  return static_cast<std::underlying_type_t<cu_up_index_t>>(cu_up_index);
}

/// Maximum number of cells per DU supported by CU-CP (implementation-defined).
enum class du_cell_index_t : uint16_t { min = 0, max = MAX_NOF_DU_CELLS - 1, invalid = MAX_NOF_DU_CELLS };

/// Convert integer to DU cell index type.
inline du_cell_index_t uint_to_du_cell_index(std::underlying_type_t<du_cell_index_t> index)
{
  return static_cast<du_cell_index_t>(index);
}

/// Convert DU cell index type to integer.
constexpr inline std::underlying_type_t<du_cell_index_t> du_cell_index_to_uint(du_cell_index_t du_cell_index)
{
  return static_cast<std::underlying_type_t<du_cell_index_t>>(du_cell_index);
}

/// QoS Configuration, i.e. 5QI and the associated PDCP
/// and SDAP configuration for DRBs
struct cu_cp_qos_config {
  pdcp_config pdcp;
};
// ASN1 types converted to common types

struct cu_cp_qos_characteristics {
  bool        is_dynamic_5qi = false;
  uint16_t    five_qi;
  uint8_t     prio_level_arp;
  std::string pre_emption_cap;
  std::string pre_emption_vulnerability;
};

struct qos_flow_setup_request_item {
  qos_flow_id_t             qos_flow_id = qos_flow_id_t::invalid;
  cu_cp_qos_characteristics qos_characteristics;
  optional<uint8_t>         erab_id;
  optional<std::string>     add_qos_flow_info;
  optional<std::string>     reflective_qos_attribute;
};

struct cu_cp_pdu_session_res_setup_item {
  pdu_session_id_t                                              pdu_session_id = pdu_session_id_t::invalid;
  byte_buffer                                                   pdu_session_nas_pdu;
  s_nssai_t                                                     s_nssai;
  uint64_t                                                      pdu_session_aggregate_maximum_bit_rate_dl;
  uint64_t                                                      pdu_session_aggregate_maximum_bit_rate_ul;
  up_transport_layer_info                                       ul_ngu_up_tnl_info;
  std::string                                                   pdu_session_type;
  slotted_id_vector<qos_flow_id_t, qos_flow_setup_request_item> qos_flow_setup_request_items;
};

struct cu_cp_pdu_session_resource_setup_request {
  ue_index_t                                                            ue_index = ue_index_t::invalid;
  slotted_id_vector<pdu_session_id_t, cu_cp_pdu_session_res_setup_item> pdu_session_res_setup_items;
  uint64_t                                                              ue_aggregate_maximum_bit_rate_dl;
  std::string                                                           serving_plmn;
  std::map<uint8_t, cu_cp_qos_config>                                   qos_config;
};

struct cu_cp_associated_qos_flow {
  qos_flow_id_t         qos_flow_id = qos_flow_id_t::invalid;
  optional<std::string> qos_flow_map_ind;
};

struct cu_cp_qos_flow_failed_to_setup_item {
  qos_flow_id_t qos_flow_id = qos_flow_id_t::invalid;
  cause_t       cause;
};

struct cu_cp_qos_flow_per_tnl_information {
  up_transport_layer_info                                     up_tp_layer_info;
  slotted_id_vector<qos_flow_id_t, cu_cp_associated_qos_flow> associated_qos_flow_list;
};

struct cu_cp_pdu_session_resource_setup_response_transfer {
  std::vector<cu_cp_qos_flow_per_tnl_information>                       add_dl_qos_flow_per_tnl_info = {};
  cu_cp_qos_flow_per_tnl_information                                    dlqos_flow_per_tnl_info;
  slotted_id_vector<qos_flow_id_t, cu_cp_associated_qos_flow>           associated_qos_flow_list;
  slotted_id_vector<qos_flow_id_t, cu_cp_qos_flow_failed_to_setup_item> qos_flow_failed_to_setup_list;
  optional<security_result_t>                                           security_result;
};

struct cu_cp_pdu_session_res_setup_response_item {
  pdu_session_id_t                                   pdu_session_id = pdu_session_id_t::invalid;
  cu_cp_pdu_session_resource_setup_response_transfer pdu_session_resource_setup_response_transfer;
};

struct cu_cp_pdu_session_resource_setup_unsuccessful_transfer {
  cause_t                      cause;
  optional<crit_diagnostics_t> crit_diagnostics;
};

struct cu_cp_pdu_session_res_setup_failed_item {
  pdu_session_id_t                                       pdu_session_id = pdu_session_id_t::invalid;
  cu_cp_pdu_session_resource_setup_unsuccessful_transfer pdu_session_resource_setup_unsuccessful_transfer;
};

struct cu_cp_pdu_session_resource_setup_response {
  slotted_id_vector<pdu_session_id_t, cu_cp_pdu_session_res_setup_response_item> pdu_session_res_setup_response_items;
  slotted_id_vector<pdu_session_id_t, cu_cp_pdu_session_res_setup_failed_item>   pdu_session_res_failed_to_setup_items;
  optional<crit_diagnostics_t>                                                   crit_diagnostics;
};

struct cu_cp_drb_setup_message {
  drb_id_t                                                      drb_id = drb_id_t::invalid;
  srsran::rlc_mode                                              rlc;
  cu_cp_qos_characteristics                                     qos_info;
  std::vector<up_transport_layer_info>                          gtp_tunnels = {};
  s_nssai_t                                                     s_nssai;
  slotted_id_vector<qos_flow_id_t, qos_flow_setup_request_item> qos_flows_mapped_to_drb;

  uint8_t dl_pdcp_sn_length; // id-DLPDCPSNLength 161
  uint8_t ul_pdcp_sn_length; // id-ULPDCPSNLength 192
};

struct cu_cp_ue_context_modification_request {
  ue_index_t                                           ue_index = ue_index_t::invalid;
  slotted_id_vector<drb_id_t, cu_cp_drb_setup_message> cu_cp_drb_setup_msgs;
  optional<uint64_t>                                   ue_aggregate_maximum_bit_rate_ul;
};

struct cu_cp_du_to_cu_rrc_info {
  byte_buffer cell_group_cfg;
  byte_buffer meas_gap_cfg;
  byte_buffer requested_p_max_fr1;
};

struct cu_cp_dl_up_tnl_info_to_be_setup_item {
  up_transport_layer_info dl_up_tnl_info;
};

struct cu_cp_drbs_setup_modified_item {
  drb_id_t                                           drb_id                          = drb_id_t::invalid;
  optional<lcid_t>                                   lcid                            = lcid_t::INVALID_LCID;
  std::vector<cu_cp_dl_up_tnl_info_to_be_setup_item> dl_up_tnl_info_to_be_setup_list = {};
};

struct cu_cp_srbs_failed_to_be_setup_mod_item {
  srb_id_t          srb_id = srb_id_t::nulltype;
  optional<cause_t> cause;
};

struct cu_cp_drbs_failed_to_be_setup_modified_item {
  drb_id_t          drb_id = drb_id_t::invalid;
  optional<cause_t> cause;
};

struct cu_cp_scell_failed_to_setup_mod_item {
  nr_cell_id_t      scell_id;
  optional<cause_t> cause;
};

struct cu_cp_associated_scell_item {
  nr_cell_id_t scell_id;
};

struct cu_cp_srbs_setup_modified_item {
  srb_id_t srb_id = srb_id_t::nulltype;
  lcid_t   lcid   = lcid_t::INVALID_LCID;
};

struct cu_cp_ue_context_modification_response {
  bool success = false;
  // ue context modification response
  byte_buffer                                                              res_coordination_transfer_container;
  cu_cp_du_to_cu_rrc_info                                                  du_to_cu_rrc_info;
  slotted_id_vector<drb_id_t, cu_cp_drbs_setup_modified_item>              drbs_setup_mod_list;
  slotted_id_vector<drb_id_t, cu_cp_drbs_setup_modified_item>              drbs_modified_list;
  slotted_id_vector<srb_id_t, cu_cp_srbs_failed_to_be_setup_mod_item>      srbs_failed_to_be_setup_mod_list;
  slotted_id_vector<drb_id_t, cu_cp_drbs_failed_to_be_setup_modified_item> drbs_failed_to_be_setup_mod_list;
  std::vector<cu_cp_scell_failed_to_setup_mod_item>                        scell_failed_to_setup_mod_list = {};
  slotted_id_vector<drb_id_t, cu_cp_drbs_failed_to_be_setup_modified_item> drbs_failed_to_be_modified_list;
  optional<std::string>                                                    inactivity_monitoring_resp;
  optional<srsran::rnti_t>                                                 c_rnti;
  std::vector<cu_cp_associated_scell_item>                                 associated_scell_list = {};
  slotted_id_vector<srb_id_t, cu_cp_srbs_setup_modified_item>              srbs_setup_mod_list;
  slotted_id_vector<srb_id_t, cu_cp_srbs_setup_modified_item>              srbs_modified_list;
  optional<std::string>                                                    full_cfg;

  // UE Context Modification Failure
  optional<cause_t> cause;

  // Common
  optional<crit_diagnostics_t> crit_diagnostics;
};

/// Arguments for the RRC Reconfiguration procedure.

struct cu_cp_srb_to_add_mod {
  bool                    reestablish_pdcp_present = false;
  bool                    discard_on_pdcp_present  = false;
  srb_id_t                srb_id                   = srb_id_t::nulltype;
  optional<pdcp_config_t> pdcp_cfg;
};

struct cu_cp_cn_assoc {
  optional<uint8_t>       eps_bearer_id;
  optional<sdap_config_t> sdap_cfg;
};

struct cu_cp_drb_to_add_mod {
  bool                     reestablish_pdcp_present = false;
  bool                     recover_pdcp_present     = false;
  optional<cu_cp_cn_assoc> cn_assoc;
  drb_id_t                 drb_id = drb_id_t::invalid;
  optional<pdcp_config_t>  pdcp_cfg;
};

struct cu_cp_security_algorithm_config {
  std::string           ciphering_algorithm;
  optional<std::string> integrity_prot_algorithm;
};

struct cu_cp_security_config {
  optional<cu_cp_security_algorithm_config> security_algorithm_cfg;
  optional<std::string>                     key_to_use;
};

struct cu_cp_radio_bearer_config {
  slotted_id_vector<srb_id_t, cu_cp_srb_to_add_mod> srb_to_add_mod_list;
  slotted_id_vector<drb_id_t, cu_cp_drb_to_add_mod> drb_to_add_mod_list;
  std::vector<drb_id_t>                             drb_to_release_list = {};
  optional<cu_cp_security_config>                   security_cfg;
  bool                                              srb3_to_release_present = false;
};

struct cu_cp_meas_config {
  // TODO: add meas config
};

struct cu_cp_master_key_upd {
  bool        key_set_change_ind = false;
  uint8_t     next_hop_chaining_count;
  byte_buffer nas_container;
};

struct cu_cp_delay_budget_report_cfg {
  std::string type;
  std::string delay_budget_report_prohibit_timer;
};

struct cu_cp_other_cfg {
  optional<cu_cp_delay_budget_report_cfg> delay_budget_report_cfg;
};

struct cu_cp_rrc_recfg_v1530_ies {
  bool                           full_cfg_present = false;
  byte_buffer                    master_cell_group;
  std::vector<byte_buffer>       ded_nas_msg_list = {};
  optional<cu_cp_master_key_upd> master_key_upd;
  byte_buffer                    ded_sib1_delivery;
  byte_buffer                    ded_sys_info_delivery;
  optional<cu_cp_other_cfg>      other_cfg;

  // TODO: Add rrc_recfg_v1540_ies_s
  // optional<cu_cp_rrc_recfg_v1540_ies> non_crit_ext;
};

struct cu_cp_rrc_reconfiguration_procedure_request {
  optional<cu_cp_radio_bearer_config> radio_bearer_cfg;
  byte_buffer                         secondary_cell_group;
  optional<cu_cp_meas_config>         meas_cfg;
  optional<cu_cp_rrc_recfg_v1530_ies> non_crit_ext;
};

struct cu_cp_ue_context_release_command {
  ue_index_t ue_index = ue_index_t::invalid;
  cause_t    cause;
};

struct cu_cp_tai {
  std::string plmn_id;
  uint32_t    tac;
};

struct cu_cp_user_location_info_nr {
  nr_cell_global_id_t nr_cgi;
  cu_cp_tai           tai;
  optional<uint64_t>  time_stamp;
};

struct cu_cp_recommended_cell_item {
  nr_cell_global_id_t ngran_cgi;
  optional<uint16_t>  time_stayed_in_cell;
};

struct cu_cp_recommended_cells_for_paging {
  std::vector<cu_cp_recommended_cell_item> recommended_cell_list;
};

struct cu_cp_global_gnb_id {
  std::string plmn_id;
  std::string gnb_id;
};

struct cu_cp_amf_paging_target {
  bool                          is_global_ran_node_id;
  bool                          is_tai;
  optional<cu_cp_global_gnb_id> global_ran_node_id;
  optional<cu_cp_tai>           tai;
};

struct cu_cp_recommended_ran_node_item {
  cu_cp_amf_paging_target amf_paging_target;
};

struct cu_cp_recommended_ran_nodes_for_paging {
  std::vector<cu_cp_recommended_ran_node_item> recommended_ran_node_list;
};

struct cu_cp_info_on_recommended_cells_and_ran_nodes_for_paging {
  cu_cp_recommended_cells_for_paging     recommended_cells_for_paging;
  cu_cp_recommended_ran_nodes_for_paging recommend_ran_nodes_for_paging;
};

struct cu_cp_ue_context_release_complete {
  optional<cu_cp_user_location_info_nr>                              user_location_info;
  optional<cu_cp_info_on_recommended_cells_and_ran_nodes_for_paging> info_on_recommended_cells_and_ran_nodes_for_paging;
  std::vector<pdu_session_id_t>                                      pdu_session_res_list_cxt_rel_cpl;
  optional<crit_diagnostics_t>                                       crit_diagnostics;
};

} // namespace srs_cu_cp
} // namespace srsran
