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

#include "srsran/cu_cp/cu_cp_types.h"
#include "srsran/ngap/ngap.h"

namespace srsran {
namespace srs_cu_cp {

// NG Application Protocol (NGSetupRequest)
//     NGAP-PDU: initiatingMessage (0)
//         initiatingMessage
//             procedureCode: id-NGSetup (21)
//             criticality: reject (0)
//             value
//                 NGSetupRequest
//                     protocolIEs: 4 items
//                         Item 0: id-GlobalRANNodeID
//                             ProtocolIE-Field
//                                 id: id-GlobalRANNodeID (27)
//                                 criticality: reject (0)
//                                 value
//                                     GlobalRANNodeID: globalGNB-ID (0)
//                                         globalGNB-ID
//                                             pLMNIdentity: 00f110
//                                                 Mobile Country Code (MCC): Unknown (1)
//                                                 Mobile Network Code (MNC): Unknown (01)
//                                             gNB-ID: gNB-ID (0)
//                                                 gNB-ID: 00066c [bit length 22, 2 LSB pad bits, 0000 0000  0000 0110
//                                                 0110 11.. decimal value 411]
//                         Item 1: id-RANNodeName
//                             ProtocolIE-Field
//                                 id: id-RANNodeName (82)
//                                 criticality: ignore (1)
//                                 value
//                                     RANNodeName: srsgnb01
//                         Item 2: id-SupportedTAList
//                             ProtocolIE-Field
//                                 id: id-SupportedTAList (102)
//                                 criticality: reject (0)
//                                 value
//                                     SupportedTAList: 1 item
//                                         Item 0
//                                             SupportedTAItem
//                                                 tAC: 7 (0x000007)
//                                                 broadcastPLMNList: 1 item
//                                                     Item 0
//                                                         BroadcastPLMNItem
//                                                             pLMNIdentity: 00f110
//                                                                 Mobile Country Code (MCC): Unknown (1)
//                                                                 Mobile Network Code (MNC): Unknown (01)
//                                                             tAISliceSupportList: 1 item
//                                                                 Item 0
//                                                                     SliceSupportItem
//                                                                         s-NSSAI
//                                                                             sST: 01
//                         Item 3: id-DefaultPagingDRX
//                             ProtocolIE-Field
//                                 id: id-DefaultPagingDRX (21)
//                                 criticality: ignore (1)
//                                 value
//                                     PagingDRX: v256 (3)
const static uint8_t ng_setup_request_packed[] = {
    0x00, 0x15, 0x00, 0x33, 0x00, 0x00, 0x04, 0x00, 0x1b, 0x00, 0x08, 0x00, 0x00, 0xf1, 0x10, 0x00, 0x00, 0x06, 0x6c,
    0x00, 0x52, 0x40, 0x0a, 0x03, 0x80, 0x73, 0x72, 0x73, 0x67, 0x6e, 0x62, 0x30, 0x31, 0x00, 0x66, 0x00, 0x0d, 0x00,
    0x00, 0x00, 0x00, 0x07, 0x00, 0x00, 0xf1, 0x10, 0x00, 0x00, 0x00, 0x08, 0x00, 0x15, 0x40, 0x01, 0x60};

/// \brief Generate a dummy NG Setup Request.
ng_setup_request generate_ng_setup_request();

/// \brief Generate a dummy NG Setup Response.
ngap_message generate_ng_setup_response();

/// \brief Generate a dummy NG Setup Failure.
ngap_message generate_ng_setup_failure();

/// \brief Generate a dummy NG Setup Failure with a time to wait.
ngap_message generate_ng_setup_failure_with_time_to_wait(asn1::ngap::time_to_wait_e time_to_wait);

const uint32_t nas_pdu_len = 4; // Dummy length used for testing (content is not important)
/// \brief Generate a dummy Initial UE Message.
ngap_initial_ue_message generate_initial_ue_message(ue_index_t ue_index);

/// \brief Generate a dummy DL NAS Transport Message.
ngap_message generate_downlink_nas_transport_message(amf_ue_id_t amf_ue_id, ran_ue_id_t ran_ue_id);

/// \brief Generate a dummy UL NAS Transport Message.
ngap_ul_nas_transport_message generate_ul_nas_transport_message(ue_index_t ue_index);

/// \brief Generate a dummy Initial Context Setup Request base.
ngap_message generate_initial_context_setup_request_base(amf_ue_id_t amf_ue_id, ran_ue_id_t ran_ue_id);

/// \brief Generate a valid dummy Initial Context Setup Request Message.
ngap_message generate_valid_initial_context_setup_request_message(amf_ue_id_t amf_ue_id, ran_ue_id_t ran_ue_id);

/// \brief Generate an invalid dummy Initial Context Setup Request Message.
ngap_message generate_invalid_initial_context_setup_request_message(amf_ue_id_t amf_ue_id, ran_ue_id_t ran_ue_id);

/// \brief Generate a dummy PDU Session Resource Setup Request base.
ngap_message generate_pdu_session_resource_setup_request_base(amf_ue_id_t amf_ue_id, ran_ue_id_t ran_ue_id);

/// \brief Generate a valid dummy PDU Session Resource Setup Request Message.
ngap_message generate_valid_pdu_session_resource_setup_request_message(amf_ue_id_t      amf_ue_id,
                                                                       ran_ue_id_t      ran_ue_id,
                                                                       pdu_session_id_t pdu_session_id);

/// \brief Generate an invalid dummy PDU Session Resource Setup Request Message.
ngap_message generate_invalid_pdu_session_resource_setup_request_message(amf_ue_id_t amf_ue_id, ran_ue_id_t ran_ue_id);

/// \brief Generate a dummy PDU Session Resource Setup Response.
cu_cp_pdu_session_resource_setup_response
generate_cu_cp_pdu_session_resource_setup_response(pdu_session_id_t pdu_session_id);

} // namespace srs_cu_cp
} // namespace srsran
