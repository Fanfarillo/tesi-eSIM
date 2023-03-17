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

#include "e1ap_asn1_packer.h"
#include "srsran/asn1/e1ap/e1ap.h"

using namespace srsran;

e1ap_asn1_packer::e1ap_asn1_packer(sctp_network_gateway_data_handler& gw_, e1ap_message_handler& e1ap_handler) :
  logger(srslog::fetch_basic_logger("E1AP-ASN1-PCK")), gw(gw_), e1ap(e1ap_handler)
{
}

// Received packed E1AP PDU that needs to be unpacked and forwarded.
void e1ap_asn1_packer::handle_packed_pdu(const byte_buffer& bytes)
{
  logger.debug("Received PDU of {} bytes", bytes.length());

  asn1::cbit_ref bref(bytes);
  e1ap_message   msg = {};
  if (msg.pdu.unpack(bref) != asn1::SRSASN_SUCCESS) {
    logger.error("Couldn't unpack PDU");
    return;
  }

  // call packet handler
  e1ap.handle_message(msg);
}

// Receive populated ASN1 struct that needs to be packed and forwarded.
void e1ap_asn1_packer::handle_message(const e1ap_message& msg)
{
  // pack PDU into temporary buffer
  byte_buffer   tx_pdu;
  asn1::bit_ref bref(tx_pdu);
  if (msg.pdu.pack(bref) != asn1::SRSASN_SUCCESS) {
    logger.error("Failed to pack PDU");
    return;
  }

  gw.handle_pdu(tx_pdu);
}