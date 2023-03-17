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

#include "dl_sch_pdu_assembler.h"
#include "srsran/adt/byte_buffer_slice_chain.h"
#include "srsran/ran/pdsch/pdsch_constants.h"
#include "srsran/support/error_handling.h"
#include "srsran/support/format_utils.h"

using namespace srsran;

unsigned dl_sch_pdu::add_sdu(lcid_t lcid_, byte_buffer_slice_chain&& sdu)
{
  lcid_dl_sch_t lcid    = lcid_;
  size_t        sdu_len = sdu.length();

  unsigned header_length = 2;
  bool     F_bit         = false;
  if (sdu_len >= MAC_SDU_SUBHEADER_LENGTH_THRES) {
    F_bit = true;
    header_length += 1;
  }

  if (byte_offset + sdu_len + header_length > pdu.size()) {
    return 0;
  }

  // Encode Header.
  encode_subheader(F_bit, lcid, header_length, sdu_len);

  // Encode Payload.
  std::copy(sdu.begin(), sdu.end(), pdu.data() + byte_offset);
  byte_offset += sdu_len;
  return sdu_len + header_length;
}

void dl_sch_pdu::add_ue_con_res_id(const ue_con_res_id_t& con_res_payload)
{
  lcid_dl_sch_t lcid        = lcid_dl_sch_t::UE_CON_RES_ID;
  unsigned      header_len  = 1;
  unsigned      payload_len = lcid.sizeof_ce();

  // Encode header and payload.
  encode_subheader(false, lcid_dl_sch_t::UE_CON_RES_ID, header_len, payload_len);

  // Encode UE ConRes ID.
  std::copy(con_res_payload.begin(), con_res_payload.end(), pdu.data() + byte_offset);
  byte_offset += con_res_payload.size();
}

void dl_sch_pdu::add_padding(unsigned len)
{
  // 1 Byte R/LCID MAC subheader.
  unsigned header_len = 1;
  unsigned sdu_len    = len - 1;
  encode_subheader(false, lcid_dl_sch_t::PADDING, header_len, sdu_len);

  // Padding bits.
  std::fill(pdu.data() + byte_offset, pdu.data() + byte_offset + sdu_len, 0);
  byte_offset += sdu_len;
}

void dl_sch_pdu::encode_subheader(bool F_bit, lcid_dl_sch_t lcid, unsigned header_len, unsigned payload_len)
{
  pdu[byte_offset++] = ((F_bit ? 1U : 0U) << 6U) | (lcid.value() & 0x3fU);
  if (header_len == 3) {
    // 3 Byte R/F/LCID/L MAC subheader with 16-bit L field
    pdu[byte_offset++] = (payload_len & 0xff00U) >> 8U;
    pdu[byte_offset++] = (payload_len & 0xffU);
  } else if (header_len == 2) {
    // 2 Byte R/F/LCID/L MAC subheader with 8-bit L field
    pdu[byte_offset++] = payload_len & 0xffU;
  } else if (header_len == 1) {
    // do nothing
  } else {
    report_fatal_error("Error while packing PDU. Unsupported header length ({})", header_len);
  }
}

// /////////////////////////

class dl_sch_pdu_assembler::dl_sch_pdu_logger
{
public:
  explicit dl_sch_pdu_logger(du_ue_index_t ue_index_, rnti_t rnti_, units::bytes tbs_, srslog::basic_logger& logger_) :
    ue_index(ue_index_), rnti(rnti_), tbs(tbs_), logger(logger_)
  {
  }

  void add_sdu(lcid_t lcid, unsigned len)
  {
    if (not logger.info.enabled()) {
      return;
    }
    fmt::format_to(fmtbuf, "{}SDU: lcid={} size={}", separator(), lcid, len);
  }

  void add_conres_id(const ue_con_res_id_t& conres)
  {
    if (not logger.info.enabled()) {
      return;
    }
    fmt::format_to(fmtbuf, "{}CON_RES: id={:x}", separator(), fmt::join(conres, ""));
  }

  void log()
  {
    if (not logger.info.enabled()) {
      return;
    }
    logger.info("DL PDU: ue={} rnti={:#x} size={}: {}", ue_index, rnti, tbs, to_c_str(fmtbuf));
  }

private:
  const char* separator() const { return fmtbuf.size() == 0 ? "" : ", "; }

  du_ue_index_t         ue_index;
  rnti_t                rnti;
  units::bytes          tbs;
  srslog::basic_logger& logger;
  fmt::memory_buffer    fmtbuf;
};

// /////////////////////////

dl_sch_pdu_assembler::dl_sch_pdu_assembler(mac_dl_ue_manager& ue_mng_) :
  ue_mng(ue_mng_), logger(srslog::fetch_basic_logger("MAC"))
{
}

// Buffer passed to the lower layers when HARQ allocation fails.
static const std::vector<uint8_t> zero_buffer(MAX_DL_PDU_LENGTH, 0);

span<const uint8_t> dl_sch_pdu_assembler::assemble_newtx_pdu(rnti_t                rnti,
                                                             harq_id_t             h_id,
                                                             unsigned              tb_idx,
                                                             const dl_msg_tb_info& tb_info,
                                                             unsigned              tb_size_bytes)
{
  span<uint8_t> buffer = ue_mng.get_dl_harq_buffer(rnti, h_id, tb_idx);
  if (buffer.size() < tb_size_bytes) {
    logger.error("DL ue={} rnti={:#x} h_id={}: Failed to assemble MAC PDU. Cause: No HARQ buffers available",
                 ue_mng.get_ue_index(rnti),
                 rnti,
                 h_id);
    return span<const uint8_t>(zero_buffer).first(tb_size_bytes);
  }
  dl_sch_pdu ue_pdu(buffer.first(tb_size_bytes));

  dl_sch_pdu_logger pdu_logger{ue_mng.get_ue_index(rnti), rnti, units::bytes{tb_size_bytes}, logger};

  // Encode added subPDUs.
  for (const dl_msg_lc_info& sched_lch : tb_info.lc_chs_to_sched) {
    if (sched_lch.lcid.is_sdu()) {
      assemble_sdus(ue_pdu, rnti, sched_lch, pdu_logger);
    } else {
      assemble_ce(ue_pdu, rnti, sched_lch, pdu_logger);
    }
  }

  // Add Padding if required.
  unsigned current_size = ue_pdu.nof_bytes();
  if (current_size < tb_size_bytes) {
    ue_pdu.add_padding(tb_size_bytes - current_size);
  } else if (current_size > tb_size_bytes) {
    logger.error("ERROR: Allocated subPDUs exceed TB size ({} > {})", current_size, tb_size_bytes);
    return {};
  }

  pdu_logger.log();

  return ue_pdu.get();
}

void dl_sch_pdu_assembler::assemble_sdus(dl_sch_pdu&           ue_pdu,
                                         rnti_t                rnti,
                                         const dl_msg_lc_info& lc_grant_info,
                                         dl_sch_pdu_logger&    pdu_logger)
{
  // Note: Do not attempt to build an SDU if there is not enough space for the MAC subheader, min payload size and
  // potential RLC header.
  static const unsigned RLC_HEADER_SIZE_ESTIM = 2;
  static const unsigned MIN_MAC_SDU_SIZE =
      MIN_MAC_SDU_SUBHEADER_SIZE + 1 + (lc_grant_info.lcid.value() != LCID_SRB0 ? RLC_HEADER_SIZE_ESTIM : 0);

  // Fetch RLC Bearer.
  mac_sdu_tx_builder* bearer = ue_mng.get_bearer(rnti, lc_grant_info.lcid.to_lcid());
  srsran_sanity_check(bearer != nullptr, "Scheduler is allocating inexistent bearers");

  unsigned rem_bytes = std::min(get_mac_sdu_required_bytes(lc_grant_info.sched_bytes), ue_pdu.nof_empty_bytes());
  while (rem_bytes >= MIN_MAC_SDU_SIZE) {
    // Fetch MAC Tx SDU.
    byte_buffer_slice_chain sdu = bearer->on_new_tx_sdu(get_mac_sdu_payload_size(rem_bytes));
    if (sdu.empty()) {
      logger.debug("ue={} rnti={:#x} lcid={}: Failed to encode MAC SDU in MAC opportunity of size={}.",
                   ue_mng.get_ue_index(rnti),
                   rnti,
                   lc_grant_info.lcid.to_lcid(),
                   get_mac_sdu_payload_size(rem_bytes));
      break;
    }
    srsran_assert(sdu.length() <= get_mac_sdu_payload_size(rem_bytes),
                  "RLC Tx SDU exceeded MAC opportunity size ({} > {})",
                  sdu.length(),
                  get_mac_sdu_payload_size(rem_bytes));

    // Add SDU as a subPDU.
    unsigned nwritten = ue_pdu.add_sdu(lc_grant_info.lcid.to_lcid(), std::move(sdu));
    if (nwritten == 0) {
      logger.error("ue={} rnti={:#x} lcid={}: Scheduled SubPDU with al={} cannot fit in scheduled DL grant",
                   ue_mng.get_ue_index(rnti),
                   rnti,
                   lc_grant_info.lcid.to_lcid(),
                   lc_grant_info.sched_bytes);
      break;
    }
    srsran_assert(rem_bytes >= nwritten, "Too many bytes were packed in MAC SDU");

    // Log SDU.
    pdu_logger.add_sdu(lc_grant_info.lcid.to_lcid(), nwritten);

    rem_bytes -= nwritten;
  }
  if (rem_bytes == get_mac_sdu_required_bytes(lc_grant_info.sched_bytes)) {
    // No SDU was encoded for this LCID.
    // Causes for failure to create MAC SDU include: RLC Tx window is full, mismatch between the logical channel
    // buffer states in the scheduler and RLC bearers, or the MAC opportunity is too small.
    if (rem_bytes < MIN_MAC_SDU_SIZE) {
      logger.warning("ue={} rnti={:#x} lcid={}: Skipping MAC SDU encoding. Cause: Allocated SDU size={} is too small.",
                     ue_mng.get_ue_index(rnti),
                     rnti,
                     lc_grant_info.lcid.to_lcid(),
                     lc_grant_info.sched_bytes);
    } else {
      logger.warning("ue={} rnti={:#x} lcid={}: Skipping MAC SDU encoding. Cause: RLC could not encode any SDU",
                     ue_mng.get_ue_index(rnti),
                     rnti,
                     lc_grant_info.lcid.to_lcid());
    }
  }
}

void dl_sch_pdu_assembler::assemble_ce(dl_sch_pdu&           ue_pdu,
                                       rnti_t                rnti,
                                       const dl_msg_lc_info& subpdu,
                                       dl_sch_pdu_logger&    pdu_logger)
{
  switch (subpdu.lcid.value()) {
    case lcid_dl_sch_t::UE_CON_RES_ID: {
      ue_con_res_id_t conres = ue_mng.get_con_res_id(rnti);
      std::copy(conres.begin(), conres.end(), conres.begin());
      ue_pdu.add_ue_con_res_id(conres);
      pdu_logger.add_conres_id(conres);
    } break;
    default:
      report_fatal_error("Invalid MAC CE lcid={}", subpdu.lcid);
  }
}

span<const uint8_t>
dl_sch_pdu_assembler::assemble_retx_pdu(rnti_t rnti, harq_id_t h_id, unsigned tb_idx, unsigned tbs_bytes)
{
  span<uint8_t> buffer = ue_mng.get_dl_harq_buffer(rnti, h_id, tb_idx);
  if (buffer.size() < tbs_bytes) {
    logger.error("DL ue={} rnti={:#x} h_id={}: Failed to assemble MAC PDU. Cause: No HARQ buffers available",
                 ue_mng.get_ue_index(rnti),
                 rnti,
                 h_id);
    return span<const uint8_t>(zero_buffer).first(tbs_bytes);
  }
  return buffer.first(tbs_bytes);
}
