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

#include "pcap_file_base.h"
#include <sys/time.h>

using namespace srsran;

bool pcap_file_base::dlt_pcap_open(uint32_t dlt_, const char* filename_)
{
  if (pcap_fstream.is_open()) {
    logger.error("PCAP {} already open", filename);
    return false;
  }

  dlt      = dlt_;
  filename = filename_;

  pcap_hdr_t file_header = {
      0xa1b2c3d4, /// magic number
      2,
      4,     /// version number is 2.4
      0,     /// timezone
      0,     /// sigfigs - apparently all tools do this
      65535, /// snaplen - this should be long enough
      dlt    /// Data Link Type (DLT).  Set as unused value 147 for now
  };

  pcap_fstream.open(filename.c_str(), std::ios::out | std::ios::binary);
  if (pcap_fstream.fail()) {
    logger.error("Failed to open file {} for writing: {}", filename, strerror(errno));
    return false;
  }
  logger.debug("Opened file {} for writing. DLT={}", filename, dlt);

  pcap_fstream.write((char*)&file_header, sizeof(file_header));
  if (pcap_fstream.fail()) {
    logger.error("Failed to write to pcap\n");
    return false;
  }

  write_enabled = true;

  return true;
}

void pcap_file_base::dlt_pcap_close()
{
  if (pcap_fstream.is_open()) {
    logger.info("Saving PCAP file (DLT={}) to {}", dlt, filename.c_str());
    write_enabled = false;
    pcap_fstream.flush();
    pcap_fstream.close();
  }
}

void pcap_file_base::write_pcap_header(uint32_t length)
{
  pcaprec_hdr_t packet_header = {};

  // PCAP header
  struct timeval t = {};
  gettimeofday(&t, nullptr);
  packet_header.ts_sec   = t.tv_sec;
  packet_header.ts_usec  = t.tv_usec;
  packet_header.incl_len = length;
  packet_header.orig_len = length;

  pcap_fstream.write((char*)&packet_header, sizeof(packet_header));
  if (pcap_fstream.fail()) {
    logger.error("Failed to write to pcap\n");
    return;
  }
}

void pcap_file_base::write_pcap_pdu(srsran::const_span<uint8_t> pdu)
{
  if (write_enabled) {
    pcap_fstream.write((char*)pdu.data(), pdu.size_bytes());
    if (pcap_fstream.fail()) {
      logger.error("Failed to write to pcap\n");
      return;
    }
    pcap_fstream.flush();
  }
}

bool pcap_file_base::is_write_enabled()
{
  return write_enabled;
}
