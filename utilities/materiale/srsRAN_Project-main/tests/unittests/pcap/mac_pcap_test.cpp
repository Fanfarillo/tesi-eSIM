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

#include "lib/pcap/mac_pcap_impl.h"
#include "srsran/asn1/ngap/ngap.h"
#include "srsran/support/test_utils.h"
#include <gtest/gtest.h>

void write_pcap_nr_thread_function_byte_buffer(srsran::mac_pcap* pcap, uint32_t num_pdus);
void write_pcap_nr_thread_function_spans(srsran::mac_pcap* pcap, uint32_t num_pdus);

class pcap_mac_test : public ::testing::Test
{
protected:
  void SetUp() override
  {
    srslog::fetch_basic_logger("PCAP").set_level(srslog::basic_levels::debug);
    srslog::fetch_basic_logger("PCAP").set_hex_dump_max_size(-1);

    test_logger.set_level(srslog::basic_levels::debug);
    test_logger.set_hex_dump_max_size(-1);

    // Start the log backend.
    srslog::init();
  }

  void TearDown() override
  {
    mac_pcap_writer.close();
    // flush logger after each test
    srslog::flush();
  }

  srsran::mac_pcap_impl mac_pcap_writer;
  srslog::basic_logger& test_logger = srslog::fetch_basic_logger("TEST");
};

TEST_F(pcap_mac_test, write_pdu)
{
  mac_pcap_writer.open("mac_write_pdu.pcap");
  std::array<uint8_t, 17> tv = {
      0x04, 0x0a, 0x0d, 0x72, 0x80, 0xd3, 0x96, 0x02, 0x7b, 0x01, 0xbd, 0x26, 0x3f, 0x00, 0x00, 0x00, 0x00};
  int                         crnti  = 0x01011;
  int                         ue_id  = 2;
  int                         harqid = 0;
  int                         tti    = 10;
  srsran::mac_nr_context_info context;
  context.radioType           = srsran::PCAP_FDD_RADIO;
  context.direction           = srsran::PCAP_DIRECTION_DOWNLINK;
  context.rntiType            = srsran::PCAP_C_RNTI;
  context.rnti                = crnti;
  context.ueid                = ue_id;
  context.harqid              = harqid;
  context.system_frame_number = tti / 10;
  context.sub_frame_number    = tti % 10;
  mac_pcap_writer.push_pdu(context, tv);
}

TEST_F(pcap_mac_test, write_many_spans)
{
  mac_pcap_writer.open("mac_write_many_spans.pcap");

  uint32_t num_threads         = 10;
  uint32_t num_pdus_per_thread = 100;

  std::vector<std::thread> writer_threads;
  test_logger.info("Start writer_threads");

  for (uint32_t i = 0; i < num_threads; i++) {
    writer_threads.push_back(std::thread(write_pcap_nr_thread_function_spans, &mac_pcap_writer, num_pdus_per_thread));
  }

  test_logger.info("Wait for writer_threads to finish");
  // wait for threads to finish
  for (std::thread& thread : writer_threads) {
    thread.join();
  }

  test_logger.info("Close PCAP handle");
  mac_pcap_writer.close();
}

TEST_F(pcap_mac_test, write_many_byte_buffers)
{
  mac_pcap_writer.open("mac_write_many_byte_buffers.pcap");

  uint32_t num_threads         = 10;
  uint32_t num_pdus_per_thread = 100;

  std::vector<std::thread> writer_threads;
  test_logger.info("Start writer_threads");

  for (uint32_t i = 0; i < num_threads; i++) {
    writer_threads.push_back(
        std::thread(write_pcap_nr_thread_function_byte_buffer, &mac_pcap_writer, num_pdus_per_thread));
  }

  test_logger.info("Wait for writer_threads to finish");
  // wait for threads to finish
  for (std::thread& thread : writer_threads) {
    thread.join();
  }

  test_logger.info("Close PCAP handle");
  mac_pcap_writer.close();
}

// Write #num_pdus DL MAC NR PDUs using PCAP handle (spans)
void write_pcap_nr_thread_function_spans(srsran::mac_pcap* pcap, uint32_t num_pdus)
{
  std::array<uint8_t, 17> tv = {
      0x04, 0x0a, 0x0d, 0x72, 0x80, 0xd3, 0x96, 0x02, 0x7b, 0x01, 0xbd, 0x26, 0x3f, 0x00, 0x00, 0x00, 0x00};
  int                         crnti  = 0x01011;
  int                         ue_id  = 2;
  int                         harqid = 0;
  int                         tti    = 10;
  srsran::mac_nr_context_info context;
  context.radioType           = srsran::PCAP_FDD_RADIO;
  context.direction           = srsran::PCAP_DIRECTION_DOWNLINK;
  context.rntiType            = srsran::PCAP_C_RNTI;
  context.rnti                = crnti;
  context.ueid                = ue_id;
  context.harqid              = harqid;
  context.system_frame_number = tti / 10;
  context.sub_frame_number    = tti % 10;
  for (uint32_t i = 0; i < num_pdus; i++) {
    pcap->push_pdu(context, tv);
  }

  std::cout << "Finished thread " << std::this_thread::get_id() << "\n";
}

// Write #num_pdus DL MAC NR PDUs using PCAP handle (byte_buffer)
void write_pcap_nr_thread_function_byte_buffer(srsran::mac_pcap* pcap, uint32_t num_pdus)
{
  srsran::byte_buffer tv = {
      0x04, 0x0a, 0x0d, 0x72, 0x80, 0xd3, 0x96, 0x02, 0x7b, 0x01, 0xbd, 0x26, 0x3f, 0x00, 0x00, 0x00, 0x00};
  int                         crnti  = 0x01011;
  int                         ue_id  = 2;
  int                         harqid = 0;
  int                         tti    = 10;
  srsran::mac_nr_context_info context;
  context.radioType           = srsran::PCAP_FDD_RADIO;
  context.direction           = srsran::PCAP_DIRECTION_DOWNLINK;
  context.rntiType            = srsran::PCAP_C_RNTI;
  context.rnti                = crnti;
  context.ueid                = ue_id;
  context.harqid              = harqid;
  context.system_frame_number = tti / 10;
  context.sub_frame_number    = tti % 10;
  for (uint32_t i = 0; i < num_pdus; i++) {
    pcap->push_pdu(context, tv.copy());
  }

  std::cout << "Finished thread " << std::this_thread::get_id() << "\n";
}
