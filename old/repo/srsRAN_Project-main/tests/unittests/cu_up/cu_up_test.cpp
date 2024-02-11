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

#include "cu_up_test_helpers.h"
#include "lib/e1ap/cu_up/e1ap_cu_up_asn1_helpers.h"
#include "srsran/cu_up/cu_up_factory.h"
#include "srsran/support/executors/task_worker.h"
#include "srsran/support/io_broker/io_broker_factory.h"
#include "srsran/support/test_utils.h"
#include <arpa/inet.h>
#include <fcntl.h>
#include <gtest/gtest.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

using namespace srsran;
using namespace srs_cu_up;
using namespace asn1::e1ap;

class dummy_e1ap_notifier : public e1ap_message_notifier
{
  void on_new_message(const e1ap_message& msg) override
  {
    // do nothing
  }
};

/// Fixture class for CU-UP test
class cu_up_test : public ::testing::Test
{
protected:
  void SetUp() override
  {
    srslog::fetch_basic_logger("TEST").set_level(srslog::basic_levels::debug);
    srslog::init();

    srslog::fetch_basic_logger("GTPU").set_level(srslog::basic_levels::debug);

    // create worker thread and executer
    worker   = std::make_unique<task_worker>("thread", 128, false, os_thread_realtime_priority::no_realtime());
    executor = make_task_executor(*worker);

    f1u_gw       = std::make_unique<dummy_f1u_gateway>(f1u_bearer);
    broker       = create_io_broker(io_broker_type::epoll);
    upf_addr_str = "127.0.0.1";
  }

  cu_up_configuration get_default_cu_up_config()
  {
    // create config
    cu_up_configuration cfg;
    cfg.cu_up_executor       = executor.get();
    cfg.gtpu_pdu_executor    = executor.get();
    cfg.e1ap_notifier        = &e1ap_message_notifier;
    cfg.f1u_gateway          = f1u_gw.get();
    cfg.epoll_broker         = broker.get();
    cfg.net_cfg.n3_bind_port = 0; // Random free port selected by the OS.

    return cfg;
  }

  void init(const cu_up_configuration& cfg) { cu_up = create_cu_up(cfg); }

  void TearDown() override
  {
    // flush logger after each test
    srslog::flush();
  }

  dummy_e1ap_notifier                         e1ap_message_notifier;
  dummy_inner_f1u_bearer                      f1u_bearer;
  std::unique_ptr<dummy_f1u_gateway>          f1u_gw;
  std::unique_ptr<io_broker>                  broker;
  std::unique_ptr<srs_cu_up::cu_up_interface> cu_up;
  srslog::basic_logger&                       test_logger = srslog::fetch_basic_logger("TEST");

  std::unique_ptr<task_worker>   worker;
  std::unique_ptr<task_executor> executor;

  std::string upf_addr_str;

  void create_drb()
  {
    // Generate BearerContextSetupRequest
    e1ap_message asn1_bearer_context_setup_msg = generate_bearer_context_setup_request_msg(9);

    // Convert to common type
    e1ap_bearer_context_setup_request bearer_context_setup;
    fill_e1ap_bearer_context_setup_request(
        bearer_context_setup, asn1_bearer_context_setup_msg.pdu.init_msg().value.bearer_context_setup_request());

    // Setup bearer
    cu_up->handle_bearer_context_setup_request(bearer_context_setup);
  }
};

//////////////////////////////////////////////////////////////////////////////////////
/* E1APonnection handling                                                           */
//////////////////////////////////////////////////////////////////////////////////////

/// Test the E1AP connection
TEST_F(cu_up_test, when_e1ap_connection_established_then_e1ap_connected)
{
  init(get_default_cu_up_config());

  // Connect E1AP
  cu_up->on_e1ap_connection_establish();

  // check that E1AP is in connected state
  ASSERT_TRUE(cu_up->e1ap_is_connected());
}

//////////////////////////////////////////////////////////////////////////////////////
/* User Data Flow                                                                   */
//////////////////////////////////////////////////////////////////////////////////////

TEST_F(cu_up_test, dl_data_flow)
{
  cu_up_configuration cfg = get_default_cu_up_config();
  test_logger.debug("Using network_interface_config: {}", cfg.net_cfg);
  init(cfg);

  create_drb();

  int sock_fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
  ASSERT_GE(sock_fd, 0);

  sockaddr_in cu_up_addr;
  cu_up_addr.sin_family      = AF_INET;
  cu_up_addr.sin_port        = htons(cu_up->get_n3_bind_port());
  cu_up_addr.sin_addr.s_addr = inet_addr(cfg.net_cfg.n3_bind_addr.c_str());

  const uint8_t gtpu_ping_vec[] = {
      0x30, 0xff, 0x00, 0x54, 0x00, 0x00, 0x00, 0x01, 0x45, 0x00, 0x00, 0x54, 0xe8, 0x83, 0x40, 0x00, 0x40, 0x01, 0xfa,
      0x00, 0xac, 0x10, 0x00, 0x03, 0xac, 0x10, 0x00, 0x01, 0x08, 0x00, 0x2c, 0xbe, 0xb4, 0xa4, 0x00, 0x01, 0xd3, 0x45,
      0x61, 0x63, 0x00, 0x00, 0x00, 0x00, 0x1a, 0x20, 0x09, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10, 0x11, 0x12, 0x13, 0x14,
      0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27,
      0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f, 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37};

  int ret = 0;

  // send message 1
  ret = sendto(sock_fd, gtpu_ping_vec, sizeof(gtpu_ping_vec), 0, (sockaddr*)&cu_up_addr, sizeof(cu_up_addr));
  ASSERT_GE(ret, 0) << "Failed to send message via sock_fd=" << sock_fd << " to `" << cfg.net_cfg.n3_bind_addr << ":"
                    << cu_up->get_n3_bind_port() << "` - " << strerror(errno);

  // send message 2
  ret = sendto(sock_fd, gtpu_ping_vec, sizeof(gtpu_ping_vec), 0, (sockaddr*)&cu_up_addr, sizeof(cu_up_addr));
  ASSERT_GE(ret, 0) << "Failed to send message via sock_fd=" << sock_fd << " to `" << cfg.net_cfg.n3_bind_addr << ":"
                    << cu_up->get_n3_bind_port() << "` - " << strerror(errno);

  close(sock_fd);

  // check reception of message 1
  pdcp_tx_pdu sdu1 = f1u_bearer.wait_tx_sdu();
  ASSERT_TRUE(sdu1.pdcp_sn.has_value());
  EXPECT_EQ(sdu1.pdcp_sn.value(), 0);

  // check reception of message 2
  pdcp_tx_pdu sdu2 = f1u_bearer.wait_tx_sdu();
  ASSERT_TRUE(sdu2.pdcp_sn.has_value());
  EXPECT_EQ(sdu2.pdcp_sn.value(), 1);

  // check nothing else was received
  EXPECT_FALSE(f1u_bearer.have_tx_sdu());
  EXPECT_TRUE(f1u_bearer.tx_discard_sdu_list.empty());
}

TEST_F(cu_up_test, ul_data_flow)
{
  cu_up_configuration cfg = get_default_cu_up_config();

  //> Test preamble: listen on a free port

  int sock_fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
  ASSERT_GE(sock_fd, 0);

  int         upf_port = 0; // Random free port selected by the OS: Avoid port conflicts with other tests.
  sockaddr_in upf_addr;
  upf_addr.sin_family      = AF_INET;
  upf_addr.sin_port        = htons(upf_port);
  upf_addr.sin_addr.s_addr = inet_addr(upf_addr_str.c_str());

  int ret = 0;

  ret = bind(sock_fd, (sockaddr*)&upf_addr, sizeof(upf_addr));
  ASSERT_GE(ret, 0) << "Failed to bind socket to `" << upf_addr_str << ":" << upf_port << "` - " << strerror(errno);

  // Find out the port that was assigned
  socklen_t upf_addr_len = sizeof(upf_addr);
  ret                    = getsockname(sock_fd, (struct sockaddr*)&upf_addr, &upf_addr_len);
  ASSERT_EQ(upf_addr_len, sizeof(upf_addr)) << "Mismatching upf_addr_len after getsockname()";
  ASSERT_GE(ret, 0) << "Failed to read port of socket bound to `" << upf_addr_str << ":0` - " << strerror(errno);

  //> Test main part: create CU-UP and transmit data

  cfg.net_cfg.upf_port = ntohs(upf_addr.sin_port);
  test_logger.debug("Using network_interface_config: {}", cfg.net_cfg);
  init(cfg);

  create_drb();

  // send message 1
  const uint8_t t_pdu_arr1[] = {
      0x80, 0x00, 0x00, 0x45, 0x00, 0x00, 0x54, 0xe8, 0x83, 0x40, 0x00, 0x40, 0x01, 0xfa, 0x00, 0xac, 0x10, 0x00,
      0x03, 0xac, 0x10, 0x00, 0x01, 0x08, 0x00, 0x2c, 0xbe, 0xb4, 0xa4, 0x00, 0x01, 0xd3, 0x45, 0x61, 0x63, 0x00,
      0x00, 0x00, 0x00, 0x1a, 0x20, 0x09, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16,
      0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28,
      0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f, 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37};
  span<const uint8_t> t_pdu_span1 = {t_pdu_arr1};
  byte_buffer         t_pdu_buf1  = {t_pdu_span1};
  nru_ul_message      nru_msg1    = {};
  nru_msg1.t_pdu                  = byte_buffer_slice_chain{std::move(t_pdu_buf1)};
  f1u_bearer.handle_pdu(std::move(nru_msg1));

  // send message 2
  const uint8_t t_pdu_arr2[] = {
      0x80, 0x00, 0x01, 0x45, 0x00, 0x00, 0x54, 0xe8, 0x83, 0x40, 0x00, 0x40, 0x01, 0xfa, 0x00, 0xac, 0x10, 0x00,
      0x03, 0xac, 0x10, 0x00, 0x01, 0x08, 0x00, 0x2c, 0xbe, 0xb4, 0xa4, 0x00, 0x01, 0xd3, 0x45, 0x61, 0x63, 0x00,
      0x00, 0x00, 0x00, 0x1a, 0x20, 0x09, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16,
      0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28,
      0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f, 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37};
  span<const uint8_t> t_pdu_span2 = {t_pdu_arr2};
  byte_buffer         t_pdu_buf2  = {t_pdu_span2};
  nru_ul_message      nru_msg2    = {};
  nru_msg2.t_pdu                  = byte_buffer_slice_chain{std::move(t_pdu_buf2)};
  f1u_bearer.handle_pdu(std::move(nru_msg2));

  std::array<uint8_t, 128> rx_buf;

  // receive message 1
  ret = recv(sock_fd, rx_buf.data(), rx_buf.size(), 0);
  ASSERT_EQ(ret, 92);
  EXPECT_TRUE(std::equal(t_pdu_span1.begin() + 3, t_pdu_span1.end(), rx_buf.begin() + 8));

  // receive message 2
  ret = recv(sock_fd, rx_buf.data(), rx_buf.size(), 0);
  ASSERT_EQ(ret, 92);
  EXPECT_TRUE(std::equal(t_pdu_span2.begin() + 3, t_pdu_span2.end(), rx_buf.begin() + 8));

  close(sock_fd);
}

int main(int argc, char** argv)
{
  ::testing::InitGoogleTest(&argc, argv);
  return RUN_ALL_TESTS();
}
