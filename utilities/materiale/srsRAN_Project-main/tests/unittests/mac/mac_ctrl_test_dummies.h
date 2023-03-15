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

#include "lib/mac/mac_config_interfaces.h"
#include "lib/mac/mac_ctrl/mac_scheduler_configurator.h"
#include "srsran/adt/optional.h"
#include "srsran/du_high/du_high_cell_executor_mapper.h"
#include "srsran/du_high/du_high_ue_executor_mapper.h"
#include "srsran/mac/mac_cell_result.h"
#include "srsran/pcap/pcap.h"
#include "srsran/support/async/manual_event.h"
#include "srsran/support/executors/task_executor.h"

namespace srsran {

class mac_ctrl_dummy_configurer final : public mac_ctrl_configurator
{
public:
  bool add_ue(du_ue_index_t ue_index, rnti_t rnti, du_cell_index_t pcell_index) override { return true; }
  void remove_ue(du_ue_index_t ue_index) override {}
};

/// Dummy class to emulate MAC UL procedures to add/remove/configure UEs
class mac_ul_dummy_configurer final : public mac_ul_configurator
{
public:
  bool                                             expected_result   = true;
  bool                                             ul_ccch_forwarded = false;
  manual_event_flag                                ue_created_ev;
  optional<mac_ue_create_request_message>          last_ue_create_request;
  optional<mac_ue_delete_request_message>          last_ue_delete_request;
  optional<mac_ue_reconfiguration_request_message> last_ue_reconfiguration_request;

  async_task<bool> add_ue(const mac_ue_create_request_message& msg) override
  {
    return launch_async([this, msg](coro_context<async_task<bool>>& ctx) {
      CORO_BEGIN(ctx);
      last_ue_create_request = msg;
      CORO_AWAIT(ue_created_ev);
      CORO_RETURN(expected_result);
    });
  }

  async_task<void> remove_ue(const mac_ue_delete_request_message& msg) override
  {
    return launch_async([this, msg](coro_context<async_task<void>>& ctx) {
      CORO_BEGIN(ctx);
      last_ue_delete_request = msg;
      CORO_RETURN();
    });
  }

  async_task<bool> reconfigure_ue(const mac_ue_reconfiguration_request_message& msg) override
  {
    return launch_async([this, msg](coro_context<async_task<bool>>& ctx) {
      CORO_BEGIN(ctx);
      last_ue_reconfiguration_request = msg;
      CORO_RETURN(true);
    });
  }

  void flush_ul_ccch_msg(du_ue_index_t ue_index, byte_buffer pdu) override { ul_ccch_forwarded = true; }
};

class mac_cell_dummy_controller final : public mac_cell_controller
{
public:
  async_task<void> start() override
  {
    return launch_async([](coro_context<async_task<void>>& ctx) {
      CORO_BEGIN(ctx);
      CORO_RETURN();
    });
  }
  async_task<void> stop() override { return start(); }
};

class mac_dl_dummy_configurer final : public mac_dl_configurator
{
public:
  bool                                             expected_result = true;
  manual_event_flag                                ue_created_ev;
  optional<mac_ue_create_request_message>          last_ue_create_request;
  optional<mac_ue_delete_request_message>          last_ue_delete_request;
  optional<mac_ue_reconfiguration_request_message> last_ue_reconfiguration_request;
  mac_cell_dummy_controller                        cell_ctrl;

  async_task<bool> add_ue(const mac_ue_create_request_message& msg) override
  {
    return launch_async([this, msg](coro_context<async_task<bool>>& ctx) {
      CORO_BEGIN(ctx);
      last_ue_create_request = msg;
      CORO_AWAIT(ue_created_ev);
      CORO_RETURN(expected_result);
    });
  }
  async_task<void> remove_ue(const mac_ue_delete_request_message& msg) override
  {
    return launch_async([this, msg](coro_context<async_task<void>>& ctx) {
      CORO_BEGIN(ctx);
      last_ue_delete_request = msg;
      CORO_RETURN();
    });
  }

  async_task<bool> reconfigure_ue(const mac_ue_reconfiguration_request_message& msg) override
  {
    return launch_async([this, msg](coro_context<async_task<bool>>& ctx) {
      CORO_BEGIN(ctx);
      last_ue_reconfiguration_request = msg;
      CORO_RETURN(true);
    });
  }

  void                 add_cell(const mac_cell_creation_request& cell_cfg) override {}
  void                 remove_cell(du_cell_index_t cell_index) override {}
  mac_cell_controller& get_cell_controller(du_cell_index_t cell_index) override { return cell_ctrl; }
};

class dummy_rach_handler_configurator : public rach_handler_configurator
{
public:
  void add_cell(du_cell_index_t cell_index) override {}
  void remove_cell(du_cell_index_t cell_index) override {}
};

class dummy_ue_executor_mapper : public du_high_ue_executor_mapper
{
public:
  dummy_ue_executor_mapper(task_executor& exec_) : exec(exec_) {}

  task_executor& rebind_executor(du_ue_index_t ue_index, du_cell_index_t pcell_index) override
  {
    return executor(ue_index);
  }
  task_executor& executor(du_ue_index_t ue_index) override { return exec; }

  task_executor& exec;
};

class dummy_dl_executor_mapper : public du_high_cell_executor_mapper
{
public:
  dummy_dl_executor_mapper(const std::initializer_list<task_executor*>& execs_) : execs(execs_.begin(), execs_.end()) {}

  task_executor& executor(du_cell_index_t cell_index) override { return *execs[cell_index % execs.size()]; }
  task_executor& slot_ind_executor(du_cell_index_t cell_index) override { return *execs[cell_index % execs.size()]; }

  std::vector<task_executor*> execs;
};

class dummy_mac_event_indicator : public mac_ul_ccch_notifier
{
public:
  optional<ul_ccch_indication_message> last_ccch_ind;

  void on_ul_ccch_msg_received(const ul_ccch_indication_message& msg) override { last_ccch_ind = msg; }

  bool verify_ul_ccch_msg(const ul_ccch_indication_message& test_msg)
  {
    if (not last_ccch_ind.has_value()) {
      return false;
    }
    bool test = last_ccch_ind.value().crnti == test_msg.crnti &&
                last_ccch_ind.value().cell_index == test_msg.cell_index &&
                last_ccch_ind.value().slot_rx == test_msg.slot_rx && last_ccch_ind.value().subpdu == test_msg.subpdu;
    return test;
  }
};

class dummy_mac_cell_result_notifier : public mac_cell_result_notifier
{
public:
  virtual ~dummy_mac_cell_result_notifier() = default;
  virtual void on_new_downlink_scheduler_results(const mac_dl_sched_result& dl_res) override {}
  virtual void on_new_downlink_data(const mac_dl_data_result& dl_data) override {}
  virtual void on_new_uplink_scheduler_results(const mac_ul_sched_result& ul_res) override {}
  virtual void on_cell_results_completion(slot_point slot) override {}
};

class dummy_mac_result_notifier : public mac_result_notifier
{
  dummy_mac_cell_result_notifier cell;

public:
  mac_cell_result_notifier& get_cell(du_cell_index_t cell_index) override { return cell; }
};

class mac_scheduler_dummy_adapter : public mac_scheduler_configurator
{
public:
  void add_cell(const mac_cell_creation_request& msg) override {}

  void remove_cell(du_cell_index_t cell_index) override {}

  async_task<bool> handle_ue_creation_request(const mac_ue_create_request_message& msg) override
  {
    return launch_async([](coro_context<async_task<bool>>& ctx) {
      CORO_BEGIN(ctx);
      CORO_RETURN(true);
    });
  }

  async_task<bool> handle_ue_reconfiguration_request(const mac_ue_reconfiguration_request_message& msg) override
  {
    return launch_async([](coro_context<async_task<bool>>& ctx) {
      CORO_BEGIN(ctx);
      CORO_RETURN(true);
    });
  }

  async_task<bool> handle_ue_removal_request(const mac_ue_delete_request_message& msg) override
  {
    return launch_async([](coro_context<async_task<bool>>& ctx) {
      CORO_BEGIN(ctx);
      CORO_RETURN(true);
    });
  }

  sched_configuration_notifier& get_sched_notifier() override { return notifier; }

  class dummy_notifier : public sched_configuration_notifier
  {
    void on_ue_config_complete(du_ue_index_t ue_index) override {}
    void on_ue_delete_response(du_ue_index_t ue_index) override {}
  } notifier;
};

} // namespace srsran
