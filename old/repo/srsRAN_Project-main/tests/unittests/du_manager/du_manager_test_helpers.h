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

#include "lib/du_manager/du_ue/ue_manager_ctrl_configurator.h"
#include "srsran/du_manager/du_manager_params.h"
#include "srsran/support/async/async_test_utils.h"
#include "srsran/support/executors/manual_task_worker.h"
#include <map>

namespace srsran {
namespace srs_du {

class dummy_ue_executor_mapper : public du_high_ue_executor_mapper
{
public:
  explicit dummy_ue_executor_mapper(task_executor& exec_) : exec(exec_) {}
  task_executor& rebind_executor(du_ue_index_t ue_index, du_cell_index_t pcell_index) override { return exec; }
  task_executor& executor(du_ue_index_t ue_index) override { return exec; }

  task_executor& exec;
};

class dummy_cell_executor_mapper : public du_high_cell_executor_mapper
{
public:
  explicit dummy_cell_executor_mapper(task_executor& exec_) : exec(exec_) {}
  task_executor& executor(du_cell_index_t cell_index) override { return exec; }
  task_executor& slot_ind_executor(du_cell_index_t cell_index) override { return exec; }

  task_executor& exec;
};

class dummy_f1c_bearer : public f1c_bearer
{
public:
  byte_buffer             last_rx_pdu;
  byte_buffer_slice_chain last_tx_sdu;

  void handle_pdu(byte_buffer pdu) override { last_rx_pdu = std::move(pdu); }
  void handle_sdu(byte_buffer_slice_chain sdu) override { last_tx_sdu = std::move(sdu); }
};

class dummy_f1u_bearer : public f1u_bearer,
                         public f1u_rx_pdu_handler,
                         public f1u_tx_delivery_handler,
                         public f1u_tx_sdu_handler
{
public:
  nru_dl_message          last_msg;
  optional<uint32_t>      last_highest_transmitted_pdcp_sn;
  optional<uint32_t>      last_highest_delivered_pdcp_sn;
  byte_buffer_slice_chain last_sdu;

  f1u_rx_pdu_handler&      get_rx_pdu_handler() override { return *this; }
  f1u_tx_delivery_handler& get_tx_delivery_handler() override { return *this; }
  f1u_tx_sdu_handler&      get_tx_sdu_handler() override { return *this; }

  void handle_pdu(nru_dl_message msg) override { last_msg = std::move(msg); }
  void handle_transmit_notification(uint32_t highest_pdcp_sn) override
  {
    last_highest_transmitted_pdcp_sn = highest_pdcp_sn;
  }
  void handle_delivery_notification(uint32_t highest_pdcp_sn) override
  {
    last_highest_delivered_pdcp_sn = highest_pdcp_sn;
  }
  void handle_sdu(byte_buffer_slice_chain sdu) override { last_sdu = std::move(sdu); }
};

class f1ap_test_dummy : public f1ap_connection_manager,
                        public f1ap_ue_context_manager,
                        public f1ap_message_handler,
                        public f1ap_rrc_message_transfer_procedure_handler
{
  struct drb_to_idx {
    size_t   get_index(drb_id_t i) const { return static_cast<size_t>(i) - 1; }
    drb_id_t get_id(size_t i) const { return static_cast<drb_id_t>(i + 1); }
  };

public:
  struct f1ap_ue_context {
    slotted_id_table<srb_id_t, dummy_f1c_bearer, MAX_NOF_SRBS> f1c_bearers;
  };

  slotted_id_table<du_ue_index_t, f1ap_ue_context, MAX_NOF_DU_UES> f1ap_ues;

  wait_manual_event_tester<f1_setup_response_message>                     wait_f1_setup;
  optional<f1ap_ue_creation_request>                                      last_ue_create{};
  f1ap_ue_creation_response                                               next_ue_create_response;
  optional<f1ap_ue_configuration_request>                                 last_ue_config{};
  f1ap_ue_configuration_response                                          next_ue_config_response;
  optional<f1ap_ue_context_release_request_message>                       last_ue_release{};
  wait_manual_event_tester<f1ap_ue_context_modification_response_message> wait_ue_mod;

  async_task<f1_setup_response_message> handle_f1_setup_request(const f1_setup_request_message& request) override
  {
    return wait_f1_setup.launch();
  }

  /// Initiates creation of UE context in F1.
  f1ap_ue_creation_response handle_ue_creation_request(const f1ap_ue_creation_request& msg) override
  {
    last_ue_create = msg;
    return next_ue_create_response;
  }

  f1ap_ue_configuration_response handle_ue_configuration_request(const f1ap_ue_configuration_request& msg) override
  {
    last_ue_config = msg;
    return next_ue_config_response;
  }

  void handle_ue_context_release_request(const f1ap_ue_context_release_request_message& request) override
  {
    last_ue_release = request;
  }

  async_task<f1ap_ue_context_modification_response_message>
  handle_ue_context_modification_required(const f1ap_ue_context_modification_required_message& msg) override
  {
    return wait_ue_mod.launch();
  }

  void handle_ue_inactivity_notification(const f1ap_ue_inactivity_notification_message& msg) override {}

  void handle_notify(const f1ap_notify_message& msg) override {}

  void handle_message(const f1ap_message& msg) override {}

  void handle_rrc_delivery_report(const f1ap_rrc_delivery_report_msg& report) override {}
};

class f1u_bearer_dummy : public f1u_bearer,
                         public f1u_rx_pdu_handler,
                         public f1u_tx_delivery_handler,
                         public f1u_tx_sdu_handler
{
public:
  srs_du::f1u_rx_sdu_notifier& du_rx;

  optional<nru_dl_message> last_pdu;
  optional<uint32_t>       last_highest_transmitted_pdcp_sn;
  optional<uint32_t>       last_highest_delivered_pdcp_sn;
  byte_buffer_slice_chain  last_sdu;

  f1u_bearer_dummy(srs_du::f1u_rx_sdu_notifier& du_rx_) : du_rx(du_rx_) {}

  f1u_rx_pdu_handler&      get_rx_pdu_handler() override { return *this; }
  f1u_tx_delivery_handler& get_tx_delivery_handler() override { return *this; }
  f1u_tx_sdu_handler&      get_tx_sdu_handler() override { return *this; }

  void handle_pdu(nru_dl_message msg) override { last_pdu = std::move(msg); }
  void handle_transmit_notification(uint32_t highest_pdcp_sn) override
  {
    last_highest_transmitted_pdcp_sn = highest_pdcp_sn;
  }
  void handle_delivery_notification(uint32_t highest_pdcp_sn) override
  {
    last_highest_delivered_pdcp_sn = highest_pdcp_sn;
  }
  void handle_sdu(byte_buffer_slice_chain sdu) override { last_sdu = std::move(sdu); }
};

class f1u_gateway_dummy : public f1u_du_gateway
{
public:
  bool next_bearer_is_created = true;

  srs_du::f1u_bearer*
  create_du_bearer(uint32_t ue_index, uint32_t dl_teid, uint32_t ul_teid, srs_du::f1u_rx_sdu_notifier& du_rx) override
  {
    if (next_bearer_is_created and f1u_bearers.count(dl_teid) == 0) {
      f1u_bearers.insert(std::make_pair(dl_teid, std::map<uint32_t, f1u_bearer_dummy>{}));
      f1u_bearers[dl_teid].emplace(ul_teid, du_rx);
      return &f1u_bearers.at(dl_teid).at(ul_teid);
    }
    return nullptr;
  }

  void remove_du_bearer(uint32_t dl_teid) override
  {
    auto bearer_it = f1u_bearers.find(dl_teid);
    if (bearer_it == f1u_bearers.end()) {
      srslog::fetch_basic_logger("TEST").warning("Could not find DL-TEID at DU to remove. DL-TEID={}", dl_teid);
      return;
    }
    f1u_bearers.erase(bearer_it);
  }

  std::map<uint32_t, std::map<uint32_t, f1u_bearer_dummy>> f1u_bearers;
};

class mac_test_dummy : public mac_cell_manager, public mac_ue_configurator, public mac_ue_control_information_handler
{
public:
  class mac_cell_dummy : public mac_cell_controller
  {
    wait_manual_event_tester<void> wait_start;
    wait_manual_event_tester<void> wait_stop;

    async_task<void> start() override { return wait_start.launch(); }
    async_task<void> stop() override { return wait_stop.launch(); }
  };

  mac_cell_dummy mac_cell;

  optional<mac_ue_create_request_message>                           last_ue_create_msg{};
  optional<mac_ue_reconfiguration_request_message>                  last_ue_reconf_msg{};
  optional<mac_ue_delete_request_message>                           last_ue_delete_msg{};
  byte_buffer                                                       last_pushed_ul_ccch_msg;
  wait_manual_event_tester<mac_ue_create_response_message>          wait_ue_create;
  wait_manual_event_tester<mac_ue_reconfiguration_response_message> wait_ue_reconf;
  wait_manual_event_tester<mac_ue_delete_response_message>          wait_ue_delete;

  void                 add_cell(const mac_cell_creation_request& cell_cfg) override {}
  void                 remove_cell(du_cell_index_t cell_index) override {}
  mac_cell_controller& get_cell_controller(du_cell_index_t cell_index) override { return mac_cell; }

  async_task<mac_ue_create_response_message> handle_ue_create_request(const mac_ue_create_request_message& msg) override
  {
    last_ue_create_msg = msg;
    return wait_ue_create.launch();
  }
  async_task<mac_ue_reconfiguration_response_message>
  handle_ue_reconfiguration_request(const mac_ue_reconfiguration_request_message& msg) override
  {
    last_ue_reconf_msg = msg;
    return wait_ue_reconf.launch();
  }
  async_task<mac_ue_delete_response_message> handle_ue_delete_request(const mac_ue_delete_request_message& msg) override
  {
    last_ue_delete_msg = msg;
    return wait_ue_delete.launch();
  }
  void handle_ul_ccch_msg(du_ue_index_t ue_index, byte_buffer pdu) override
  {
    last_pushed_ul_ccch_msg = std::move(pdu);
  }

  void handle_dl_buffer_state_update_required(const mac_dl_buffer_state_indication_message& dl_bs) override {}
};

class dummy_ue_resource_configurator_factory : public du_ran_resource_manager
{
public:
  class dummy_resource_updater : public ue_ran_resource_configurator::resource_updater
  {
  public:
    dummy_resource_updater(dummy_ue_resource_configurator_factory& parent_, du_ue_index_t ue_index_);
    ~dummy_resource_updater();
    du_ue_resource_update_response update(du_cell_index_t                       pcell_index,
                                          const f1ap_ue_context_update_request& upd_req) override;
    const cell_group_config&       get() override;

    du_ue_index_t                           ue_index;
    dummy_ue_resource_configurator_factory& parent;
  };

  optional<du_ue_index_t>                    last_ue_index;
  optional<du_cell_index_t>                  last_ue_pcell;
  f1ap_ue_context_update_request             last_ue_ctx_upd;
  std::map<du_ue_index_t, cell_group_config> ue_resource_pool;
  cell_group_config                          next_context_update_result;

  dummy_ue_resource_configurator_factory();

  ue_ran_resource_configurator create_ue_resource_configurator(du_ue_index_t   ue_index,
                                                               du_cell_index_t pcell_index) override;
};

f1ap_ue_context_update_request create_f1ap_ue_context_update_request(du_ue_index_t                   ue_idx,
                                                                     std::initializer_list<srb_id_t> srbs_to_addmod,
                                                                     std::initializer_list<drb_id_t> drbs_to_addmod);

class du_manager_test_bench
{
public:
  du_manager_test_bench(span<const du_cell_config> cells) :
    du_cells(cells.begin(), cells.end()),
    worker(128),
    du_mng_exec(worker),
    ue_exec_mapper(worker),
    cell_exec_mapper(worker),
    params{{"srsgnb", 1, 1, du_cells},
           {timers, du_mng_exec, ue_exec_mapper, cell_exec_mapper},
           {f1ap, f1ap},
           {f1u_gw},
           {mac, f1ap, f1ap},
           {mac, mac}},
    logger(srslog::fetch_basic_logger("DU-MNG"))
  {
    logger.set_level(srslog::basic_levels::debug);

    srslog::init();
  }

  std::vector<du_cell_config>            du_cells;
  timer_manager                          timers;
  manual_task_worker                     worker;
  task_executor&                         du_mng_exec;
  dummy_ue_executor_mapper               ue_exec_mapper;
  dummy_cell_executor_mapper             cell_exec_mapper;
  f1ap_test_dummy                        f1ap;
  f1u_gateway_dummy                      f1u_gw;
  mac_test_dummy                         mac;
  du_manager_params                      params;
  dummy_ue_resource_configurator_factory cell_res_alloc;
  srslog::basic_logger&                  logger;
};

} // namespace srs_du
} // namespace srsran
