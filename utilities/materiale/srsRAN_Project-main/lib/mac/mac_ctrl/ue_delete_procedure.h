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

#include "../mac_config.h"
#include "../mac_config_interfaces.h"

namespace srsran {

class mac_ue_delete_procedure
{
public:
  explicit mac_ue_delete_procedure(const mac_ue_delete_request_message& msg,
                                   mac_common_config_t&                 cfg_,
                                   mac_ctrl_configurator&               mac_ctrl_,
                                   mac_ul_configurator&                 mac_ul_,
                                   mac_dl_configurator&                 mac_dl_,
                                   mac_scheduler_configurator&          sched_configurator_) :
    req(msg),
    cfg(cfg_),
    logger(cfg.logger),
    ctrl_mac(mac_ctrl_),
    ul_mac(mac_ul_),
    dl_mac(mac_dl_),
    sched_configurator(sched_configurator_)
  {
  }

  void operator()(coro_context<async_task<mac_ue_delete_response_message>>& ctx)
  {
    CORO_BEGIN(ctx);

    log_proc_started(logger, req.ue_index, req.rnti, name());

    // 1. Remove UE from scheduler.
    // Note: Removing the UE from the scheduler before the MAC avoids potential race conditions (assuming the scheduler
    // doesn't allocate UEs after being removed).
    CORO_AWAIT(sched_configurator.handle_ue_removal_request(req));

    // 2. Remove UE and associated DL channels from the MAC DL.
    CORO_AWAIT(dl_mac.remove_ue(req));

    // 3. Remove UE associated UL channels from the MAC UL.
    CORO_AWAIT(ul_mac.remove_ue(req));

    // 4. Enqueue UE deletion
    ctrl_mac.remove_ue(req.ue_index);

    log_proc_completed(logger, req.ue_index, req.rnti, "UE Delete Request");

    // 4. Signal end of procedure and pass response
    CORO_RETURN(mac_ue_delete_response_message{true});
  }

  static const char* name() { return "UE Delete Request"; }

private:
  mac_ue_delete_request_message req;
  mac_common_config_t&          cfg;
  srslog::basic_logger&         logger;
  mac_ctrl_configurator&        ctrl_mac;
  mac_ul_configurator&          ul_mac;
  mac_dl_configurator&          dl_mac;
  mac_scheduler_configurator&   sched_configurator;
};

} // namespace srsran
