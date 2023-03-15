
#pragma once

#include "srsran/du/du_cell_config.h"
#include "srsran/du/du_qos_config.h"
#include "srsran/du_high/du_high_cell_executor_mapper.h"
#include "srsran/du_high/du_high_ue_executor_mapper.h"
#include "srsran/f1ap/du/f1ap_du.h"
#include "srsran/mac/mac_cell_result.h"
#include "srsran/pcap/pcap.h"
#include "srsran/scheduler/config/scheduler_expert_config.h"
#include "srsran/scheduler/scheduler_metrics.h"
#include <map>

namespace srsran {
namespace srs_du {

class f1u_du_gateway;

/// Configuration passed to DU-High.
struct du_high_configuration {
  task_executor*                   du_mng_executor  = nullptr;
  du_high_ue_executor_mapper*      ue_executors     = nullptr;
  du_high_cell_executor_mapper*    cell_executors   = nullptr;
  f1ap_message_notifier*           f1ap_notifier    = nullptr;
  f1u_du_gateway*                  f1u_gw           = nullptr;
  mac_result_notifier*             phy_adapter      = nullptr;
  timer_manager*                   timers           = nullptr;
  scheduler_ue_metrics_notifier*   metrics_notifier = nullptr;
  std::vector<du_cell_config>      cells;
  std::map<uint8_t, du_qos_config> qos; // 5QI as key
  scheduler_expert_config          sched_cfg;
  mac_pcap*                        pcap = nullptr;
};

} // namespace srs_du
} // namespace srsran
