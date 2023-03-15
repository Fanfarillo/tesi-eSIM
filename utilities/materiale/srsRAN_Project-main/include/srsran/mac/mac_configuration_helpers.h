
#pragma once

#include "srsran/mac/cell_configuration.h"
#include "srsran/mac/mac_ue_configurator.h"
#include "srsran/scheduler/scheduler_configurator.h"

namespace srsran {

/// Convert a UE creation request for the MAC into a UE creation request of the scheduler.
sched_ue_creation_request_message make_scheduler_ue_creation_request(const mac_ue_create_request_message& request);

/// Convert a UE reconfiguration request for the MAC into a UE reconfiguration request of the scheduler.
sched_ue_reconfiguration_message
make_scheduler_ue_reconfiguration_request(const mac_ue_reconfiguration_request_message& request);

} // namespace srsran
