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

#include "srsran/adt/expected.h"
#include "srsran/scheduler/sched_consts.h"
#include "srsran/scheduler/scheduler_configurator.h"

namespace srsran {
namespace config_validators {

/// \brief Validates \c sched_ue_creation_request_message used to create a UE.
/// \param[in] msg scheduler ue creation request message to be validated.
/// \return In case an invalid parameter is detected, returns a string containing an error message.
error_type<std::string> validate_sched_ue_creation_request_message(const sched_ue_creation_request_message& msg);

/// \brief Validates PUCCH Config in \c sched_ue_creation_request_message used to create a UE.
/// \param[in] msg scheduler ue creation request message to be validated.
/// \return In case an invalid parameter is detected, returns a string containing an error message.
error_type<std::string> validate_pucch_cfg(const sched_ue_creation_request_message& msg);

/// \brief Validates PDSCH Config in \c sched_ue_creation_request_message used to create a UE.
/// \param[in] msg scheduler ue creation request message to be validated.
/// \return In case an invalid parameter is detected, returns a string containing an error message.
error_type<std::string> validate_pdsch_cfg(const sched_ue_creation_request_message& msg);

/// \brief Validates CSI-MeasConfig in \c sched_ue_creation_request_message used to create a UE.
/// \param[in] msg scheduler ue creation request message to be validated.
/// \return In case an invalid parameter is detected, returns a string containing an error message.
error_type<std::string> validate_csi_meas_cfg(const sched_ue_creation_request_message& msg);

} // namespace config_validators
} // namespace srsran
