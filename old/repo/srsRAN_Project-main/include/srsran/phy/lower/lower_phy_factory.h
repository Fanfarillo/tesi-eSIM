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

#include "srsran/phy/lower/amplitude_controller/amplitude_controller_factories.h"
#include "srsran/phy/lower/lower_phy.h"
#include "srsran/phy/lower/lower_phy_configuration.h"
#include "srsran/phy/lower/modulation/modulation_factories.h"
#include "srsran/phy/lower/processors/prach/prach_processor_factories.h"
#include <memory>

namespace srsran {

/// Lower physical layer factory.
class lower_phy_factory
{
public:
  /// Default destructor.
  virtual ~lower_phy_factory() = default;

  /// Creates a lower physical layer.
  virtual std::unique_ptr<lower_phy> create(lower_phy_configuration& config) = 0;
};

/// Creates a software based lower physical layer factory.
std::unique_ptr<lower_phy_factory>
create_lower_phy_factory_sw(std::shared_ptr<ofdm_modulator_factory>       modulator_factory,
                            std::shared_ptr<ofdm_demodulator_factory>     demodulator_factory,
                            std::shared_ptr<prach_processor_factory>      prach_processor_factory,
                            std::shared_ptr<amplitude_controller_factory> amplitude_control_factory);

} // namespace srsran
