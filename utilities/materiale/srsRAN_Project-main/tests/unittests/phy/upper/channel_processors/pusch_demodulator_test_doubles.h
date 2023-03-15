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

#include "../../phy_test_utils.h"
#include "srsran/phy/upper/channel_processors/channel_processor_factories.h"

namespace srsran {

class pusch_demodulator_spy : public pusch_demodulator
{
public:
  struct entry_t {
    span<log_likelihood_ratio>  data;
    const resource_grid_reader* grid;
    const channel_estimate*     estimates;
    configuration               config;
  };

  demodulation_status demodulate(span<log_likelihood_ratio>  data,
                                 const resource_grid_reader& grid,
                                 const channel_estimate&     estimates,
                                 const configuration&        config) override
  {
    entries.emplace_back();
    entry_t& entry  = entries.back();
    entry.data      = data;
    entry.grid      = &grid;
    entry.estimates = &estimates;
    entry.config    = config;

    return demodulation_status();
  }

  const std::vector<entry_t>& get_entries() const { return entries; }

private:
  std::vector<entry_t> entries;
};

PHY_SPY_FACTORY_TEMPLATE(pusch_demodulator);

} // namespace srsran
