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

#include "srsran/phy/upper/channel_processors/ulsch_demultiplex.h"

namespace srsran {

class ulsch_demultiplex_spy : public ulsch_demultiplex
{
public:
  struct demultiplex_entry {
    span<const log_likelihood_ratio> sch_data;
    span<const log_likelihood_ratio> harq_ack;
    span<const log_likelihood_ratio> csi_part1;
    span<const log_likelihood_ratio> csi_part2;
    span<const log_likelihood_ratio> input;
    configuration                    config;
  };

  struct placeholders_entry {
    message_information    msg_info;
    configuration          config;
    ulsch_placeholder_list list;
  };

  ulsch_demultiplex_spy() : placeholder_dist(0, ulsch_placeholder_list::MAX_NOF_PLACEHOLDERS - 1)
  {
    // Do nothing.
  }

  void demultiplex(span<log_likelihood_ratio>       sch_data,
                   span<log_likelihood_ratio>       harq_ack,
                   span<log_likelihood_ratio>       csi_part1,
                   span<log_likelihood_ratio>       csi_part2,
                   span<const log_likelihood_ratio> input,
                   const configuration&             config) override
  {
    demultiplex_entries.emplace_back();
    demultiplex_entry& entry = demultiplex_entries.back();
    entry.sch_data           = sch_data;
    entry.harq_ack           = harq_ack;
    entry.csi_part1          = csi_part1;
    entry.csi_part2          = csi_part2;
    entry.input              = input;
    entry.config             = config;
  }

  ulsch_placeholder_list get_placeholders(const message_information& uci_message_info,
                                          const configuration&       config) override
  {
    placeholder_entries.emplace_back();
    placeholders_entry& entry = placeholder_entries.back();
    entry.msg_info            = uci_message_info;
    entry.config              = config;

    // Generate a random list of trivial placeholders.
    for (unsigned count = 0, nof_placeholders = placeholder_dist(rgen); count != nof_placeholders; ++count) {
      entry.list.push_back(placeholder_dist(rgen));
    }

    return entry.list;
  }

  const std::vector<demultiplex_entry>&  get_demultiplex_entries() const { return demultiplex_entries; }
  const std::vector<placeholders_entry>& get_placeholders_entries() const { return placeholder_entries; }
  void                                   clear()
  {
    demultiplex_entries.clear();
    placeholder_entries.clear();
  }

private:
  std::mt19937                            rgen;
  std::uniform_int_distribution<unsigned> placeholder_dist;
  std::vector<demultiplex_entry>          demultiplex_entries;
  std::vector<placeholders_entry>         placeholder_entries;
};

PHY_SPY_FACTORY_TEMPLATE(ulsch_demultiplex);

} // namespace srsran