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

#include "srsran/asn1/rrc_nr/tdd_cfg_helper.h"
#include "srsran/ran/slot_point.h"

using namespace srsran;
using namespace asn1::rrc_nr;

float srsran::tdd_cfg_helper::get_period_ms(tdd_ul_dl_pattern_s::dl_ul_tx_periodicity_e_ cfg)
{
  using options = asn1::rrc_nr::tdd_ul_dl_pattern_s::dl_ul_tx_periodicity_opts::options;

  switch (cfg.value) {
    case options::ms0p5:
      return 0.5;
    case options::ms0p625:
      return 0.625;
    case options::ms1:
      return 1;
    case options::ms1p25:
      return 1.25;
    case options::ms2:
      return 2;
    case options::ms2p5:
      return 2.5;
    case options::ms5:
      return 5;
    case options::ms10:
      return 10;
    default:
      break;
  }
  return -1;
}

unsigned srsran::tdd_cfg_helper::nof_slots_per_period(const asn1::rrc_nr::tdd_ul_dl_cfg_common_s& cfg)
{
  float pattern1_period_ms = get_period_ms(cfg.pattern1.dl_ul_tx_periodicity);
  float total_tdd_period_ms =
      pattern1_period_ms + (cfg.pattern2_present ? get_period_ms(cfg.pattern2.dl_ul_tx_periodicity) : 0);
  return (unsigned)std::round(total_tdd_period_ms *
                              get_nof_slots_per_subframe((subcarrier_spacing)cfg.ref_subcarrier_spacing.value));
}

bool srsran::tdd_cfg_helper::slot_is_dl(const tdd_ul_dl_cfg_common_s& cfg, slot_point slot)
{
  float pattern1_period_ms = get_period_ms(cfg.pattern1.dl_ul_tx_periodicity);
  float total_tdd_period_ms =
      pattern1_period_ms + (cfg.pattern2_present ? get_period_ms(cfg.pattern2.dl_ul_tx_periodicity) : 0);
  unsigned pattern1_period_slots = (unsigned)(pattern1_period_ms * slot.nof_slots_per_subframe());
  unsigned sum_period_slots      = (unsigned)std::round(total_tdd_period_ms * slot.nof_slots_per_subframe());

  // Calculate slot index within the TDD overall period
  unsigned slot_idx_period = slot.to_uint() % sum_period_slots; // Slot index within the period

  // Select pattern
  const tdd_ul_dl_pattern_s* pattern = &cfg.pattern1;
  if (slot_idx_period >= pattern1_period_slots) {
    pattern = &cfg.pattern2;
    slot_idx_period -= pattern1_period_slots; // Remove pattern 1 offset
  }

  // Check DL boundaries. Both fully DL slots and partially DL slots return true.
  return (slot_idx_period < pattern->nrof_dl_slots ||
          (slot_idx_period == pattern->nrof_dl_slots && pattern->nrof_dl_symbols != 0));
}

bool srsran::tdd_cfg_helper::slot_is_ul(const asn1::rrc_nr::tdd_ul_dl_cfg_common_s& cfg, slot_point slot)
{
  // TODO: Implement it properly
  return not slot_is_dl(cfg, slot);
}
