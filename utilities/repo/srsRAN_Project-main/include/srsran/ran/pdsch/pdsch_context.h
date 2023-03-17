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
#include "srsran/ran/rnti.h"
#include "srsran/scheduler/harq_id.h"

namespace srsran {

/// PDSCH transmission context.
class pdsch_context
{
public:
  /// Default constructor.
  pdsch_context() = default;

  /// Constructs from values.
  explicit pdsch_context(harq_id_t h_id_, unsigned k1_) : h_id(h_id_), k1(k1_) {}

private:
  friend struct fmt::formatter<pdsch_context>;
  harq_id_t h_id = INVALID_HARQ_ID;
  unsigned  k1   = 0;
};

} // namespace srsran
