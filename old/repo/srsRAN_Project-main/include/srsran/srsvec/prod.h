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

#include "srsran/srsvec/types.h"

namespace srsran {
namespace srsvec {

void prod(span<const cf_t> x, span<const cf_t> y, span<cf_t> z);
void prod(span<const cf_t> x, span<const float> y, span<cf_t> z);
void prod(span<const float> x, span<const cf_t> y, span<cf_t> z);
void prod(span<const float> x, span<const float> y, span<float> z);

void prod_conj(span<const cf_t> x, span<const cf_t> y, span<cf_t> z);

} // namespace srsvec
} // namespace srsran
