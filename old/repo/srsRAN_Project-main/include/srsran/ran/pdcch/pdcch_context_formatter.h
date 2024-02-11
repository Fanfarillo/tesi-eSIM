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
#include "srsran/ran/pdcch/pdcch_context.h"
#include "srsran/support/format_utils.h"

namespace fmt {

/// \brief Custom formatter for \c pdcch_context.
template <>
struct formatter<srsran::pdcch_context> {
public:
  template <typename ParseContext>
  auto parse(ParseContext& ctx) -> decltype(ctx.begin())
  {
    return helper.parse(ctx);
  }

  template <typename FormatContext>
  auto format(const srsran::pdcch_context& context, FormatContext& ctx) -> decltype(std::declval<FormatContext>().out())
  {
    helper.format_always(ctx, "ss_id={}", context.ss_id);
    helper.format_always(ctx, "format={}", context.dci_format);
    if (context.harq_feedback_timing.has_value()) {
      helper.format_if_verbose(ctx, "harq_feedback_timing={}", context.harq_feedback_timing.value());
    }
    return ctx.out();
  }

private:
  srsran::delimited_formatter helper;
};

} // namespace fmt