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

#include "srsran/gtpu/gtpu_demux_factory.h"
#include "gtpu_demux_impl.h"

using namespace srsran;

std::unique_ptr<gtpu_demux> srsran::create_gtpu_demux(const gtpu_demux_creation_request& msg)
{
  report_fatal_error_if_not(msg.cu_up_exec, "CU-UP exec is uninitialized");
  return std::make_unique<gtpu_demux_impl>(*msg.cu_up_exec);
}
