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

#include "ue_manager_test_helpers.h"
#include <gtest/gtest.h>

using namespace srsran;
using namespace srs_cu_cp;

ue_manager_test::ue_manager_test()
{
  test_logger.set_level(srslog::basic_levels::debug);
  ue_mng_logger.set_level(srslog::basic_levels::debug);
  srslog::init();
}

ue_manager_test::~ue_manager_test()
{
  // flush logger after each test
  srslog::flush();
}

ue_index_t ue_manager_test::create_ue(du_index_t du_index, rnti_t rnti)
{
  auto* ue = ue_mng.add_ue(du_index, rnti);
  if (ue == nullptr) {
    test_logger.error("Failed to create UE with rnti={}", rnti);
    return ue_index_t::invalid;
  }

  return ue->get_ue_index();
}
