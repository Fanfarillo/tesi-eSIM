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

#include "downlink_processor_single_executor_impl.h"
#include "srsran/phy/upper/upper_phy_rg_gateway.h"
#include "srsran/support/executors/task_executor.h"

using namespace srsran;

downlink_processor_single_executor_impl::downlink_processor_single_executor_impl(
    upper_phy_rg_gateway&                 gateway_,
    std::unique_ptr<pdcch_processor>      pdcch_proc_,
    std::unique_ptr<pdsch_processor>      pdsch_proc_,
    std::unique_ptr<ssb_processor>        ssb_proc_,
    std::unique_ptr<nzp_csi_rs_generator> csi_rs_proc_,
    task_executor&                        executor_) :
  gateway(gateway_),
  current_grid(nullptr),
  pdcch_proc(std::move(pdcch_proc_)),
  pdsch_proc(std::move(pdsch_proc_)),
  ssb_proc(std::move(ssb_proc_)),
  csi_rs_proc(std::move(csi_rs_proc_)),
  executor(executor_),
  pending_pdus(0),
  is_send_allowed(false)
{
  srsran_assert(pdcch_proc, "Invalid PDCCH processor received.");
  srsran_assert(pdsch_proc, "Invalid PDSCH processor received.");
  srsran_assert(ssb_proc, "Invalid SSB processor received.");
  srsran_assert(csi_rs_proc, "Invalid CSI-RS processor received.");
}

void downlink_processor_single_executor_impl::process_pdcch(const pdcch_processor::pdu_t& pdu)
{
  if (current_grid == nullptr) {
    return;
  }

  increase_pending_pdus();

  executor.execute([this, pdu]() {
    pdcch_proc->process(*current_grid, pdu);

    decrease_pending_pdus_and_try_sending_grid();
  });
}

void downlink_processor_single_executor_impl::process_pdsch(
    const static_vector<span<const uint8_t>, pdsch_processor::MAX_NOF_TRANSPORT_BLOCKS>& data,
    const pdsch_processor::pdu_t&                                                        pdu)
{
  if (current_grid == nullptr) {
    return;
  }

  increase_pending_pdus();

  executor.execute([this, data, pdu]() {
    pdsch_proc->process(*current_grid, data, pdu);

    decrease_pending_pdus_and_try_sending_grid();
  });
}

void downlink_processor_single_executor_impl::process_ssb(const ssb_processor::pdu_t& pdu)
{
  if (current_grid == nullptr) {
    return;
  }

  increase_pending_pdus();

  executor.execute([this, pdu]() {
    ssb_proc->process(*current_grid, pdu);

    decrease_pending_pdus_and_try_sending_grid();
  });
}

void downlink_processor_single_executor_impl::process_nzp_csi_rs(const nzp_csi_rs_generator::config_t& config)
{
  if (current_grid == nullptr) {
    return;
  }

  increase_pending_pdus();

  executor.execute([this, config]() {
    csi_rs_proc->map(*current_grid, config);

    decrease_pending_pdus_and_try_sending_grid();
  });
}

void downlink_processor_single_executor_impl::configure_resource_grid(const resource_grid_context& context,
                                                                      resource_grid&               grid)
{
  {
    std::lock_guard<std::mutex> lock(mutex);
    is_send_allowed = false;
    srsran_assert(pending_pdus == 0, "Reusing downlink processor that it is still processing PDUs.");
  }

  rg_context   = context;
  current_grid = &grid;

  // Initialize the resource grid asynchronously.
  increase_pending_pdus();
  executor.execute([this]() {
    current_grid->set_all_zero();
    decrease_pending_pdus_and_try_sending_grid();
  });
}

void srsran::downlink_processor_single_executor_impl::finish_processing_pdus()
{
  {
    std::lock_guard<std::mutex> lock(mutex);
    // No more slot messages will be received.
    is_send_allowed = true;
  }

  // Send the grid if all the PDUs finished to process.
  handle_resource_grid_send_opportunity();
}

void downlink_processor_single_executor_impl::handle_resource_grid_send_opportunity()
{
  std::lock_guard<std::mutex> lock(mutex);
  if (is_send_allowed && (pending_pdus == 0) && (current_grid != nullptr)) {
    gateway.send(rg_context, *current_grid);

    is_send_allowed = false;
    current_grid    = nullptr;
  }
}

void downlink_processor_single_executor_impl::increase_pending_pdus()
{
  std::lock_guard<std::mutex> lock(mutex);
  ++pending_pdus;
}

void downlink_processor_single_executor_impl::decrease_pending_pdus_and_try_sending_grid()
{
  {
    std::lock_guard<std::mutex> lock(mutex);
    --pending_pdus;
  }

  handle_resource_grid_send_opportunity();
}

bool downlink_processor_single_executor_impl::is_reserved() const
{
  std::lock_guard<std::mutex> lock(mutex);
  return (current_grid != nullptr);
}
