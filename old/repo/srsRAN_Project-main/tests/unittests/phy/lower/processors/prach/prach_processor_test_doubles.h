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

#include "srsran/phy/lower/processors/prach/prach_processor_baseband.h"
#include "srsran/phy/lower/processors/prach/prach_processor_factories.h"
#include "srsran/phy/lower/processors/prach/prach_processor_notifier.h"
#include "srsran/phy/lower/processors/prach/prach_processor_request_handler.h"
#include "srsran/phy/support/prach_buffer.h"
#include "srsran/phy/support/prach_buffer_context.h"
#include "srsran/srslog/srslog.h"
#include <vector>

namespace srsran {

class prach_processor_notifier_spy : public prach_processor_notifier
{
private:
  struct rx_prach_window_entry {
    prach_buffer_context context;
    const prach_buffer*  buffer;
  };

  srslog::basic_logger&              logger;
  std::vector<prach_buffer_context>  request_late_entries;
  std::vector<prach_buffer_context>  request_overflow_entries;
  std::vector<rx_prach_window_entry> rx_prach_window_entries;

public:
  explicit prach_processor_notifier_spy(const std::string& log_level = "info") :
    logger(srslog::fetch_basic_logger("Notifier", false))
  {
    srslog::init();
    logger.set_level(srslog::str_to_basic_level(log_level));
  }

  void on_prach_request_late(const prach_buffer_context& context) override
  {
    logger.info("PRACH request is late. Sector/Port {}/{}. Slot/Symbol {}/{}.",
                context.sector,
                context.port,
                context.slot,
                context.start_symbol);
    request_late_entries.push_back(context);
  }

  void on_prach_request_overflow(const prach_buffer_context& context) override
  {
    logger.info("PRACH request discarded. Sector/Port {}/{}. Slot/Symbol {}/{}.",
                context.sector,
                context.port,
                context.slot,
                context.start_symbol);
    request_overflow_entries.push_back(context);
  }

  void on_rx_prach_window(const prach_buffer& buffer, const prach_buffer_context& context) override
  {
    logger.info("PRACH Rx Window Processed. Sector/Port {}/{}. Slot/Symbol {}/{}.",
                context.sector,
                context.port,
                context.slot,
                context.start_symbol);
    rx_prach_window_entries.emplace_back();
    rx_prach_window_entry& entry = rx_prach_window_entries.back();
    entry.context                = context;
    entry.buffer                 = &buffer;
  }

  unsigned get_nof_notifications() const
  {
    return request_late_entries.size() + request_overflow_entries.size() + rx_prach_window_entries.size();
  }

  void clear_notifications()
  {
    request_late_entries.clear();
    request_overflow_entries.clear();
    rx_prach_window_entries.clear();
  }

  const std::vector<prach_buffer_context>& get_request_late_entries() const { return request_late_entries; }

  const std::vector<prach_buffer_context>& get_request_overflow_entries() const { return request_overflow_entries; }

  const std::vector<rx_prach_window_entry>& get_rx_prach_window_entries() const { return rx_prach_window_entries; }
};

class prach_processor_baseband_spy : public prach_processor_baseband
{
public:
  void process_symbol(span<const cf_t> samples, const symbol_context& context) override
  {
    // TBD.
  }
};

class prach_processor_request_handler_spy : public prach_processor_request_handler
{
public:
  void handle_request(prach_buffer& buffer, const prach_buffer_context& context) override
  {
    // TBD.
  }
};

class prach_processor_spy : public prach_processor
{
public:
  void                             connect(prach_processor_notifier& notifier) override {}
  prach_processor_request_handler& get_request_handler() override { return request_handler; }
  prach_processor_baseband&        get_baseband() override { return baseband; }

private:
  prach_processor_request_handler_spy request_handler;
  prach_processor_baseband_spy        baseband;
};

class prach_processor_factory_spy : public prach_processor_factory
{
public:
  std::unique_ptr<prach_processor> create(task_executor& /**/) override
  {
    return std::make_unique<prach_processor_spy>();
  }
};

} // namespace srsran