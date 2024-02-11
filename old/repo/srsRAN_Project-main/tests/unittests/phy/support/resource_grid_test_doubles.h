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

#include "srsran/adt/tensor.h"
#include "srsran/phy/constants.h"
#include "srsran/phy/support/resource_grid.h"
#include "srsran/ran/cyclic_prefix.h"
#include "srsran/srsvec/copy.h"
#include "srsran/support/error_handling.h"
#include "srsran/support/file_vector.h"
#include "srsran/support/srsran_assert.h"
#include "srsran/support/srsran_test.h"
#include <map>
#include <random>
#include <tuple>

namespace srsran {

/// Describes a resource grid writer spy for testing classes that write in the resource grid.
class resource_grid_writer_spy : public resource_grid_writer
{
public:
  /// Describes an expected resource grid writer spy entry.
  struct expected_entry_t {
    /// Indicates the port index.
    uint8_t port;
    /// Indicates the symbol index.
    uint8_t symbol;
    /// Indicates the subcarrier index.
    uint16_t subcarrier;
    /// Provides the complex resource element value.
    cf_t value;
  };

  /// Constructs a resource spy.
  resource_grid_writer_spy(unsigned max_ports_, unsigned max_symb_, unsigned max_prb_, std::string log_level = "none") :
    max_ports(max_ports_),
    max_symb(max_symb_),
    max_prb(max_prb_),
    logger(srslog::fetch_basic_logger("unittest/resource_grid_spy", false))
  {
    srslog::init();
    logger.set_level(srslog::str_to_basic_level(log_level));
  }

  // See interface for documentation.
  void put(unsigned port, span<const resource_grid_coordinate> coordinates, span<const cf_t> symbols) override
  {
    const cf_t* symbol_ptr = symbols.begin();
    for (const resource_grid_coordinate& coordinate : coordinates) {
      put(port, coordinate.symbol, coordinate.subcarrier, *(symbol_ptr++));
    }
  }

  // See interface for documentation.
  span<const cf_t>
  put(unsigned port, unsigned l, unsigned k_init, span<const bool> mask, span<const cf_t> symbols) override
  {
    TESTASSERT(k_init + mask.size() <= max_prb * NRE,
               "The mask staring at {} for {} subcarriers exceeds the resource grid bandwidth (max {}).",
               k_init,
               mask.size(),
               max_prb * NRE);
    unsigned count = 0;
    for (unsigned k = 0; k != mask.size(); ++k) {
      if (mask[k]) {
        put(port, l, k_init + k, symbols[count]);
        count++;
      }
    }

    // Consume buffer.
    return symbols.last(symbols.size() - count);
  }

  span<const cf_t> put(unsigned                            port,
                       unsigned                            l,
                       unsigned                            k_init,
                       const bounded_bitset<NRE * MAX_RB>& mask,
                       span<const cf_t>                    symbols) override
  {
    unsigned count = 0;
    for (unsigned k = 0; k != mask.size(); ++k) {
      if (mask.test(k)) {
        put(port, l, k + k_init, symbols[count]);
        count++;
      }
    }

    // Consume buffer.
    return symbols.last(symbols.size() - count);
  }

  // See interface for documentation.
  void put(unsigned port, unsigned l, unsigned k_init, span<const cf_t> symbols) override
  {
    for (unsigned i = 0; i != symbols.size(); ++i) {
      put(port, l, k_init + i, symbols[i]);
    }
  }

  /// \brief Asserts that the mapped resource elements match with a list of expected entries.
  ///
  /// This method asserts that mapped resource elements using the put() methods match a list of expected entries
  /// without considering any writing order.
  ///
  /// \param[in] expected_entries Provides a list of golden symbols to assert.
  /// \note The test is terminated in case of mismatch.
  void assert_entries(span<const expected_entry_t> expected_entries) const
  {
    // Make sure the number of elements match.
    TESTASSERT_EQ(entries.size(), expected_entries.size());

    // Iterate each expected entry, check that there is an entry and that the expected value error is below a threshold.
    for (const auto& entry : expected_entries) {
      entry_key_t key = {entry.port, entry.symbol, entry.subcarrier};
      TESTASSERT(entries.count(key),
                 "No resource element was written for port={}, symbol={} and subcarrier={}.",
                 entry.port,
                 entry.symbol,
                 entry.subcarrier);

      cf_t  value = entries.at(key);
      float err   = std::abs(entry.value - value);
      TESTASSERT(err < ASSERT_MAX_ERROR, "Mismatched value {} but expected {}", value, entry.value);
    }
  }

  /// \brief Asserts that the mapped resource elements match with a list of expected entries.
  ///
  /// This method asserts that mapped resource elements using the put() methods match a list of expected entries
  /// without considering any writing order, while using a parametrizable maximkum error threshold.
  ///
  /// \param[in] expected_entries Provides a list of golden symbols to assert.
  /// \param[in] max_error Provides the maximum allowable error when comparing the data in the entries.
  /// \note The test is terminated in case of mismatch.
  void assert_entries(span<const expected_entry_t> expected_entries, float max_error) const
  {
    // Make sure the number of elements match.
    TESTASSERT_EQ(entries.size(), expected_entries.size());

    // Iterate each expected entry, check that there is an entry and that the expected value error is below a threshold.
    for (const auto& entry : expected_entries) {
      entry_key_t key = {entry.port, entry.symbol, entry.subcarrier};
      TESTASSERT(entries.count(key),
                 "No resource element was written for port={}, symbol={} and subcarrier={}.",
                 entry.port,
                 entry.symbol,
                 entry.subcarrier);

      cf_t  value = entries.at(key);
      float err   = std::abs(entry.value - value);
      TESTASSERT(err < max_error, "Mismatched value {} but expected {}", value, entry.value);
    }
  }

  /// Clears any possible state.
  void reset() { entries.clear(); }

private:
  /// \brief Defines the resource grid indexing key as the tuple of the port, symbol and subcarrier indexes.
  using entry_key_t = std::tuple<uint8_t, uint8_t, uint16_t>;

  /// Defines the maximum allowed error when asserting the resource grid.
  static constexpr float ASSERT_MAX_ERROR = 1e-6;

  /// Stores the resource grid written entries.
  std::map<entry_key_t, cf_t> entries;

  /// Maximum number of ports.
  unsigned max_ports;

  /// Maximum number of OFDM symbols.
  unsigned max_symb;

  /// Maximum number of RB.
  unsigned max_prb;

  /// Stores logger.
  srslog::basic_logger& logger;

  /// \brief This method writes a resource element in the allocation given by the port, symbol and subcarrier indexes.
  ///
  /// \param[in] port Indicates the port index.
  /// \param[in] symbol Indicates the symbol index.
  /// \param[in] subcarrier Indicates the subcarrier index.
  /// \param[in] value Indicates the RE value.
  /// \note The test is terminated in case of resource element overwrite.
  void put(uint8_t port, uint8_t symbol, uint16_t subcarrier, cf_t value)
  {
    // Generate key.
    entry_key_t key{port, symbol, subcarrier};

    // Ensure the port, symbol and subcarrier indexes are in range.
    TESTASSERT(port < max_ports, "Port index {} exceeded maximum {}.", port, max_ports);
    TESTASSERT(symbol < max_symb, "Symbol index {} exceeded maximum {}.", symbol, max_symb);
    TESTASSERT(subcarrier < max_prb * NRE, "Subcarrier index {} exceeded maximum {}.", subcarrier, max_prb * NRE);

    // Ensure the resource element does not exist.
    TESTASSERT(entries.count(key) == 0,
               "Detected resource grid overwrite for port={}, symbol={} and subcarrier={}.",
               port,
               symbol,
               subcarrier);

    // Debug trace.
    logger.debug("[put] port={:>2}; symbol={:>2}; subcarrier={:>4}; value={}; count={};",
                 port,
                 symbol,
                 subcarrier,
                 value,
                 entries.size() + 1);

    // Write element.
    entries.emplace(key, value);
  }
};

/// Describes a resource grid reader spy.
class resource_grid_reader_spy : public resource_grid_reader
{
public:
  using expected_entry_t = resource_grid_writer_spy::expected_entry_t;

  bool is_empty(unsigned port) const override { return entries.empty(); }
  void get(span<cf_t> symbols, unsigned port, span<const resource_grid_coordinate> coordinates) const override
  {
    TESTASSERT_EQ(symbols.size(), coordinates.size(), "Number of symbols and coordinates must be the equal.");
    for (unsigned idx = 0; idx != coordinates.size(); ++idx) {
      symbols[idx] = get(static_cast<uint8_t>(port), coordinates[idx].symbol, coordinates[idx].subcarrier);
    }
  }
  span<cf_t> get(span<cf_t> symbols, unsigned port, unsigned l, unsigned k_init, span<const bool> mask) const override
  {
    unsigned count = 0;
    for (unsigned k = 0; k != mask.size(); ++k) {
      if (mask[k]) {
        symbols[count] = get(static_cast<uint8_t>(port), l, k_init + k);
        count++;
      }
    }

    // Consume buffer.
    return symbols.last(symbols.size() - count);
  }
  span<cf_t> get(span<cf_t>                          symbols,
                 unsigned                            port,
                 unsigned                            l,
                 unsigned                            k_init,
                 const bounded_bitset<MAX_RB * NRE>& mask) const override
  {
    mask.for_each(0, mask.size(), [&](unsigned i_subc) {
      symbols.front() = get(static_cast<uint8_t>(port), l, k_init + i_subc);
      symbols         = symbols.last(symbols.size() - 1);
    });

    // Consume buffer.
    return symbols;
  }
  void get(span<cf_t> symbols, unsigned port, unsigned l, unsigned k_init) const override
  {
    cf_t* symbol_ptr = symbols.data();
    for (unsigned k = k_init, k_end = k_init + symbols.size(); k != k_end; ++k) {
      *(symbol_ptr++) = get(port, l, k);
    }
  }

  void write(span<const expected_entry_t> entries_)
  {
    for (const expected_entry_t& e : entries_) {
      write(e);
    }
  }

  void write(const expected_entry_t& entry)
  {
    entry_key_t key = {entry.port, entry.symbol, entry.subcarrier};

    entries.emplace(key, entry.value);
  }

  /// Clears any possible state.
  void reset() { entries.clear(); }

private:
  /// \brief Defines the resource grid indexing key as the tuple of the port, symbol and subcarrier indexes.
  using entry_key_t = std::tuple<uint8_t, uint8_t, uint16_t>;

  /// Stores the resource grid written entries.
  std::map<entry_key_t, cf_t> entries;

  cf_t get(uint8_t port, uint8_t symbol, uint16_t subcarrier) const
  {
    // Generate key.
    entry_key_t key{port, symbol, subcarrier};

    // Ensure the resource element exist.
    srsran_assert(entries.count(key) == 1,
                  "Resource grid for port={}, symbol={} and subcarrier={} does not exist.",
                  port,
                  symbol,
                  subcarrier);

    return entries.at(key);
  }
};

/// Describes a resource grid spy.
class resource_grid_spy : public resource_grid
{
public:
  resource_grid_spy() : writer(MAX_PORTS, MAX_NSYMB_PER_SLOT, MAX_RB)
  {
    // Do nothing.
  }

  void set_all_zero() override
  {
    ++set_all_zero_count;

    // Reset the reader and writer.
    reader.reset();
    writer.reset();
  }

  void set_empty(bool empty_) { empty = empty_; }

  bool is_empty(unsigned port) const override { return empty; }

  void get(span<cf_t> symbols, unsigned port, span<const resource_grid_coordinate> coordinates) const override
  {
    ++get_count;
    reader.get(symbols, port, coordinates);
  }

  span<cf_t> get(span<cf_t> symbols, unsigned port, unsigned l, unsigned k_init, span<const bool> mask) const override
  {
    ++get_count;
    return reader.get(symbols, port, l, k_init, mask);
  }

  span<cf_t> get(span<cf_t>                          symbols,
                 unsigned                            port,
                 unsigned                            l,
                 unsigned                            k_init,
                 const bounded_bitset<MAX_RB * NRE>& mask) const override
  {
    ++get_count;
    return reader.get(symbols, port, l, k_init, mask);
  }

  void get(span<cf_t> symbols, unsigned port, unsigned l, unsigned k_init) const override
  {
    ++get_count;
    reader.get(symbols, port, l, k_init);
  }

  void put(unsigned port, span<const resource_grid_coordinate> coordinates, span<const cf_t> symbols) override
  {
    ++put_count;
    writer.put(port, coordinates, symbols);
  }

  span<const cf_t>
  put(unsigned port, unsigned l, unsigned k_init, span<const bool> mask, span<const cf_t> symbols) override
  {
    ++put_count;
    return writer.put(port, l, k_init, mask, symbols);
  }

  span<const cf_t> put(unsigned                            port,
                       unsigned                            l,
                       unsigned                            k_init,
                       const bounded_bitset<NRE * MAX_RB>& mask,
                       span<const cf_t>                    symbols) override
  {
    ++put_count;
    return writer.put(port, l, k_init, mask, symbols);
  }

  void put(unsigned port, unsigned l, unsigned k_init, span<const cf_t> symbols) override
  {
    ++put_count;
    writer.put(port, l, k_init, symbols);
  }
  /// Returns true if the \c set_all_zero() method has been called, otherwise false.
  bool has_set_all_zero_method_been_called() const { return set_all_zero_count > 0; }

  /// Returns the global number of calls to any method.
  unsigned get_total_count() const { return set_all_zero_count + put_count + get_count; }

  /// Resets all counters.
  void clear()
  {
    set_all_zero_count = 0;
    put_count          = 0;
    get_count          = 0;
  }

private:
  resource_grid_reader_spy reader;
  resource_grid_writer_spy writer;
  bool                     empty              = true;
  unsigned                 set_all_zero_count = 0;
  unsigned                 put_count          = 0;
  mutable unsigned         get_count          = 0;
};

/// \brief Describes a resource grid dummy used for testing classes that handle resource grids but do not use the
/// interface.
///
/// \note The test terminates if any component under test calls any method from the interface.
class resource_grid_dummy : public resource_grid
{
private:
  /// Throws a assertion failure due to an overridden method call.
  void failure() const
  {
    srsran_assertion_failure(
        "Components using resource grid dummy are not allowed to call any method from the interface.");
  }

public:
  unsigned set_all_zero_count = 0;

  void put(unsigned port, span<const resource_grid_coordinate> coordinates, span<const cf_t> symbols) override
  {
    failure();
  }
  span<const cf_t>
  put(unsigned port, unsigned l, unsigned k_init, span<const bool> mask, span<const cf_t> symbols) override
  {
    failure();
    return {};
  }
  span<const cf_t> put(unsigned                            port,
                       unsigned                            l,
                       unsigned                            k_init,
                       const bounded_bitset<NRE * MAX_RB>& mask,
                       span<const cf_t>                    symbols) override
  {
    failure();
    return {};
  }
  void put(unsigned port, unsigned l, unsigned k_init, span<const cf_t> symbols) override { failure(); }
  bool is_empty(unsigned port) const override
  {
    failure();
    return true;
  }
  void get(span<cf_t> symbols, unsigned port, span<const resource_grid_coordinate> coordinates) const override
  {
    failure();
  }
  span<cf_t> get(span<cf_t> symbols, unsigned port, unsigned l, unsigned k_init, span<const bool> mask) const override
  {
    failure();
    return {};
  }
  span<cf_t> get(span<cf_t>                          symbols,
                 unsigned                            port,
                 unsigned                            l,
                 unsigned                            k_init,
                 const bounded_bitset<MAX_RB * NRE>& mask) const override
  {
    failure();
    return {};
  }
  void get(span<cf_t> symbols, unsigned port, unsigned l, unsigned k_init) const override { failure(); }
  void set_all_zero() override { ++set_all_zero_count; }

  void clear_set_all_zero_count() { set_all_zero_count = 0; }
};

} // namespace srsran
