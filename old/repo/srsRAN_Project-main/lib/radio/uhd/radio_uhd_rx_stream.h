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

#include "radio_uhd_exception_handler.h"
#include "radio_uhd_multi_usrp.h"
#include "srsran/gateways/baseband/baseband_gateway_buffer.h"
#include "srsran/radio/radio_configuration.h"
#include "srsran/radio/radio_notification_handler.h"
#include <mutex>

namespace srsran {
class radio_uhd_rx_stream : public uhd_exception_handler
{
private:
  /// Receive timeout in seconds.
  static constexpr double RECEIVE_TIMEOUT_S = 0.2f;
  /// Set to true for receiving data in a single packet.
  static constexpr bool ONE_PACKET = false;

  /// Defines the Rx stream internal states.
  enum class states { UNINITIALIZED, SUCCESSFUL_INIT, STREAMING, STOP };
  /// Indicates the current stream state.
  std::atomic<states> state = {states::UNINITIALIZED};
  /// Indicates the stream identification for notifications.
  unsigned id;
  /// Radio notification interface.
  radio_notification_handler& notifier;
  /// Owns the UHD Tx stream.
  uhd::rx_streamer::sptr stream;
  /// Maximum number of samples in a single packet.
  unsigned max_packet_size;
  /// Indicates the number of channels.
  unsigned nof_channels;
  /// Protects stream from concurrent receive and stop.
  std::mutex stream_mutex;

  /// \brief Receives a single block of baseband samples.
  /// \param[out] nof_rxd_samples Indicate the number of samples received in the block.
  /// \param[in,out] buffs Provides the reception buffers.
  /// \param[in] buffer_offset Indicates the data offset in the reception buffers.
  /// \param[in] metadata Provides the reception metadata.
  /// \return True if no exception is caught. Otherwise false.
  bool receive_block(unsigned&                nof_rxd_samples,
                     baseband_gateway_buffer& buffs,
                     unsigned                 buffer_offset,
                     uhd::rx_metadata_t&      metadata);

public:
  /// Describes the necessary parameters to create an UHD transmit stream.
  struct stream_description {
    /// Identifies the stream.
    unsigned id;
    /// Over-the-wire format.
    radio_configuration::over_the_wire_format otw_format;
    /// Stream arguments.
    std::string args;
    /// Indicates the port indexes for the stream.
    std::vector<size_t> ports;
  };

  /// \brief Constructs a receive UHD stream.
  /// \param[in] usrp Provides the USRP context.
  /// \param[in] description Provides the stream configuration parameters.
  /// \param[in] notifier_ Provides the radio event notification handler.
  radio_uhd_rx_stream(uhd::usrp::multi_usrp::sptr& usrp,
                      const stream_description&    description,
                      radio_notification_handler&  notifier_);

  /// \brief Starts the stream reception.
  /// \param[in] time_spec Indicates the start time of the stream.
  /// \return True if no exception is caught. Otherwise false.
  bool start(const uhd::time_spec_t& time_spec);

  /// \brief Receives a baseband transmission.
  /// \param[in,out] buffs Provides the baseband buffers to receive.
  /// \param[in] time_spec Indicates the baseband reception time.
  /// \return True if no exception is caught. Otherwise false.
  bool receive(baseband_gateway_buffer& buffs, uhd::time_spec_t& time_spec);

  /// \brief Stops the reception stream.
  /// \return True if no exception is caught. Otherwise false.
  bool stop();
};
} // namespace srsran
