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

#include "lower_phy_state_fsm.h"
#include "processors/adaptors/processor_notifier_adaptor.h"
#include "srsran/adt/circular_array.h"
#include "srsran/adt/optional.h"
#include "srsran/gateways/baseband/baseband_gateway.h"
#include "srsran/phy/lower/amplitude_controller/amplitude_controller.h"
#include "srsran/phy/lower/lower_phy.h"
#include "srsran/phy/lower/lower_phy_configuration.h"
#include "srsran/phy/lower/lower_phy_controller.h"
#include "srsran/phy/lower/lower_phy_error_notifier.h"
#include "srsran/phy/lower/lower_phy_request_handler.h"
#include "srsran/phy/lower/lower_phy_rg_handler.h"
#include "srsran/phy/lower/lower_phy_rx_symbol_notifier.h"
#include "srsran/phy/lower/lower_phy_timing_notifier.h"
#include "srsran/phy/lower/modulation/ofdm_demodulator.h"
#include "srsran/phy/lower/modulation/ofdm_modulator.h"
#include "srsran/phy/lower/processors/prach/prach_processor.h"
#include "srsran/phy/support/resource_grid_pool.h"
#include "srsran/support/stats.h"

namespace srsran {

/// Describes the factory configuration.
struct lower_phy_common_configuration {
  /// Provides OFDM modulators. Each entry belongs to a different sector.
  std::vector<std::unique_ptr<ofdm_symbol_modulator>> modulators;
  /// Provides OFDM demodulators. Each entry belongs to a different sector.
  std::vector<std::unique_ptr<ofdm_symbol_demodulator>> demodulators;
  /// PRACH processor.
  std::unique_ptr<prach_processor> prach_proc;
  /// Provides amplitude controllers. Each entry belongs to a different sector.
  std::vector<std::unique_ptr<amplitude_controller>> amplitude_controllers;
};

template <class RG>
class lower_phy_rg_buffer
{
private:
  /// Stores resource grid pointers for every sector.
  std::vector<RG*> grids;
  /// Protects grids access from concurrent read/write.
  std::mutex mutex;

public:
  void set_nof_sectors(unsigned nof_sectors) { grids.resize(nof_sectors); }

  void set_grid(RG& grid, unsigned sector_id)
  {
    std::lock_guard<std::mutex> lock(mutex);
    grids[sector_id] = &grid;
  }

  RG* get_grid(unsigned sector_id)
  {
    std::lock_guard<std::mutex> lock(mutex);
    return grids[sector_id];
  }

  /// Resets all pointers.
  void reset()
  {
    std::lock_guard<std::mutex> lock(mutex);
    std::fill(grids.begin(), grids.end(), nullptr);
  }
};

/// Lower physical layer implementation.
// TODO: Reduce the inheritance list of this class by splitting it into smaller subcomponents that handle more specific
// responsabilities.
class lower_phy_impl : public lower_phy,
                       public lower_phy_controller,
                       public lower_phy_rg_handler,
                       public lower_phy_request_handler
{
private:
  /// Number of resource grid buffers.
  static constexpr unsigned NOF_RG_BUFFER = 40;

  /// Logger.
  srslog::basic_logger& logger;
  /// Baseband gateway transmitter.
  baseband_gateway_transmitter& transmitter;
  /// Baseband gateway receiver.
  baseband_gateway_receiver& receiver;
  /// Receive symbol handler.
  lower_phy_rx_symbol_notifier& rx_symbol_notifier;
  /// Timing boundary handler.
  lower_phy_timing_notifier& timing_notifier;
  /// Error handler.
  lower_phy_error_notifier& error_notifier;
  /// Container for downlink resource grids buffers. Each entry belongs to a slot.
  circular_array<lower_phy_rg_buffer<const resource_grid_reader>, NOF_RG_BUFFER> dl_rg_buffers;
  /// Container for uplink resource grids buffers. Each entry belongs to a slot.
  circular_array<lower_phy_rg_buffer<resource_grid>, NOF_RG_BUFFER> ul_rg_buffers;
  /// Container for radio baseband buffers for each stream. Common for transmit and receive. The number of entries
  /// indicates the number of streams.
  std::vector<baseband_gateway_buffer_dynamic> radio_buffers;
  /// Container for radio receive metadata for each stream. The number of entries indicates the number of streams.
  std::vector<baseband_gateway_receiver::metadata> receive_metadata;
  /// Container for OFDM modulators. Each entry belongs to a different sector.
  std::vector<std::unique_ptr<ofdm_symbol_modulator>> modulators;
  /// Container for OFDM demodulators. Each entry belongs to a different sector.
  std::vector<std::unique_ptr<ofdm_symbol_demodulator>> demodulators;
  /// Container for amplitude controllers. Each entry belongs to a different sector.
  std::vector<std::unique_ptr<amplitude_controller>> amplitude_controllers;
  /// PRACH processor.
  std::unique_ptr<prach_processor> prach_proc;
  /// Receive-to-transmit delay in clock ticks.
  const baseband_gateway_timestamp rx_to_tx_delay;
  /// Maximum allowed processing delay in slots.
  const unsigned max_processing_delay_slots;
  /// Number of symbols per slot.
  const unsigned nof_symbols_per_slot;
  /// Sector configurations.
  const std::vector<lower_phy_sector_description> sectors;
  /// Current uplink processing slot context.
  slot_point ul_slot_context = {};
  /// Current downlink processing slot context.
  slot_point dl_slot_context = {};
  /// Current symbol index within the processing slot.
  unsigned symbol_slot_idx = 0;
  /// State of the lower PHY finite-state machine.
  lower_phy_state_fsm state_fsm;
  /// Processor notification adaptor.
  processor_notifier_adaptor notification_adaptor;
  /// Average symbol power statistics.
  sample_statistics<float> avg_symbol_power;
  /// Peak symbol power statistics.
  sample_statistics<float> peak_symbol_power;
  /// Symbol PAPR statistics.
  sample_statistics<float> symbol_papr;

  /// \brief Processes an uplink symbol.
  /// \param[in] symbol_idx Symbol index within a subframe.
  /// \return The radio timestamp of the received block.
  baseband_gateway_timestamp process_ul_symbol(unsigned symbol_idx);

  /// \brief Processes a downlink symbol.
  /// \param[in] symbol_idx Symbol index within a subframe.
  /// \param[in] timestamp Radio timestamp for the transmitted symbol.
  void process_dl_symbol(unsigned symbol_idx, baseband_gateway_timestamp timestamp);

  /// \brief Processes uplink and downlink slots.
  void process_symbol();

  /// Runs the lower physical layer.
  void realtime_process_loop(task_executor& realtime_task_executor);

  /// \brief Calculates the reception-to-transmission (Rx-to-Tx) delay as a number of samples.
  ///
  /// On the radio channel, uplink and downlink frames coexist on the same carrier. As explained in TS38.211
  /// Section 4.3.1, the sequence of uplink frames precedes the sequence of downlink frames by a given time
  /// \f$T_{\textup{offset}} = N_{\textup{TA,offset}} \cdot T_c\f$ (recall that TS38.211 Section 4.3.1 describes the
  /// issue from the UE standpoint, hence the extra term \f$N_{\textup{TA}} \cdot T_c\f$). In other words, uplink frame
  /// \f$i\f$ starts \f$T_{\textup{offset}}\f$ units of time before the downlink frame with the same index \f$i\f$.
  /// Equivalently, one can index the OFDM symbols comprising the frames and draw the same timing relationship between
  /// symbols with the same index. By increasing the granularity even further, the alignment can be thought of as if at
  /// sample level.
  ///
  /// On the other hand, for an uplink and a downlink sample to coincide on the carrier at the same time, it is required
  /// that the lower PHY processes the downlink (transmit) sample in advance with respect to the uplink (receive) one,
  /// because of the delays introduced by the underlying radio device. The Rx-to-Tx delay is thus the number of
  /// samples by which the sequence of transmitted samples must precede that of received samples, as seen by the lower
  /// PHY processor, in order to achieve the aforementioned carrier alignment between uplink and downlink frames.
  ///
  /// More specifically, let \f$N_{\textup{offset}}\f$ be the "round-trip" delay introduced by the radio device
  /// (i.e., it is the sum of the delay experienced by a received sample before reaching the lower PHY plus the delay
  /// undergone by a downlink sample leaving the lower PHY, before transmission). Also, let \f$N_{\textup{TA,
  /// offset}}\f$ be the time-advance offset between downlink and uplink, as defined in TS38.211 Section 4.3.1. Finally,
  /// let \f$N_{\textup{cal}}\f$ be a calibration term that takes into account time-advance impairments due radio
  /// device buffering. All three offsets are expressed as a number of samples. Then, the Rx-to-Tx delay \f$N\f$ is
  /// given by \f[ N=N_{\textup{offset}} - N_{\textup{cal}} + N_{\textup{TA, offset}} \f] samples or, equivalently,
  /// physical layer units of time.
  ///
  /// \param[in] ul_to_dl_subframe_offset   UL-to-DL offset in subframes (recall, 1 subframe = 1ms). It maps to
  ///                                       \f$N_{\textup{offset}}\f$.
  /// \param[in] time_alignment_calibration Time-advance radio calibration time, in number of samples. It
  ///                                       maps to \f$N_{\textup{cal}}\f$. Positive values cause a reduction of the RF
  ///                                       transmission delay with respect to the RF reception, while negative values
  ///                                       increase it.
  /// \param[in] ta_offset                  Time advance offset (see \ref lower_phy_ta_offset for more information). It
  ///                                       maps to \f$N_{\textup{TA, offset}}\f$.
  /// \param[in] srate                      Sampling rate.
  /// \return The reception-to-transmission delay as a number of samples.
  static inline unsigned get_rx_to_tx_delay(unsigned            ul_to_dl_subframe_offset,
                                            int                 time_alignment_calibration,
                                            lower_phy_ta_offset ta_offset,
                                            sampling_rate       srate)
  {
    // Calculate time between the UL signal reception and the transmission.
    phy_time_unit ul_to_dl_delay = phy_time_unit::from_seconds(0.001 * static_cast<double>(ul_to_dl_subframe_offset));

    // UL to DL delay in number of samples.
    unsigned ul_to_dl_delay_samples = ul_to_dl_delay.to_samples(srate.to_Hz());

    // Apply time alingment calibration.
    ul_to_dl_delay_samples -= time_alignment_calibration;

    // Apply the time alignment offset.
    phy_time_unit time_alignment_offset = phy_time_unit::from_units_of_Tc(static_cast<unsigned>(ta_offset));

    ul_to_dl_delay_samples += time_alignment_offset.to_samples(srate.to_Hz());

    return ul_to_dl_delay_samples;
  }

public:
  /// \brief Constructs a generic lower physical layer.
  /// \param[in] common_config Provides the factory specific necessary parameters to construct the lower physical
  /// layer.
  /// \param[in] config Provides the common lower PHY parameters to construct the lower physical layer.
  explicit lower_phy_impl(lower_phy_common_configuration&& common_config, const lower_phy_configuration& config);

  // See interface for documentation.
  void start(task_executor& realtime_task_executor) override;

  // See interface for documentation.
  void stop() override;

  // See interface for documentation.
  void request_prach_window(const prach_buffer_context& context, prach_buffer& buffer) override;

  // See interface for documentation.
  void request_uplink_slot(const resource_grid_context& context, resource_grid& grid) override;

  // See interface for documentation.
  void handle_resource_grid(const resource_grid_context& context, const resource_grid_reader& grid) override;

  // See interface for documentation.
  lower_phy_request_handler& get_request_handler() override { return *this; }

  // See interface for documentation.
  lower_phy_rg_handler& get_rg_handler() override { return *this; }

  // See interface for documentation.
  lower_phy_controller& get_controller() override { return *this; }
};

} // namespace srsran
