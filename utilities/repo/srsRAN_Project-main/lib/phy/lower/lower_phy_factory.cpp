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

#include "srsran/phy/lower/lower_phy_factory.h"
#include "lower_phy_impl.h"

using namespace srsran;

class lower_phy_factory_generic : public lower_phy_factory
{
public:
  std::shared_ptr<ofdm_modulator_factory>       modulator_factory;
  std::shared_ptr<ofdm_demodulator_factory>     demodulator_factory;
  std::shared_ptr<prach_processor_factory>      prach_factory;
  std::shared_ptr<amplitude_controller_factory> amplitude_control_factory;

  lower_phy_factory_generic(std::shared_ptr<ofdm_modulator_factory>&       modulator_factory_,
                            std::shared_ptr<ofdm_demodulator_factory>&     demodulator_factory_,
                            std::shared_ptr<prach_processor_factory>&      prach_processor_factory_,
                            std::shared_ptr<amplitude_controller_factory>& amplitude_control_factory_) :
    modulator_factory(modulator_factory_),
    demodulator_factory(demodulator_factory_),
    prach_factory(prach_processor_factory_),
    amplitude_control_factory(amplitude_control_factory_)
  {
    srsran_assert(modulator_factory, "Invalid modulator factory.");
    srsran_assert(demodulator_factory, "Invalid demodulator factory.");
    srsran_assert(prach_factory, "Invalid PRACH processor factory.");
    srsran_assert(amplitude_control_factory, "Invalid amplitude controller factory");
  }

  std::unique_ptr<srsran::lower_phy> create(lower_phy_configuration& config) override
  {
    srsran_assert((config.dft_window_offset >= 0.0) && (config.dft_window_offset < 1.0F), "");

    lower_phy_common_configuration common_config;
    common_config.modulators.reserve(config.sectors.size());
    common_config.demodulators.reserve(config.sectors.size());
    common_config.amplitude_controllers.reserve(config.sectors.size());

    // For each sector, create a modulator.
    for (const lower_phy_sector_description& sector : config.sectors) {
      // Prepare sector modulator.
      ofdm_modulator_configuration configuration = {};
      configuration.numerology                   = to_numerology_value(config.scs);
      configuration.bw_rb                        = sector.bandwidth_rb;
      configuration.dft_size                     = config.srate.get_dft_size(config.scs);
      configuration.cp                           = config.cp;
      configuration.scale                        = config.tx_scale;
      configuration.center_freq_hz               = sector.dl_freq_hz;

      // Create modulator.
      common_config.modulators.emplace_back(modulator_factory->create_ofdm_symbol_modulator(configuration));

      // Make sure the modulator creation is successful.
      srsran_assert(common_config.modulators.back(), "Failed to create OFDM modulator.");
    }

    // For each sector, create a demodulator.
    for (const lower_phy_sector_description& sector : config.sectors) {
      // Prepare sector demodulator.
      ofdm_demodulator_configuration configuration = {};
      configuration.numerology                     = to_numerology_value(config.scs);
      configuration.bw_rb                          = sector.bandwidth_rb;
      configuration.dft_size                       = config.srate.get_dft_size(config.scs);
      configuration.cp                             = config.cp;
      configuration.nof_samples_window_offset =
          config.cp.get_length(1, config.scs).to_samples(config.srate.to_Hz()) * config.dft_window_offset;
      configuration.scale          = 1.0F;
      configuration.center_freq_hz = sector.ul_freq_hz;

      // Create demodulator.
      common_config.demodulators.emplace_back(demodulator_factory->create_ofdm_symbol_demodulator(configuration));

      // Make sure the demodulator creation is successful.
      srsran_assert(common_config.demodulators.back(), "Error: failed to create OFDM demodulator.");
    }

    // For each sector, create an amplitude controller.
    for (unsigned i = 0; i != config.sectors.size(); ++i) {
      // Prepare sector amplitude controller.
      common_config.amplitude_controllers.emplace_back(amplitude_control_factory->create_amplitude_controller());

      // Make sure the amplitude controller creation is successful.
      srsran_assert(common_config.amplitude_controllers.back() != nullptr,
                    "Error: failed to create amplitude controller.");
    }

    common_config.prach_proc = prach_factory->create(*config.prach_async_executor);
    srsran_assert(common_config.prach_proc, "Failed to create PRACH processor.");

    return std::make_unique<lower_phy_impl>(std::move(common_config), config);
  }
};

std::unique_ptr<lower_phy_factory>
srsran::create_lower_phy_factory_sw(std::shared_ptr<ofdm_modulator_factory>       modulator_factory,
                                    std::shared_ptr<ofdm_demodulator_factory>     demodulator_factory,
                                    std::shared_ptr<prach_processor_factory>      prach_processor_factory,
                                    std::shared_ptr<amplitude_controller_factory> amplitude_control_factory)
{
  return std::make_unique<lower_phy_factory_generic>(
      modulator_factory, demodulator_factory, prach_processor_factory, amplitude_control_factory);
}
