
#pragma once

#include "srsran/phy/generic_functions/dft_processor.h"
#include "srsran/srsvec/aligned_vec.h"

namespace srsran {

/// Generic interface of an N-point DFT calculator.
class generic_dft_N
{
public:
  virtual ~generic_dft_N()                          = default;
  virtual void run(cf_t* out, const cf_t* in) const = 0;
};

/// Describes a DFT processor class configuration based on the FFTW library.
class dft_processor_generic_impl : public dft_processor
{
private:
  /// Stores the DFT direction.
  direction dir;
  /// DFT input buffer ownership.
  srsvec::aligned_vec<cf_t> input;
  /// DFT output buffer ownership.
  srsvec::aligned_vec<cf_t> output;
  /// Generic FFT.
  std::unique_ptr<generic_dft_N> generic_dft;

public:
  /// \brief Constructs a generic DFT processor.
  /// \param [in] dft_config Provides the generic DFT processor parameters.
  dft_processor_generic_impl(const configuration& dft_config);

  /// Determines whether the initialization was successful.
  bool is_valid() const { return generic_dft != nullptr; }

  // See interface for documentation.
  direction get_direction() const override { return dir; }

  // See interface for documentation.
  unsigned int get_size() const override { return input.size(); }

  // See interface for documentation.
  span<cf_t> get_input() override { return input; }

  // See interface for documentation.
  span<const cf_t> run() override;
};

} // namespace srsran
