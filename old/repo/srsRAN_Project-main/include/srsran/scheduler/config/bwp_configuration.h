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

#include "dmrs.h"
#include "srsran/adt/optional.h"
#include "srsran/adt/slotted_array.h"
#include "srsran/ran/band_helper.h"
#include "srsran/ran/frame_types.h"
#include "srsran/ran/ofdm_symbol_range.h"
#include "srsran/ran/pcch/pcch_configuration.h"
#include "srsran/ran/pdcch/coreset.h"
#include "srsran/ran/pdcch/search_space.h"
#include "srsran/ran/prach/restricted_set_config.h"
#include "srsran/ran/pucch/pucch_configuration.h"
#include "srsran/ran/resource_block.h"
#include "srsran/scheduler/prb_grant.h"
#include <bitset>

namespace srsran {

/// \remark See TS 38.331, "PDCCH-ConfigCommon"
struct pdcch_config_common {
  /// Contains Coreset#0.
  optional<coreset_configuration> coreset0;
  /// Contains common Coreset.
  optional<coreset_configuration> common_coreset;
  /// Contains SearchSpaceZero and commonSearchSpaceList. Size: (0..4).
  std::vector<search_space_configuration> search_spaces;
  search_space_id                         sib1_search_space_id;
  search_space_id                         other_si_search_space_id;
  optional<search_space_id>               paging_search_space_id;
  /// SearchSpace of RA procedure. If field is invalid, the UE does not receive RAR in this BWP.
  search_space_id ra_search_space_id;
};

/// BWP-Id used to identify a BWP from the perspective of a UE.
/// \remark See TS 38.331, "BWP-Id" and "maxNrofBWPs".
enum bwp_id_t : uint8_t { MIN_BWP_ID = 0, MAX_BWP_ID = 3, MAX_NOF_BWPS = 4 };

/// Converts integer value to BWP-Id".
constexpr inline bwp_id_t to_bwp_id(std::underlying_type_t<bwp_id_t> value)
{
  return static_cast<bwp_id_t>(value);
}

/// Generic parameters of a bandwidth part as defined in TS 38.211, clause 4.5 and TS 38.213, clause 12.
/// \remark See TS 38.331, Bandwidth-Part (BWP).
struct bwp_configuration {
  bool               cp_extended;
  subcarrier_spacing scs;
  /// Common RBs where the BWP is located. CRB=0 overlaps with pointA.
  crb_interval crbs;

  bool operator==(const bwp_configuration& other) const
  {
    return std::tie(cp_extended, scs, crbs) == std::tie(other.cp_extended, other.scs, other.crbs);
  }

  bool operator<(const bwp_configuration& other) const
  {
    return std::tie(cp_extended, scs, crbs) < std::tie(other.cp_extended, other.scs, other.crbs);
  }
};

/// \brief Physical shared channels Mapping Type.
/// \remark see TS38.214 Section 5.3 for PDSCH and TS38.214 Section 6.4 for PUSCH.
enum class sch_mapping_type {
  /// TypeA time allocation, it can start only at symbol 2 or 3 within a slot.
  typeA,
  /// TypeB time allocation.
  typeB
};

struct pdsch_time_domain_resource_allocation {
  /// Values: (0..32).
  unsigned          k0;
  sch_mapping_type  map_type;
  ofdm_symbol_range symbols;

  bool operator==(const pdsch_time_domain_resource_allocation& rhs) const
  {
    return k0 == rhs.k0 && map_type == rhs.map_type && symbols == rhs.symbols;
  }
  bool operator!=(const pdsch_time_domain_resource_allocation& rhs) const { return !(rhs == *this); }
};

struct pdsch_config_common {
  /// PDSCH time domain resource allocations. Size: (0..maxNrofDL-Allocations=16).
  std::vector<pdsch_time_domain_resource_allocation> pdsch_td_alloc_list;
};

/// Used to configure the common, cell-specific parameters of a DL BWP.
/// \remark See TS 38.331, BWP-DownlinkCommon.
struct bwp_downlink_common {
  bwp_configuration   generic_params;
  pdcch_config_common pdcch_common;
  pdsch_config_common pdsch_common;
};

/// \remark See TS 38.331, RACH-ConfigGeneric.
struct rach_config_generic {
  /// Values: {0,...,255}.
  uint8_t prach_config_index;
  /// Msg2 RAR window length in #slots. Network configures a value < 10msec. Values: (1, 2, 4, 8, 10, 20, 40, 80).
  unsigned ra_resp_window;
  /// Number of PRACH occasions FDMed in one time instance as per TS38.211, clause 6.3.3.2.
  unsigned msg1_fdm;
  /// Offset of lowest PRACH transmission occasion in frequency domain respective to PRB 0,
  /// as per TS38.211, clause 6.3.3.2. Possible values: {0,...,MAX_NOF_PRB - 1}.
  unsigned msg1_frequency_start;
  /// Zero-correlation zone configuration number as per TS38.331 "zeroCorrelationZoneConfig", used to derive N_{CS}.
  uint16_t zero_correlation_zone_config;
};

/// Used to specify the cell-specific random-access parameters as per TS38.331, "RACH-ConfigCommon".
struct rach_config_common {
  rach_config_generic rach_cfg_generic;
  /// Total number of prambles used for contention based and contention free RA. Values: (1..64).
  unsigned total_nof_ra_preambles;
  /// PRACH root sequence index. Values: (1..839).
  /// \remark See TS 38.211, clause 6.3.3.1.
  bool     prach_root_seq_index_l839_present;
  unsigned prach_root_seq_index;
  /// \brief Subcarrier spacing of PRACH as per TS38.331, "RACH-ConfigCommon". If invalid, the UE applies the SCS as
  /// derived from the prach-ConfigurationIndex in RACH-ConfigGeneric as per TS38.211 Tables 6.3.3.1-[1-3].
  subcarrier_spacing    msg1_scs;
  restricted_set_config restricted_set;
  /// Enables the transform precoder for Msg3 transmission according to clause 6.1.3 of TS 38.214.
  bool msg3_transform_precoder;
};

struct pusch_time_domain_resource_allocation {
  /// Values: (0..32).
  unsigned         k2;
  sch_mapping_type map_type;
  /// OFDM symbol boundaries for PUSCH. Network configures the fields so it does not cross the slot boundary.
  ofdm_symbol_range symbols;

  bool operator==(const pusch_time_domain_resource_allocation& rhs) const
  {
    return k2 == rhs.k2 && map_type == rhs.map_type && symbols == rhs.symbols;
  }
  bool operator!=(const pusch_time_domain_resource_allocation& rhs) const { return !(rhs == *this); }
};

/// \remark See TS 38.331, "PUSCH-ConfigCommon".
struct pusch_config_common {
  /// PUSCH time domain resource allocations. Size: (0..maxNrofUL-Allocations=16).
  std::vector<pusch_time_domain_resource_allocation> pusch_td_alloc_list;
};

/// \remark See TS 38.331, "PUCCH-ConfigCommon".
struct pucch_config_common {
  /// Values: {0,...,15}.
  uint8_t             pucch_resource_common;
  pucch_group_hopping group_hopping;
  /// Values: {0, ..., 1023}.
  optional<unsigned> hopping_id;
  /// Values: {-202, ..., 24}
  int p0_nominal;
};

/// Used to configure the common, cell-specific parameters of an UL BWP.
/// \remark See TS 38.331, BWP-UplinkCommon.
struct bwp_uplink_common {
  bwp_configuration             generic_params;
  optional<rach_config_common>  rach_cfg_common;
  optional<pusch_config_common> pusch_cfg_common;
  optional<pucch_config_common> pucch_cfg_common;
};

/// \brief It provides parameters determining the location and width of the actual carrier.
/// \remark See TS 38.331, "SCS-SpecificCarrier".
struct scs_specific_carrier {
  /// Offset between Point A (lowest subcarrier of common RB 0) and the lowest usable subcarrier in this carrier in
  /// number of PRBs. Values: (0..2199).
  unsigned           offset_to_carrier;
  subcarrier_spacing scs;
  /// Width of this carrier in number of PRBs. Values: (0..MAX_NOF_PRBS).
  unsigned carrier_bandwidth;
};

/// \brief Used to indicate a frequency band
struct freq_band_indicator {
  nr_band band;
};

/// \brief This class provides basic parameters of a downlink carrier and transmission.
/// \remark See TS 38.331, "FrequencyInfoDL-SIB".
struct frequency_info_dl {
  /// Represents the offset to Point A, as defined in TS 38.211, clause 4.4.4.2. Values: (0..2199).
  unsigned offset_to_point_a;
  /// Set of carriers for different subcarrier spacings. The network configures this for all SCSs that are used in
  /// DL BWPs in this serving cell. Size: (1..maxSCSs=5).
  std::vector<scs_specific_carrier> scs_carrier_list;

  /// Set of frequency bands.
  std::vector<freq_band_indicator> freq_band_list;
};

/// \brief Downlink Configuration, common to the serving cell.
/// \remark See TS 38.331, "DownlinkConfigCommonSIB".
struct dl_config_common {
  frequency_info_dl   freq_info_dl;
  bwp_downlink_common init_dl_bwp;
  pcch_config         pcch_cfg;
};

struct frequency_info_ul {
  /// Absolute frequency (in ARFCN) of the CRB0.
  unsigned absolute_freq_point_a;
  /// Set of carriers for different subcarrier spacings. The network configures this for all SCSs that are used in
  /// UL BWPs in this serving cell. Size: (1..maxSCSs=5).
  std::vector<scs_specific_carrier> scs_carrier_list;
  bool                              freq_shift_7p5khz_present;

  /// Set of frequency bands.
  std::vector<freq_band_indicator> freq_band_list;
  // TODO: Add other fields.
};

/// \brief Uplink Configuration, common to the serving cell.
/// \remark See TS 38.331, "UplinkConfigCommonSIB".
struct ul_config_common {
  frequency_info_ul freq_info_ul;
  bwp_uplink_common init_ul_bwp;
};

} // namespace srsran
