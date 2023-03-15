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

#include "rrc_du_impl.h"
#include "../ran/gnb_format.h"
#include "srsran/ran/nr_cgi_helpers.h"

using namespace srsran;
using namespace srs_cu_cp;
using namespace asn1::rrc_nr;

rrc_du_impl::rrc_du_impl(const rrc_cfg_t&              cfg_,
                         rrc_ue_du_processor_notifier& rrc_ue_du_proc_notif_,
                         rrc_ue_nas_notifier&          nas_notif_,
                         rrc_ue_control_notifier&      ngap_ctrl_notif_) :
  cfg(cfg_),
  rrc_ue_du_proc_notifier(rrc_ue_du_proc_notif_),
  nas_notifier(nas_notif_),
  ngap_ctrl_notifier(ngap_ctrl_notif_),
  logger(cfg_.logger)
{
}

rrc_ue_interface* rrc_du_impl::add_ue(rrc_ue_creation_message msg)
{
  // Unpack DU to CU container
  asn1::rrc_nr::cell_group_cfg_s cell_group_cfg;
  asn1::cbit_ref                 bref({msg.du_to_cu_container.begin(), msg.du_to_cu_container.end()});
  if (cell_group_cfg.unpack(bref) != asn1::SRSASN_SUCCESS) {
    logger.error("Failed to unpack DU to CU RRC container - aborting user creation");
    return nullptr;
  }

  if (logger.debug.enabled()) {
    asn1::json_writer js;
    cell_group_cfg.to_json(js);
    logger.debug("Containerized MasterCellGroup: {}", js.to_string());
  }

  // create UE object
  ue_index_t ue_index = msg.ue_index;
  auto       res      = ue_db.emplace(ue_index,
                           std::make_unique<rrc_ue_impl>(rrc_ue_du_proc_notifier,
                                                         nas_notifier,
                                                         ngap_ctrl_notifier,
                                                         msg.ue_index,
                                                         msg.c_rnti,
                                                         msg.cell,
                                                         cfg.ue_default_cfg,
                                                         msg.srbs,
                                                         msg.du_to_cu_container,
                                                         *msg.ue_task_sched,
                                                         reject_users));

  if (res.second) {
    auto& u = ue_db.at(ue_index);
    return u.get();
  } else {
    return nullptr;
  }
}

void rrc_du_impl::remove_ue(ue_index_t ue_index)
{
  ue_db.erase(ue_index);
}

void rrc_du_impl::release_ues()
{
  // release all UEs connected to this RRC entity
}

bool rrc_du_impl::is_rrc_connect_allowed()
{
  return !reject_users;
}

void rrc_du_impl::handle_amf_connection()
{
  reject_users = false;
}

void rrc_du_impl::handle_amf_connection_drop()
{
  reject_users = true;
}