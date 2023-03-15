#
# Copyright 2013-2023 Software Radio Systems Limited
#
# By using this file, you agree to the terms and conditions set
# forth in the LICENSE file which can be found at the top level of
# the distribution.
#

import logging
import os
from collections import defaultdict
from contextlib import contextmanager, suppress
from pprint import pformat

import grpc
from pytest_html import extras
from retina.launcher.utils import get_retina_force_report
from retina.protocol.base_pb2 import Empty

ATTACH_TIMEOUT = 120
STARTUP_TIMEOUT = 120
DEFAULT_MCS = 10


@contextmanager
def get_ue_gnb_epc(self, extra, band, common_scs, bandwidth, mcs, ue_count):
    """
    Get test elements
    """
    test_successful = True
    try:
        test_config = {
            "ue": {
                "parameters": {
                    "band": band,
                    "dl_arfcn": get_dl_arfcn(band),
                    "ssb_arfcn": get_ssb_arfcn(band, bandwidth),
                    "common_scs": common_scs,
                    "ssb_scs": common_scs,
                    "bandwidth": bandwidth,
                    "log_level": get_loglevel(),
                    "ue_count": ue_count,
                }
            },
            "gnb": {
                "parameters": {
                    "band": band,
                    "dl_arfcn": get_dl_arfcn(band),
                    "common_scs": common_scs,
                    "bandwidth": bandwidth,
                    "mcs": mcs,
                    "log_level": get_loglevel(),
                    "pcap": get_pcap(),
                }
            },
        }
        logging.info("Test config: \n%s", pformat(test_config))
        self.test_config = test_config
        self.retina_manager.parse_configuration(test_config)

        # Get clients
        ue = self.retina_manager.get_ue()
        gnb = self.retina_manager.get_gnb()
        epc = self.retina_manager.get_epc()

        yield ue, gnb, epc

    except Exception as err:
        test_successful = False
        raise err from None

    finally:
        teardown_ok = True

        with suppress(NameError, grpc._channel._InactiveRpcError):
            return_code = gnb.Stop(Empty()).value
            if return_code < 0:
                teardown_ok = False
                logging.error("GNB crashed with exit code %s", return_code)
            elif return_code > 0:
                if get_fail_if_internal_errors():
                    teardown_ok = False
                logging.error("GNB has %d errors or warnings", return_code)
        with suppress(NameError, grpc._channel._InactiveRpcError):
            epc.Stop(Empty()).value
        with suppress(NameError, grpc._channel._InactiveRpcError):
            return_code = ue.Stop(Empty()).value
            teardown_ok &= return_code == 0
            if return_code < 0:
                teardown_ok = False
                logging.error("UE crashed with exit code %s", return_code)
            elif return_code > 0:
                if get_fail_if_internal_errors():
                    teardown_ok = False
                logging.error("UE has %d errors or warnings", return_code)
        if teardown_ok is False:
            test_successful = False

        if test_successful:
            self.disable_download_report()
        if test_successful is False or get_retina_force_report():
            with suppress(UnboundLocalError, NameError):
                extra.append(extras.url(self.relative_output_html_path, name="[[ Go to logs and configs ]]"))
        assert teardown_ok is True


def get_dl_arfcn(band):
    """
    Get dl arfcn
    """
    return {3: 368500, 7: 536020, 41: 520002}[band]


def get_ssb_arfcn(band, bandwidth):
    """
    Get SSB arfcn
    """
    return {
        3: defaultdict(
            lambda: 368410,
            {
                30: 367450,
                40: 366490,
                50: 365530,
            },
        ),
        7: defaultdict(
            lambda: 535930,
            {
                30: 534970,
                40: 534010,
                50: 533050,
            },
        ),
        41: defaultdict(
            lambda: 519870,
            {
                20: 520110,
                30: 518910,
                40: 517950,
                50: 517230,
            },
        ),
    }[band][bandwidth]


def get_loglevel():
    """
    Get retina loglevel
    """
    try:
        return os.environ["RETINA_LOGLEVEL"]
    except KeyError:
        return "info"


def get_pcap():
    """
    Return True / False
    """
    try:
        return bool(os.environ["RETINA_PCAP_ENABLE"])
    except KeyError:
        return False


def get_fail_if_internal_errors():
    """
    Return True / False
    """
    try:
        return bool(os.environ["RETINA_FAIL_IF_INTERNAL_ERRORS"])
    except KeyError:
        return True
