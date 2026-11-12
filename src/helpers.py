# Copyright (c) 2026 Splunk Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""Shared validation and Nmap executable prerequisites."""

import re
from shutil import which


def is_valid_portlist(portlist: str) -> bool:
    if not re.fullmatch(r"\d+(?:-\d+)?(?:,\d+(?:-\d+)?)*", str(portlist)):
        return False
    for item in str(portlist).split(","):
        bounds = [int(part) for part in item.split("-")]
        if any(value < 1 or value > 65535 for value in bounds):
            return False
        if len(bounds) == 2 and bounds[0] > bounds[1]:
            return False
    return True


def get_nmap_binary() -> str:
    binary = which("nmap")
    if binary is None:
        raise RuntimeError(
            "Nmap executable was not found in the SOAR service user's PATH. "
            "Ask the host administrator to install Nmap (for example, sudo yum install nmap "
            "or sudo apt-get install nmap). See the app's installation prerequisites."
        )
    return binary
