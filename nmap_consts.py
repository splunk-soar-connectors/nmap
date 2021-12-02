# File: nmap_consts.py
#
# Copyright (c) 2016-2021 Splunk Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software distributed under
# the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND,
# either express or implied. See the License for the specific language governing permissions
# and limitations under the License.
NMAP_JSON_IP_HOSTNAME = "ip_hostname"
NMAP_JSON_PORTLIST = "portlist"
NMAP_JSON_UDP = "udp_scan"
NMAP_JSON_SCRIPT = "script"
NMAP_JSON_SCRIPT_ARGS = "script_args"
NMAP_ERR_SCAN = "nmap scan failed"
NMAP_SUCC_SCAN = "nmap scan successful"
NMAP_ERR_SCAN_RETURNED_NO_DATA = "nmap scan did not return any information"
NMAP_ERR_SERVER_CONNECTION = "Connection to server failed"
NMAP_ERR_CONNECTIVITY_TEST = "Connectivity test failed"
NMAP_SUCC_CONNECTIVITY_TEST = "Connectivity test passed"
NMAP_DEFAULT_IP_CONNECTIVITY = "8.8.8.8"
NMAP_DEFAULT_PORTLIST_CONNECTIVITY = "80,443"
