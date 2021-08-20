# File: nmap_consts.py
# Copyright (c) 2016-2021 Splunk Inc.
#
# SPLUNK CONFIDENTIAL - Use or disclosure of this material in whole or in part
# without a valid written license from Splunk Inc. is PROHIBITED.

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
