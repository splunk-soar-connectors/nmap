# File: nmap_connector.py
#
# Copyright (c) 2016-2025 Splunk Inc.
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
#
#
# Phantom App imports
import ipaddress
import socket
import traceback

import nmapthon2
import phantom.app as phantom
import phantom.utils as ph_utils
import simplejson as json
from nmapthon2.exceptions import NmapScanError
from phantom.action_result import ActionResult
from phantom.base_connector import BaseConnector

from nmap_consts import *


# Define the App Class
class NmapConnector(BaseConnector):
    ACTION_ID_SCAN = "nmap_scan"
    ACTION_ID_TEST_ASSET_CONNECTIVITY = "test_asset_connectivity"

    def _handle_test_connectivity(self, param):
        self.save_progress(f"In action handler for: {self.get_action_identifier()}")
        try:
            # This call is specific to the nmap python module.  It is instantiating the scanner.
            nm = nmapthon2.NmapScanner()
        except Exception as e:
            self.save_progress(f"Unable to instantiate NmapScanner object. You might need to yum install nmap. Error: {e}")
            self.save_progress("Test Connectivity Failed")
            return self.set_status(phantom.APP_ERROR)

        try:
            self.save_progress(f"Scanning IP: {self._ip_address}, Ports: {self._portlist}")
            nm.scan([self._ip_address], ports=self._portlist)

            self.save_progress("Test Connectivity Passed")
        except Exception as e:
            try:
                self.save_progress(f"Scan Failed for the given configuration parameters. Error: {e}")
            except:
                self.save_progress("Scan Failed for the given configuration parameters. Error: Unable to get the error message.")
            self.save_progress("Test Connectivity Failed")
            return self.set_status(phantom.APP_ERROR)

        return self.set_status(phantom.APP_SUCCESS)

    def _handle_nmap_scan(self, param):
        self.debug_print("param", param)

        action_result = self.add_action_result(ActionResult(dict(param)))

        # This API call is retrieving the value associated with the ip field in the ACTION
        # configuration (the IP target for the scan) and storing it in the ip variable.
        ip_hostname = param[NMAP_JSON_IP_HOSTNAME]

        # PAPP-1802
        if ph_utils.is_url(ip_hostname):
            ip_hostname = ph_utils.get_host_from_url(ip_hostname)

        portlist = param.get(NMAP_JSON_PORTLIST)
        args = []

        if self._is_valid_ipv6_address(ip_hostname):
            args.append("-6")

        udp_flag = param.get(NMAP_JSON_UDP, False)

        if udp_flag:
            # Arguments needed for the workaround.  Since Phantom cannot be elevated to a root user,
            # (well it can, but it's just not safe), this takes advantage of a linux workaround
            # For this to work, the bash command in the docs must be run first
            args.append("-sU")
            args.append("--privileged")

        script = param.get(NMAP_JSON_SCRIPT)
        script_args = param.get(NMAP_JSON_SCRIPT_ARGS)
        if script:
            args.append(f"--script={script}")
            if script_args:
                args.append("--script-args")
                args.append(script_args)

        try:
            if udp_flag:
                # This call is specific to the nmap python module.  It is instantiating the scanner.
                nm = nmapthon2.NmapAsyncScanner()
            else:
                # This call is specific to the nmap python module.  It is instantiating the scanner.
                nm = nmapthon2.NmapScanner()
        except Exception as e:
            return action_result.set_status(phantom.APP_ERROR, "Unable to instantiate NmapScanner object. You might need to yum install nmap", e)

        # This call is actually executing the scan using the nmap pythong module and storing the
        # results in nmap_output
        nmap_output = {}
        try:
            result = nm.scan(targets=ip_hostname, ports=portlist, arguments=" ".join(args))
        except NmapScanError as scan_err:
            self.save_progress(f"Error: {traceback.format_exc()}")
            self.save_progress(f"Scan failed with error: {scan_err}")
            return action_result.set_status(phantom.APP_ERROR, "Scan failed", scan_err)
        except Exception as e:
            self.save_progress(f"Error: {traceback.format_exc()}")
            return action_result.set_status(phantom.APP_ERROR, "Scan failed", e)

        if udp_flag:
            nm.wait()

        if udp_flag and not nm.finished():
            return action_result.set_status(phantom.APP_ERROR, f"UDP scan failed: {nm.fatal_error()}")

        if udp_flag:
            result = nm.get_result()
        # parse results
        try:
            summary = {}
            summary["start_time"] = result.start_datetime.strftime("%H:%M:%S %d-%-m-%Y")
            summary["end_time"] = result.end_datetime.strftime("%H:%M:%S %d-%-m-%Y")
            summary["version"] = result.version
            summary["tolerant_errors"] = result.tolerant_errors
            summary["summary"] = result.summary
            summary["exit_status"] = result.exit_status
            action_result.update_summary(summary)
        except Exception as e:
            return action_result.set_status(phantom.APP_ERROR, f"Exception while retrieving results from NMAP scan: {e}")

        if summary["tolerant_errors"]:
            return action_result.set_status(phantom.APP_ERROR, "Error(s) occurred while scanning: {}".format(summary["tolerant_errors"]))

        try:
            nmap_output["hosts"] = []
            for scanned_host in result.scanned_hosts():
                host_output = {}
                # get ports information for tcp protocol
                host_output["tcp"] = {}
                scanned_tcp_ports = scanned_host.tcp_ports()
                host_output["tcp"]["ports"] = self._retrieve_ports_information(scanned_tcp_ports)

                # get ports information for udp protocol
                host_output["udp"] = {}
                scanned_udp_ports = scanned_host.udp_ports()
                host_output["udp"]["ports"] = self._retrieve_ports_information(scanned_udp_ports)

                # get script output for host
                if script:
                    host_output["scripts"] = []
                    for script_name, script_output in scanned_host.all_scripts():
                        host_output["scripts"].append({"name": script_name, "output": script_output})

                host_output["state"] = scanned_host.state
                host_output["reason"] = scanned_host.reason
                host_output["hostnames"] = [{"name": hostname} for hostname in scanned_host.hostnames()]
                # get ipv4 or ipv6 for host
                host_ipv4 = scanned_host.ipv4
                host_ipv6 = scanned_host.ipv6
                host_output["addrtype"] = "ipv4" if host_ipv4 else "ipv6"
                host_output["ip"] = host_ipv4 if host_ipv4 else host_ipv6
                nmap_output["hosts"].append(host_output)
        except NmapScanError as scan_err:
            return action_result.set_status(phantom.APP_ERROR, f"Error while scanning: {scan_err}")
        except Exception:
            return action_result.set_status(phantom.APP_ERROR, f"Exception occurred while parsing output: {traceback.format_exc()}")

        action_result.add_data(nmap_output)
        return action_result.set_status(phantom.APP_SUCCESS)

    def _retrieve_ports_information(self, ports):
        all_port_data = []
        for port in ports:
            port_data = {}
            port_data["port"] = port.number
            port_data["state"] = port.state
            port_data["reason"] = port.reason

            # get script output
            port_data["scripts"] = self._retrieve_port_script_output(port)

            # get service info
            service = port.get_service()

            if service is not None:
                port_data["service"] = {}
                port_data["service"]["name"] = service.name
                port_data["service"]["product"] = service.product

                # get CPEs
                cpe_str = ""
                for cpe in service.cpes:
                    cpe_str += cpe
                port_data["cpe"] = cpe_str

                port_data["service"]["scripts"] = []
                for name, output in service.all_scripts():
                    script_data = {}
                    script_data["name"] = name
                    script_data["output"] = output

                    port_data["service"]["scripts"].append(script_data)
            all_port_data.append(port_data)

        return all_port_data

    def _retrieve_port_script_output(self, port):
        scripts = []
        for script_name, script_output in port.service.all_scripts():
            scripts.append({"name": script_name, "output": script_output})

        return scripts

    def _is_valid_ipv6_address(self, address):
        try:
            socket.inet_pton(socket.AF_INET6, address)

        except OSError:  # not a valid v6 address
            return False

        return True

    def validate_ip(self, param):
        # TODO: Implement this to validate ip ranges etc.
        return True

    def initialize(self):
        """Don't use BaseConnector's validations, for ip use our own"""
        self.set_validator("ip", self.validate_ip)

        config = self.get_config()
        self._ip_address = config.get("ip_address", NMAP_DEFAULT_IP_CONNECTIVITY)
        self._portlist = config.get("ports", NMAP_DEFAULT_PORTLIST_CONNECTIVITY)

        try:
            ipaddress.ip_address(self._ip_address)
        except:
            return self.set_status(phantom.APP_ERROR, "Please provide a valid IP Address in the configuration parameters")

        return phantom.APP_SUCCESS

    def handle_action(self, param):
        ret_val = phantom.APP_SUCCESS

        # Get the action that we are supposed to execute for this App Run
        action_id = self.get_action_identifier()

        self.debug_print("action_id", self.get_action_identifier())

        # Check the action_id and align it with the correct function.
        if action_id == self.ACTION_ID_SCAN:
            ret_val = self._handle_nmap_scan(param)
        elif action_id == self.ACTION_ID_TEST_ASSET_CONNECTIVITY:
            ret_val = self._handle_test_connectivity(param)

        return ret_val


if __name__ == "__main__":
    import sys

    import pudb

    pudb.set_trace()

    if len(sys.argv) < 2:
        print("No test json specified as input")
        sys.exit(0)

    with open(sys.argv[1]) as f:
        in_json = f.read()
        in_json = json.loads(in_json)
        print(json.dumps(in_json, indent=4))

        connector = NmapConnector()
        connector.print_progress_message = True
        ret_val = connector._handle_action(json.dumps(in_json), None)
        print(ret_val)

    sys.exit(0)
