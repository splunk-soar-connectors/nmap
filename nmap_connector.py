# File: nmap_connector.py
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
#
#
# Phantom App imports
import phantom.app as phantom

from phantom.base_connector import BaseConnector
from phantom.action_result import ActionResult
import phantom.utils as ph_utils

from nmap_consts import *

import simplejson as json
import nmapthon
from nmapthon.exceptions import NmapScanError
import traceback

import socket
import ipaddress


# Define the App Class
class NmapConnector(BaseConnector):

    ACTION_ID_SCAN = "nmap_scan"
    ACTION_ID_TEST_ASSET_CONNECTIVITY = "test_asset_connectivity"

    def _handle_test_connectivity(self, param):
        self.save_progress('In action handler for: {0}'.format(self.get_action_identifier()))
        try:
            # This call is specific to the nmap python module.  It is instantiating the scanner.
            nm = nmapthon.NmapScanner([self._ip_address], ports=self._portlist)
        except Exception as e:
            self.save_progress('Unable to instantiate NmapScanner object. You might need to yum install nmap. Error: {}'.format(e))
            self.save_progress("Test Connectivity Failed")
            return self.set_status(phantom.APP_ERROR)

        try:
            self.save_progress("Scanning IP: {}, Ports: {}".format(self._ip_address, self._portlist))
            nm.run()

            self.save_progress("Test Connectivity Passed")
        except Exception as e:
            try:
                self.save_progress("Scan Failed for the given configuration parameters. Error: {}".format(e))
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
        if (ph_utils.is_url(ip_hostname)):
            ip_hostname = ph_utils.get_host_from_url(ip_hostname)

        portlist = param.get(NMAP_JSON_PORTLIST)
        args = []

        if self._is_valid_ipv6_address(ip_hostname):
            args.append('-6')

        udp_flag = param.get(NMAP_JSON_UDP, False)

        if udp_flag:
            # Arguments needed for the workaround.  Since Phantom cannot be elevated to a root user,
            # (well it can, but it's just not safe), this takes advantage of a linux workaround
            # For this to work, the bash command in the docs must be run first
            args.append('-sU')
            args.append('--privileged')

        script = param.get(NMAP_JSON_SCRIPT)
        script_args = param.get(NMAP_JSON_SCRIPT_ARGS)
        if script:
            args.append('--script={}'.format(script))
            if script_args:
                args.append('--script-args')
                args.append(script_args)

        try:
            if udp_flag:
                # This call is specific to the nmap python module.  It is instantiating the scanner.
                nm = nmapthon.AsyncNmapScanner(target=ip_hostname, ports=portlist, arguments=args)
            else:
                # This call is specific to the nmap python module.  It is instantiating the scanner.
                nm = nmapthon.NmapScanner(targets=ip_hostname, ports=portlist, arguments=args)
        except Exception as e:
            return action_result.set_status(phantom.APP_ERROR,
                    'Unable to instantiate NmapScanner object. You might need to yum install nmap', e)

        # This call is actually executing the scan using the nmap pythong module and storing the
        # results in nmap_output
        nmap_output = {}
        try:
            nm.run()
        except NmapScanError as scan_err:
            self.save_progress("Error: {}".format(traceback.format_exc()))
            self.save_progress("Scan failed with error: {}".format(scan_err))
            return action_result.set_status(phantom.APP_ERROR, 'Scan failed', scan_err)
        except Exception as e:
            self.save_progress("Error: {}".format(traceback.format_exc()))
            return action_result.set_status(phantom.APP_ERROR, 'Scan failed', e)

        if udp_flag:
            nm.wait()

        if udp_flag and not nm.finished_successfully():
            return action_result.set_status(phantom.APP_ERROR, "UDP scan failed: {}".format(nm.fatal_error()))

        # parse results
        try:
            summary = {}
            summary['start_time'] = nm.start_time
            summary['end_time'] = nm.end_time
            summary['version'] = nm.version
            summary['tolerant_errors'] = nm.tolerant_errors
            summary['summary'] = nm.summary
            summary['exit_status'] = nm.exit_status
            action_result.update_summary(summary)
        except Exception as e:
            return action_result.set_status(phantom.APP_ERROR, "Exception while retrieving results from NMAP scan: {}".format(e))

        if summary['tolerant_errors']:
            return action_result.set_status(phantom.APP_ERROR, "Error(s) occurred while scanning: {}".format(summary['tolerant_errors']))

        try:
            nmap_output['hosts'] = []
            for scanned_host in nm.scanned_hosts():
                host_output = {}
                # for every protocol scanned for each host
                for proto in nm.all_protocols(scanned_host):
                    host_output[proto] = {}
                    # for each scanned port
                    host_output[proto]["ports"] = []
                    for port in nm.scanned_ports(scanned_host, proto):
                        port_data = {}
                        port_data['port'] = port

                        state, reason = nm.port_state(scanned_host, proto, port)
                        port_data['state'] = state
                        port_data['reason'] = reason

                        # get script output
                        port_data['scripts'] = self._retrieve_port_script_output(nm, scanned_host, proto, port)

                        # get service info
                        service = nm.service(scanned_host, proto, port)

                        if service is not None:
                            port_data['service'] = {}
                            port_data['service']['name'] = service.name
                            port_data['service']['product'] = service.product

                            # get CPEs
                            cpe_str = ""
                            for cpe in service.all_cpes():
                                cpe_str += cpe
                            port_data['cpe'] = cpe_str

                            port_data['service']['scripts'] = []
                            for name, output in service.all_scripts():
                                script_data = {}
                                script_data['name'] = name
                                script_data['output'] = output

                                port_data['service']['scripts'].append(script_data)

                        host_output[proto]["ports"].append(port_data)

                # get script output for host
                if script:
                    host_output['scripts'] = []
                    for script_name, script_output in nm.host_scripts(scanned_host):
                        host_output['scripts'].append({
                            'name': script_name,
                            'output': script_output
                        })

                host_output['state'] = nm.state(scanned_host)
                host_output['reason'] = nm.reason(scanned_host)
                host_output['addrtype'] = nm.addrtype(scanned_host)
                host_output['hostnames'] = [
                    {'name': hostname} for hostname in nm.hostnames(scanned_host)
                ]
                host_output['ip'] = scanned_host
                nmap_output['hosts'].append(host_output)
        except NmapScanError as scan_err:
            return action_result.set_status(phantom.APP_ERROR, "Error while scanning: {}".format(scan_err))
        except Exception:
            return action_result.set_status(phantom.APP_ERROR, "Exception occurred while parsing output: {}".format(traceback.format_exc()))

        action_result.add_data(nmap_output)
        return action_result.set_status(phantom.APP_SUCCESS)

    def _retrieve_port_script_output(self, nm, host, proto, port):
        scripts = []
        for script_name, script_output in nm.port_scripts(host, proto, port):
            scripts.append({
                'name': script_name,
                'output': script_output
            })

        return scripts

    def _is_valid_ipv6_address(self, address):

        try:
            socket.inet_pton(socket.AF_INET6, address)

        except socket.error:  # not a valid v6 address
            return False

        return True

    def validate_ip(self, param):
        # TODO: Implement this to validate ip ranges etc.
        return True

    def initialize(self):
        """Don't use BaseConnector's validations, for ip use our own
        """
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
        if (action_id == self.ACTION_ID_SCAN):
            ret_val = self._handle_nmap_scan(param)
        elif (action_id == self.ACTION_ID_TEST_ASSET_CONNECTIVITY):
            ret_val = self._handle_test_connectivity(param)

        return ret_val


if __name__ == '__main__':

    import sys
    import pudb
    pudb.set_trace()

    if (len(sys.argv) < 2):
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
