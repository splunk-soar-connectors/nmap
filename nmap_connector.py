# --
# File: nmap_connector.py
# Copyright (c) 2016-2021 Splunk Inc.
#
# SPLUNK CONFIDENTIAL - Use or disclosure of this material in whole or in part
# without a valid written license from Splunk Inc. is PROHIBITED.
#
# --

# Phantom App imports
import phantom.app as phantom

from phantom.base_connector import BaseConnector
from phantom.action_result import ActionResult
from nmap_consts import *
import phantom.utils as ph_utils

# Imports local to this App

# import simplejson as json
import simplejson as json
import nmap
import socket


# Define the App Class
class NmapConnector(BaseConnector):

    ACTION_ID_SCAN = "nmap_scan"

    def _handle_nmap_scan(self, param):

        # self.get_config() is retrieving the configuration for the asset associated with this action.
        # The configuration is stored wtihin the Phantom platform via the base connector, and is
        # therefore accessed through the BaseConnector class function get_config()
        # config = self.get_config()

        # Debug command that is printing the parameters associated with the specific action being
        # executed by the platform.  These parameters are the inputs to the action from the user or
        # playbook (e.g. the IP address of fileHash used for an investigation)
        self.debug_print("param", param)

        # Instantiation of the data structure holding the results for the specific action being run.
        # The parameters to the ActionResult are used as the key to uniquly identify the App Run.  Note
        # that multiple parameters provided to an action result in the app being executed multiple
        # times (multiple App Runs).  The paramter used for the action execution instance is used to
        # as the key to uniquely identify the App Run.
        action_result = ActionResult(dict(param))

        # This API call is retrieving the value associated with the ip field in the ACTION
        # configuration (the IP target for the scan) and storing it in the ip variable.
        ip_hostname = param[NMAP_JSON_IP_HOSTNAME]

        # PAPP-1802
        if (ph_utils.is_url(ip_hostname)):
            ip_hostname = ph_utils.get_host_from_url(ip_hostname)

        is_hostname = False
        if (ph_utils.is_hostname(ip_hostname)):
            is_hostname = True

        portlist = param.get(NMAP_JSON_PORTLIST)
        args = []

        if self._is_valid_ipv6_address(ip_hostname):
            args.append('-6')

        udp_flag = param.get(NMAP_JSON_UDP, False)

        if udp_flag:
            # Arguments needed for the workaround.  Since Phantom cannot be elevated to a root user,
            # (well it can, but it's just not safe), this takes advantage of a linux workaround
            # For this to work, the bash command in the docs must be run first
            args.append('--privileged -sU')

        script = param.get(NMAP_JSON_SCRIPT)
        script_args = param.get(NMAP_JSON_SCRIPT_ARGS)
        if script:
            args.append('--script={}'.format(script))
            if script_args:
                args.append('--script-args {}'.format(script_args))

        # This call sends a progress message to the Phantom platform where it is saved in
        # persistent storage
        self.save_progress("Running nmap")

        try:
            # This call is specific to the nmap python module.  It is instantiating the scanner.
            nm = nmap.PortScanner()
        except Exception as e:
            self.add_action_result(action_result)
            return action_result.set_status(phantom.APP_ERROR,
                    'Unable to instantiate PortScanner object. You might need to yum install nmap', e)

        # This call is actually executing the scan using the nmap pythong module and storing the
        # results in nmap_output
        nmap_output = {}
        try:
            nmap_output = nm.scan(ip_hostname, portlist, arguments=' '.join(args))
        except Exception as e:
            self.add_action_result(action_result)
            return action_result.set_status(phantom.APP_ERROR, 'Scan failed', e)

        # convert the nmap output to json format
        try:
            nmap_output = json.loads(json.dumps(nmap_output))
        except Exception as e:
            self.add_action_result(action_result)
            return action_result.set_status(phantom.APP_ERROR, 'Unable to parse nmap output', e)

        nmap_scan = nmap_output.get('scan')
        nmap_output = nmap_output.get('nmap')
        scanstats = nm.scanstats()

        if (scanstats['uphosts'] == '0'):
            self.add_action_result(action_result)
            return action_result.set_status(phantom.APP_SUCCESS, "No hosts were detected in scan")

        if (not nmap_output):
            self.add_action_result(action_result)
            return action_result.set_status(phantom.APP_ERROR, "Output does not contain 'nmap' key")

        # Get the scaninfo
        scaninfo = nmap_output.get('scaninfo')

        if (not scaninfo):
            self.add_action_result(action_result)
            return action_result.set_status(phantom.APP_ERROR, 'Nmap output does not contain scaninfo')

        error = scaninfo.get('error', '')

        if (error):
            self.add_action_result(action_result)
            return action_result.set_status(phantom.APP_ERROR,
                    'Nmap command failed, ERROR: {0}'.format(error))

        # now parse through the scan results and create/add action results
        for k, v in nmap_scan.items():
            curr_param = {NMAP_JSON_IP_HOSTNAME: k}
            if (portlist):
                curr_param.update({NMAP_JSON_PORTLIST: portlist})
            if (udp_flag):
                curr_param.update({"udp_scan": udp_flag})

            action_result = self.add_action_result(ActionResult(curr_param))
            self._process_scan_result(v)
            add_data = action_result.add_data(v)
            action_result.set_status(phantom.APP_SUCCESS)
            if 'udp' in v:
                length = len(v.get('udp'))
            elif 'tcp' in v:
                length = len(v.get('tcp'))
            else:
                length = 0
            scan_type = 'tcp' if len(v.get('tcp', [])) > 0 else 'udp'
            length_key = 'total_open_{0}_ports'.format(scan_type)
            summary = {
                    'endpoint_state': v.get('status', {}).get('state', 'unknown'),
                    length_key: length
                      }
            action_result.set_summary(summary)
            # modify the ipv4 key from the result if present
            ipv4s = add_data.get('addresses', {}).get('ipv4')
            if (not ipv4s):
                continue

            if (type(ipv4s) != list):
                ipv4s = [ipv4s]

            for i, ipv4 in enumerate(ipv4s):
                ipv4s[i] = {'ip': ipv4}

        if (is_hostname):
            # Have to set the parameter to the hostname
            act_results = self.get_action_results()

            if (act_results and len(act_results) == 1):
                act_res = act_results[0]
                act_res.update_param({NMAP_JSON_IP_HOSTNAME: ip_hostname})

        return phantom.APP_SUCCESS

    def _normalize_children_into_list(self, input_dict):

        if (not input_dict):
            return {}

        for key in list(input_dict.keys()):
            if (type(input_dict[key]) != list):
                input_dict[key] = [input_dict[key]]
            input_dict[key.lower()] = input_dict.pop(key)

        return input_dict

    def _normalize_into_list(self, input_dict, key):

        if (not input_dict):
            return None

        if (key not in input_dict):
            return None

        if (type(input_dict[key]) != list):
            input_dict[key] = [input_dict[key]]
        input_dict[key.lower()] = input_dict.pop(key)

        return input_dict

    def _move_port_into_dict(self, input_dict, key):

        # convert tcp['80'] = {'product', 'Apache'} to tcp[N] = {'port': 80, 'product': 'Apache'}
        # it makes displaying it in the view easier

        value_dict = input_dict.get(key)
        if (not value_dict):
            return

        mod_list = []
        for k, v in value_dict.items():
            v['port'] = k
            mod_list.append(v)
        input_dict[key] = mod_list

        return phantom.APP_SUCCESS

    def _process_scan_result(self, scan_result):
        """Cleans up the result for the sake of everybody involved"""

        scan_result['addresses'] = self._normalize_children_into_list(scan_result.get('addresses'))
        self._normalize_into_list(scan_result, 'hostnames')
        if ('tcp' in scan_result):
            self._move_port_into_dict(scan_result, 'tcp')
        elif ('udp' in scan_result):
            self._move_port_into_dict(scan_result, 'udp')

        if 'hostscript' in scan_result:
            for i in scan_result['hostscript']:
                if 'output' in i:
                    i['output'] = [a.strip() for a in i['output'].split('\n') if a.strip()]

        return phantom.APP_SUCCESS

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
        return phantom.APP_SUCCESS

    def handle_action(self, param):

        ret_val = phantom.APP_SUCCESS

        # Get the action that we are supposed to execute for this App Run
        action_id = self.get_action_identifier()

        self.debug_print("action_id", self.get_action_identifier())

        # Check the action_id and align it with the correct function.
        if (action_id == self.ACTION_ID_SCAN):
            ret_val = self._handle_nmap_scan(param)

        return ret_val


if __name__ == '__main__':

    import sys
    import pudb
    pudb.set_trace()

    if (len(sys.argv) < 2):
        print("No test json specified as input")
        exit(0)

    with open(sys.argv[1]) as f:
        in_json = f.read()
        in_json = json.loads(in_json)
        print(json.dumps(in_json, indent=4))

        connector = NmapConnector()
        connector.print_progress_message = True
        ret_val = connector._handle_action(json.dumps(in_json), None)
        print(ret_val)

    exit(0)
