# NMAP Scanner

Publisher: Splunk <br>
Connector Version: 3.0.13 <br>
Product Vendor: Generic <br>
Product Name: NMAP <br>
Minimum Product Version: 5.2.0

This app integrates with NMAP in order to provide detailed network information

### Configuration variables

This table lists the configuration variables required to operate NMAP Scanner. These variables are specified when configuring a NMAP asset in Splunk SOAR.

VARIABLE | REQUIRED | TYPE | DESCRIPTION
-------- | -------- | ---- | -----------
**ip_address** | optional | string | IP Address for testing connectivity (default: 8.8.8.8) |
**ports** | optional | string | Ports e.g. 22,80,443,1000-1024 (default: 80,443) |

### Supported Actions

[test connectivity](#action-test-connectivity) - Validate the asset configuration for connectivity. This action runs nmap on the IP mentioned in the configuration parameters <br>
[scan network](#action-scan-network) - Execute NMAP scan against a host or subnet

## action: 'test connectivity'

Validate the asset configuration for connectivity. This action runs nmap on the IP mentioned in the configuration parameters

Type: **test** <br>
Read only: **True**

#### Action Parameters

No parameters are required for this action

#### Action Output

No Output

## action: 'scan network'

Execute NMAP scan against a host or subnet

Type: **investigate** <br>
Read only: **True**

<p>If <b>udp_scan</b> is false (it is by default), this action will use the following NMAP command line options: nmap -oX - -sV IP_ADDRESS.</p><p>If <b>udp_scan</b> is true, this action will use the following NMAP command line options: nmap -oX - -sU --privileged IP_ADDRESS.</p><p>Performing a UDP scan requires elevated permissions.  Privileged permissions can be used, if and only if the user first runs this command as root on Phantom:<br><code>sudo setcap cap_net_raw,cap_net_admin,cap_net_bind_service+eip /usr/bin/nmap</code></p><p><b>Warning:</b> UDP function is limited to root for very good reason.  This is dangerous. The NMAP Scripting Engine (NSE) allows scripts to sniff the network, change firewall rules and interface configuration, or exploit vulnerabilities including on localhost. It's possible, especially with elevated capabilities, for a clever person to use NMAP and NSE to escalate to full root privileges. If you do not understand these risks, do not do this.</p><p>To undo the setcap command from before, just run:<br><code>sudo setcap cap_net_raw,cap_net_admin,cap_net_bind_service-eip /usr/bin/nmap</code><br><p>action_result.data.\*.udp.\* data paths will only be present if <b>udp_scan</b> is true.  They replace action_result.data.\*.tcp.\* data paths.</p>

#### Action Parameters

PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**ip_hostname** | required | IP address/hostname (CIDR notation supported) | string | `ip` `host name` `url` |
**portlist** | optional | Portlist e.g. 22,80,443,1000-1024 | string | |
**udp_scan** | optional | UDP Scan | boolean | |
**script** | optional | NSE Script | string | |
**script_args** | optional | Script parameters | string | |

#### Action Output

DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.data.\*.hosts.\*.udp.ports.\*.port | string | `port` | |
action_result.data.\*.hosts.\*.udp.ports.\*.state | string | | |
action_result.data.\*.hosts.\*.udp.ports.\*.reason | string | | |
action_result.data.\*.hosts.\*.udp.ports.\*.service.name | string | | |
action_result.data.\*.hosts.\*.udp.ports.\*.service.product | string | | |
action_result.data.\*.hosts.\*.udp.ports.\*.cpe | string | | |
action_result.data.\*.hosts.\*.udp.ports.\*.scripts.\*.name | string | | |
action_result.data.\*.hosts.\*.udp.ports.\*.scripts.\*.output | string | | |
action_result.data.\*.hosts.\*.tcp.ports.\*.port | string | `port` | 80 |
action_result.data.\*.hosts.\*.tcp.ports.\*.state | string | | open |
action_result.data.\*.hosts.\*.tcp.ports.\*.reason | string | | syn-ack |
action_result.data.\*.hosts.\*.tcp.ports.\*.service.name | string | `url` | http |
action_result.data.\*.hosts.\*.tcp.ports.\*.service.product | string | | |
action_result.data.\*.hosts.\*.tcp.ports.\*.cpe | string | | |
action_result.data.\*.hosts.\*.tcp.ports.\*.scripts.\*.name | string | | |
action_result.data.\*.hosts.\*.tcp.ports.\*.scripts.\*.output | string | | |
action_result.data.\*.hosts.\*.ip | string | `ip` | 52.7.97.246 |
action_result.data.\*.hosts.\*.addrtype | string | | ipv4 ipv6 |
action_result.data.\*.hosts.\*.scripts.\*.name | string | | dns-brute |
action_result.data.\*.hosts.\*.scripts.\*.output | string | | DNS Brute-force hostnames www.phantom.us - 52.7.97.246 |
action_result.data.\*.hosts.\*.state | string | | up |
action_result.data.\*.hosts.\*.reason | string | | syn-ack |
action_result.data.\*.hosts.\*.hostnames.\*.name | string | `host name` | phantom.us |
action_result.status | string | | success failed |
action_result.message | string | | Start time: 21:44:25 10-8-2021, End time: 21:45:56 10-8-2021, Version: 1.04, Tolerant errors: None, Summary: Nmap done at Tue Aug 10 21:45:56 2021; 1 IP address (1 host up) scanned in 91.14 seconds, Exit status: success |
action_result.summary.start_time | string | | 21:44:25 10-8-2021 |
action_result.summary.end_time | string | | 21:45:56 10-8-2021 |
action_result.summary.version | string | | 1.04 |
action_result.summary.tolerant_errors | string | | |
action_result.summary.summary | string | | Nmap done at Tue Aug 10 21:45:56 2021; 1 IP address (1 host up) scanned in 91.14 seconds |
action_result.summary.exit_status | string | | success |
action_result.parameter.portlist | string | | 1-1024 |
action_result.parameter.ip_hostname | string | `ip` `host name` `url` | phantom.us |
action_result.parameter.udp_scan | boolean | | False |
action_result.parameter.script | string | | dns-brute.nse |
action_result.parameter.script_args | string | | |
summary.total_objects | numeric | | 1 |
summary.total_objects_successful | numeric | | 1 |

______________________________________________________________________

Auto-generated Splunk SOAR Connector documentation.

Copyright 2025 Splunk Inc.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing,
software distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and limitations under the License.
