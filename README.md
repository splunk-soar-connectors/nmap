# NMAP Scanner

Publisher: Splunk <br>
Connector Version: 3.0.17 <br>
Product Vendor: Generic <br>
Product Name: NMAP <br>
Minimum Product Version: 7.0.0

This app integrates with NMAP in order to provide detailed network information

### Configuration variables

This table lists the configuration variables required to operate NMAP Scanner. These variables are specified when configuring a NMAP asset in Splunk SOAR.

VARIABLE | REQUIRED | TYPE | DESCRIPTION
-------- | -------- | ---- | -----------
**ip_address** | optional | string | IP Address for testing connectivity (default: 8.8.8.8) |
**ports** | optional | string | Ports e.g. 22,80,443,1000-1024 (default: 80,443) |

### Supported Actions

[test connectivity](#action-test-connectivity) - test connectivity <br>
[scan network](#action-scan-network) - Execute NMAP scan against a host or subnet

## action: 'test connectivity'

test connectivity

Type: **test** <br>
Read only: **True**

Basic test for app.

#### Action Parameters

No parameters are required for this action

#### Action Output

DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string | | success failure |
action_result.message | string | | |
summary.total_objects | numeric | | 1 |
summary.total_objects_successful | numeric | | 1 |

## action: 'scan network'

Execute NMAP scan against a host or subnet

Type: **investigate** <br>
Read only: **False**

Scan a host or subnet with NMAP and return host, port, and service details.

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
action_result.status | string | | success failure |
action_result.message | string | | |
action_result.parameter.ip_hostname | string | `ip` `host name` `url` | |
action_result.parameter.portlist | string | | |
action_result.parameter.udp_scan | boolean | | |
action_result.parameter.script | string | | |
action_result.parameter.script_args | string | | |
action_result.data.\*.ip_hostname | string | `ip` `host name` `url` | |
action_result.data.\*.hosts.\*.udp.ports.\*.port | numeric | `port` | 80 |
action_result.data.\*.hosts.\*.udp.ports.\*.state | string | | open |
action_result.data.\*.hosts.\*.udp.ports.\*.reason | string | | syn-ack |
action_result.data.\*.hosts.\*.udp.ports.\*.service.name | string | `url` | http |
action_result.data.\*.hosts.\*.udp.ports.\*.service.product | string | | |
action_result.data.\*.hosts.\*.udp.ports.\*.service.scripts.\*.name | string | | dns-brute |
action_result.data.\*.hosts.\*.udp.ports.\*.service.scripts.\*.output | string | | DNS Brute-force hostnames www.phantom.us - 52.7.97.246 |
action_result.data.\*.hosts.\*.udp.ports.\*.cpe | string | | |
action_result.data.\*.hosts.\*.udp.ports.\*.scripts.\*.name | string | | dns-brute |
action_result.data.\*.hosts.\*.udp.ports.\*.scripts.\*.output | string | | DNS Brute-force hostnames www.phantom.us - 52.7.97.246 |
action_result.data.\*.hosts.\*.tcp.ports.\*.port | numeric | `port` | 80 |
action_result.data.\*.hosts.\*.tcp.ports.\*.state | string | | open |
action_result.data.\*.hosts.\*.tcp.ports.\*.reason | string | | syn-ack |
action_result.data.\*.hosts.\*.tcp.ports.\*.service.name | string | `url` | http |
action_result.data.\*.hosts.\*.tcp.ports.\*.service.product | string | | |
action_result.data.\*.hosts.\*.tcp.ports.\*.service.scripts.\*.name | string | | dns-brute |
action_result.data.\*.hosts.\*.tcp.ports.\*.service.scripts.\*.output | string | | DNS Brute-force hostnames www.phantom.us - 52.7.97.246 |
action_result.data.\*.hosts.\*.tcp.ports.\*.cpe | string | | |
action_result.data.\*.hosts.\*.tcp.ports.\*.scripts.\*.name | string | | dns-brute |
action_result.data.\*.hosts.\*.tcp.ports.\*.scripts.\*.output | string | | DNS Brute-force hostnames www.phantom.us - 52.7.97.246 |
action_result.data.\*.hosts.\*.ip | string | `ip` | 52.7.97.246 |
action_result.data.\*.hosts.\*.addrtype | string | | ipv4 ipv6 |
action_result.data.\*.hosts.\*.scripts.\*.name | string | | dns-brute |
action_result.data.\*.hosts.\*.scripts.\*.output | string | | DNS Brute-force hostnames www.phantom.us - 52.7.97.246 |
action_result.data.\*.hosts.\*.state | string | | up |
action_result.data.\*.hosts.\*.reason | string | | syn-ack |
action_result.data.\*.hosts.\*.hostnames.\*.name | string | `host name` | phantom.us |
summary.total_objects | numeric | | 1 |
summary.total_objects_successful | numeric | | 1 |

______________________________________________________________________

Auto-generated Splunk SOAR Connector documentation.

Copyright 2026 Splunk Inc.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing,
software distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and limitations under the License.
