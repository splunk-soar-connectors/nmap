[comment]: # "Auto-generated SOAR connector documentation"
# NMAP Scanner

Publisher: Splunk  
Connector Version: 3\.0\.11  
Product Vendor: Generic  
Product Name: NMAP  
Product Version Supported (regex): "\.\*"  
Minimum Product Version: 5\.1\.0  

This app integrates with NMAP in order to provide detailed network information

[comment]: # "File: README.md"
[comment]: # "Copyright (c) 2016-2022 Splunk Inc."
[comment]: # ""
[comment]: # "Licensed under the Apache License, Version 2.0 (the 'License');"
[comment]: # "you may not use this file except in compliance with the License."
[comment]: # "You may obtain a copy of the License at"
[comment]: # ""
[comment]: # "    http://www.apache.org/licenses/LICENSE-2.0"
[comment]: # ""
[comment]: # "Unless required by applicable law or agreed to in writing, software distributed under"
[comment]: # "the License is distributed on an 'AS IS' BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND,"
[comment]: # "either express or implied. See the License for the specific language governing permissions"
[comment]: # "and limitations under the License."
[comment]: # ""
Currently the app does not support OS Fingerprinting.

Below are the ports used by NMAP.

|         Service Name | Port | Transport Protocol |
|----------------------|------|--------------------|
|          **NMAP**    | 689  | tcp                |
|          **NMAP**    | 689  | udp                |


### Configuration Variables
The below configuration variables are required for this Connector to operate.  These variables are specified when configuring a NMAP asset in SOAR.

VARIABLE | REQUIRED | TYPE | DESCRIPTION
-------- | -------- | ---- | -----------
**ip\_address** |  optional  | string | IP Address for testing connectivity \(default\: 8\.8\.8\.8\)
**ports** |  optional  | string | Ports e\.g\. 22,80,443,1000\-1024 \(default\: 80,443\)

### Supported Actions  
[test connectivity](#action-test-connectivity) - Validate the asset configuration for connectivity\. This action runs nmap on the IP mentioned in the configuration parameters  
[scan network](#action-scan-network) - Execute NMAP scan against a host or subnet  

## action: 'test connectivity'
Validate the asset configuration for connectivity\. This action runs nmap on the IP mentioned in the configuration parameters

Type: **test**  
Read only: **True**

#### Action Parameters
No parameters are required for this action

#### Action Output
No Output  

## action: 'scan network'
Execute NMAP scan against a host or subnet

Type: **investigate**  
Read only: **True**

<p>If <b>udp\_scan</b> is false \(it is by default\), this action will use the following NMAP command line options\: nmap \-oX \- \-sV IP\_ADDRESS\.</p><p>If <b>udp\_scan</b> is true, this action will use the following NMAP command line options\: nmap \-oX \- \-sU \-\-privileged IP\_ADDRESS\.</p><p>Performing a UDP scan requires elevated permissions\.  Privileged permissions can be used, if and only if the user first runs this command as root on Phantom\:<br><code>sudo setcap cap\_net\_raw,cap\_net\_admin,cap\_net\_bind\_service\+eip /usr/bin/nmap</code></p><p><b>Warning\:</b> UDP function is limited to root for very good reason\.  This is dangerous\. The NMAP Scripting Engine \(NSE\) allows scripts to sniff the network, change firewall rules and interface configuration, or exploit vulnerabilities including on localhost\. It's possible, especially with elevated capabilities, for a clever person to use NMAP and NSE to escalate to full root privileges\. If you do not understand these risks, do not do this\.</p><p>To undo the setcap command from before, just run\:<br><code>sudo setcap cap\_net\_raw,cap\_net\_admin,cap\_net\_bind\_service\-eip /usr/bin/nmap</code><br><p>action\_result\.data\.\*\.udp\.\* data paths will only be present if <b>udp\_scan</b> is true\.  They replace action\_result\.data\.\*\.tcp\.\* data paths\.</p>

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**ip\_hostname** |  required  | IP address/hostname \(CIDR notation supported\) | string |  `ip`  `host name`  `url` 
**portlist** |  optional  | Portlist e\.g\. 22,80,443,1000\-1024 | string | 
**udp\_scan** |  optional  | UDP Scan | boolean | 
**script** |  optional  | NSE Script | string | 
**script\_args** |  optional  | Script parameters | string | 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.data\.\*\.hosts\.\*\.udp\.ports\.\*\.port | string |  `port` 
action\_result\.data\.\*\.hosts\.\*\.udp\.ports\.\*\.state | string | 
action\_result\.data\.\*\.hosts\.\*\.udp\.ports\.\*\.reason | string | 
action\_result\.data\.\*\.hosts\.\*\.udp\.ports\.\*\.service\.name | string | 
action\_result\.data\.\*\.hosts\.\*\.udp\.ports\.\*\.service\.product | string | 
action\_result\.data\.\*\.hosts\.\*\.udp\.ports\.\*\.cpe | string | 
action\_result\.data\.\*\.hosts\.\*\.udp\.ports\.\*\.scripts\.\*\.name | string | 
action\_result\.data\.\*\.hosts\.\*\.udp\.ports\.\*\.scripts\.\*\.output | string | 
action\_result\.data\.\*\.hosts\.\*\.tcp\.ports\.\*\.port | string |  `port` 
action\_result\.data\.\*\.hosts\.\*\.tcp\.ports\.\*\.state | string | 
action\_result\.data\.\*\.hosts\.\*\.tcp\.ports\.\*\.reason | string | 
action\_result\.data\.\*\.hosts\.\*\.tcp\.ports\.\*\.service\.name | string |  `url` 
action\_result\.data\.\*\.hosts\.\*\.tcp\.ports\.\*\.service\.product | string | 
action\_result\.data\.\*\.hosts\.\*\.tcp\.ports\.\*\.cpe | string | 
action\_result\.data\.\*\.hosts\.\*\.tcp\.ports\.\*\.scripts\.\*\.name | string | 
action\_result\.data\.\*\.hosts\.\*\.tcp\.ports\.\*\.scripts\.\*\.output | string | 
action\_result\.data\.\*\.hosts\.\*\.ip | string |  `ip` 
action\_result\.data\.\*\.hosts\.\*\.addrtype | string | 
action\_result\.data\.\*\.hosts\.\*\.scripts\.\*\.name | string | 
action\_result\.data\.\*\.hosts\.\*\.scripts\.\*\.output | string | 
action\_result\.data\.\*\.hosts\.\*\.state | string | 
action\_result\.data\.\*\.hosts\.\*\.reason | string | 
action\_result\.data\.\*\.hosts\.\*\.hostnames\.\*\.name | string |  `host name` 
action\_result\.status | string | 
action\_result\.message | string | 
action\_result\.summary\.start\_time | string | 
action\_result\.summary\.end\_time | string | 
action\_result\.summary\.version | string | 
action\_result\.summary\.tolerant\_errors | string | 
action\_result\.summary\.summary | string | 
action\_result\.summary\.exit\_status | string | 
action\_result\.parameter\.portlist | string | 
action\_result\.parameter\.ip\_hostname | string |  `ip`  `host name`  `url` 
action\_result\.parameter\.udp\_scan | boolean | 
action\_result\.parameter\.script | string | 
action\_result\.parameter\.script\_args | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric | 