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

"""Scan Network action."""

import re

from soar_sdk.abstract import SOARClient
from soar_sdk.action_results import ActionOutput, OutputField
from soar_sdk.logging import getLogger
from soar_sdk.params import Param, Params

from ..app import Asset, app

logger = getLogger()


class ScanNetworkParams(Params):
    ip_hostname: str = Param(
        description="IP address/hostname (CIDR notation supported)",
        required=True,
        primary=True,
        cef_types=["ip", "host name", "url"],
    )
    portlist: str | None = Param(description="Portlist e.g. 22,80,443,1000-1024")
    udp_scan: bool | None = Param(description="UDP Scan")
    script: str | None = Param(description="NSE Script")
    script_args: str | None = Param(description="Script parameters")


class ScriptsOutput(ActionOutput):
    name: str = OutputField(example_values=["dns-brute"])
    output: str = OutputField(
        example_values=[
            "\n  DNS Brute-force hostnames\n    www.phantom.us - 52.7.97.246\n"
        ]
    )


class ServiceOutput(ActionOutput):
    name: str | None = OutputField(cef_types=["url"], example_values=["http"])
    product: str | None = OutputField(example_values=[])
    scripts: list[ScriptsOutput]


class PortsOutput(ActionOutput):
    port: int = OutputField(cef_types=["port"], example_values=[80])
    state: str | None = OutputField(example_values=["open"])
    reason: str | None = OutputField(example_values=["syn-ack"])
    service: ServiceOutput | None = None
    cpe: str | None = OutputField(example_values=[""])
    scripts: list[ScriptsOutput]


class UdpOutput(ActionOutput):
    ports: list[PortsOutput]


class TcpOutput(ActionOutput):
    ports: list[PortsOutput]


class HostnamesOutput(ActionOutput):
    name: str = OutputField(cef_types=["host name"], example_values=["phantom.us"])


class HostsOutput(ActionOutput):
    udp: UdpOutput
    tcp: TcpOutput
    ip: str | None = OutputField(cef_types=["ip"], example_values=["52.7.97.246"])
    addrtype: str | None = OutputField(example_values=["ipv4", "ipv6"])
    scripts: list[ScriptsOutput]
    state: str | None = OutputField(example_values=["up"])
    reason: str | None = OutputField(example_values=["syn-ack"])
    hostnames: list[HostnamesOutput]


class ScanNetworkOutput(ActionOutput):
    ip_hostname: str = OutputField(cef_types=["ip", "host name", "url"])
    hosts: list[HostsOutput]


class ScanSummary(ActionOutput):
    start_time: str | None = OutputField()
    end_time: str | None = OutputField()
    version: str | None = OutputField()
    tolerant_errors: str | None = OutputField()
    summary: str | None = OutputField()
    exit_status: str | None = OutputField()


def nmap_scan(
    params: ScanNetworkParams, soar: SOARClient, asset: Asset
) -> ScanNetworkOutput:
    import ipaddress  # noqa: PLC0415
    from urllib.parse import urlsplit  # noqa: PLC0415

    import nmapthon2  # noqa: PLC0415
    from nmapthon2.exceptions import NmapScanError  # noqa: PLC0415

    target = params.ip_hostname.strip()
    if not target:
        raise ValueError("ip_hostname must not be empty")
    if "://" in target:
        parsed = urlsplit(target)
        if not parsed.hostname or parsed.username or parsed.password:
            raise ValueError("Unable to extract a hostname from the provided URL")
        target = parsed.hostname
    portlist = params.portlist
    if portlist is not None and not _is_valid_portlist(portlist):
        raise ValueError("Port list must contain only ports and comma-separated port ranges")
    try:
        ipaddress.ip_address(target)
        is_ipv6 = ":" in target
    except ValueError:
        is_ipv6 = False
    args = []
    if is_ipv6:
        args.append("-6")
    if params.udp_scan:
        args.extend(["-sU", "--privileged"])
    if params.script:
        args.append(f"--script={params.script}")
        if params.script_args:
            args.extend(["--script-args", params.script_args])
    try:
        scanner = nmapthon2.NmapAsyncScanner() if params.udp_scan else nmapthon2.NmapScanner()
        result = scanner.scan(targets=target, ports=portlist, arguments=" ".join(args))
        if params.udp_scan:
            scanner.wait()
            if not scanner.finished():
                raise RuntimeError(getattr(scanner, "_stored_error_buffer", "UDP scan did not complete"))
            result = scanner.get_result()
    except NmapScanError as exc:
        soar.set_message(f"Scan failed: {exc}")
        raise RuntimeError("Scan failed") from exc
    except Exception as exc:
        soar.set_message(f"Scan failed: {exc}")
        raise RuntimeError("Scan failed") from exc

    try:
        summary = {
            "start_time": result.start_datetime.strftime("%H:%M:%S %d-%-m-%Y"),
            "end_time": result.end_datetime.strftime("%H:%M:%S %d-%-m-%Y"),
            "version": str(result.version),
            "tolerant_errors": str(result.tolerant_errors) if result.tolerant_errors else None,
            "summary": str(result.summary),
            "exit_status": str(result.exit_status),
        }
        if result.tolerant_errors:
            raise RuntimeError(f"Error(s) occurred while scanning: {result.tolerant_errors}")
        hosts = []
        for host in result.scanned_hosts():
            ipv4, ipv6 = host.ipv4, host.ipv6
            host_data = {
                "tcp": {"ports": _retrieve_ports(host.tcp_ports())},
                "udp": {"ports": _retrieve_ports(host.udp_ports())},
                "state": host.state,
                "reason": host.reason,
                "hostnames": [{"name": name} for name in host.hostnames()],
                "addrtype": "ipv4" if ipv4 else "ipv6",
                "ip": ipv4 or ipv6,
                "scripts": [],
            }
            if params.script:
                host_data["scripts"] = [{"name": name, "output": output} for name, output in host.all_scripts()]
            hosts.append(HostsOutput(**host_data))
        soar.set_summary(ScanSummary(**summary))
        return ScanNetworkOutput(ip_hostname=params.ip_hostname, hosts=hosts)
    except Exception as exc:
        soar.set_message(f"Exception while retrieving NMAP results: {exc}")
        raise


def _is_valid_portlist(portlist: str) -> bool:
    if not re.fullmatch(r"\d+(?:-\d+)?(?:,\d+(?:-\d+)?)*", str(portlist)):
        return False
    for item in str(portlist).split(","):
        bounds = [int(part) for part in item.split("-")]
        if any(value < 1 or value > 65535 for value in bounds):
            return False
        if len(bounds) == 2 and bounds[0] > bounds[1]:
            return False
    return True


def _retrieve_ports(ports: list) -> list[PortsOutput]:
    output = []
    for port in ports:
        service = port.get_service()
        service_data = None
        cpe = None
        if service:
            service_data = {
                "name": service.name,
                "product": service.product,
                "scripts": [{"name": name, "output": value} for name, value in service.all_scripts()],
            }
            cpe = "".join(service.cpes)
        scripts = [{"name": name, "output": value} for name, value in port.service.all_scripts()] if port.service else []
        output.append(PortsOutput(port=port.number, state=port.state, reason=port.reason, service=service_data, cpe=cpe, scripts=scripts))
    return output


def render_scan_network(output: list[ScanNetworkOutput]) -> dict:
    return {
        "results": [
            {
                "ip_hostname": item.ip_hostname,
                "hosts": [
                    {
                        "ip": host.ip,
                        "state": host.state,
                        "hostnames": [name.name for name in host.hostnames],
                        "tcp_ports": host.tcp.ports,
                        "udp_ports": host.udp.ports,
                    }
                    for host in item.hosts
                ],
            }
            for item in output
        ]
    }


app.register_action(
    nmap_scan,
    name="scan network",
    description="Execute NMAP scan against a host or subnet",
    verbose="Scan a host or subnet with NMAP and return host, port, and service details.",
    action_type="investigate",
    read_only=False,
    params_class=ScanNetworkParams,
    output_class=ScanNetworkOutput,
    view_handler=render_scan_network,
    view_template="nmap_scan.html",
)

