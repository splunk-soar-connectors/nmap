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

"""Regression coverage for connectivity, summary adaptation, and scan rendering."""

from datetime import datetime, UTC
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock

import pytest
from jinja2 import ChoiceLoader, DictLoader, Environment, FileSystemLoader

from src import helpers
from src.app import Asset, app, test_connectivity as connectivity_handler
from src.actions import scan_network


@pytest.mark.parametrize(
    "config",
    [
        {"ip_address": "not-an-ip"},
        {"ip_address": "192.0.2.0/24"},
        {"ip_address": ""},
        {"ports": ""},
        {"ports": "0"},
        {"ports": "65536"},
        {"ports": "90-80"},
        {"ports": "80;443"},
    ],
)
def test_invalid_asset_does_not_start_scanner(monkeypatch, config):
    scanner = Mock()
    monkeypatch.setattr("nmapthon2.NmapScanner", scanner)
    with pytest.raises(ValueError, match="configuration parameters"):
        connectivity_handler.__wrapped__(Mock(), Asset(**config))
    scanner.assert_not_called()


def test_missing_executable_has_installation_guidance(monkeypatch):
    monkeypatch.setattr(helpers, "which", lambda _: None)
    with pytest.raises(RuntimeError, match="install Nmap"):
        helpers.get_nmap_binary()


def test_connectivity_uses_defaults_and_resolved_binary(monkeypatch):
    scanner = Mock()
    monkeypatch.setattr("nmapthon2.NmapScanner", scanner)
    monkeypatch.setattr(helpers, "which", lambda _: "/usr/bin/nmap")
    connectivity_handler.__wrapped__(Mock(), Asset())
    scanner.assert_called_once_with(nmap_bin="/usr/bin/nmap")
    scanner.return_value.scan.assert_called_once_with(["8.8.8.8"], ports="80,443")


@pytest.mark.parametrize("failure", ["tolerant_errors", "host_parsing", None])
def test_sdk_action_preserves_summary(monkeypatch, failure):
    timestamp = datetime(2026, 11, 12, tzinfo=UTC)
    result = SimpleNamespace(
        start_datetime=timestamp,
        end_datetime=timestamp,
        version="7.95",
        tolerant_errors="partial scan error" if failure == "tolerant_errors" else None,
        summary="Scan complete",
        exit_status="error" if failure else "success",
        scanned_hosts=Mock(return_value=[]),
    )
    if failure == "host_parsing":
        result.scanned_hosts.side_effect = ValueError("bad host result")
    scanner = Mock()
    scanner.return_value.scan.return_value = result
    monkeypatch.setattr("nmapthon2.NmapScanner", scanner)
    monkeypatch.setattr(helpers, "which", lambda _: "/usr/bin/nmap")
    add_result = Mock()
    monkeypatch.setattr(app.actions_manager, "add_result", add_result)
    client = Mock()
    client.get_summary.side_effect = lambda: client.set_summary.call_args.args[0]
    client.get_message.return_value = ""
    params = scan_network.ScanNetworkParams(ip_hostname="192.0.2.1")
    status = app.get_actions()["nmap_scan"](params, soar=client, asset=Asset())
    assert status == (failure is None)
    emitted = add_result.call_args.args[0]
    assert emitted.get_summary()["version"] == "7.95"
    assert emitted.get_summary()["summary"] == "Scan complete"
    if failure == "tolerant_errors":
        assert emitted.get_summary()["tolerant_errors"] == "partial scan error"
    metadata = app.get_actions()["nmap_scan"].meta.model_dump()
    paths = {field["data_path"] for field in metadata["output"]}
    assert "action_result.summary.exit_status" in paths
    assert "action_result.summary.tolerant_errors" in paths


def test_widget_keeps_scripts_cpe_and_license_within_root():
    output = scan_network.ScanNetworkOutput(
        ip_hostname="192.0.2.1",
        hosts=[
            {
                "ip": "192.0.2.1",
                "state": "up",
                "hostnames": [],
                "scripts": [
                    {"name": "host-script", "output": "<script>alert(1)</script>"}
                ],
                "udp": {"ports": []},
                "tcp": {
                    "ports": [
                        {
                            "port": 80,
                            "state": "open",
                            "cpe": "cpe:/a:example:http:1",
                            "scripts": [
                                {"name": "port-script", "output": "port details"}
                            ],
                        }
                    ]
                },
            }
        ],
    )
    env = Environment(
        loader=ChoiceLoader(
            [
                DictLoader(
                    {
                        "widgets/widget_template.html": '<section id="widget">{% block widget_content %}{% endblock %}</section>'
                    }
                ),
                FileSystemLoader(Path(__file__).resolve().parents[1] / "templates"),
            ]
        ),
        autoescape=True,
    )
    rendered = env.get_template("nmap_scan.html").render(
        **scan_network.render_scan_network.__wrapped__([output])
    )
    assert rendered.startswith('<section id="widget">')
    assert rendered.index('class="nmap-scanner-network"') < rendered.index("Copyright")
    assert "host-script" in rendered
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in rendered
    assert "port-script" in rendered
    assert "port details" in rendered
    assert "cpe:/a:example:http:1" in rendered
