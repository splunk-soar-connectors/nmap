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
from soar_sdk.abstract import SOARClient
from soar_sdk.app import App
from soar_sdk.asset import BaseAsset, AssetField
from soar_sdk.logging import getLogger

logger = getLogger()


class Asset(BaseAsset):
    ip_address: str | None = AssetField(
        description="IP Address for testing connectivity (default: 8.8.8.8)"
    )
    ports: str | None = AssetField(
        description="Ports e.g. 22,80,443,1000-1024 (default: 80,443)"
    )


app = App(
    name="NMAP Scanner",
    app_type="information",
    logo="logo_nmap.svg",
    logo_dark="logo_nmap_dark.svg",
    product_vendor="Generic",
    product_name="NMAP",
    publisher="Splunk",
    appid="1fedc03f-4593-4ad5-81cf-fa7cff652e70",
    fips_compliant=True,
    encrypt_cache_state=True,
    encrypt_ingest_state=True,
    asset_cls=Asset,
)


@app.test_connectivity()
def test_connectivity(soar: SOARClient, asset: Asset) -> None:
    import nmapthon2  # noqa: PLC0415

    target = asset.ip_address or "8.8.8.8"
    ports = asset.ports or "80,443"
    logger.progress(f"Testing NMAP connectivity against {target}")
    try:
        nmapthon2.NmapScanner().scan([target], ports=ports)
    except Exception as exc:
        raise RuntimeError(f"NMAP connectivity test failed: {exc}") from exc
    logger.progress("Test Connectivity Passed")


# Import action modules to register their handlers with the app.
from . import actions  # noqa: F401


if __name__ == "__main__":
    app.cli()
