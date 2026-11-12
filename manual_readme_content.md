**Installation prerequisites**

This app runs the external Nmap executable through the `nmapthon2` Python wrapper.
The SDK package installs the Python dependencies; a host administrator must install
Nmap separately on every SOAR host that executes this app and make it available in
the SOAR service user's `PATH`. For example, use `sudo yum install nmap` on a
compatible RPM-based host or `sudo apt-get install nmap` on an Ubuntu host. Verify
`nmap --version` as the SOAR service user, then run **test connectivity**.
Both connectivity and network scans fail with an installation message when Nmap
cannot be found. Installing the Python wrapper alone is insufficient.

**UDP scans**

TCP scans run without elevated permissions. UDP scans use `-sU --privileged` and
require additional privileges. An administrator can grant the legacy app's Nmap
capabilities on the SOAR execution host:

```sh
sudo setcap cap_net_raw,cap_net_admin,cap_net_bind_service+eip /usr/bin/nmap
```

Use the actual executable path if Nmap is installed elsewhere. These capabilities
apply to the executable and can be lost when the Nmap package is replaced or
upgraded. Verify them with `getcap /usr/bin/nmap` before running UDP scans.

Granting these capabilities also grants them to NSE scripts executed by Nmap.
NSE scripts can sniff traffic, change network configuration, exploit systems, and
potentially escalate privileges on the host. Grant these capabilities only after
an administrator has reviewed the permitted scans and scripts. To remove the
capabilities granted above:

```sh
sudo setcap cap_net_raw,cap_net_admin,cap_net_bind_service-eip /usr/bin/nmap
```

**SDK migration scope**

The SDK app provides **test connectivity** and **scan network**. A generic HTTP
`make_request` action is not applicable because this connector invokes the local
Nmap executable and does not integrate with an HTTP API.
