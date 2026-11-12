**Unreleased**

* Convert NMAP Scanner to the SOAR SDK. The `scan network` action retains its target, host, port, service, and scan-summary fields, and its custom scan view is now rendered from typed SDK output.
* Preserve asset IP and port validation, scan summary metadata and summaries on result-processing failures, and NSE/CPE details in the custom scan view.
* Nmap must be installed separately on the SOAR execution host. See the installation prerequisites and UDP capability setup instructions in the app documentation.
