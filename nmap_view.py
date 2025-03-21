# File: nmap_view.py
#
# Copyright (c) 2016-2025 Splunk Inc.
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
import phantom.utils as ph_utils


def get_ctx_result(result):
    ctx_result = {}
    param = result.get_param()
    data = result.get_data()
    status = result.get_status()

    ctx_result["param"] = param
    ip_hostname = param["ip_hostname"]

    ctx_result["param_contains"] = ["ip"]

    if ph_utils.is_hostname(ip_hostname) or ph_utils.is_domain(ip_hostname):
        ctx_result["param_contains"] = ["host name"]

    ctx_result["status"] = status
    if data:
        ctx_result["data"] = data[0]

    return ctx_result


def display_scannetwork(provides, all_app_runs, context):
    context["results"] = results = []
    for summary, action_results in all_app_runs:
        for result in action_results:
            ctx_result = get_ctx_result(result)
            if not ctx_result:
                continue
            results.append(ctx_result)
    return "display_scannetwork.html"
