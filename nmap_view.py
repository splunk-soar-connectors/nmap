# File: nmap_view.py
# Copyright (c) 2016-2021 Splunk Inc.
#
# SPLUNK CONFIDENTIAL - Use or disclosure of this material in whole or in part
# without a valid written license from Splunk Inc. is PROHIBITED.


import phantom.utils as ph_utils


def get_ctx_result(result):

    ctx_result = {}
    param = result.get_param()
    data = result.get_data()
    status = result.get_status()

    ctx_result['param'] = param
    ip_hostname = param['ip_hostname']

    ctx_result['param_contains'] = ['ip']

    if (ph_utils.is_hostname(ip_hostname) or ph_utils.is_domain(ip_hostname)):
        ctx_result['param_contains'] = ['host name']

    ctx_result['status'] = status
    if (data):
        ctx_result['data'] = data[0]

    return ctx_result


def display_scannetwork(provides, all_app_runs, context):

    context['results'] = results = []
    for summary, action_results in all_app_runs:
        for result in action_results:

            ctx_result = get_ctx_result(result)
            if (not ctx_result):
                continue
            results.append(ctx_result)
    return 'display_scannetwork.html'
