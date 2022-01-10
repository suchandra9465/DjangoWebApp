import re
from logger import log, debug
from network_helper import expand_address, expand_service, get_ports_of, get_prot_of


def find_ip_address(config, ip_address_list, context_list, exact=False):
    ##  Given an IP address, find all the address and address-group objects that contain the address

    return_list = []
    import ipaddress
    import re

    for ip_to_find in ip_address_list:
        if re.findall('/', ip_to_find):
            ipaddr, netmask = ip_to_find.split('/')
        else:
            ipaddr = ip_to_find
            netmask = '32'
        log("=" * 120)
        log('Searching for IP address : ' + ip_to_find)
        for context in context_list:
            found = False
            if context in config:
                # only print this header if something is found in each context

                for address_index in config[context]['addresses']:
                    if 'addrObjId' in config[context]['addresses'][address_index] and 'addressmappings' in config[
                        context]:
                        for expanded_index in expand_address(config[context]['addresses'],
                                                             config[context]['addresses'][address_index]['addrObjId'],
                                                             config[context]['addressmappings']):
                            for network in config[context]['addresses'][expanded_index]['IPv4Networks']:
                                if ((ipaddress.IPv4Network(ipaddr + '/' + netmask, strict=False).overlaps(
                                        network) or network.overlaps(ipaddress.IPv4Network(ipaddr + '/' + netmask,
                                                                                           strict=False))) and not exact) or (
                                        ipaddress.IPv4Network(ipaddr + '/' + netmask,
                                                              strict=False) == network and exact):
                                    if network != ipaddress.IPv4Network('0.0.0.0/0') or options.zero_network:
                                        if found == False:
                                            found = True
                                            log('-' * 120)
                                            log('%-40s :' % ' Device Group', end='')
                                            log('%-40s :' % ' Root Object Name', end='')
                                            log('%-40s' % ' Member Address Object')
                                            log('-' * 120)
                                        log('%-40s : ' % context, end='')
                                        log('%-40s : ' % config[context]['addresses'][address_index]['addrObjId'],
                                            end='')
                                        log('%-40s : ' % expanded_index, end='')
                                        log('%-40s' % config[context]['addresses'][address_index]['addrObjComment'])

                                        return_list.append(expanded_index)
            else:
                log('Device Group (context)' + context + ' not found, Skipped!')
    return return_list


def find_service(config, search_list, context_list, exact=False):
    ## Given a service definition "protocol/port", find all the service and service-group objects that contain the service
    return_list = []
    for service_to_find in search_list:
        prot, port = service_to_find.split('/')
        log('-' * 120)
        log('%-40s : ' % 'Device Group', end='')
        log('%-40s : ' % 'Root Object Name', end='')
        log('%-40s' % 'Member Service Object')
        log('-' * 120)

        ## svcPortSet FIX

        for context in context_list:
            for service_index in config[context]['services']:
                for expanded_index in expand_service(config[context]['services'],
                                                     config[context]['services'][service_index]['svcObjId'],
                                                     config[context]['servicemappings']):
                    # start, end = get_port_of(config[context]['services'],expanded_index)
                    portlist = get_ports_of(config[context]['services'], expanded_index)
                    # start=int(start)
                    # end=int(end)
                    if (prot.lower() == get_prot_of(config[context]['services'], expanded_index)):
                        if (int(port) in portlist and not exact) or (
                                config[context]['services'][service_index]['svcObjType'] == '1' and [
                            int(port)] == portlist and exact):
                            log('%-40s : ' % context, end='')
                            log('%-40s : ' % config[context]['services'][service_index]['svcObjId'], end='')
                            log('%-40s' % expanded_index)
                            return_list.append(expanded_index)
    return return_list


def show_found_ips(config, search_list, context_list):
    return


def show_found_services(config, search_list, contexts):
    return


def find_matching_rules(config, shared, params, contextnames, modify=None):
    ## redo this using IPset like I do for inverse matching

    import ipaddress
    import re
    from netaddr import IPSet
    from urllib.parse import unquote as url_unquote

    if params[0].count(',') != 2:
        log('Search string must contain exactly 3 fields source_ip,destination_ip,service')
        return False
    log('!-- Finding matching rules ' + str(params))
    if modify:
        log(modify)
        if len(modify.split(',')) > 1:
            modify_group, modify_addr = modify.split(',', 1)
            if len(modify_addr.split(',')) > 1:
                modify_addr = modify_addr.split(',')
            else:
                modify_addr = [modify_addr]
        else:
            modify = None

        ## verify that each of the address objects exists

        # for addr in modify_addr:
        # addr_found=False
        #   for context in contexts:
        #       if addr in config[context]['addresses']:
        #           addr_found=True
        #           break
        #       else:
        #           log('Address not available')
        #    if not addr_found:
        #        modify=None
        #        break

    source, dest, service = params[0].split(',')

    # log(params[0])

    if source.lower() == 'any':
        source = '0.0.0.0/0'
        log('setting source to 0.0.0.0')
    if re.findall('/', source) != []:
        src_ipaddr, src_netmask = source.split('/')
    else:
        src_ipaddr = source
        src_netmask = '32'
    sourceIPv4 = ipaddress.IPv4Network(src_ipaddr + '/' + src_netmask, strict=False)
    firstsource = sourceIPv4[0]
    lastsource = sourceIPv4[-1]

    if dest.lower() == 'any':
        dest = '0.0.0.0/0'
        log('setting dest to 0.0.0.0')
    if re.findall('/', dest):
        dst_ipaddr, dst_netmask = dest.split('/')
    else:
        dst_ipaddr = dest
        dst_netmask = '32'
    destIPv4 = ipaddress.IPv4Network(dst_ipaddr + '/' + dst_netmask, strict=False)
    firstdest = destIPv4[0]
    lastdest = destIPv4[-1]

    if service.lower() == 'any':
        service = 'any/any'
    prot, port = service.split('/')
    try:
        portnum = int(port)
    except:
        if port == 'any': portnum = 0
    return_list = []

    nomatches = []
    for context in contextnames:
        policymatches = 0
        if 'policies' in config[context]:
            for policy in config[context]['policies']:
                log(config[context]['policies'][policy])
                if (config[context]['config']['fw_type'] == 'checkpoint' and config[context]['policies'][policy][
                    'policyName'] in options.policynames) or config[context]['config']['fw_type'] != 'checkpoint' or \
                        options.policynames[0].lower() in ['', 'any', 'all']:
                    if (len(set(config[context]['policies'][policy]['policySrcZone']) & set(
                            config[context]['usedzones'])) > 0 or config[context]['usedzones'] == []) and (
                            len(set(config[context]['policies'][policy]['policyDstZone']) & set(
                                    config[context]['usedzones'])) > 0 or config[context]['usedzones'] == []):
                        found_in_source = False
                        found_in_dest = False
                        found_in_service = False
                        prefix = ''
                        if source == '0.0.0.0/0':  # and options.zero_network: -- not applicable here
                            found_in_source = True
                            if len(config[context]['policies'][policy]['policySrcNet']) >= 1:
                                source_addr = config[context]['policies'][policy]['policySrcNet']
                                if source_addr == ['']: source_addr = ['Any']
                            else:
                                source_addr = ['Any']
                        else:
                            for source_index in config[context]['policies'][policy]['policySrcNet']:
                                if source_index.lower() == 'any' and options.zero_network:
                                    found_in_source = True
                                    source_addr = ['Any']
                                    break
                                policyIPv4_list = []
                                if (source_index in config[context]['addresses']):
                                    for expanded_index in expand_address(config[context]['addresses'],
                                                                         config[context]['addresses'][source_index][
                                                                             'addrObjId'],
                                                                         config[context]['addressmappings']):
                                        if (expanded_index in config[context]['addresses']):
                                            policyIPv4_list.extend(
                                                config[context]['addresses'][expanded_index]['IPv4Networks'])
                                        elif (expanded_index in shared['addresses']):
                                            policyIPv4_list.extend(shared['addresses'][expanded_index]['IPv4Networks'])
                                elif (source_index in shared['addresses']):
                                    for expanded_index in expand_address(shared['addresses'],
                                                                         shared['addresses'][source_index]['addrObjId'],
                                                                         shared['addressmappings']):
                                        policyIPv4_list.extend(shared['addresses'][expanded_index]['IPv4Networks'])
                                        prefix = '*'
                                else:
                                    try:
                                        if re.findall('-', source_index) != []:
                                            first, last = source_index.split('-')
                                            for x in ipaddress.summarize_address_range(ipaddress.IPv4Address(first),
                                                                                       ipaddress.IPv4Address(last)):
                                                policyIPv4_list.extend([x])
                                        else:
                                            first = source_index
                                            last = source_index
                                            if re.findall('/', first) == []:
                                                first = first + '/32'
                                            policyIPv4_list.extend([ipaddress.IPv4Network(first)])
                                    except Exception as e:
                                        pass

                                polSet = IPSet([])
                                srcSet = IPSet([])
                                for x in policyIPv4_list:
                                    polSet.add(str(x))
                                srcSet.add(sourceIPv4.with_netmask)
                                if (srcSet & polSet) or ((
                                                                 source_index.lower() == 'any' or source.lower() == '0.0.0.0/0') and options.zero_network):
                                    found_in_source = True
                                    source_addr = config[context]['policies'][policy]['policySrcNet']
                                    break
                        if found_in_source:
                            prefix = ''
                            if dest == '0.0.0.0/0':  # and options.zero_network: -- not applicable here
                                found_in_dest = True
                                if len(config[context]['policies'][policy]['policyDstNet']) >= 1:
                                    dest_addr = config[context]['policies'][policy]['policyDstNet']
                                    if dest_addr == ['']: dest_addr = ['Any']
                                else:
                                    dest_addr = ['Any']
                            else:
                                for dest_index in config[context]['policies'][policy]['policyDstNet']:
                                    if dest_index.lower() == 'any' and options.zero_network:
                                        found_in_dest = True
                                        dest_addr = ['Any']
                                        break
                                    policyIPv4_list = []
                                    if (dest_index in config[context]['addresses']):
                                        for expanded_index in expand_address(config[context]['addresses'],
                                                                             config[context]['addresses'][dest_index][
                                                                                 'addrObjId'],
                                                                             config[context]['addressmappings']):
                                            if (expanded_index in config[context]['addresses']):
                                                policyIPv4_list.extend(
                                                    config[context]['addresses'][expanded_index]['IPv4Networks'])
                                            elif (expanded_index in shared['addresses']):
                                                policyIPv4_list.extend(
                                                    shared['addresses'][expanded_index]['IPv4Networks'])
                                    elif (dest_index in shared['addresses']):
                                        for expanded_index in expand_address(shared['addresses'],
                                                                             shared['addresses'][dest_index][
                                                                                 'addrObjId'],
                                                                             shared['addressmappings']):
                                            policyIPv4_list.extend(shared['addresses'][expanded_index]['IPv4Networks'])
                                            prefix = '*'
                                    else:
                                        try:
                                            if re.findall('-', dest_index) != []:
                                                first, last = dest_index.split('-')
                                                for x in ipaddress.summarize_address_range(ipaddress.IPv4Address(first),
                                                                                           ipaddress.IPv4Address(last)):
                                                    policyIPv4_list.extend([x])
                                            else:
                                                first = dest_index
                                                last = dest_index
                                                if re.findall('/', first) == []:
                                                    first = first + '/32'
                                                policyIPv4_list.extend([ipaddress.IPv4Network(first)])
                                        except Exception as e:
                                            pass
                                    polSet = IPSet([])
                                    destSet = IPSet([])
                                    for x in policyIPv4_list: polSet.add(str(x))
                                    destSet.add(destIPv4.with_netmask)
                                    if (polSet & destSet) or ((
                                                                      dest_index.lower() == 'any' or dest.lower() == '0.0.0.0/0') and options.zero_network):
                                        found_in_dest = True
                                        dest_addr = config[context]['policies'][policy]['policyDstNet']
                                        break

                        if found_in_dest:
                            # perform checking of service
                            # verify that get port of icmp returns "any"
                            if (config[context]['policies'][policy]['policyDstSvc'] == [
                                ''] and options.zero_network) or (
                                    [x.lower() for x in config[context]['policies'][policy]['policyDstSvc']] == [
                                'any'] and options.zero_network) or config[context]['policies'][policy][
                                'policyDstSvc'] == ['application-default']:
                                found_in_service = True
                                if config[context]['policies'][policy]['policyDstSvc'] == ['']:
                                    dest_service = ['any']
                                else:
                                    dest_service = config[context]['policies'][policy]['policyDstSvc']
                            elif service == 'any/any' and options.zero_network:
                                found_in_service = True
                                dest_service = config[context]['policies'][policy]['policyDstSvc']
                            else:
                                for dest_index in config[context]['policies'][policy]['policyDstSvc']:
                                    if (dest_index in config[context]['services']):
                                        for expanded_index in expand_service(config[context]['services'],
                                                                             config[context]['services'][dest_index][
                                                                                 'svcObjId'],
                                                                             config[context]['servicemappings']):
                                            policy_prot = get_prot_of(config[context]['services'], expanded_index)
                                            # start_port, end_port = get_port_of(config[context]['services'],expanded_index)
                                            policy_ports = get_ports_of(config[context]['services'], expanded_index)
                                            # if start_port=='': start_port='0'
                                            # if end_port=='': end_port='0'

                                            try:
                                                if ((prot.lower() == policy_prot or prot.lower() == 'any') and (
                                                        int(portnum) in policy_ports)) or (
                                                        dest_index.lower() == 'any' and options.zero_network) or (
                                                        service.lower() == 'any/any' and options.zero_network):
                                                    if found_in_service == False:
                                                        found_in_service = True
                                                        dest_service = config[context]['policies'][policy][
                                                            'policyDstSvc']
                                                        break
                                            except Exception as e:
                                                # print(type(prot.lower()))
                                                print(prot.lower())

                                                # print(type(policy_prot))
                                                print(policy_prot)
                                                print("'" + start_port + "'")
                                                print(end_port)
                                                print(expanded_index)
                                                log(e)

                                    if (dest_index in shared['services']):
                                        for expanded_index in expand_service(shared['services'],
                                                                             shared['services'][dest_index]['svcObjId'],
                                                                             shared['servicemappings']):
                                            policy_prot = get_prot_of(shared['services'], expanded_index).lower()
                                            # start_port, end_port = get_port_of(shared['services'],expanded_index)
                                            policy_ports = get_ports_of(config[context]['services'], expanded_index)
                                            # if start_port=='': start_port='0'
                                            # if end_port=='': end_port='0'
                                            if ((
                                                        prot.lower() == policy_prot or prot.lower() == 'any') and portnum in policy_ports) or dest_index.lower() == 'any' or (
                                                    service.lower() == 'any/any' and options.zero_network):
                                                if found_in_service == False:
                                                    found_in_service = True
                                                    dest_service = config[context]['policies'][policy]['policyDstSvc']
                                                    break

                        if found_in_source and found_in_dest and found_in_service:
                            # I believe zone/net/service is empty if "any", so temporarily set these values to variables before printing them
                            if config[context]['policies'][policy]['policyEnabled'] == '0':
                                enabled = "."
                            elif config[context]['policies'][policy]['policyEnabled'] == '1':
                                if not options.web:
                                    enabled = u'\u2713'
                                else:
                                    enabled = 'Y'
                            if config[context]['policies'][policy]['policyAction'] == '0':
                                action = 'deny'
                            elif config[context]['policies'][policy]['policyAction'] == '1':
                                action = 'discard'
                            elif config[context]['policies'][policy]['policyAction'] == '2':
                                action = 'allow'
                            elif config[context]['policies'][policy]['policyAction'] == '3':
                                action = 'CltAuth'
                            name = config[context]['policies'][policy]['policyName']

                            if config[context]['policies'][policy]['policySrcZone'] == []:
                                source_zone = ['any']
                            else:
                                source_zone = config[context]['policies'][policy]['policySrcZone']

                            if config[context]['policies'][policy]['policyDstZone'] == []:
                                dest_zone = ['any']
                            else:
                                dest_zone = config[context]['policies'][policy]['policyDstZone']

                            policymatches += 1

                            if config[context]['policies'][policy]['policySrcZone'] == [] or \
                                    config[context]['policies'][policy]['policySrcZone'] == ['']:
                                source_zones = ['any']
                            else:
                                source_zones = config[context]['policies'][policy]['policySrcZone']

                            if config[context]['policies'][policy]['policyDstZone'] == [] or \
                                    config[context]['policies'][policy]['policyDstZone'] == ['']:
                                dest_zones = ['any']
                            else:
                                dest_zones = config[context]['policies'][policy]['policyDstZone']

                            if config[context]['policies'][policy]['policySrcNet'] == [] or \
                                    config[context]['policies'][policy]['policySrcNet'] == ['']:
                                source_nets = ['any']
                            else:
                                source_nets = config[context]['policies'][policy]['policySrcNet']

                            if config[context]['policies'][policy]['policyDstNet'] == [] or \
                                    config[context]['policies'][policy]['policyDstNet'] == ['']:
                                dest_nets = ['any']
                            else:
                                dest_nets = config[context]['policies'][policy]['policyDstNet']

                            if config[context]['policies'][policy]['policyDstSvc'] == [] or \
                                    config[context]['policies'][policy]['policyDstSvc'] == ['']:
                                dest_services = ['any']
                            else:
                                dest_services = config[context]['policies'][policy]['policyDstSvc']

                            if options.web:
                                if policymatches == 1:
                                    log('<p align=center><font size=8 >')
                                    log('context: ' + context)
                                    log('</font></p>')
                                    log('<table border="1" width="90%">')
                                    if config[context]['config']['fw_type'] == 'checkpoint':
                                        log('<th>Enabled</th><th>Action</th><th>Name</th><th>Source Zone</th><th>Dest Zone</th><th>Source Address</th><th>Destination Address</th><th>Service</th>')
                                    else:
                                        log('<th>Enabled</th><th>Action</th><th>Name</th><th>UiNum</th><th>IndexNum</th><th>Source Address</th><th>Destination Address</th><th>Service</th>')
                                if enabled != "Y":
                                    trcolor = '#aaaaaa'
                                elif action.lower() == 'allow':
                                    trcolor = '#00aa00'
                                else:
                                    trcolor = '#aa0000'
                                log('<tr bgcolor="' + trcolor + '">')
                                log('<td>' + enabled + '</td>')
                                log('<td>' + action + '</td>')
                                log('<td>' + name + '</td>')
                                ## only do src/dest zones for non-checkpoint
                                ## for checkpoint, add ruleUI number
                                if config[context]['config']['fw_type'] == 'checkpoint':
                                    log('<td>' + str(config[context]['policies'][policy]['policyUiNum']) + '</td>')
                                    log('<td>' + str(config[context]['policies'][policy]['policyNum']) + '</td>')
                                else:
                                    log('<td>')
                                    for source_zone in source_zones:
                                        log(url_unquote(source_zone) + '<br>')
                                    log('</td>')
                                    log('<td>')
                                    for dest_zone in dest_zones:
                                        log(url_unquote(dest_zone) + '<br>')
                                    log('</td>')
                                log('<td>')
                                for source_address in source_nets:
                                    log(url_unquote(source_address) + '<br>')
                                log('</td>')
                                log('<td>')
                                for dest_address in dest_nets:
                                    log(url_unquote(dest_address) + '<br>')
                                log('</td>')
                                log('<td>')
                                for dest_service in dest_services:
                                    log(url_unquote(dest_service) + '<br>')
                                log('</td>')
                                log('<tr>')

                            else:
                                if policymatches == 1:
                                    log('Context : ' + context)
                                    if config[context]['config']['fw_type'] == 'checkpoint':
                                        log('{:2.2s} {:8.8s} {:15.15s} {:30.30s} {:8.8s} {:8.8s} {:40.40s} {:40.40s} {:40.40s}'.format(
                                            'En', 'Action', 'CMA', 'Policy Name', 'Rule UI#', 'Rule Idx',
                                            'Source Address', 'Destination Address', 'Service'))
                                    else:
                                        log('{:2.2s} {:8.8s} {:30.30s} {:20.20s} {:20.20s} {:40.40s} {:40.40s} {:40.40s}'.format(
                                            'En', 'Action', 'Rule Name', 'Source Zone', 'Destination Zone',
                                            'Source Address', 'Destination Address', 'Service'))
                                    log('=' * 200)
                                if config[context]['config']['fw_type'] == 'checkpoint':
                                    log('{:2.2s} {:8.8s} {:15.15s} {:30.30s} {:8.8s} {:8.8s} {:40.40s} {:40.40s} {:40.40s}'.format(
                                        enabled, action, context, url_unquote(name),
                                        str(config[context]['policies'][policy]['policyUiNum']),
                                        str(config[context]['policies'][policy]['policyNum']),
                                        url_unquote(source_addr[0]), url_unquote(dest_addr[0]),
                                        url_unquote(dest_service[0])))
                                else:
                                    log('{:2.2s} {:8.8s} {:30.30s} {:20.20s} {:20.20s} {:40.40s} {:40.40s} {:40.40s}'.format(
                                        enabled, action, url_unquote(name), url_unquote(source_zone[0]),
                                        url_unquote(dest_zone[0]), url_unquote(source_addr[0]),
                                        url_unquote(dest_addr[0]), url_unquote(dest_service[0])))
                                longestval = max(len(source_addr), len(dest_addr), len(dest_service))
                                if longestval > 1:
                                    for index in range(1, longestval):
                                        tmpsrc = ''
                                        tmpdst = ''
                                        tmpsvc = ''
                                        if index < len(source_addr):
                                            tmpsrc = source_addr[index]
                                        if index < len(dest_addr):
                                            tmpdst = dest_addr[index]
                                        if index < len(dest_service):
                                            tmpsvc = dest_service[index]
                                        if config[context]['config']['fw_type'] == 'checkpoint':
                                            log('{:2.2s} {:8.8s} {:15.15s} {:30.30s} {:8.8s} {:8.8s} {:40.40s} {:40.40s} {:40.40s}'.format(
                                                '', '', '', '', '', '', url_unquote(tmpsrc), url_unquote(tmpdst),
                                                url_unquote(tmpsvc)))
                                        else:
                                            log('{:2.2s} {:8.8s} {:30.30s} {:20.20s} {:20.20s} {:40.40s} {:40.40s} {:40.40s}'.format(
                                                '', '', '', '', '', url_unquote(tmpsrc), url_unquote(tmpdst),
                                                url_unquote(tmpsvc)))
                                log('-' * 200)
                                if modify:
                                    if modify_group not in config[context]['policies'][policy]['policyDstNet']:
                                        for addr in modify_addr:
                                            log('addelement fw_policies {} rule:{}:dst:\'\' network_objects:{}'.format(
                                                url_unquote(name), config[context]['policies'][policy]['policyNum'],
                                                addr))
                                    else:
                                        log('Rule already contains group: ' + modify_group)

            if policymatches != 0 and options.web:
                log('</table>')
                log('<hr>')

            if policymatches == 0:
                nomatches.append(context)
    if len(nomatches) > 0:
        log('No matches were found for the following contexts')
        log('"{}'.format(nomatches))
        for nomatch in nomatches:
            log(nomatch)
            if options.web: log('<br>')
    return


def find_matching_rules2(config, shared, params_list, contextnames, modify=None):
    ## redo this using IPset like I do for inverse matching

    import ipaddress
    import re
    from netaddr import IPSet
    from urllib.parse import unquote as url_unquote
    import codecs

    ##CHANGEME - move excluded addresses to a CLI option

    excluded_addresses = []
    excluded_addresses = options.excludeaddress
    excluded_src_networks = IPSet([addr for addr in options.excludesrcnetwork])
    excluded_dst_networks = IPSet([addr for addr in options.excludedstnetwork])
    # log(excluded_networks)

    # ['Net_10.0.0.0', 'DellNets', 'glbl-Dell_Internal_Networks', 'DellNets-Only', 'Dell-10.0.0.0', 'Net10', 'Dell-DMS-Users', 'DellAssignedNets-NonDell', 'DC-Networks']

    for params in params_list:
        if params.count(',') != 2:
            log('Search string must contain exactly 3 fields source_ip,destination_ip,service')
            return False
        if not options.web:
            log('!-- Finding matching rules ' + str(params))
        if modify:
            log(modify)
            if len(modify.split(',')) > 1:
                modify_group, modify_addr = modify.split(',', 1)
                if len(modify_addr.split(',')) > 1:
                    modify_addr = modify_addr.split(',')
                else:
                    modify_addr = [modify_addr]
            else:
                modify = None

            ## verify that each of the address objects exists

            # for addr in modify_addr:
            # addr_found=False
            #   for context in contexts:
            #       if addr in config[context]['addresses']:
            #           addr_found=True
            #           break
            #       else:
            #           log('Address not available')
            #    if not addr_found:
            #        modify=None
            #        break

        source, dest, service = params.split(',')

        if source.lower() == 'any':
            source = '0.0.0.0/0'
        if re.findall('/', source) != []:
            src_ipaddr, src_netmask = source.split('/')
        else:
            src_ipaddr = source
            src_netmask = '32'
        sourceIPv4 = ipaddress.IPv4Network(src_ipaddr + '/' + src_netmask, strict=False)
        firstsource = sourceIPv4[0]
        lastsource = sourceIPv4[-1]

        if dest.lower() == 'any':
            dest = '0.0.0.0/0'
        if re.findall('/', dest):
            dst_ipaddr, dst_netmask = dest.split('/')
        else:
            dst_ipaddr = dest
            dst_netmask = '32'
        destIPv4 = ipaddress.IPv4Network(dst_ipaddr + '/' + dst_netmask, strict=False)
        firstdest = destIPv4[0]
        lastdest = destIPv4[-1]

        if service.lower() == 'any':
            service = 'any/any'
        prot, port = service.split('/')
        try:
            portnum = int(port)
        except:
            if port == 'any': portnum = 0
        return_list = []

        nomatches = []
        # if options.csv:
        #    with codecs.open('/opt/scripts/downloads/rulematch.csv', 'w', 'utf-8') as outfile:
        #        pass
        for context in contextnames:
            #log(context)
            policymatches = 0
            if 'policies' in config[context]:
                for policy in config[context]['policies']:
                    source_match_type = None
                    dest_match_type = None
                    if 'policySrcNegate' in config[context]['policies'][policy]:
                        negate_source = config[context]['policies'][policy]['policySrcNegate']
                    else:
                        negate_source = False
                    if negate_source:
                        pass
                        # log('SOURCE NEGATED Idx: {} UI: {} '.format(str(config[context]['policies'][policy]['policyNum']), str(config[context]['policies'][policy]['policyUiNum'])))
                    if 'policyDstNegate' in config[context]['policies'][policy]:
                        negate_dest = config[context]['policies'][policy]['policyDstNegate']
                    else:
                        negate_dest = False

                    if (config[context]['config']['fw_type'] == 'checkpoint' and config[context]['policies'][policy][
                        'policyName'] in options.policynames) or config[context]['config']['fw_type'] != 'checkpoint' or \
                            options.policynames[0].lower() in ['', 'any', 'all']:

                        # log(config[context]['usedzones'])
                        # if (len(set(config[context]['policies'][policy]['policySrcZone']) & set(config[context]['usedzones']))>0 or config[context]['usedzones']==[]  ) and (len(set(config[context]['policies'][policy]['policyDstZone']) & set(config[context]['usedzones']))>0 or config[context]['usedzones']==[]) or config[context]['config']['fw_type']=='checkpoint':
                        # log(config[context]['policies'][policy])
                        # log('jeff')
                        found_in_source = False
                        found_in_dest = False
                        found_in_service = False
                        prefix = ''
                        source_found_index = []
                        if source == '0.0.0.0/0':  # and options.zero_network: -- not applicable here
                            found_in_source = True
                            source_match_type = "Any"
                            if len(config[context]['policies'][policy]['policySrcNet']) >= 1:
                                source_addr = config[context]['policies'][policy]['policySrcNet']
                                if source_addr == ['']: source_addr = ['Any']
                            else:
                                source_addr = ['Any']
                        else:
                            for source_index in config[context]['policies'][policy]['policySrcNet']:
                                if source_index.lower() in ['any', ''] and options.zero_network:
                                    found_in_source = True
                                    source_addr = ['Any']
                                    break
                                policyIPv4_list = []
                                if source_index not in excluded_addresses:
                                    if (source_index in config[context]['addresses']):
                                        for expanded_index in expand_address(config[context]['addresses'],
                                                                             config[context]['addresses'][source_index][
                                                                                 'addrObjId'],
                                                                             config[context]['addressmappings']):
                                            if (expanded_index in config[context]['addresses']):
                                                policyIPv4_list.extend(
                                                    config[context]['addresses'][expanded_index]['IPv4Networks'])
                                            elif (expanded_index in shared['addresses']):
                                                policyIPv4_list.extend(
                                                    shared['addresses'][expanded_index]['IPv4Networks'])
                                    elif (source_index in shared['addresses']):
                                        for expanded_index in expand_address(shared['addresses'],
                                                                             shared['addresses'][source_index][
                                                                                 'addrObjId'],
                                                                             shared['addressmappings']):
                                            policyIPv4_list.extend(shared['addresses'][expanded_index]['IPv4Networks'])
                                            prefix = '*'
                                    else:
                                        if source_index.lower() not in ['any', '']: log(
                                            'UNKNOWN SOURCE "{}"'.format(source_index))
                                        try:
                                            if re.findall('-', source_index) != []:
                                                first, last = source_index.split('-')
                                                for x in ipaddress.summarize_address_range(ipaddress.IPv4Address(first),
                                                                                           ipaddress.IPv4Address(last)):
                                                    policyIPv4_list.extend([x])
                                                    debug('Adding Range to policy list {}'.format(x))
                                            else:
                                                first = source_index
                                                last = source_index
                                                if re.findall('/', first) == []:
                                                    first = first + '/32'
                                                policyIPv4_list.extend([ipaddress.IPv4Network(first)])
                                                debug('Adding network/host to policy list {}'.format(x))
                                        except Exception as e:
                                            # if source_index.lower() not in ['any', '']: log('UNKNOWN SOURCE "{}"'.format(source_index))
                                            log('Exception {} handling unknown source : {}'.format(e, source_index))
                                            pass

                                polSet = IPSet([])
                                srcSet = IPSet([])
                                for x in policyIPv4_list:
                                    polSet.add(str(x))
                                srcSet.add(sourceIPv4.with_netmask)
                                # log('intersection', excluded_networks & polSet)
                                # if excluded_networks not in polSet:
                                if excluded_src_networks & polSet == IPSet([]):
                                    if (srcSet & polSet) or ((
                                                                     source_index.lower() == 'any' or source.lower() == '0.0.0.0/0') and options.zero_network):
                                        if srcSet == polSet:
                                            source_match_type = 'Exact'
                                        elif (srcSet & polSet) == srcSet:
                                            source_match_type = 'Complete'
                                        elif (srcSet & polSet) == polSet:
                                            source_match_type = 'Partial'
                                        elif (source_index.lower() == 'any' or source.lower() == '0.0.0.0/0'):
                                            source_match_type = 'Any'
                                        else:
                                            source_match_type = 'Mixed'
                                        found_in_source = True
                                        source_addr = config[context]['policies'][policy]['policySrcNet']
                                        source_found_index.append(source_index)
                                        # break
                                else:
                                    source_addr = config[context]['policies'][policy]['policySrcNet']
                                    debug('Excluded network found in source - skipping rule')
                        if negate_source:
                            found_in_source = not found_in_source
                        if found_in_source:
                            prefix = ''
                            dest_found_index = []
                            if dest == '0.0.0.0/0':  # and options.zero_network: -- not applicable here
                                found_in_dest = True
                                dest_match_type = "Any"
                                if len(config[context]['policies'][policy]['policyDstNet']) >= 1:
                                    dest_addr = config[context]['policies'][policy]['policyDstNet']
                                    if dest_addr == ['']: dest_addr = ['Any']
                                else:
                                    dest_addr = ['Any']
                            else:
                                for dest_index in config[context]['policies'][policy]['policyDstNet']:
                                    # print(dest_index)
                                    if dest_index.lower() in ['any', ''] and options.zero_network:
                                        found_in_dest = True
                                        dest_addr = ['Any']
                                        break
                                    policyIPv4_list = []
                                    if dest_index in config[context]['addresses'] or dest_index.lower() in ['any', '']:
                                        dest_addr = ['']
                                        pass
                                    else:
                                        print('{} not found in config'.format(dest_index))
                                    if dest_index not in excluded_addresses:
                                        if (dest_index in config[context]['addresses']):
                                            for expanded_index in expand_address(config[context]['addresses'],
                                                                                 config[context]['addresses'][
                                                                                     dest_index]['addrObjId'],
                                                                                 config[context]['addressmappings']):
                                                if (expanded_index in config[context]['addresses']):
                                                    policyIPv4_list.extend(
                                                        config[context]['addresses'][expanded_index]['IPv4Networks'])
                                                elif (expanded_index in shared['addresses']):
                                                    policyIPv4_list.extend(
                                                        shared['addresses'][expanded_index]['IPv4Networks'])
                                                # else:
                                                #    print('{} not found in config'.format(dest_index))

                                        elif (dest_index in shared['addresses']):
                                            for expanded_index in expand_address(shared['addresses'],
                                                                                 shared['addresses'][dest_index][
                                                                                     'addrObjId'],
                                                                                 shared['addressmappings']):
                                                policyIPv4_list.extend(
                                                    shared['addresses'][expanded_index]['IPv4Networks'])
                                                prefix = '*'
                                        # else:
                                        #
                                        else:
                                            if dest_index.lower() not in ['any', '']:  log(
                                                'UNKNOWN DEST in policy {} "{}"'.format(
                                                    config[context]['policies'][policy]['policyName'], dest_index))
                                            try:
                                                if re.findall('-', dest_index) != []:
                                                    first, last = dest_index.split('-')
                                                    for x in ipaddress.summarize_address_range(
                                                            ipaddress.IPv4Address(first), ipaddress.IPv4Address(last)):
                                                        policyIPv4_list.extend([x])
                                                else:
                                                    first = dest_index
                                                    last = dest_index
                                                    if re.findall('/', first) == []:
                                                        first = first + '/32'
                                                    policyIPv4_list.extend([ipaddress.IPv4Network(first)])

                                            except Exception as e:
                                                pass
                                    polSet = IPSet([])
                                    destSet = IPSet([])
                                    for x in policyIPv4_list:
                                        polSet.add(str(x))
                                    destSet.add(destIPv4.with_netmask)
                                    # log(polSet)
                                    # log('intersection', excluded_networks & polSet)
                                    if excluded_dst_networks & polSet == IPSet([]):
                                        if (polSet & destSet) or ((
                                                                          dest_index.lower() == 'any' or dest.lower() == '0.0.0.0/0') and options.zero_network):
                                            if destSet == polSet:
                                                dest_match_type = 'Exact'
                                            elif (destSet & polSet) == destSet:
                                                dest_match_type = 'Complete'
                                            elif (destSet & polSet) == polSet:
                                                dest_match_type = 'Partial'
                                            elif (dest_index.lower() == 'any' or dest.lower() == '0.0.0.0/0'):
                                                dest_match_type = 'Any'
                                            else:
                                                dest_match_type = 'Mixed'
                                            found_in_dest = True
                                            dest_addr = config[context]['policies'][policy]['policyDstNet']
                                            dest_found_index.append(dest_index)
                                            if dest_match_type == 'Exact':
                                                debug(policyIPv4_list)
                                                debug(polSet)
                                                debug(destSet)
                                            # break
                                    else:
                                        dest_addr = config[context]['policies'][policy]['policyDstNet']
                                        debug('Excluded network found in dest - skipping rule')
                        if negate_dest:
                            found_in_dest = not found_in_dest
                        if found_in_dest:
                            # perform checking of service
                            # verify that get port of icmp returns "any"
                            if (config[context]['policies'][policy]['policyDstSvc'] == [
                                ''] and options.zero_service) or (
                                    [x.lower() for x in config[context]['policies'][policy]['policyDstSvc']] == [
                                'any'] and options.zero_service) or config[context]['policies'][policy][
                                'policyDstSvc'] == ['application-default']:
                                found_in_service = True
                                if config[context]['policies'][policy]['policyDstSvc'] == ['']:
                                    dest_service = ['any']
                                else:
                                    dest_service = config[context]['policies'][policy]['policyDstSvc']
                            elif service == 'any/any':  # and options.zero_network:
                                found_in_service = True
                                dest_service = config[context]['policies'][policy]['policyDstSvc']
                            else:
                                for dest_index in config[context]['policies'][policy]['policyDstSvc']:
                                    if (dest_index in config[context]['services']):
                                        for expanded_index in expand_service(config[context]['services'],
                                                                             config[context]['services'][dest_index][
                                                                                 'svcObjId'],
                                                                             config[context]['servicemappings']):
                                            policy_prot = get_prot_of(config[context]['services'], expanded_index)
                                            # start_port, end_port = get_port_of(config[context]['services'],expanded_index)
                                            policy_ports = get_ports_of(config[context]['services'], expanded_index)
                                            # log(policy_ports)
                                            # if start_port=='': start_port='0'
                                            # if end_port=='': end_port='0'
                                            ## svcPortSet FIX
                                            try:
                                                if ((prot.lower() == policy_prot or prot.lower() == 'any') and (
                                                        int(portnum) in policy_ports)) or (
                                                        dest_index.lower() == 'any' and options.zero_network) or (
                                                        service.lower() == 'any/any' and options.zero_network):
                                                    if found_in_service == False:
                                                        found_in_service = True
                                                        dest_service = config[context]['policies'][policy][
                                                            'policyDstSvc']
                                                        break
                                            except Exception as e:
                                                # print(type(prot.lower()))
                                                print(prot.lower())

                                                # print(type(policy_prot))
                                                print(policy_prot)
                                                print("'" + start_port + "'")
                                                print(end_port)
                                                print(expanded_index)
                                                log(e)

                                    if (dest_index in shared['services']):
                                        for expanded_index in expand_service(shared['services'],
                                                                             shared['services'][dest_index]['svcObjId'],
                                                                             shared['servicemappings']):
                                            policy_prot = get_prot_of(shared['services'], expanded_index).lower()
                                            # start_port, end_port = get_port_of(shared['services'],expanded_index)
                                            policy_ports = get_ports_of(config[context]['services'], expanded_index)
                                            # if start_port=='': start_port='0'
                                            # if end_port=='': end_port='0'
                                            if ((
                                                        prot.lower() == policy_prot or prot.lower() == 'any') and portnum in policy_ports) or dest_index.lower() == 'any' or (
                                                    service.lower() == 'any/any' and options.zero_network):
                                                if found_in_service == False:
                                                    found_in_service = True
                                                    dest_service = config[context]['policies'][policy]['policyDstSvc']
                                                    break

                        if found_in_source and found_in_dest and found_in_service and (
                                options.matchtypes in [['all'], ['any']] or (
                                source_match_type.lower() in [x.lower() for x in
                                                              options.matchtypes] or source_match_type.lower() == 'any') and (
                                        dest_match_type.lower() in [x.lower() for x in
                                                                    options.matchtypes] or dest_match_type.lower() == 'any')):
                            # I believe zone/net/service is empty if "any", so temporarily set these values to variables before printing them
                            if config[context]['policies'][policy]['policyEnabled'] == '0':
                                enabled = "."
                            elif config[context]['policies'][policy]['policyEnabled'] == '1':
                                if options.web or options.csv:
                                    enabled = 'Y'
                                else:
                                    enabled = u'\u2713'

                            comment = re.sub('"', "'", str(config[context]['policies'][policy]['policyComment']))
                            if 'policyUUID' in config[context]['policies'][policy]:
                                uuid = config[context]['policies'][policy]['policyUUID']
                            elif 'policyUid' in config[context]['policies'][policy]:
                                uuid = config[context]['policies'][policy]['policyUid']
                            else:
                                uuid = 'unknown'

                            if config[context]['policies'][policy]['policyAction'] == '0':
                                action = 'deny'
                            elif config[context]['policies'][policy]['policyAction'] == '1':
                                action = 'discard'
                            elif config[context]['policies'][policy]['policyAction'] == '2':
                                action = 'allow'
                            elif config[context]['policies'][policy]['policyAction'] == '3':
                                action = 'CltAuth'
                            name = config[context]['policies'][policy]['policyName']

                            if config[context]['policies'][policy]['policySrcZone'] == []:
                                source_zone = ['any']
                            else:
                                source_zone = config[context]['policies'][policy]['policySrcZone']

                            if config[context]['policies'][policy]['policyDstZone'] == []:
                                dest_zone = ['any']
                            else:
                                dest_zone = config[context]['policies'][policy]['policyDstZone']

                            policymatches += 1

                            if config[context]['policies'][policy]['policySrcZone'] == [] or \
                                    config[context]['policies'][policy]['policySrcZone'] == ['']:
                                source_zones = ['any']
                            else:
                                source_zones = config[context]['policies'][policy]['policySrcZone']

                            if config[context]['policies'][policy]['policyDstZone'] == [] or \
                                    config[context]['policies'][policy]['policyDstZone'] == ['']:
                                dest_zones = ['any']
                            else:
                                dest_zones = config[context]['policies'][policy]['policyDstZone']

                            if config[context]['policies'][policy]['policySrcNet'] == [] or \
                                    config[context]['policies'][policy]['policySrcNet'] == ['']:
                                source_nets = ['any']
                            else:
                                source_nets = config[context]['policies'][policy]['policySrcNet']

                            if config[context]['policies'][policy]['policyDstNet'] == [] or \
                                    config[context]['policies'][policy]['policyDstNet'] == ['']:
                                dest_nets = ['any']
                            else:
                                dest_nets = config[context]['policies'][policy]['policyDstNet']

                            if config[context]['policies'][policy]['policyDstSvc'] == [] or \
                                    config[context]['policies'][policy]['policyDstSvc'] == ['']:
                                dest_services = ['any']
                            else:
                                dest_services = config[context]['policies'][policy]['policyDstSvc']
                            if 'policySection' in config[context]['policies'][policy]:
                                section = config[context]['policies'][policy]['policySection']
                            else:
                                section = 'Unknown'

                            if options.html:
                                if policymatches == 1:
                                    log('<p align=center><font size=8 >')
                                    log('context: ' + context)
                                    log('</font></p>')
                                    log('<table border="1" width="90%">')
                                    if config[context]['config']['fw_type'] == 'checkpoint':
                                        log('<th>Enabled</th><th>Action</th><th>PolicyName</th><th>UiNum</th><th>IndexNum</th><th>Source Address</th><th>Destination Address</th><th>Service</th>')
                                    else:
                                        log('<th>Enabled</th><th>Action</th><th>Name</th><th>Source Zone</th><th>Dest Zone</th><th>Source Address</th><th>Destination Address</th><th>Service</th>')
                                if enabled != "Y":
                                    trcolor = '#aaaaaa'
                                elif action.lower() == 'allow':
                                    trcolor = '#00aa00'
                                else:
                                    trcolor = '#aa0000'
                                log('<tr bgcolor="' + trcolor + '">')
                                log('<td>' + enabled + '</td>')
                                log('<td>' + action + '</td>')
                                log('<td>' + name + '</td>')
                                ## only do src/dest zones for non-checkpoint
                                ## for checkpoint, add ruleUI number
                                if config[context]['config']['fw_type'] == 'checkpoint':
                                    log('<td>' + str(config[context]['policies'][policy]['policyUiNum']) + '</td>')
                                    log('<td>' + str(config[context]['policies'][policy]['policyNum']) + '</td>')
                                else:
                                    log('<td>')
                                    for source_zone in source_zones:
                                        log(url_unquote(source_zone) + '<br>')
                                    log('</td>')
                                    log('<td>')
                                    for dest_zone in dest_zones:
                                        log(url_unquote(dest_zone) + '<br>')
                                    log('</td>')
                                log('<td>')
                                for source_address in source_nets:
                                    if source_address in source_found_index:
                                        log('<p style="color:green">{}</p><br>'.format(url_unquote(source_address)))
                                    else:
                                        log(url_unquote(source_address) + '<br>')
                                log('</td>')
                                log('<td>')
                                for dest_address in dest_nets:
                                    if dest_address in dest_found_index:
                                        log('<p style="color:green">{}</p><br>'.format(url_unquote(dest_address)))
                                    else:
                                        log(url_unquote(dest_address) + '<br>')
                                log('</td>')
                                log('<td>')
                                for dest_service in dest_services:
                                    log(url_unquote(dest_service) + '<br>')
                                log('</td>')
                                log('<tr>')
                            elif options.csv:
                                with codecs.open(options.csv, 'a+', 'utf-8') as outfile:
                                    if policymatches == 1:  ## this is to print a header line
                                        if config[context]['config']['fw_type'] == 'checkpoint':
                                            outfile.write(
                                                'Context,Enabled,Action,PolicyName,Section,UiNum,IndexNum,Source Address,Destination Address,Service,Comment,UUID\n')

                                        else:
                                            outfile.write(
                                                'Context,Enabled,Action,Name,Source Zone,Dest Zone,Source Address,Destination Address,Service,Comment,UUID\n')

                                    # with codecs.open('/dev/stdout', 'w', 'utf-8') as outfile:
                                    # outfile.write('-' * 180+'\n')
                                    # outfile.write ('context: ' + context + '\n')
                                    # outfile.write('\n')

                                    outfile.write('"{}",'.format(context))
                                    outfile.write('"{}",'.format(enabled))
                                    outfile.write('"{}",'.format(action))
                                    outfile.write('"{}",'.format(name))
                                    ## only do src/dest zones for non-checkpoint
                                    ## for checkpoint, add ruleUI number
                                    if config[context]['config']['fw_type'] == 'checkpoint':
                                        outfile.write('"{}",'.format(str(section)))
                                        outfile.write(
                                            '"{}",'.format(str(config[context]['policies'][policy]['policyUiNum'])))
                                        outfile.write(
                                            '"{}",'.format(str(config[context]['policies'][policy]['policyNum'])))
                                    # else:

                                    outfile.write('"')
                                    if config[context]['config']['fw_type'] != 'checkpoint':
                                        for source_zone in source_zones:
                                            outfile.write('{}'.format(url_unquote(source_zone)))
                                            if source_zone == source_zones[-1]:
                                                outfile.write('",')
                                            else:
                                                outfile.write('\n')
                                        outfile.write('"')
                                        for dest_zone in dest_zones:
                                            outfile.write('{}'.format(url_unquote(dest_zone)))
                                            if dest_zone == dest_zones[-1]:
                                                outfile.write('",')
                                            else:
                                                outfile.write('\n')
                                        outfile.write('"')
                                    for source_address in source_nets:
                                        if source_address in source_found_index:
                                            sourceprefix = '*'
                                        else:
                                            sourceprefix = ''
                                        outfile.write('{}{}'.format(sourceprefix, url_unquote(source_address)))
                                        if source_address == source_nets[-1]:
                                            outfile.write('",')
                                        else:
                                            outfile.write('\n')
                                    outfile.write('"')
                                    for dest_address in dest_nets:
                                        if dest_address in dest_found_index:
                                            destprefix = '*'
                                        else:
                                            destprefix = ''
                                        outfile.write('{}{}'.format(destprefix, url_unquote(dest_address)))
                                        if dest_address == dest_nets[-1]:
                                            outfile.write('",')
                                        else:
                                            outfile.write('\n')
                                    outfile.write('"')
                                    for dest_service in dest_services:
                                        outfile.write('{}'.format(url_unquote(dest_service)))
                                        if dest_service == dest_services[-1]:
                                            outfile.write('",')
                                        else:
                                            outfile.write('\n')
                                    outfile.write('"{}",'.format(comment))
                                    outfile.write('"{}"'.format(uuid))
                                    outfile.write('\n')  # end of line

                            else:
                                # print (source_match_type)
                                if policymatches == 1:
                                    log('Context : ' + context)
                                    if config[context]['config']['fw_type'] == 'checkpoint':
                                        log('{:2.2s} | {:8.8s} | {:15.15s} | {:30.30s} | {:8.8s} | {:8.8s} | {:10.10s} | {:60.60s} | {:10.10s} | {:40.40s} | {:40.40s}'.format(
                                            'En', 'Action', 'CMA', 'Policy Name', 'Rule UI#', 'Rule Idx', 'Src_match',
                                            'Source Address', 'Dst_match', 'Destination Address', 'Service'))
                                    else:
                                        log('{:2.2s} | {:8.8s} | {:30.30s} | {:20.20s} | {:20.20s} | {:10.10s} | {:60.60s} | {:10.10s} | {:40.40s} | {:40.40s}'.format(
                                            'En', 'Action', 'Rule Name', 'Source Zone', 'Destination Zone', 'Src_match',
                                            'Source Address', 'Dst_match', 'Destination Address', 'Service'))
                                    log('=' * 250)
                                # if config[context]['config']['fw_type']=='checkpoint':
                                #    log ('{:2.2s} {:8.8s} {:15.15s} {:30.30s} {:8.8s} {:8.8s} {:10.10s} {:60.60s} {:10.10s} {:40.40s} {:40.40s}'.format(enabled, action, context, url_unquote(name), str(config[context]['policies'][policy]['policyUiNum']), str(config[context]['policies'][policy]['policyNum']), str(source_match_type), url_unquote(source_addr[0]), str(dest_match_type), url_unquote(dest_addr[0]), url_unquote(dest_service[0])))
                                # else:
                                #    log ('{:2.2s} {:8.8s} {:30.30s} {:20.20s} {:20.20s} {:10.10s} {:60.60s} {:10.10s} {:40.40s} {:40.40s}'.format(enabled, action, url_unquote(name), url_unquote(source_zone[0]), url_unquote(dest_zone[0]), str(source_match_type), url_unquote(source_addr[0]), str(dest_match_type), url_unquote(dest_addr[0]), url_unquote(dest_service[0])))
                                longestval = max(len(source_addr), len(dest_addr), len(dest_service), len(source_zone),
                                                 len(dest_zone))
                                # if longestval>1:
                                for index in range(0, longestval):
                                    tmpsrc = ''
                                    tmpdst = ''
                                    tmpsvc = ''
                                    tmpszone = ''
                                    tmpdzone = ''
                                    srcprefix = ''
                                    dstprefix = ''
                                    if index < len(source_zone):
                                        tmpszone = source_zone[index]
                                    if index < len(dest_zone):
                                        tmpdzone = dest_zone[index]
                                    if index < len(source_addr):
                                        tmpsrc = source_addr[index]
                                    if index < len(dest_addr):
                                        tmpdst = dest_addr[index]
                                    if index < len(dest_service):
                                        tmpsvc = dest_service[index]
                                    if tmpsrc in source_found_index:  # and source_found_index != []:
                                        srcprefix = '*'
                                    if tmpdst in dest_found_index:  # and dest_found_index != []:
                                        dstprefix = '*'
                                    if index == 0:
                                        if config[context]['config']['fw_type'] == 'checkpoint':
                                            log('{:2.2s} | {:8.8s} | {:15.15s} | {:30.30s} | {:8.8s} | {:8.8s} | {:10.10s} | {:1.1s}{:60.60s} | {:10.10s} | {:1.1s}{:40.40s} | {:40.40s}'.format(
                                                enabled, action, context, url_unquote(name),
                                                str(config[context]['policies'][policy]['policyUiNum']),
                                                str(config[context]['policies'][policy]['policyNum']),
                                                str(source_match_type), srcprefix, url_unquote(source_addr[0]),
                                                str(dest_match_type), dstprefix, url_unquote(dest_addr[0]),
                                                url_unquote(dest_service[0])))
                                        else:
                                            log('{:2.2s} | {:8.8s} | {:30.30s} | {:20.20s} | {:20.20s} | {:10.10s} | {:1.1s}{:60.60s} | {:10.10s} | {:1.1s}{:40.40s} | {:40.40s}'.format(
                                                enabled, action, url_unquote(name), url_unquote(source_zone[0]),
                                                url_unquote(dest_zone[0]), str(source_match_type), srcprefix,
                                                url_unquote(source_addr[0]), str(dest_match_type), dstprefix,
                                                url_unquote(dest_addr[0]), url_unquote(dest_service[0])))
                                    else:
                                        if config[context]['config']['fw_type'] == 'checkpoint':
                                            log('{:2.2s} | {:8.8s} | {:15.15s} | {:30.30s} | {:8.8s} | {:8.8s} | {:10.10s} | {:1.1s}{:60.60s} | {:10.10s} | {:1.1s}{:40.40s} | {:40.40s}'.format(
                                                '', '', '', '', '', '', '', srcprefix, url_unquote(tmpsrc), '',
                                                dstprefix, url_unquote(tmpdst), url_unquote(tmpsvc)))
                                        else:
                                            log('{:2.2s} | {:8.8s} | {:30.30s} | {:20.20s} | {:20.20s} | {:10.10s} | {:1.1s}{:60.60s} | {:10.10s} | {:1.1s}{:40.40s} | {:40.40s}'.format(
                                                '', '', '', tmpszone, tmpdzone, '', str(source_match_type), srcprefix,
                                                url_unquote(tmpsrc), '', str(dest_match_type), dstprefix,
                                                url_unquote(tmpdst), url_unquote(tmpsvc)))
                                log('-' * 250)
                                if modify:
                                    if modify_group not in config[context]['policies'][policy]['policyDstNet']:
                                        for addr in modify_addr:
                                            log('addelement fw_policies {} rule:{}:dst:\'\' network_objects:{}'.format(
                                                url_unquote(name), config[context]['policies'][policy]['policyNum'],
                                                addr))
                                    else:
                                        log('Rule already contains group: ' + modify_group)

                if policymatches != 0 and options.web:
                    log('</table>')
                    log('<hr>')

                if policymatches == 0:
                    nomatches.append(context)
    if len(nomatches) > 0:
        log('No matches were found for the following contexts')
        log('"{}'.format(nomatches))
        for nomatch in nomatches:
            log(nomatch)
            if options.web: log('<br>')
    return


def find_ip_address_in_policy(policies, addresses, address_map, ip_address):
    ## Given a list of IP addresses, find all the policy objects that contain the address
    ## CHANGEME - NOT WORKING AS expand_address is at least one thing broken here
    ## need to also receive address map config

    ## not working properly for ranges - false positives

    ## this routine is not really needed as the inverse match routines now perform this function, although that matches policies and addresses

    import ipaddress
    import re
    return_list = []
    for ip_to_find in ip_address:
        if not re.findall('/', ip_to_find):  ## if netmask is not given, add /32 host mask
            ip_to_find = ip_to_find + '/32'
        log('-' * 120)
        log('Searching policies for : ' + ip_to_find)
        log('-' * 120)
        log('%-60s :' % 'Rule Description', end=' ')
        log('%-30s :' % 'Root Object Name', end=' ')
        log('%-30s' % 'Member Address Object')
        log('-' * 120)
        for policy_index in policies:
            if policies[policy_index]['policySrcNet'] != []:
                for src in range(0, len(policies[policy_index]['policySrcNet'])):
                    for expanded_index in expand_address(addresses, policies[policy_index]['policySrcNet'][src],
                                                         address_map):
                        for network_index in range(0, len(addresses[expanded_index]['IPv4Networks'])):
                            if ipaddress.IPv4Network(ip_to_find, strict=False).overlaps(
                                    addresses[expanded_index]['IPv4Networks'][network_index]):
                                try:
                                    policydesc = re.sub(r'\n', '##', policies[policy_index]['policyName'][:60])
                                except:
                                    policydesc = ''
                                log('{:60.60}'.format(policydesc), end=' : ')
                                log('{:30.30}'.format(policies[policy_index]['policySrcNet'][src]), end=' : ')
                                log('{:30.30}'.format(expanded_index))
                                return_list.append(expanded_index)
            if policies[policy_index]['policyDstNet'] != []:
                for dst in range(0, len(policies[policy_index]['policyDstNet'])):
                    for expanded_index in expand_address(addresses, policies[policy_index]['policyDstNet'][dst],
                                                         address_map):
                        for network_index in range(0, len(addresses[expanded_index]['IPv4Networks'])):
                            if ipaddress.IPv4Network(ip_to_find, strict=False).overlaps(
                                    addresses[expanded_index]['IPv4Networks'][network_index]):
                                try:
                                    policydesc = re.sub(r'\n', '##', policies[policy_index]['policyName'][:60])
                                except:
                                    policydesc = ''
                                log('{:60.60}'.format(policydesc), end=' : ')
                                log('{:30.30}'.format(policies[policy_index]['policyDstNet'][dst]), end=' : ')
                                log('{:30.30}'.format(expanded_index))

                                return_list.append(expanded_index)
    return return_list


def find_description(policies, descriptions):
    ## Given a string, find all the policy objects that contain the string given
    ## What fields should be checked?
    ## Should it work as a regex?

    ## Test this

    return_list = []
    for desc_to_find in descriptions:
        log('-' * 120)
        log('Searching policies for : ' + desc_to_find)
        log('-' * 120)
        log('%-60s :' % 'Rule Description', end=' ')
        log('%30s :' % 'Source', end=' ')
        log('%-30s' % 'Destination')
        log('-' * 120)
        for policy_index in policies:
            if re.findall(desc_to_find, policies[policy_index]['policyComment'], flags=re.IGNORECASE):
                log('%-60s :' % policies[policy_index]['policyComment'], end=' ')
                log('%30s :' % policies[policy_index]['policySrcNet'], end=' ')
                log('%-30s' % policies[policy_index]['policyDstNet'])
                return_list.append('')
    return return_list
