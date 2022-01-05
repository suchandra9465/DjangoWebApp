import ipaddress
import re
from netaddr import IPSet
from urllib.parse import unquote as url_unquote
import codecs


# Todo: What is config?
def get_prot_of(services, service_object, config):
    ## Given a service object name, will return the IP protocol number of it.

    if service_object not in services:
        # Todo: If service object is not in service get it from config
        services = config['shared']['services']
    if service_object == '0':
        return 'any'
    if services[service_object]['svcObjIpType'] == '6':
        return 'tcp'
    elif services[service_object]['svcObjIpType'] == '17':
        return 'udp'
    elif services[service_object]['svcObjIpType'] == '1':
        return 'icmp'
    else:
        return services[service_object]['svcObjIpType']
    return


def get_port_of(services, service_object, config):
    ## Given a service object name, will return the L4 protocol number of it.

    if service_object not in services:
        # Todo: If service object is not in service get it from config
        services = config['shared']['services']
    if service_object == '0':
        return 'any', 'any'
    else:
        return services[service_object]['svcObjPort1'], services[
            service_object]['svcObjPort2']
    return


def get_ports_of(services, service_object, config):
    ## Given a service object name, will return the L4 protocol number of it.

    portlist = []
    if service_object == '0':
        return ['any']  # list(range(1))
    if service_object not in services:
        # Todo: If service object is not in service get it from config
        services = config['shared']['services']
    if service_object in services:
        if services[service_object]['svcObjType'] == '1':
            if services[service_object]['svcObjPort1'] == '':
                # debug(services[service_object])
                services[service_object]['svcObjPort1'] = '0'
            if services[service_object]['svcObjPort2'] == '':
                services[service_object]['svcObjPort2'] = services[
                    service_object]['svcObjPort1']
            # log(services[service_object]['svcObjPort1'])
            # log(services[service_object]['svcObjPort2'])
            if services[service_object]['svcObjPort1'] == 'echo-request':
                services[service_object]['svcObjPort1'] = '8'
            elif services[service_object]['svcObjPort1'] == 'echo-reply':
                services[service_object]['svcObjPort1'] = '0'
            elif services[service_object]['svcObjPort1'] == 'alternative-host':
                services[service_object]['svcObjPort1'] = '6'
            elif services[service_object][
                'svcObjPort1'] == 'mobile-registration-reply':
                services[service_object]['svcObjPort1'] = '36'
            elif services[service_object]['svcObjPort1'] in [
                'mobile-registration-request', 'mobile-host-redirect',
                'datagram-error', 'traceroute', 'address-mask-reply',
                'address-mask-request', 'info-reply', 'info-request',
                'timestamp-reply', 'timestamp', 'parameter-problem'
            ]:
                services[service_object]['svcObjPort1'] = '99'
                services[service_object]['svcObjPort2'] = '99'

            if services[service_object][
                'svcObjPort2'] == 'echo-request':  ## needed to fix Port2 value for icmp objects read in via sonicwall API
                services[service_object]['svcObjPort2'] = '8'
            elif services[service_object]['svcObjPort2'] == 'echo-reply':
                services[service_object]['svcObjPort2'] = '0'
            elif services[service_object]['svcObjPort2'] == 'alternative-host':
                services[service_object]['svcObjPort2'] = '6'
            elif services[service_object][
                'svcObjPort2'] == 'mobile-registration-reply':
                services[service_object]['svcObjPort2'] = '36'
            elif services[service_object]['svcObjPort2'] in [
                'mobile-registration-request', 'mobile-host-redirect',
                'datagram-error', 'traceroute'
            ]:
                services[service_object]['svcObjPort2'] = '99'
            try:
                tmp = int(services[service_object]['svcObjPort1'])
            except:
                services[service_object]['svcObjPort1'] = '99'
                services[service_object]['svcObjPort2'] = '99'

            return list(
                range(int(services[service_object]['svcObjPort1']),
                      int(services[service_object]['svcObjPort2']) + 1))
        elif services[service_object]['svcObjType'] == '4':
            for ports in services[service_object]['svcObjPortSet']:
                if re.findall('-', ports) != []:
                    first, last = ports.split('-')
                    portlist.extend(list(range(int(first), int(last) + 1)))
                else:
                    portlist.extend([int(ports)])
        elif services[service_object][
            'svcObjType'] == '4':  ## add support to get port list for service group
            pass
        return portlist

    return []


def expand_service(service_dict,
                   service_object,
                   service_map,
                   config,
                   inc_group=False):
    ## Takes a service group object (by name) and expands it into a list of all of its individual service objects

    expanded_services = []
    if service_object.lower() in [name.lower() for name in service_dict
                                  ]:  # do case insensitive match
        if service_object in service_dict:
            if service_dict[service_object]['svcObjIpType'] != '0':
                expanded_services.append(service_object)
            else:
                if inc_group:
                    expanded_services.append(service_object)
                if service_object in service_map:
                    for member in service_map[service_dict[service_object]
                    ['svcObjId']]:
                        for members in expand_service(service_dict, member,
                                                      service_map, config,
                                                      inc_group):
                            expanded_services.append(members)
        elif service_object in config['shared']['services']:
            if config['shared']['services'][service_object][
                'svcObjIpType'] != '0':
                expanded_services.append(service_object)
            else:
                if inc_group:
                    expanded_services.append(service_object)
                if service_object in config['shared']['servicemappings']:
                    for member in config['shared']['servicemappings'][config[
                        'shared']['services'][service_object]['svcObjId']]:
                        for members in expand_service(
                                config['shared']['services'], member,
                                config['shared']['servicemappings'], config,
                                inc_group):
                            expanded_services.append(members)
    return expanded_services


def expand_address(address_dict,
                   address_object,
                   address_map,
                   config,
                   inc_group=False):
    ## Takes an address group object (by name) and expands it into a list of all of its individual address objects

    expanded_addresses = []
    if address_object in address_dict:
        if 'addrObjType' in address_dict[address_object]:
            if address_dict[address_object]['addrObjType'] != '8':
                expanded_addresses.append(address_object)
            else:
                if inc_group:
                    expanded_addresses.append(address_object)
                if address_object in address_map:
                    # for group_members in address_map[address_dict[address_object]['addrObjId']]:
                    for group_members in address_map[address_object]:
                        for group_member in expand_address(
                                address_dict, group_members, address_map,
                                config, inc_group):
                            expanded_addresses.append(group_member)
    elif 'addresses' in config['shared']:
        if address_object in config['shared']['addresses']:
            if 'addrObjType' in config['shared']['addresses'][address_object]:
                if config['shared']['addresses'][address_object][
                    'addrObjType'] != '8':
                    expanded_addresses.append(address_object)
                else:
                    if inc_group:
                        expanded_addresses.append(address_object)
                    if address_object in address_map:
                        for group_members in config['shared'][
                            'addressesmappings'][config['shared'][
                            'addresses'][address_object]['addrObjId']]:
                            for group_member in expand_address(
                                    config['shared']['addresses'],
                                    group_members,
                                    config['shared']['addressesmappings'],
                                    config, inc_group):
                                expanded_addresses.append(group_member)

    return expanded_addresses


def find_matching_rules2(config,
                         shared,
                         params_list,
                         contextnames,
                         options,
                         job_id,
                         modify=None):
    excluded_addresses = []
    excluded_addresses = options.excludeaddress
    excluded_src_networks = IPSet([addr for addr in options.excludesrcnetwork])
    excluded_dst_networks = IPSet([addr for addr in options.excludedstnetwork])

    for params in params_list:
        if params.count(',') != 2:
            log('Search string must contain exactly 3 fields source_ip,destination_ip,service'
                )
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

        source, dest, service = params.split(',')

        if source.lower() == 'any':
            source = '0.0.0.0/0'
        if re.findall('/', source):
            src_ipaddr, src_netmask = source.split('/')
        else:
            src_ipaddr = source
            src_netmask = '32'
        sourceIPv4 = ipaddress.IPv4Network(src_ipaddr + '/' + src_netmask,
                                           strict=False)
        firstsource = sourceIPv4[0]
        lastsource = sourceIPv4[-1]

        if dest.lower() == 'any':
            dest = '0.0.0.0/0'
        if re.findall('/', dest):
            dst_ipaddr, dst_netmask = dest.split('/')
        else:
            dst_ipaddr = dest
            dst_netmask = '32'
        destIPv4 = ipaddress.IPv4Network(dst_ipaddr + '/' + dst_netmask,
                                         strict=False)
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
            log(context)
            policymatches = 0
            if 'policies' in config[context]:
                for policy in config[context]['policies']:
                    source_match_type = None
                    dest_match_type = None
                    if 'policySrcNegate' in config[context]['policies'][
                        policy]:
                        negate_source = config[context]['policies'][policy][
                            'policySrcNegate']
                    else:
                        negate_source = False
                    if negate_source:
                        pass
                        # log('SOURCE NEGATED Idx: {} UI: {} '.format(str(config[context]['policies'][policy]['policyNum']), str(config[context]['policies'][policy]['policyUiNum'])))
                    if 'policyDstNegate' in config[context]['policies'][
                        policy]:
                        negate_dest = config[context]['policies'][policy][
                            'policyDstNegate']
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
                            if len(config[context]['policies'][policy]
                                   ['policySrcNet']) >= 1:
                                source_addr = config[context]['policies'][
                                    policy]['policySrcNet']
                                if source_addr == ['']: source_addr = ['Any']
                            else:
                                source_addr = ['Any']
                        else:
                            for source_index in config[context]['policies'][
                                policy]['policySrcNet']:
                                if source_index.lower() in [
                                    'any', ''
                                ] and options.zero_network:
                                    found_in_source = True
                                    source_addr = ['Any']
                                    break
                                policyIPv4_list = []
                                if source_index not in excluded_addresses:
                                    if (source_index
                                            in config[context]['addresses']):
                                        for expanded_index in expand_address(
                                                config[context]['addresses'],
                                                config[context]['addresses']
                                                [source_index]['addrObjId'],
                                                config[context]
                                                ['addressmappings'], config):
                                            if (expanded_index
                                                    in config[context]
                                                    ['addresses']):
                                                policyIPv4_list.extend(
                                                    config[context]
                                                    ['addresses']
                                                    [expanded_index]
                                                    ['IPv4Networks'])
                                            elif (expanded_index
                                                  in shared['addresses']):
                                                policyIPv4_list.extend(
                                                    shared['addresses']
                                                    [expanded_index]
                                                    ['IPv4Networks'])
                                    elif (source_index in shared['addresses']):
                                        for expanded_index in expand_address(
                                                shared['addresses'],
                                                shared['addresses']
                                                [source_index]['addrObjId'],
                                                shared['addressmappings'],
                                                config):
                                            policyIPv4_list.extend(
                                                shared['addresses']
                                                [expanded_index]
                                                ['IPv4Networks'])
                                            prefix = '*'
                                    else:
                                        if source_index.lower() not in [
                                            'any', ''
                                        ]:
                                            log('UNKNOWN SOURCE "{}"'.format(
                                                source_index))
                                        try:
                                            if re.findall('-', source_index):
                                                first, last = source_index.split(
                                                    '-')
                                                for x in ipaddress.summarize_address_range(
                                                        ipaddress.IPv4Address(
                                                            first),
                                                        ipaddress.IPv4Address(
                                                            last)):
                                                    policyIPv4_list.extend([x])
                                                    debug(
                                                        'Adding Range to policy list {}'
                                                            .format(x))
                                            else:
                                                first = source_index
                                                last = source_index
                                                if not re.findall('/', first):
                                                    first = first + '/32'
                                                policyIPv4_list.extend([
                                                    ipaddress.IPv4Network(
                                                        first)
                                                ])
                                                debug(
                                                    'Adding network/host to policy list {}'
                                                        .format(x))
                                        except Exception as e:
                                            # if source_index.lower() not in ['any', '']: log('UNKNOWN SOURCE "{}"'.format(source_index))
                                            log('Exception {} handling unknown source : {}'
                                                .format(e, source_index))
                                            pass

                                polSet = IPSet([])
                                srcSet = IPSet([])
                                for x in policyIPv4_list:
                                    polSet.add(str(x))
                                srcSet.add(sourceIPv4.with_netmask)
                                # log('intersection', excluded_networks & polSet)
                                # if excluded_networks not in polSet:
                                if excluded_src_networks & polSet == IPSet([]):
                                    if (srcSet & polSet) or (
                                            (source_index.lower() == 'any'
                                             or source.lower() == '0.0.0.0/0')
                                            and options.zero_network):
                                        if srcSet == polSet:
                                            source_match_type = 'Exact'
                                        elif (srcSet & polSet) == srcSet:
                                            source_match_type = 'Complete'
                                        elif (srcSet & polSet) == polSet:
                                            source_match_type = 'Partial'
                                        elif (source_index.lower() == 'any' or
                                              source.lower() == '0.0.0.0/0'):
                                            source_match_type = 'Any'
                                        else:
                                            source_match_type = 'Mixed'
                                        found_in_source = True
                                        source_addr = config[context][
                                            'policies'][policy]['policySrcNet']
                                        source_found_index.append(source_index)
                                        # break
                                else:
                                    source_addr = config[context]['policies'][
                                        policy]['policySrcNet']
                                    debug('Excluded network found in source - skipping rule')
                        if negate_source:
                            found_in_source = not found_in_source
                        if found_in_source:
                            prefix = ''
                            dest_found_index = []
                            if dest == '0.0.0.0/0':  # and options.zero_network: -- not applicable here
                                found_in_dest = True
                                dest_match_type = "Any"
                                if len(config[context]['policies'][policy]
                                       ['policyDstNet']) >= 1:
                                    dest_addr = config[context]['policies'][
                                        policy]['policyDstNet']
                                    if dest_addr == ['']: dest_addr = ['Any']
                                else:
                                    dest_addr = ['Any']
                            else:
                                for dest_index in config[context]['policies'][
                                    policy]['policyDstNet']:
                                    # print(dest_index)
                                    if dest_index.lower() in [
                                        'any', ''
                                    ] and options.zero_network:
                                        found_in_dest = True
                                        dest_addr = ['Any']
                                        break
                                    policyIPv4_list = []
                                    if dest_index in config[context][
                                        'addresses'] or dest_index.lower(
                                    ) in ['any', '']:
                                        dest_addr = ['']
                                        pass
                                    else:
                                        print('{} not found in config'.format(
                                            dest_index))
                                    if dest_index not in excluded_addresses:
                                        if (dest_index in config[context]['addresses']):
                                            for expanded_index in expand_address(
                                                    config[context]
                                                    ['addresses'], config[context]
                                                    ['addresses'][dest_index]
                                                    ['addrObjId'], config[context]
                                                    ['addressmappings'], config):
                                                if (expanded_index
                                                        in config[context]['addresses']):
                                                    policyIPv4_list.extend(
                                                        config[context]
                                                        ['addresses']
                                                        [expanded_index]
                                                        ['IPv4Networks'])
                                                elif (expanded_index
                                                      in shared['addresses']):
                                                    policyIPv4_list.extend(
                                                        shared['addresses']
                                                        [expanded_index]
                                                        ['IPv4Networks'])
                                                # else:
                                                #    print('{} not found in config'.format(dest_index))

                                        elif (dest_index
                                              in shared['addresses']):
                                            for expanded_index in expand_address(
                                                    shared['addresses'],
                                                    shared['addresses']
                                                    [dest_index]['addrObjId'],
                                                    shared['addressmappings'],
                                                    config):
                                                policyIPv4_list.extend(
                                                    shared['addresses']
                                                    [expanded_index]
                                                    ['IPv4Networks'])
                                                prefix = '*'
                                        # else:
                                        #
                                        else:
                                            if dest_index.lower() not in [
                                                'any', ''
                                            ]:
                                                log('UNKNOWN DEST in policy {} "{}"'
                                                    .format(
                                                    config[context]
                                                    ['policies'][policy]
                                                    ['policyName'],
                                                    dest_index))
                                            try:
                                                if re.findall('-', dest_index):
                                                    first, last = dest_index.split(
                                                        '-')
                                                    for x in ipaddress.summarize_address_range(
                                                            ipaddress.
                                                                    IPv4Address(first),
                                                            ipaddress.
                                                                    IPv4Address(last)):
                                                        policyIPv4_list.extend(
                                                            [x])
                                                else:
                                                    first = dest_index
                                                    last = dest_index
                                                    if not re.findall(
                                                            '/', first):
                                                        first = first + '/32'
                                                    policyIPv4_list.extend([
                                                        ipaddress.IPv4Network(
                                                            first)
                                                    ])

                                            except Exception as e:
                                                pass
                                    polSet = IPSet([])
                                    destSet = IPSet([])
                                    for x in policyIPv4_list:
                                        polSet.add(str(x))
                                    destSet.add(destIPv4.with_netmask)
                                    # log(polSet)
                                    # log('intersection', excluded_networks & polSet)
                                    if excluded_dst_networks & polSet == IPSet(
                                            []):
                                        if (polSet & destSet) or (
                                                (dest_index.lower() == 'any'
                                                 or dest.lower() == '0.0.0.0/0')
                                                and options.zero_network):
                                            if destSet == polSet:
                                                dest_match_type = 'Exact'
                                            elif (destSet & polSet) == destSet:
                                                dest_match_type = 'Complete'
                                            elif (destSet & polSet) == polSet:
                                                dest_match_type = 'Partial'
                                            elif (dest_index.lower() == 'any'
                                                  or dest.lower()
                                                  == '0.0.0.0/0'):
                                                dest_match_type = 'Any'
                                            else:
                                                dest_match_type = 'Mixed'
                                            found_in_dest = True
                                            dest_addr = config[context][
                                                'policies'][policy][
                                                'policyDstNet']
                                            dest_found_index.append(dest_index)
                                            if dest_match_type == 'Exact':
                                                debug(policyIPv4_list)
                                                debug(polSet)
                                                debug(destSet)
                                            # break
                                    else:
                                        dest_addr = config[context][
                                            'policies'][policy]['policyDstNet']
                                        debug(
                                            'Excluded network found in dest - skipping rule'
                                        )
                        if negate_dest:
                            found_in_dest = not found_in_dest
                        if found_in_dest:
                            # perform checking of service
                            # verify that get port of icmp returns "any"
                            if (config[context]['policies'][policy]
                                ['policyDstSvc'] == ['']
                                and options.zero_service
                            ) or ([
                                      x.lower() for x in config[context]
                                ['policies'][policy]['policyDstSvc']
                                  ] == ['any'] and options.zero_service
                            ) or config[context]['policies'][policy][
                                'policyDstSvc'] == [
                                'application-default'
                            ]:
                                found_in_service = True
                                if config[context]['policies'][policy][
                                    'policyDstSvc'] == ['']:
                                    dest_service = ['any']
                                else:
                                    dest_service = config[context]['policies'][
                                        policy]['policyDstSvc']
                            elif service == 'any/any':  # and options.zero_network:
                                found_in_service = True
                                dest_service = config[context]['policies'][
                                    policy]['policyDstSvc']
                            else:
                                for dest_index in config[context]['policies'][policy]['policyDstSvc']:
                                    if (dest_index
                                            in config[context]['services']):
                                        for expanded_index in expand_service(
                                                config[context]['services'],
                                                config[context]['services']
                                                [dest_index]['svcObjId'],
                                                config[context]
                                                ['servicemappings'], config):
                                            policy_prot = get_prot_of(
                                                config[context]['services'],
                                                expanded_index, config)
                                            policy_ports = get_ports_of(
                                                config[context]['services'],
                                                expanded_index, config)

                                            try:
                                                if ((prot.lower()
                                                     == policy_prot or
                                                     prot.lower() == 'any') and
                                                    (int(portnum)
                                                     in policy_ports)) or (
                                                        dest_index.lower()
                                                        == 'any' and
                                                        options.zero_network
                                                ) or (
                                                        service.lower()
                                                        == 'any/any' and
                                                        options.zero_network):
                                                    if found_in_service == False:
                                                        found_in_service = True
                                                        dest_service = config[
                                                            context]['policies'][
                                                            policy][
                                                            'policyDstSvc']
                                                        break
                                            except Exception as e:
                                                print(prot.lower())
                                                print(policy_prot)
                                                print("'" + start_port + "'")
                                                print(end_port)
                                                print(expanded_index)
                                                log(e)

                                    if dest_index in shared['services']:
                                        for expanded_index in expand_service(
                                                shared['services'],
                                                shared['services'][dest_index]
                                                ['svcObjId'],
                                                shared['servicemappings'],
                                                config):
                                            policy_prot = get_prot_of(
                                                shared['services'],
                                                expanded_index,
                                                config).lower()
                                            # start_port, end_port = get_port_of(shared['services'],expanded_index, config)
                                            policy_ports = get_ports_of(
                                                config[context]['services'],
                                                expanded_index, config)
                                            # if start_port=='': start_port='0'
                                            # if end_port=='': end_port='0'
                                            if ((prot.lower() == policy_prot
                                                 or prot.lower() == 'any')
                                                and portnum in policy_ports
                                            ) or dest_index.lower(
                                            ) == 'any' or (
                                                    service.lower()
                                                    == 'any/any'
                                                    and options.zero_network):
                                                if found_in_service == False:
                                                    found_in_service = True
                                                    dest_service = config[
                                                        context]['policies'][
                                                        policy][
                                                        'policyDstSvc']
                                                    break

                        if found_in_source and found_in_dest and found_in_service and (
                                options.matchtypes in [['all'], ['any']] or
                                (source_match_type.lower()
                                 in [x.lower() for x in options.matchtypes]
                                 or source_match_type.lower() == 'any') and
                                (dest_match_type.lower()
                                 in [x.lower() for x in options.matchtypes]
                                 or dest_match_type.lower() == 'any')):
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

                            if not config[context]['policies'][policy]['policySrcZone']:
                                source_zone = ['any']
                            else:
                                source_zone = config[context]['policies'][policy]['policySrcZone']

                            if not config[context]['policies'][policy]['policyDstZone']:
                                dest_zone = ['any']
                            else:
                                dest_zone = config[context]['policies'][policy]['policyDstZone']

                            policymatches += 1

                            if config[context]['policies'][policy]['policySrcZone'] == [] or \
                                    config[context]['policies'][policy]['policySrcZone'] == ['']:
                                source_zones = ['any']
                            else:
                                source_zones = config[context]['policies'][
                                    policy]['policySrcZone']

                            if config[context]['policies'][policy]['policyDstZone'] == [] or \
                                    config[context]['policies'][policy]['policyDstZone'] == ['']:
                                dest_zones = ['any']
                            else:
                                dest_zones = config[context]['policies'][
                                    policy]['policyDstZone']

                            if config[context]['policies'][policy]['policySrcNet'] == [] or \
                                    config[context]['policies'][policy]['policySrcNet'] == ['']:
                                source_nets = ['any']
                            else:
                                source_nets = config[context]['policies'][
                                    policy]['policySrcNet']

                            if config[context]['policies'][policy]['policyDstNet'] == [] or \
                                    config[context]['policies'][policy]['policyDstNet'] == ['']:
                                dest_nets = ['any']
                            else:
                                dest_nets = config[context]['policies'][
                                    policy]['policyDstNet']

                            if config[context]['policies'][policy]['policyDstSvc'] == [] or \
                                    config[context]['policies'][policy]['policyDstSvc'] == ['']:
                                dest_services = ['any']
                            else:
                                dest_services = config[context]['policies'][
                                    policy]['policyDstSvc']
                            if 'policySection' in config[context]['policies'][
                                policy]:
                                section = config[context]['policies'][policy][
                                    'policySection']
                            else:
                                section = 'Unknown'

                            if options.html:
                                if policymatches == 1:
                                    log('<p align=cneter><font size=8 >')
                                    log('context: ' + context)
                                    log('</font></p>')
                                    log('<table border="1" width="90%">')
                                    if config[context]['config'][
                                        'fw_type'] == 'checkpoint':
                                        log(
                                            '<th>Enabled</th><th>Action</th><th>PolicyName</th><th>UiNum</th><th>IndexNum</th><th>Source Address</th><th>Destination Address</th><th>Service</th>'
                                            )
                                    else:
                                        log(
                                            '<th>Enabled</th><th>Action</th><th>Name</th><th>Source Zone</th><th>Dest Zone</th><th>Source Address</th><th>Destination Address</th><th>Service</th>'
                                            )
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
                                if config[context]['config'][
                                    'fw_type'] == 'checkpoint':
                                    log('<td>' +
                                        str(config[context]['policies'][policy]
                                            ['policyUiNum']) + '</td>')
                                    log('<td>' +
                                        str(config[context]['policies'][policy]
                                            ['policyNum']) + '</td>')
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
                                        log('<p style="color:green">{}</p><br>'
                                            .format(
                                            url_unquote(source_address)))
                                    else:
                                        log(
                                            url_unquote(source_address) +
                                            '<br>')
                                log('</td>')
                                log('<td>')
                                for dest_address in dest_nets:
                                    if dest_address in dest_found_index:
                                        log('<p style="color:green">{}</p><br>'
                                            .format(url_unquote(dest_address)))
                                    else:
                                        log(url_unquote(dest_address) + '<br>')
                                log('</td>')
                                log('<td>')
                                for dest_service in dest_services:
                                    log(url_unquote(dest_service) + '<br>')
                                log('</td>')
                                log('<tr>')
                            elif options.csv:
                                with codecs.open(options.csv, 'a+',
                                                 'utf-8') as outfile:
                                    if policymatches == 1:  ## this is to print a header line
                                        if config[context]['config']['fw_type'] == 'checkpoint':
                                            outfile.write(
                                                'Context,Enabled,Action,PolicyName,Section,UiNum,IndexNum,Source Address,Destination Address,Service,Comment,UUID\n'
                                            )

                                        else:
                                            outfile.write(
                                                'Context,Enabled,Action,Name,Source Zone,Dest Zone,Source Address,Destination Address,Service,Comment,UUID\n'
                                            )

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
                                    if config[context]['config'][
                                        'fw_type'] == 'checkpoint':
                                        outfile.write('"{}",'.format(
                                            str(section)))
                                        outfile.write('"{}",'.format(
                                            str(config[context]['policies']
                                                [policy]['policyUiNum'])))
                                        outfile.write('"{}",'.format(
                                            str(config[context]['policies']
                                                [policy]['policyNum'])))
                                    # else:

                                    outfile.write('"')
                                    if config[context]['config']['fw_type'] != 'checkpoint':
                                        for source_zone in source_zones:
                                            outfile.write('{}'.format(
                                                url_unquote(source_zone)))
                                            if source_zone == source_zones[-1]:
                                                outfile.write('",')
                                            else:
                                                outfile.write('\n')
                                        outfile.write('"')
                                        for dest_zone in dest_zones:
                                            outfile.write('{}'.format(
                                                url_unquote(dest_zone)))
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
                                        outfile.write('{}{}'.format(
                                            sourceprefix,
                                            url_unquote(source_address)))
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
                                        outfile.write('{}{}'.format(
                                            destprefix,
                                            url_unquote(dest_address)))
                                        if dest_address == dest_nets[-1]:
                                            outfile.write('",')
                                        else:
                                            outfile.write('\n')
                                    outfile.write('"')
                                    for dest_service in dest_services:
                                        outfile.write('{}'.format(
                                            url_unquote(dest_service)))
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
                                    if config[context]['config'][
                                        'fw_type'] == 'checkpoint':
                                        log(
                                            '{:2.2s} | {:8.8s} | {:15.15s} | {:30.30s} | {:8.8s} | {:8.8s} | {:10.10s} | {:60.60s} | {:10.10s} | {:40.40s} | {:40.40s}'
                                            .format('En', 'Action', 'CMA',
                                                    'Policy Name', 'Rule UI#',
                                                    'Rule Idx', 'Src_match',
                                                    'Source Address',
                                                    'Dst_match',
                                                    'Destination Address',
                                                    'Service'))
                                    else:
                                        log(
                                            '{:2.2s} | {:8.8s} | {:30.30s} | {:20.20s} | {:20.20s} | {:10.10s} | {:60.60s} | {:10.10s} | {:40.40s} | {:40.40s}'
                                            .format('En', 'Action',
                                                    'Rule Name', 'Source Zone',
                                                    'Destination Zone',
                                                    'Src_match',
                                                    'Source Address',
                                                    'Dst_match',
                                                    'Destination Address',
                                                    'Service'))
                                    log('=' * 250)
                                # if config[context]['config']['fw_type']=='checkpoint':
                                #    log ('{:2.2s} {:8.8s} {:15.15s} {:30.30s} {:8.8s} {:8.8s} {:10.10s} {:60.60s} {:10.10s} {:40.40s} {:40.40s}'.format(enabled, action, context, url_unquote(name), str(config[context]['policies'][policy]['policyUiNum']), str(config[context]['policies'][policy]['policyNum']), str(source_match_type), url_unquote(source_addr[0]), str(dest_match_type), url_unquote(dest_addr[0]), url_unquote(dest_service[0])))
                                # else:
                                #    log ('{:2.2s} {:8.8s} {:30.30s} {:20.20s} {:20.20s} {:10.10s} {:60.60s} {:10.10s} {:40.40s} {:40.40s}'.format(enabled, action, url_unquote(name), url_unquote(source_zone[0]), url_unquote(dest_zone[0]), str(source_match_type), url_unquote(source_addr[0]), str(dest_match_type), url_unquote(dest_addr[0]), url_unquote(dest_service[0])))
                                longestval = max(len(source_addr),
                                                 len(dest_addr),
                                                 len(dest_service),
                                                 len(source_zone),
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
                                        if config[context]['config'][
                                            'fw_type'] == 'checkpoint':
                                            log(
                                                '{:2.2s} | {:8.8s} | {:15.15s} | {:30.30s} | {:8.8s} | {:8.8s} | {:10.10s} | {:1.1s}{:60.60s} | {:10.10s} | {:1.1s}{:40.40s} | {:40.40s}'
                                                    .format(
                                                    enabled, action, context,
                                                    url_unquote(name),
                                                    str(config[context]
                                                        ['policies'][policy]
                                                        ['policyUiNum']),
                                                    str(config[context]
                                                        ['policies'][policy]
                                                        ['policyNum']),
                                                    str(source_match_type),
                                                    srcprefix,
                                                    url_unquote(
                                                        source_addr[0]),
                                                    str(dest_match_type),
                                                    dstprefix,
                                                    url_unquote(dest_addr[0]),
                                                    url_unquote(
                                                        dest_service[0])))
                                        else:
                                            log(
                                                '{:2.2s} | {:8.8s} | {:30.30s} | {:20.20s} | {:20.20s} | {:10.10s} | {:1.1s}{:60.60s} | {:10.10s} | {:1.1s}{:40.40s} | {:40.40s}'
                                                    .format(
                                                    enabled, action,
                                                    url_unquote(name),
                                                    url_unquote(
                                                        source_zone[0]),
                                                    url_unquote(dest_zone[0]),
                                                    str(source_match_type),
                                                    srcprefix,
                                                    url_unquote(
                                                        source_addr[0]),
                                                    str(dest_match_type),
                                                    dstprefix,
                                                    url_unquote(dest_addr[0]),
                                                    url_unquote(
                                                        dest_service[0])))
                                    else:
                                        if config[context]['config'][
                                            'fw_type'] == 'checkpoint':
                                            log(
                                                '{:2.2s} | {:8.8s} | {:15.15s} | {:30.30s} | {:8.8s} | {:8.8s} | {:10.10s} | {:1.1s}{:60.60s} | {:10.10s} | {:1.1s}{:40.40s} | {:40.40s}'
                                                    .format(
                                                    '', '', '', '', '', '', '',
                                                    srcprefix,
                                                    url_unquote(tmpsrc), '',
                                                    dstprefix,
                                                    url_unquote(tmpdst),
                                                    url_unquote(tmpsvc)))
                                        else:
                                            log(
                                                '{:2.2s} | {:8.8s} | {:30.30s} | {:20.20s} | {:20.20s} | {:10.10s} | {:1.1s}{:60.60s} | {:10.10s} | {:1.1s}{:40.40s} | {:40.40s}'
                                                    .format(
                                                    '', '', '', tmpszone,
                                                    tmpdzone, '',
                                                    str(source_match_type),
                                                    srcprefix,
                                                    url_unquote(tmpsrc), '',
                                                    str(dest_match_type),
                                                    dstprefix,
                                                    url_unquote(tmpdst),
                                                    url_unquote(tmpsvc)))
                                log('-' * 250)
                                if modify:
                                    if modify_group not in config[context][
                                        'policies'][policy][
                                        'policyDstNet']:
                                        for addr in modify_addr:
                                            log('addelement fw_policies {} rule:{}:dst:\'\' network_objects:{}'
                                                .format(
                                                url_unquote(name),
                                                config[context]['policies']
                                                [policy]['policyNum'],
                                                addr))
                                    else:
                                        log('Rule already contains group: ' +
                                            modify_group)

                if policymatches != 0 and options.web:
                    log('</table>')
                    log('<hr>')

                if policymatches == 0:
                    nomatches.append(context)

    log('No matches were found for the following contexts')
    for nomatch in nomatches:
        log(nomatch)
        if options.web: log('<br>')
    return
