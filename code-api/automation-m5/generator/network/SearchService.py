import re
import ipaddress
import codecs
import sys

from collections import defaultdict
from collections import OrderedDict

from copy import deepcopy
from netaddr import IPSet
from urllib.parse import unquote as url_unquote


from ...generator import NetworkLogs
import CreateService as CS
import GetService as GS

class SearchNetworkService:

    def _init_(self, options, config):
        self.log = NetworkLogs().log
        self.sc = NetworkLogs().sc
        self.ss = NetworkLogs().ss
        self.debug = NetworkLogs().debug
        self.options = options
        self.config = config
        self.createNetworkService = CS.CreateNetworkService(self.options, self.config)
        self.getNetworkService = GS.GetNetworkService(self.config)

    #  Given an IP address, find all the address and address-group objects that contain the address
    def find_ip_address(self, config, ip_address_list, context_list, exact=False):
        return_list = []

        for ip_to_find in ip_address_list:
            if re.findall('/', ip_to_find):
                ipaddr, netmask = ip_to_find.split('/')
            else:
                ipaddr = ip_to_find
                netmask = '32'
            self.log("=" * 120)
            self.log('Searching for IP address : ' + ip_to_find)
            for context in context_list:
                found = False
                # only print this header if something is found in each context
                if context in config:
                    for address_index in config[context]['addresses']:
                        if 'addrObjId' in config[context]['addresses'][address_index] and \
                                'addressmappings' in config[context]:

                            for expanded_index in self.createNetworkService.expand_address(config[context]['addresses'],
                                                                 config[context]['addresses'][address_index][
                                                                     'addrObjId'],
                                                                 config[context]['addressmappings']):
                                for network in config[context]['addresses'][expanded_index]['IPv4Networks']:
                                    if ((ipaddress.IPv4Network(ipaddr + '/' + netmask, strict=False).overlaps(
                                            network) or network.overlaps(ipaddress.IPv4Network(ipaddr + '/' + netmask,
                                                                                               strict=False))) and not exact) or (
                                            ipaddress.IPv4Network(ipaddr + '/' + netmask,
                                                                  strict=False) == network and exact):
                                        if network != ipaddress.IPv4Network('0.0.0.0/0') or self.options.zero_network:
                                            if not found:
                                                found = True
                                                self.log('-' * 120)
                                                self.log('%-40s :' % ' Device Group', end='')
                                                self.log('%-40s :' % ' Root Object Name', end='')
                                                self.log('%-40s' % ' Member Address Object')
                                                self.log('-' * 120)
                                            self.log('%-40s : ' % context, end='')
                                            self.log(
                                                '%-40s : ' % config[context]['addresses'][address_index]['addrObjId'],
                                                end='')
                                            self.log('%-40s : ' % expanded_index, end='')
                                            self.log(
                                                '%-40s' % config[context]['addresses'][address_index]['addrObjComment'])

                                            return_list.append(expanded_index)
                else:
                    self.log('Device Group (context)' + context + ' not found, Skipped!')
        return return_list

    # Given a service definition "protocol/port", find all the service and service-group objects that contain the
    # service
    def find_service(self, config, search_list, context_list, exact=False):

        return_list = []
        for service_to_find in search_list:
            prot, port = service_to_find.split('/')
            self.log('-' * 120)
            self.log('%-40s : ' % 'Device Group', end='')
            self.log('%-40s : ' % 'Root Object Name', end='')
            self.log('%-40s' % 'Member Service Object')
            self.log('-' * 120)

            for context in context_list:
                for service_index in config[context]['services']:
                    for expanded_index in self.createNetworkService.expand_service(config[context]['services'],
                                                         config[context]['services'][service_index]['svcObjId'],
                                                         config[context]['servicemappings']):
                        # start, end = get_port_of(config[context]['services'],expanded_index)
                        portlist = self.getNetworkService.get_ports_of(config[context]['services'], expanded_index)
                        # start=int(start)
                        # end=int(end)
                        if (prot.lower() == self.getNetworkService.get_prot_of(config[context]['services'], expanded_index)):
                            if (int(port) in portlist and not exact) or (
                                    config[context]['services'][service_index]['svcObjType'] == '1' and [
                                int(port)] == portlist and exact):
                                self.log('%-40s : ' % context, end='')
                                self.log('%-40s : ' % config[context]['services'][service_index]['svcObjId'], end='')
                                self.log('%-40s' % expanded_index)
                                return_list.append(expanded_index)
        return return_list

    def show_found_ips(self, config, search_list, context_list):
        return

    def show_found_services(self, config, search_list, contexts):
        return

    # redo this using IPset like I do for inverse matching
    def find_matching_rules2(self, config, shared, params_list, contextnames, modify=None):

        # CHANGEME - move excluded addresses to a CLI option

        excluded_addresses = []
        excluded_addresses = self.options.excludeaddress
        excluded_src_networks = IPSet([addr for addr in self.options.excludesrcnetwork])
        excluded_dst_networks = IPSet([addr for addr in self.options.excludedstnetwork])
        # self.log(excluded_networks)
        # ['Net_10.0.0.0', 'DellNets', 'glbl-Dell_Internal_Networks', 'DellNets-Only', 'Dell-10.0.0.0', 'Net10', 'Dell-DMS-Users', 'DellAssignedNets-NonDell', 'DC-Networks']

        for params in params_list:
            if params.count(',') != 2:
                self.log('Search string must contain exactly 3 fields source_ip,destination_ip,service')
                return False
            if not options.web:
                self.log('!-- Finding matching rules ' + str(params))
            if modify:
                self.log(modify)
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
                #self.log(context)
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
                            # self.log('SOURCE NEGATED Idx: {} UI: {} '.format(str(config[context]['policies'][policy]['policyNum']), str(config[context]['policies'][policy]['policyUiNum'])))
                        if 'policyDstNegate' in config[context]['policies'][policy]:
                            negate_dest = config[context]['policies'][policy]['policyDstNegate']
                        else:
                            negate_dest = False

                        if (config[context]['config']['fw_type'] == 'checkpoint' and
                            config[context]['policies'][policy][
                                'policyName'] in self.options.policynames) or config[context]['config'][
                            'fw_type'] != 'checkpoint' or \
                                self.options.policynames[0].lower() in ['', 'any', 'all']:

                            # self.log(config[context]['usedzones'])
                            # if (len(set(config[context]['policies'][policy]['policySrcZone']) & set(config[context]['usedzones']))>0 or config[context]['usedzones']==[]  ) and (len(set(config[context]['policies'][policy]['policyDstZone']) & set(config[context]['usedzones']))>0 or config[context]['usedzones']==[]) or config[context]['config']['fw_type']=='checkpoint':
                            # self.log(config[context]['policies'][policy])
                            # self.log('jeff')
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
                                    if source_index.lower() in ['any', ''] and self.options.zero_network:
                                        found_in_source = True
                                        source_addr = ['Any']
                                        break
                                    policyIPv4_list = []
                                    if source_index not in excluded_addresses:
                                        if (source_index in config[context]['addresses']):
                                            for expanded_index in self.createNetworkService.expand_address(config[context]['addresses'],
                                                                                 config[context]['addresses'][
                                                                                     source_index][
                                                                                     'addrObjId'],
                                                                                 config[context]['addressmappings']):
                                                if (expanded_index in config[context]['addresses']):
                                                    policyIPv4_list.extend(
                                                        config[context]['addresses'][expanded_index]['IPv4Networks'])
                                                elif (expanded_index in shared['addresses']):
                                                    policyIPv4_list.extend(
                                                        shared['addresses'][expanded_index]['IPv4Networks'])
                                        elif (source_index in shared['addresses']):
                                            for expanded_index in self.createNetworkService.expand_address(shared['addresses'],
                                                                                 shared['addresses'][source_index][
                                                                                     'addrObjId'],
                                                                                 shared['addressmappings']):
                                                policyIPv4_list.extend(
                                                    shared['addresses'][expanded_index]['IPv4Networks'])
                                                prefix = '*'
                                        else:
                                            if source_index.lower() not in ['any', '']: self.log(
                                                'UNKNOWN SOURCE "{}"'.format(source_index))
                                            try:
                                                if re.findall('-', source_index) != []:
                                                    first, last = source_index.split('-')
                                                    for x in ipaddress.summarize_address_range(
                                                            ipaddress.IPv4Address(first),
                                                            ipaddress.IPv4Address(last)):
                                                        policyIPv4_list.extend([x])
                                                        self.debug('Adding Range to policy list {}'.format(x))
                                                else:
                                                    first = source_index
                                                    last = source_index
                                                    if re.findall('/', first) == []:
                                                        first = first + '/32'
                                                    policyIPv4_list.extend([ipaddress.IPv4Network(first)])
                                                    self.debug('Adding network/host to policy list {}'.format(x))
                                            except Exception as e:
                                                # if source_index.lower() not in ['any', '']: self.log('UNKNOWN SOURCE "{}"'.format(source_index))
                                                self.log(
                                                    'Exception {} handling unknown source : {}'.format(e, source_index))
                                                pass

                                    polSet = IPSet([])
                                    srcSet = IPSet([])
                                    for x in policyIPv4_list:
                                        polSet.add(str(x))
                                    srcSet.add(sourceIPv4.with_netmask)
                                    # self.log('intersection', excluded_networks & polSet)
                                    # if excluded_networks not in polSet:
                                    if excluded_src_networks & polSet == IPSet([]):
                                        if (srcSet & polSet) or \
                                                ((source_index.lower() == 'any' or source.lower() == '0.0.0.0/0')
                                                 and self.options.zero_network):
                                            if srcSet == polSet:
                                                source_match_type = 'Exact'
                                            elif (srcSet & polSet) == srcSet:
                                                source_match_type = 'Complete'
                                            elif (srcSet & polSet) == polSet:
                                                source_match_type = 'Partial'
                                            elif source_index.lower() == 'any' or source.lower() == '0.0.0.0/0':
                                                source_match_type = 'Any'
                                            else:
                                                source_match_type = 'Mixed'
                                            found_in_source = True
                                            source_addr = config[context]['policies'][policy]['policySrcNet']
                                            source_found_index.append(source_index)
                                            # break
                                    else:
                                        source_addr = config[context]['policies'][policy]['policySrcNet']
                                        self.debug('Excluded network found in source - skipping rule')
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
                                        if dest_index.lower() in ['any', ''] and self.options.zero_network:
                                            found_in_dest = True
                                            dest_addr = ['Any']
                                            break
                                        policyIPv4_list = []
                                        if dest_index in config[context]['addresses'] or dest_index.lower() in ['any',
                                                                                                                '']:
                                            pass
                                        else:
                                            print('{} not found in config'.format(dest_index))
                                        if dest_index not in excluded_addresses:
                                            if (dest_index in config[context]['addresses']):
                                                for expanded_index in self.createNetworkService.expand_address(config[context]['addresses'],
                                                                                     config[context]['addresses'][
                                                                                         dest_index]['addrObjId'],
                                                                                     config[context][
                                                                                         'addressmappings']):
                                                    if (expanded_index in config[context]['addresses']):
                                                        policyIPv4_list.extend(
                                                            config[context]['addresses'][expanded_index][
                                                                'IPv4Networks'])
                                                    elif (expanded_index in shared['addresses']):
                                                        policyIPv4_list.extend(
                                                            shared['addresses'][expanded_index]['IPv4Networks'])
                                                    # else:
                                                    #    print('{} not found in config'.format(dest_index))

                                            elif (dest_index in shared['addresses']):
                                                for expanded_index in self.createNetworkService.expand_address(shared['addresses'],
                                                                                     shared['addresses'][dest_index][
                                                                                         'addrObjId'],
                                                                                     shared['addressmappings']):
                                                    policyIPv4_list.extend(
                                                        shared['addresses'][expanded_index]['IPv4Networks'])
                                                    prefix = '*'
                                            # else:
                                            #
                                            else:
                                                if dest_index.lower() not in ['any', '']:  self.log(
                                                    'UNKNOWN DEST in policy {} "{}"'.format(
                                                        config[context]['policies'][policy]['policyName'], dest_index))
                                                try:
                                                    if re.findall('-', dest_index) != []:
                                                        first, last = dest_index.split('-')
                                                        for x in ipaddress.summarize_address_range(
                                                                ipaddress.IPv4Address(first),
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
                                        for x in policyIPv4_list:
                                            polSet.add(str(x))
                                        destSet.add(destIPv4.with_netmask)
                                        # self.log(polSet)
                                        # self.log('intersection', excluded_networks & polSet)
                                        if excluded_dst_networks & polSet == IPSet([]):
                                            if (polSet & destSet) or ((
                                                                              dest_index.lower() == 'any' or dest.lower() == '0.0.0.0/0') and self.options.zero_network):
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
                                                    self.debug(policyIPv4_list)
                                                    self.debug(polSet)
                                                    self.debug(destSet)
                                                # break
                                        else:
                                            dest_addr = config[context]['policies'][policy]['policyDstNet']
                                            self.debug('Excluded network found in dest - skipping rule')
                            if negate_dest:
                                found_in_dest = not found_in_dest
                            if found_in_dest:
                                # perform checking of service
                                # verify that get port of icmp returns "any"
                                if (config[context]['policies'][policy]['policyDstSvc'] == [
                                    ''] and self.options.zero_service) or (
                                        [x.lower() for x in config[context]['policies'][policy]['policyDstSvc']] == [
                                    'any'] and self.options.zero_service) or config[context]['policies'][policy][
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
                                            for expanded_index in self.createNetworkService.expand_service(config[context]['services'],
                                                                                 config[context]['services'][
                                                                                     dest_index][
                                                                                     'svcObjId'],
                                                                                 config[context]['servicemappings']):
                                                policy_prot = self.getNetworkService.get_prot_of(config[context]['services'], expanded_index)
                                                # start_port, end_port = get_port_of(config[context]['services'],expanded_index)
                                                policy_ports = self.getNetworkService.get_ports_of(config[context]['services'], expanded_index)
                                                # self.log(policy_ports)
                                                # if start_port=='': start_port='0'
                                                # if end_port=='': end_port='0'
                                                ## svcPortSet FIX
                                                try:
                                                    if ((prot.lower() == policy_prot or prot.lower() == 'any') and (
                                                            int(portnum) in policy_ports)) or (
                                                            dest_index.lower() == 'any' and self.options.zero_network) or (
                                                            service.lower() == 'any/any' and self.options.zero_network):
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
                                                    self.log(e)

                                        if (dest_index in shared['services']):
                                            for expanded_index in self.createNetworkService.expand_service(shared['services'],
                                                                                 shared['services'][dest_index][
                                                                                     'svcObjId'],
                                                                                 shared['servicemappings']):
                                                policy_prot = self.getNetworkService.get_prot_of(shared['services'], expanded_index).lower()
                                                # start_port, end_port = get_port_of(shared['services'],expanded_index)
                                                policy_ports = self.getNetworkService.get_ports_of(config[context]['services'], expanded_index)
                                                # if start_port=='': start_port='0'
                                                # if end_port=='': end_port='0'
                                                if ((
                                                            prot.lower() == policy_prot or prot.lower() == 'any') and portnum in policy_ports) or dest_index.lower() == 'any' or (
                                                        service.lower() == 'any/any' and self.options.zero_network):
                                                    if found_in_service == False:
                                                        found_in_service = True
                                                        dest_service = config[context]['policies'][policy][
                                                            'policyDstSvc']
                                                        break

                            if found_in_source and found_in_dest and found_in_service and (
                                    self.options.matchtypes in [['all'], ['any']] or (
                                    source_match_type.lower() in [x.lower() for x in
                                                                  self.options.matchtypes] or source_match_type.lower() == 'any') and (
                                            dest_match_type.lower() in [x.lower() for x in
                                                                        self.options.matchtypes] or dest_match_type.lower() == 'any')):
                                # I believe zone/net/service is empty if "any", so temporarily set these values to variables before printing them
                                if config[context]['policies'][policy]['policyEnabled'] == '0':
                                    enabled = "."
                                elif config[context]['policies'][policy]['policyEnabled'] == '1':
                                    if self.options.web or self.options.csv:
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

                                if self.options.html:
                                    if policymatches == 1:
                                        self.log('<p align=center><font size=8 >')
                                        self.log('context: ' + context)
                                        self.log('</font></p>')
                                        self.log('<table border="1" width="90%">')
                                        if config[context]['config']['fw_type'] == 'checkpoint':
                                            self.log(
                                                '<th>Enabled</th><th>Action</th><th>PolicyName</th><th>UiNum</th><th>IndexNum</th><th>Source Address</th><th>Destination Address</th><th>Service</th>')
                                        else:
                                            self.log(
                                                '<th>Enabled</th><th>Action</th><th>Name</th><th>Source Zone</th><th>Dest Zone</th><th>Source Address</th><th>Destination Address</th><th>Service</th>')
                                    if enabled != "Y":
                                        trcolor = '#aaaaaa'
                                    elif action.lower() == 'allow':
                                        trcolor = '#00aa00'
                                    else:
                                        trcolor = '#aa0000'
                                    self.log('<tr bgcolor="' + trcolor + '">')
                                    self.log('<td>' + enabled + '</td>')
                                    self.log('<td>' + action + '</td>')
                                    self.log('<td>' + name + '</td>')
                                    ## only do src/dest zones for non-checkpoint
                                    ## for checkpoint, add ruleUI number
                                    if config[context]['config']['fw_type'] == 'checkpoint':
                                        self.log(
                                            '<td>' + str(config[context]['policies'][policy]['policyUiNum']) + '</td>')
                                        self.log(
                                            '<td>' + str(config[context]['policies'][policy]['policyNum']) + '</td>')
                                    else:
                                        self.log('<td>')
                                        for source_zone in source_zones:
                                            self.log(url_unquote(source_zone) + '<br>')
                                        self.log('</td>')
                                        self.log('<td>')
                                        for dest_zone in dest_zones:
                                            self.log(url_unquote(dest_zone) + '<br>')
                                        self.log('</td>')
                                    self.log('<td>')
                                    for source_address in source_nets:
                                        if source_address in source_found_index:
                                            self.log(
                                                '<p style="color:green">{}</p><br>'.format(url_unquote(source_address)))
                                        else:
                                            self.log(url_unquote(source_address) + '<br>')
                                    self.log('</td>')
                                    self.log('<td>')
                                    for dest_address in dest_nets:
                                        if dest_address in dest_found_index:
                                            self.log(
                                                '<p style="color:green">{}</p><br>'.format(url_unquote(dest_address)))
                                        else:
                                            self.log(url_unquote(dest_address) + '<br>')
                                    self.log('</td>')
                                    self.log('<td>')
                                    for dest_service in dest_services:
                                        self.log(url_unquote(dest_service) + '<br>')
                                    self.log('</td>')
                                    self.log('<tr>')
                                elif self.options.csv:
                                    with codecs.open(self.options.csv, 'a+', 'utf-8') as outfile:
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
                                        self.log('Context : ' + context)
                                        if config[context]['config']['fw_type'] == 'checkpoint':
                                            self.log(
                                                '{:2.2s} | {:8.8s} | {:15.15s} | {:30.30s} | {:8.8s} | {:8.8s} | {:10.10s} | {:60.60s} | {:10.10s} | {:40.40s} | {:40.40s}'.format(
                                                    'En', 'Action', 'CMA', 'Policy Name', 'Rule UI#', 'Rule Idx',
                                                    'Src_match',
                                                    'Source Address', 'Dst_match', 'Destination Address', 'Service'))
                                        else:
                                            self.log(
                                                '{:2.2s} | {:8.8s} | {:30.30s} | {:20.20s} | {:20.20s} | {:10.10s} | {:60.60s} | {:10.10s} | {:40.40s} | {:40.40s}'.format(
                                                    'En', 'Action', 'Rule Name', 'Source Zone', 'Destination Zone',
                                                    'Src_match',
                                                    'Source Address', 'Dst_match', 'Destination Address', 'Service'))
                                        self.log('=' * 250)
                                    # if config[context]['config']['fw_type']=='checkpoint':
                                    #    log ('{:2.2s} {:8.8s} {:15.15s} {:30.30s} {:8.8s} {:8.8s} {:10.10s} {:60.60s} {:10.10s} {:40.40s} {:40.40s}'.format(enabled, action, context, url_unquote(name), str(config[context]['policies'][policy]['policyUiNum']), str(config[context]['policies'][policy]['policyNum']), str(source_match_type), url_unquote(source_addr[0]), str(dest_match_type), url_unquote(dest_addr[0]), url_unquote(dest_service[0])))
                                    # else:
                                    #    log ('{:2.2s} {:8.8s} {:30.30s} {:20.20s} {:20.20s} {:10.10s} {:60.60s} {:10.10s} {:40.40s} {:40.40s}'.format(enabled, action, url_unquote(name), url_unquote(source_zone[0]), url_unquote(dest_zone[0]), str(source_match_type), url_unquote(source_addr[0]), str(dest_match_type), url_unquote(dest_addr[0]), url_unquote(dest_service[0])))
                                    longestval = max(len(source_addr), len(dest_addr), len(dest_service),
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
                                            if config[context]['config']['fw_type'] == 'checkpoint':
                                                self.log(
                                                    '{:2.2s} | {:8.8s} | {:15.15s} | {:30.30s} | {:8.8s} | {:8.8s} | {:10.10s} | {:1.1s}{:60.60s} | {:10.10s} | {:1.1s}{:40.40s} | {:40.40s}'.format(
                                                        enabled, action, context, url_unquote(name),
                                                        str(config[context]['policies'][policy]['policyUiNum']),
                                                        str(config[context]['policies'][policy]['policyNum']),
                                                        str(source_match_type), srcprefix, url_unquote(source_addr[0]),
                                                        str(dest_match_type), dstprefix, url_unquote(dest_addr[0]),
                                                        url_unquote(dest_service[0])))
                                            else:
                                                self.log(
                                                    '{:2.2s} | {:8.8s} | {:30.30s} | {:20.20s} | {:20.20s} | {:10.10s} | {:1.1s}{:60.60s} | {:10.10s} | {:1.1s}{:40.40s} | {:40.40s}'.format(
                                                        enabled, action, url_unquote(name), url_unquote(source_zone[0]),
                                                        url_unquote(dest_zone[0]), str(source_match_type), srcprefix,
                                                        url_unquote(source_addr[0]), str(dest_match_type), dstprefix,
                                                        url_unquote(dest_addr[0]), url_unquote(dest_service[0])))
                                        else:
                                            if config[context]['config']['fw_type'] == 'checkpoint':
                                                self.log(
                                                    '{:2.2s} | {:8.8s} | {:15.15s} | {:30.30s} | {:8.8s} | {:8.8s} | {:10.10s} | {:1.1s}{:60.60s} | {:10.10s} | {:1.1s}{:40.40s} | {:40.40s}'.format(
                                                        '', '', '', '', '', '', '', srcprefix, url_unquote(tmpsrc), '',
                                                        dstprefix, url_unquote(tmpdst), url_unquote(tmpsvc)))
                                            else:
                                                self.log(
                                                    '{:2.2s} | {:8.8s} | {:30.30s} | {:20.20s} | {:20.20s} | {:10.10s} | {:1.1s}{:60.60s} | {:10.10s} | {:1.1s}{:40.40s} | {:40.40s}'.format(
                                                        '', '', '', tmpszone, tmpdzone, '', str(source_match_type),
                                                        srcprefix,
                                                        url_unquote(tmpsrc), '', str(dest_match_type), dstprefix,
                                                        url_unquote(tmpdst), url_unquote(tmpsvc)))
                                    self.log('-' * 250)
                                    if modify:
                                        if modify_group not in config[context]['policies'][policy]['policyDstNet']:
                                            for addr in modify_addr:
                                                self.log(
                                                    'addelement fw_policies {} rule:{}:dst:\'\' network_objects:{}'.format(
                                                        url_unquote(name),
                                                        config[context]['policies'][policy]['policyNum'],
                                                        addr))
                                        else:
                                            self.log('Rule already contains group: ' + modify_group)

                    if policymatches != 0 and self.options.web:
                        self.log('</table>')
                        self.log('<hr>')

                    if policymatches == 0:
                        nomatches.append(context)

        if len(nomatches) > 0:
            self.log('No matches were found for the following contexts')
            self.log('"{}'.format(nomatches))
            for nomatch in nomatches:
                self.log(nomatch)
                if self.options.web: self.log('<br>')
        return

    # Given a list of IP addresses, find all the policy objects that contain the address
    # CHANGEME - NOT WORKING AS expand_address is at least one thing broken here
    # need to also receive address map config
    # not working properly for ranges - false positives
    # this routine is not really needed as the inverse match routines now perform this function,
    # although that matches policies and addresses
    def find_ip_address_in_policy(self, policies, addresses, address_map, ip_address):

        return_list = []
        for ip_to_find in ip_address:
            if not re.findall('/', ip_to_find):  ## if netmask is not given, add /32 host mask
                ip_to_find = ip_to_find + '/32'
            self.log('-' * 120)
            self.log('Searching policies for : ' + ip_to_find)
            self.log('-' * 120)
            self.log('%-60s :' % 'Rule Description', end=' ')
            self.log('%-30s :' % 'Root Object Name', end=' ')
            self.log('%-30s' % 'Member Address Object')
            self.log('-' * 120)
            for policy_index in policies:
                if policies[policy_index]['policySrcNet'] != []:
                    for src in range(0, len(policies[policy_index]['policySrcNet'])):
                        for expanded_index in self.createNetworkService.expand_address(addresses, policies[policy_index]['policySrcNet'][src],
                                                             address_map):
                            for network_index in range(0, len(addresses[expanded_index]['IPv4Networks'])):
                                if ipaddress.IPv4Network(ip_to_find, strict=False).overlaps(
                                        addresses[expanded_index]['IPv4Networks'][network_index]):
                                    try:
                                        policydesc = re.sub(r'\n', '##', policies[policy_index]['policyName'][:60])
                                    except:
                                        policydesc = ''
                                    self.log('{:60.60}'.format(policydesc), end=' : ')
                                    self.log('{:30.30}'.format(policies[policy_index]['policySrcNet'][src]), end=' : ')
                                    self.log('{:30.30}'.format(expanded_index))
                                    return_list.append(expanded_index)
                if policies[policy_index]['policyDstNet'] != []:
                    for dst in range(0, len(policies[policy_index]['policyDstNet'])):
                        for expanded_index in self.createNetworkService.expand_address(addresses, policies[policy_index]['policyDstNet'][dst],
                                                             address_map):
                            for network_index in range(0, len(addresses[expanded_index]['IPv4Networks'])):
                                if ipaddress.IPv4Network(ip_to_find, strict=False).overlaps(
                                        addresses[expanded_index]['IPv4Networks'][network_index]):
                                    try:
                                        policydesc = re.sub(r'\n', '##', policies[policy_index]['policyName'][:60])
                                    except:
                                        policydesc = ''
                                    self.log('{:60.60}'.format(policydesc), end=' : ')
                                    self.log('{:30.30}'.format(policies[policy_index]['policyDstNet'][dst]), end=' : ')
                                    self.log('{:30.30}'.format(expanded_index))

                                    return_list.append(expanded_index)
        return return_list

    # Given a string, find all the policy objects that contain the string given
    # What fields should be checked?
    # Should it work as a regex?
    # Test this
    def find_description(self, policies, descriptions):

        return_list = []
        for desc_to_find in descriptions:
            self.log('-' * 120)
            self.log('Searching policies for : ' + desc_to_find)
            self.log('-' * 120)
            self.log('%-60s :' % 'Rule Description', end=' ')
            self.log('%30s :' % 'Source', end=' ')
            self.log('%-30s' % 'Destination')
            self.log('-' * 120)
            for policy_index in policies:
                if re.findall(desc_to_find, policies[policy_index]['policyComment'], flags=re.IGNORECASE):
                    self.log('%-60s :' % policies[policy_index]['policyComment'], end=' ')
                    self.log('%30s :' % policies[policy_index]['policySrcNet'], end=' ')
                    self.log('%-30s' % policies[policy_index]['policyDstNet'])
                    return_list.append('')
        return return_list

    def find_dupes(self, config):
        duplicates = OrderedDict()
        count = 0

        total = len(config['addresses'])
        tmpaddresses = deepcopy(config['addresses'])

        for address in tmpaddresses:
            del tmpaddresses[address]['addrObjId']
            del tmpaddresses[address]['addrObjIdDisp']

        duplicates['addresses'] = OrderedDict()

        for masterindex in tmpaddresses:
            masterobject = tmpaddresses[masterindex]
            # If master object is already marked as a duplicate object, skip it
            if masterindex not in duplicates['addresses']:
                # Only find dupes if address object is not a group (8)
                if masterobject['addrObjType'] != '8':  # and masterobject['addrObjProperties'] == '14':
                    for candidate in tmpaddresses:
                        if masterindex != candidate:  # don't compare master with itself
                            candidateobject = tmpaddresses[candidate]
                            # only remove candidates that are a user-defined object
                            if masterobject == candidateobject and candidateobject['addrObjProperties'] == '14':
                                # Only add the candidate if its not already in the dupe list
                                if candidate not in duplicates['addresses']:
                                    duplicates['addresses'][candidate] = masterindex
                                # break
                                # break removed, as it would stop searching for candidate in address1 after first match
                                # (not desired)
            count = count + 1

        # Find duplicate address groups - very low priority.  duplicates of entire groups not likely and would be slow
        # Find duplicate services

        total = len(config['services'])
        count = 0

        tmpservices = deepcopy(config['services'])

        for service in tmpservices:
            del tmpservices[service]['svcObjId']

        duplicates['services'] = OrderedDict()

        for masterindex in tmpservices:
            masterobject = tmpservices[masterindex]
            # If master object is already marked as a duplicate object, skip it
            if masterindex not in duplicates['services']:
                # Only find dupes if service object is not a group
                # master object can be any type, and masterobject['svcObjProperties'] == '14':
                if masterobject['svcObjType'] == '1':
                    for candidate in tmpservices:
                        # don't compare master with itself
                        if masterindex != candidate:
                            candidateobject = tmpservices[candidate]
                            # only remove candidates that are a user-defined object
                            if masterobject == candidateobject and candidateobject['svcObjProperties'] == '14':
                                # Only add the candidate if its not already in the dupe list
                                if candidate not in duplicates['services']:
                                    duplicates['services'][candidate] = masterindex
            count = count + 1

        # Find duplicate service groups - very low priority.  duplicates of entire groups not likely and would be slow
        return duplicates

    # Original script does de-dupe before find_unused, so at the moment, this script returns too many results
    def find_unused2(self, config, context):
        # multiple passes for checkpoint is useless as results need to be verified with whereused
        # add support to check routing tables (sonicwall)
        # add support to check NAT policies (DONE)
        # only check "active" policies and "enabled" rules - this will require more parsing of the whereused command

        unused = defaultdict(dict)
        unused['addresses'] = set()
        unused['addressgroups'] = set()
        unused['services'] = set()
        unused['servicegroups'] = set()
        expanded_addrgroup = defaultdict(dict)
        expanded_svcgroup = defaultdict(dict)
        all_address_group_members = set()
        all_service_group_members = set()
        all_policy_address_members = set()
        all_policy_service_members = set()
        self.log('!-- Building set of address group members')
        for address in config['addresses']:
            if config['addresses'][address]['addrObjType'] == '8':
                expanded_addrgroup[address] = self.createNetworkService.expand_address(config['addresses'],
                                                             config['addresses'][address]['addrObjId'],
                                                             config['addressmappings'], True)
                for member in expanded_addrgroup[address]:
                    all_address_group_members.add(member)
        self.log('!-- Building set of service group members')
        for service in config['services']:
            if config['services'][service]['svcObjType'] == '2':
                expanded_svcgroup[service] = self.createNetworkService.expand_service(config['services'], config['services'][service]['svcObjId'],
                                                            config['servicemappings'], True)
                for member in expanded_svcgroup[service]:
                    all_service_group_members.add(member)
        self.log('!-- Building sets for policy sources, destinations and services')
        for policy in config['policies']:
            for src in config['policies'][policy]['policySrcNet']:
                # self.debug(config['policies'][policy]['policyName'], config['policies'][policy]['policyUiNum'], 'SRC:',src)
                all_policy_address_members.add(src)
            for dst in config['policies'][policy]['policyDstNet']:
                # self.debug(config['policies'][policy]['policyName'], config['policies'][policy]['policyUiNum'], 'DST:',dst)
                all_policy_address_members.add(dst)
            for svc in config['policies'][policy]['policyDstSvc']:
                # self.debug(config['policies'][policy]['policyName'], config['policies'][policy]['policyUiNum'], 'DST:',dst)
                all_policy_service_members.add(svc)

        for policy in config['nat']:
            # 'natPolicyOrigSrc', 'natPolicyOrigDst', 'natPolicyOrigSvc', 'natPolicyTransSrc', 'natPolicyTransDst', 'natPolicyTransSvc'
            for src in config['nat'][policy]['natPolicyOrigSrc']:
                all_policy_address_members.add(src)
            for dst in config['nat'][policy]['natPolicyOrigDst']:
                all_policy_address_members.add(dst)
            for svc in config['nat'][policy]['natPolicyOrigSvc']:
                all_policy_service_members.add(svc)
            for src in config['nat'][policy]['natPolicyTransSrc']:
                all_policy_address_members.add(src)
            for dst in config['nat'][policy]['natPolicyTransDst']:
                all_policy_address_members.add(dst)
            for svc in config['nat'][policy]['natPolicyTransSvc']:
                all_policy_service_members.add(svc)

        unused_count = -1
        while len(unused['addresses']) + len(unused['addressgroups']) > unused_count:
            self.debug(len(unused['addresses']) + len(unused['addressgroups']), unused_count)
            self.debug('looping addresses')
            unused_count = len(unused['addresses']) + len(unused['addressgroups'])
            for address in config['addresses']:
                groupfound = None
                if config['addresses'][address]['addrObjType'] != '8':
                    if not (address in all_address_group_members) and not (address in all_policy_address_members):
                        unused['addresses'].add(address)
                else:
                    for group in expanded_addrgroup:
                        if address != group:
                            if address in expanded_addrgroup[group]:
                                groupfound = True
                                break
                    if not groupfound:
                        if not (address in all_policy_address_members):
                            unused['addressgroups'].add(address)
                            if address in all_policy_address_members:
                                self.debug('removing {} from pol set'.format(address))
                                all_policy_address_members.remove(address)
                            if address in all_address_group_members:
                                self.debug('removing {} from address set'.format(address))
                                all_address_group_members.remove(address)
        self.debug(len(unused['addresses']) + len(unused['addressgroups']), unused_count)

        unused_count = -1
        while len(unused['services']) > unused_count:
            self.debug(len(unused['services']) + len(unused['servicegroups']), unused_count)
            self.debug('looping services')
            unused_count = len(unused['services']) + len(unused['servicegroups'])
            for service in config['services']:
                groupfound = None
                if config['services'][service]['svcObjType'] != '2':
                    if not (service in all_service_group_members) and not (service in all_policy_service_members):
                        unused['services'].add(service)
                else:
                    for group in expanded_svcgroup:
                        if service != group:
                            if service in expanded_svcgroup[group]:
                                groupfound = True
                                break
                    if not groupfound:
                        if not (service in all_policy_service_members):
                            unused['servicegroups'].add(service)
                            if service in all_policy_service_members:
                                self.debug('removing {} from pol set'.format(service))
                                all_policy_service_members.remove(service)
                            if service in all_service_group_members:
                                self.debug('removing {} from service set'.format(service))
                                all_service_group_members.remove(service)
        self.debug(len(unused['services']) + len(unused['servicegroups']), unused_count)
        # print(expanded_svcgroup)

        return unused

    # WARNING :  This routine only checks for unused objects in areas that are loaded from the config for migration.
    # For example an address object could be used for a NAT rule, but since NAT rules are not currently migrated, NAT
    # rules are not searched.  This find_unused function should only be used for migration script purposes, and updated
    # if/when new migration functionality is added.  A second function should be created to count the number of
    # occurrances an object name exists in the entire configuration file, if broader support for unused object detection
    # is needed.
    def find_unused(self, config, context):

        unused = defaultdict(dict)
        expanded_addrgroup = defaultdict(dict)

        total = len(config['addresses'])
        count = 0
        loopcount = 0

        unused['addressgroups'] = []
        unused['addresses'] = []

        # FIND UNUSED ADDRESS GROUPS
        # create list of all address objects
        addr_list = list(config['addresses'].keys())

        # build expanded address list for all address groups
        # improves speed by about 6x
        for address in config['addresses']:
            if config['addresses'][address]['addrObjType'] == '8':
                expanded_addrgroup[address] = self.createNetworkService.expand_address(config['addresses'],
                                                             config['addresses'][address]['addrObjId'],
                                                             config['addressmappings'], True)

        for index1, address1 in enumerate(addr_list):
            # Check maps first
            found_in_policy = False
            # CHECK IF ADDRESS IS USED IN POLICY
            for policy in config['policies']:
                # CHECK EACH SOURCE ADDRESS OBJECT IN POLICY
                for source in config['policies'][policy]['policySrcNet']:
                    # DOES THE ADDRESS MATCH THE SOURCE EXACTLY?
                    if config['addresses'][address1]['addrObjId'] == source:
                        found_in_policy = True
                        break

                    if config['addresses'][address1]['addrObjId'] in expanded_addrgroup[source]:
                        found_in_policy = True
                        break

                # CHECK EACH DESTINATION ADDRESS OBJECT IN POLICY
                for dest in config['policies'][policy]['policyDstNet']:
                    if config['addresses'][address1]['addrObjId'] == dest:
                        found_in_policy = True
                        break

                    if config['addresses'][address1]['addrObjId'] in expanded_addrgroup[source]:
                        found_in_policy = True
                        break

            # CHECK IF THE ADDRESS IS PART OF AN ADDRESS GROUP
            # check to see if address is used in a group, somewhere
            if not found_in_policy:
                found_in_group = False

                for address2 in addr_list:
                    if address1 != address2:
                        # Check to see if address is part of an adress group mapping
                        if config['addresses'][address1]['addrObjId'] in \
                                expanded_addrgroup[config['addresses'][address2]['addrObjId']]:
                            found_in_group = True
                            break

                if not found_in_group:
                    found_in_route = False
                    for route in config['routing']:
                        if address1 == config['routing'][route]['pbrObjSrc'] or \
                                address1 == config['routing'][route]['pbrObjDst'] or \
                                address1 == config['routing'][route]['pbrObjGw']:
                            found_in_route = True
                            break
                        if address1 in expanded_addrgroup[config['routing'][route]['pbrObjSrc']] or address1 in \
                                expanded_addrgroup[config['routing'][route]['pbrObjDst']] or address1 in \
                                expanded_addrgroup[
                                    config['routing'][route]['pbrObjGw']]:
                            found_in_route = True
                            break

                    if not found_in_route:
                        if config['addresses'][address1]['addrObjType'] == '8':
                            unused['addressgroups'].append(address1)
                        else:
                            unused['addresses'].append(address1)
            count = count + 1
            if not self.options.web: self.log('[' + str(count) + '/' + str(total) + ']   ', end='\r')

        total = len(config['services'])
        count = 0

        unused['servicegroups'] = []

        # FIND UNUSED SERVICE GROUPS
        for service1 in config['services']:
            if config['services'][service1]['svcObjType'] == '2':
                found_in_policy = False
                # CHECK IF SERVICE IS USED IN POLICY
                for policy in config['policies']:
                    # CHECK EACH DEST SERVICE OBJECT IN POLICY
                    for service in config['policies'][policy]['policyDstSvc']:
                        if config['services'][service1]['svcObjId'] in \
                                self.createNetworkService.expand_service(config['services'], service, config['servicemappings'], True):
                            found_in_policy = True
                            break

                        # DOES THE SERVICE MATCH THE SOURCE EXACTLY?
                        if config['services'][service1]['svcObjId'] == service:
                            found_in_policy = True
                            break

                # CHECK IF THE SERVICE IS PART OF A SERVICE GROUP
                # (DONE) CHANGEME - expand_service needs to be updated to include service groups
                # (inc_group=True param now passed to function)

                # check to see if service is used in a group, somewhere
                if not found_in_policy:
                    found_in_group = False
                    for service2 in config['services']:
                        loopcount = loopcount + 1
                        if service1 != service2:
                            # Check to see if service is in an expanded service object
                            # (should not need to perform this check for service groups) WHY NOT?
                            if config['services'][service1]['svcObjId'] in \
                                    self.createNetworkService.expand_service(config['services'], config['services'][service2]['svcObjId'],
                                                   config['servicemappings'], True):
                                found_in_group = True
                                break
                    if not found_in_group:
                        found_in_route = False
                        for route in config['routing']:
                            if service1 == config['routing'][route]['pbrObjSvc']:
                                found_in_route = True
                        if not found_in_route:
                            unused['servicegroups'].append(service1)
            count = count + 1
            if not self.options.web: self.log('[' + str(count) + '/' + str(total) + ']   ', end='\r')

        total = len(config['services'])
        count = 0

        # FIND UNUSED SERVICES
        unused['services'] = []
        for service1 in config['services']:
            if config['services'][service1]['svcObjType'] != '2':
                found_in_policy = False
                for policy in config['policies']:
                    for service in config['policies'][policy]['policyDstSvc']:
                        if 'servicemappings' in config:
                            if service in config['servicemappings']:
                                if config['services'][service1]['svcObjId'] in \
                                        self.createNetworkService.expand_service(config['services'], service, context, True):
                                    found_in_policy = True
                                    break

                        if config['services'][service1]['svcObjId'] == service:
                            found_in_policy = True
                            break

                # check to see if service is used in a group, somewhere
                if not found_in_policy:
                    found_in_group = False
                    for service2 in config['services']:
                        if service1 != service2 and config['services'][service2]['svcObjType'] == "2":
                            if config['services'][service1]['svcObjId'] in \
                                    self.createNetworkService.expand_service(config['services'], config['services'][service2]['svcObjId'],
                                                   config['servicemappings'], True):
                                found_in_group = True
                                break

                    if not found_in_group:
                        unused['services'].append(service1)
            count = count + 1
            if not self.options.web: self.log('[' + str(count) + '/' + str(total) + ']    ', end='\r')
        return unused