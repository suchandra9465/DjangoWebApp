import os
from collections import defaultdict, OrderedDict

import Service as S
from ... import NetworkLogs


class LoadService:

    def _init_(self, options):
        self.log = NetworkLogs().log
        self.sc = NetworkLogs().sc
        self.ss = NetworkLogs().ss
        self.debug = NetworkLogs().debug
        self.options = options
        self.service = S.Service(self.options)
        self.return_address = OrderedDict();

    # Load Panorama configuration .xml file
    # Loading Shared objects not fully implemented CHANGEME (load policies)
    # DONE Detect Pano vs Palo config and load appropriately
    # DONE Pano should have xpath /config/mgt-config/devices
    def load_xml(self, infile, memoryconfig=None):

        def load_addresses(address_list):

            return_address = OrderedDict()

            for address in address_list:
                current_address = address.get('name')
                return_address[current_address] = OrderedDict()
                return_address[current_address]['addrObjId'] = current_address
                return_address[current_address]['addrObjIdDisp'] = ''
                return_address[current_address]['addrObjType'] = ''
                return_address[current_address]['addrObjZone'] = ''
                return_address[current_address]['addrObjProperties'] = '14'
                return_address[current_address]['addrObjIp1'] = ''
                return_address[current_address]['addrObjIp2'] = ''
                return_address[current_address]['addrObjComment'] = ''
                return_address[current_address]['addrObjColor'] = ''
                return_address[current_address]['IPv4Networks'] = [ipaddress.IPv4Network(u'255.255.255.255/32')]

                for address_tags in address.findall('.'):

                    for item in address_tags.iter():
                        if item.tag in ['ip-netmask', 'ip-range', 'description', 'fqdn']:
                            if item.tag.lower() == 'ip-netmask':
                                if re.findall('/', item.text):
                                    ipaddr, mask = item.text.split('/')
                                    if mask == '32':
                                        return_address[current_address]['addrObjType'] = '1'
                                        return_address[current_address]['addrObjIp1'] = ipaddr
                                        return_address[current_address]['addrObjIp2'] = '255.255.255.255'
                                    elif int(mask) < 32:
                                        return_address[current_address]['addrObjType'] = '4'
                                        return_address[current_address]['addrObjIp2'] = self.service.cidr_to_netmask(mask)
                                        return_address[current_address]['addrObjIp1'] = ipaddr
                                    else:
                                        return_address[current_address][
                                            'addrObjType'] = '66'  # placeholder for IPv6 Addresses
                                    try:
                                        return_address[current_address]['IPv4Networks'] = [
                                            ipaddress.IPv4Network(item.text, strict=False)]
                                    except:
                                        pass
                                else:
                                    return_address[current_address]['addrObjIp1'] = item.text
                                    return_address[current_address]['addrObjIp2'] = '255.255.255.255'
                                    return_address[current_address]['addrObjType'] = '1'
                                    try:
                                        return_address[current_address]['IPv4Networks'] = [
                                            ipaddress.IPv4Network(item.text + '/32', strict=False)]
                                    except:
                                        pass
                            elif item.tag.lower() == 'ip-range':
                                range_start, range_end = item.text.split('-')
                                return_address[current_address]['addrObjIp1'] = range_start
                                return_address[current_address]['addrObjIp2'] = range_end
                                return_address[current_address]['addrObjType'] = '2'
                                return_address[current_address]['IPv4Networks'] = [
                                    ipaddress.IPv4Network(u'255.255.255.254/32')]  ## why 255.255.255.254/32??
                                try:
                                    return_address[current_address]['IPv4Networks'] = [ipaddr for ipaddr in
                                                                                       ipaddress.summarize_address_range(
                                                                                           ipaddress.IPv4Address(
                                                                                               range_start),
                                                                                           ipaddress.IPv4Address(
                                                                                               range_end))]
                                except:
                                    pass
                            elif item.tag.lower() == 'fqdn':
                                return_address[current_address]['fqdn'] = item.text
                                return_address[current_address]['IPv4Networks'] = [
                                    ipaddress.IPv4Network(u'255.255.255.254/32')]
                                return_address[current_address][
                                    'addrObjType'] = '89'  ## Set a type not used by sonicwall

                            elif item.tag.lower() == 'description':
                                return_address[current_address]['addrObjIdDisp'] = item.text
                                return_address[current_address]['addrObjIdComment'] = item.text

            return return_address

        def load_address_groups(address_list):

            return_address_group = OrderedDict()
            addr_mappings = OrderedDict()
            for address in address_list:
                current_address = address.get('name')
                return_address_group[current_address] = OrderedDict()
                return_address_group[current_address]['addrObjId'] = current_address
                return_address_group[current_address]['addrObjIdDisp'] = ''
                return_address_group[current_address]['addrObjType'] = '8'
                return_address_group[current_address]['addrObjZone'] = ''
                return_address_group[current_address]['addrObjProperties'] = '14'
                return_address_group[current_address]['addrObjIp1'] = ''
                return_address_group[current_address]['addrObjIp2'] = ''
                return_address_group[current_address]['addrObjComment'] = ''
                return_address_group[current_address]['IPv4Networks'] = []
                addr_mappings[current_address] = []
                if address.find('description') != None:
                    return_address_group[current_address]['addrObjIdDisp'] = address.find('description').text
                    return_address_group[current_address]['addrObjComment'] = address.find('description').text
                for address_group_member in address.findall('./static/member'):
                    addr_mappings[current_address].append(address_group_member.text)
            return return_address_group, addr_mappings

        def load_services(service_list):

            return_service = OrderedDict()
            for service in service_list:
                current_service = service.get('name')
                return_service[current_service] = OrderedDict()
                return_service[current_service]['svcObjId'] = current_service
                return_service[current_service]['svcObjType'] = '1'
                return_service[current_service]['svcObjProperties'] = '14'
                return_service[current_service]['svcObjIpType'] = '1'
                return_service[current_service]['svcObjPort1'] = ''
                return_service[current_service]['svcObjPort2'] = ''
                return_service[current_service]['svcObj'] = '0'
                return_service[current_service]['svcObjManagement'] = ''
                return_service[current_service]['svcObjHigherPrecedence'] = ''
                return_service[current_service][
                    'svcObjComment'] = ''  # root.find('./devices/entry/device-group/entry[@name=\''+current_group+'\']/service/entry[@name=\''+current_service+'\']').findtext('description')
                if service.find('description') != None:
                    return_service[current_service]['svcObjComment'] = service.find('description').text
                if service.findall('./protocol/tcp'):
                    return_service[current_service]['svcObjIpType'] = '6'
                    port = service.find('./protocol/tcp').findtext('port')
                elif service.findall('./protocol/udp'):
                    return_service[current_service]['svcObjIpType'] = '17'
                    port = service.find('./protocol/udp').findtext('port')

                if re.findall(',', port):  ## list of ports
                    return_service[current_service]['svcObjPort1'], return_service[current_service]['svcObjPort2'] = (
                        None, None)
                    return_service[current_service]['svcObjPortSet'] = port.split(',')
                    self.debug('PORTSET: ', current_service, return_service[current_service]['svcObjPortSet'])
                    return_service[current_service]['svcObjPort1'] = '0'
                    return_service[current_service]['svcObjPort2'] = '0'
                    return_service[current_service]['svcObjType'] = '4'
                elif re.findall('-', port):  ## Port range
                    return_service[current_service]['svcObjType'] = '1'
                    return_service[current_service]['svcObjPort1'], return_service[current_service][
                        'svcObjPort2'] = port.split('-')
                else:  ## Single port
                    return_service[current_service]['svcObjType'] = '1'
                    return_service[current_service]['svcObjPort1'] = port
                    return_service[current_service]['svcObjPort2'] = port
            return return_service

        def load_service_groups(service_list):

            return_service = OrderedDict()
            svc_mappings = OrderedDict()
            for service in service_list:
                current_service = service.get('name')
                return_service[current_service] = OrderedDict()
                return_service[current_service]['svcObjId'] = current_service
                return_service[current_service]['svcObjType'] = '2'
                return_service[current_service]['svcObjProperties'] = '14'
                return_service[current_service]['svcObjIpType'] = '0'
                return_service[current_service]['svcObjPort1'] = ''
                return_service[current_service]['svcObjPort2'] = ''
                return_service[current_service]['svcObjManagement'] = ''
                return_service[current_service]['svcObjHigherPrecedence'] = ''
                return_service[current_service]['svcObjComment'] = ''
                svc_mappings[current_service] = []
                if service.find('description') != None:
                    return_service[current_service]['svcObjComment'] = service.find('description').text
                for service_group_member in service.findall('./members/member'):
                    svc_mappings[current_service].append(service_group_member.text)
            return return_service, svc_mappings

        def load_policies(policy_list):

            policy_index = 0
            return_policy = OrderedDict()

            for policy in policy_list:

                disabled = policy.find('.').findtext('disabled')
                if disabled:
                    disabled = disabled.lower()
                if not (disabled == 'yes' and self.options.skip_disabled):
                    current_policy = policy.get('name')
                    return_policy[policy_index] = OrderedDict()
                    return_policy[policy_index]['policyName'] = current_policy
                    return_policy[policy_index]['policyAction'] = ''
                    return_policy[policy_index]['policySrcZone'] = []
                    return_policy[policy_index]['policyDstZone'] = []
                    return_policy[policy_index]['policySrcNet'] = []
                    return_policy[policy_index]['policyDstNet'] = []
                    return_policy[policy_index]['policyDstSvc'] = []
                    return_policy[policy_index]['policyDstApps'] = []
                    return_policy[policy_index]['policyLog'] = ''
                    return_policy[policy_index]['policyEnabled'] = '1'
                    return_policy[policy_index]['policyProps'] = '0'
                    return_policy[policy_index]['policyNum'] = None
                    return_policy[policy_index]['policyUiNum'] = None
                    return_policy[policy_index]['policySrcNegate'] = False
                    return_policy[policy_index]['policyDstNegate'] = False
                    return_policy[policy_index]['policySvcNegate'] = False
                    return_policy[policy_index]['policyComment'] = policy.find('.').findtext('description')
                    if return_policy[policy_index]['policyComment'] == None: return_policy[policy_index][
                        'policyComment'] = ''  # Set Comment to blank if not found
                    return_policy[policy_index]['policyLogSetting'] = policy.find('.').findtext('log-setting')
                    if return_policy[policy_index]['policyLogSetting'] == None: return_policy[policy_index][
                        'policyLogSetting'] = ''  # Set Log Setting to blank if not found
                    return_policy[policy_index]['policyLogStart'] = policy.find('.').findtext('log-start')
                    if return_policy[policy_index]['policyLogStart'] == None: return_policy[policy_index][
                        'policyLogStart'] = ''  # Set Log Setting to blank if not found
                    return_policy[policy_index]['policyLogEnd'] = policy.find('.').findtext('log-end')
                    if return_policy[policy_index]['policyLogEnd'] == None: return_policy[policy_index][
                        'policyLogEnd'] = ''  # Set Log Setting to blank if not found

                    disabled = policy.find('.').findtext('disabled')
                    action = policy.find('.').findtext('action')
                    if disabled == 'yes':
                        return_policy[policy_index]['policyEnabled'] = '0'
                    if action.lower() == 'allow':
                        return_policy[policy_index]['policyAction'] = '2'
                    elif action == 'deny':
                        return_policy[policy_index]['policyAction'] = '0'
                    elif action.lower() == 'drop':
                        return_policy[policy_index]['policyAction'] = '1'
                    for member in policy.findall('./to/member'):
                        return_policy[policy_index]['policyDstZone'].append(member.text)
                    for member in policy.findall('./from/member'):
                        return_policy[policy_index]['policySrcZone'].append(member.text)
                    for member in policy.findall('./source/member'):
                        return_policy[policy_index]['policySrcNet'].append(member.text)
                    for member in policy.findall('./destination/member'):
                        return_policy[policy_index]['policyDstNet'].append(member.text)
                    for member in policy.findall('./service/member'):
                        return_policy[policy_index]['policyDstSvc'].append(member.text)
                    for member in policy.findall('./application/member'):
                        return_policy[policy_index]['policyDstApps'].append(member.text)
                    policy_index = policy_index + 1
            return return_policy

        def load_nat(policy_list, interfaces):

            policy_index = 0
            return_nat = OrderedDict()

            for policy in policy_list:
                disabled = policy.find('.').findtext('disabled')
                if disabled:
                    disabled = disabled.lower()
                if not (disabled == 'yes' and self.options.skip_disabled):
                    current_policy = policy.get('name')
                    return_nat[policy_index] = OrderedDict()
                    return_nat[policy_index]['natPolicyName'] = current_policy
                    return_nat[policy_index]['natPolicySrcZone'] = []
                    return_nat[policy_index]['natPolicyDstZone'] = []
                    return_nat[policy_index]['natPolicyOrigSrc'] = []
                    return_nat[policy_index]['natPolicyOrigDst'] = []
                    return_nat[policy_index]['natPolicyOrigSvc'] = []
                    return_nat[policy_index]['natPolicyTransSrc'] = []
                    return_nat[policy_index]['natPolicyTransDst'] = []
                    return_nat[policy_index]['natPolicyTransSvc'] = []
                    return_nat[policy_index]['natPolicySrcIface'] = []
                    return_nat[policy_index]['natPolicyDstIface'] = []
                    return_nat[policy_index]['natPolicyEnabled'] = '1'
                    return_nat[policy_index]['natPolicyProperties'] = '0'
                    return_nat[policy_index]['natPolicyComment'] = policy.find('.').findtext('description')
                    if return_nat[policy_index]['natPolicyComment'] == None: return_nat[policy_index][
                        'natPolicyComment'] = ''  # Set Comment to blank if not found
                    disabled = policy.find('.').findtext('disabled')
                    if disabled == 'yes':
                        return_nat[policy_index]['natPolicyEnabled'] = '0'
                    for member in policy.findall('./to/member'):
                        return_nat[policy_index]['natPolicyDstZone'].append(member.text)
                    for member in policy.findall('./from/member'):
                        return_nat[policy_index]['natPolicySrcZone'].append(member.text)
                    for member in policy.findall('./source/member'):
                        return_nat[policy_index]['natPolicyOrigSrc'].append(member.text)
                    for member in policy.findall('./destination/member'):
                        return_nat[policy_index]['natPolicyOrigDst'].append(member.text)
                    for member in policy.findall('./service/member'):
                        return_nat[policy_index]['natPolicyOrigSvc'].append(member.text)

                    #### Need to figure out how to determine translated values based on NAT type set in config
                    if policy.find('.').findtext('source-translation'):
                        if policy.find('./source-translation').findtext('dynamic-ip-and-port'):
                            if policy.find('./source-translation/dynamic-ip-and-port').findtext('translated-address'):
                                for member in policy.findall(
                                        './source-translation/dynamic-ip-and-port/translated-address/member'):
                                    return_nat[policy_index]['natPolicyTransSrc'].append(member.text)
                            if policy.find('./source-translation/dynamic-ip-and-port').findtext('interface-address'):
                                int_name = policy.find(
                                    './source-translation/dynamic-ip-and-port/interface-address').findtext('interface')
                                if int_name in interfaces:
                                    return_nat[policy_index]['natPolicyTransSrc'] = [
                                        interfaces[int_name]['iface_static_ip']]
                                else:
                                    return_nat[policy_index]['natPolicyTransSrc'] = 'UNKNOWN'
                                if policy.find('./source-translation/dynamic-ip-and-port/interface-address').findtext(
                                        'ip'):
                                    return_nat[policy_index]['natPolicyTransSrc'] = [policy.find(
                                        './source-translation/dynamic-ip-and-port/interface-address/ip').text]
                        if policy.find('./source-translation').findtext('dynamic-ip'):
                            if policy.find('./source-translation/dynamic-ip').findtext('translated-address'):
                                for member in policy.findall(
                                        './source-translation/dynamic-ip/translated-address/member'):
                                    return_nat[policy_index]['natPolicyTransSrc'].append(member.text)
                                if policy.find('./source-translation/dynamic-ip').findtext('fallback'):
                                    self.log('WARNING: FALLBACK settings not supoprted in source-translation dynamic-ip ')
                        if policy.find('./source-translation').findtext('static-ip'):
                            if policy.find('./source-translation/static-ip').findtext('translated-address'):
                                return_nat[policy_index]['natPolicyTransSrc'] = [
                                    policy.find('./source-translation/static-ip/translated-address').text]
                    if policy.find('.').findtext('destination-translation'):
                        if policy.find('./destination-translation').findtext('translated-address'):
                            return_nat[policy_index]['natPolicyTransDst'] = [
                                policy.find('./destination-translation/translated-address').text]
                        if policy.find('./destination-translation').findtext('translated-port'):
                            return_nat[policy_index]['natPolicyTransSvc'] = [
                                policy.find('./destination-translation/translated-port').text]
                    if policy.find('.').findtext('dynamic-destination-translation'):
                        self.log('dynamic-destination-translation set')
                        if policy.find('./dynamic-destination-translation').findtext('translated-address'):
                            return_nat[policy_index]['natPolicyTransDst'] = [
                                policy.find('./dynamic-destination-translation/translated-address').text]
                        if policy.find('./dynamic-destination-translation').findtext('translated-port'):
                            return_nat[policy_index]['natPolicyTransSvc'] = [
                                policy.find('./dynamic-destination-translation/translated-port').text]

                    policy_index = policy_index + 1
            return return_nat

        def load_zones(zone_list):

            return_zones = OrderedDict()
            # if root.find(zone_base)!=None:
            # zone_props = ['zoneObjId', 'zoneObjComment']

            for zone in zone_list:
                zone_name = zone.get('name')
                return_zones[zone_name] = OrderedDict()
                return_zones[zone_name]['zoneObjId'] = zone_name
                return_zones[zone_name]['zoneObjComment'] = 'Zone Comment'
                return_zones[zone_name]['zoneObjMembers'] = []
                # print(zone.get('name'))
                for interface in zone.findall('.//member'):
                    # print(interface.text)
                    return_zones[zone_name]['zoneObjMembers'].append(interface.text)

            return return_zones

        def load_variables(variable_list):

            variables = {}
            for variable in variable_list:
                if variable:
                    variables[variable.get('name')] = variable.find('.//ip-netmask').text
                # debug('variable_name', variable.get('name'))
                # debug('variable_def', variable.find('.//ip-netmask').text)
            return variables

        def load_interface(interface_base):

            return_interface = OrderedDict()

            index = 0
            # print(root.findall(interface_base))
            if root.find(interface_base) != None:
                for interface_type in root.find(interface_base):
                    for interface_names in root.findall(interface_base + '/' + interface_type.tag + '/entry'):
                        interface_name = interface_names.get('name')
                        return_interface[interface_name] = OrderedDict()
                        return_interface[interface_name]['iface_ifnum'] = str(index)
                        return_interface[interface_name]['iface_type'] = interface_type.tag
                        return_interface[interface_name]['iface_name'] = interface_name
                        return_interface[interface_name]['interface_Zone'] = ''  # this would get set when reading zones
                        return_interface[interface_name]['iface_comment'] = ''
                        return_interface[interface_name]['iface_static_ip'] = ''
                        return_interface[interface_name]['iface_static_mask'] = ''
                        return_interface[interface_name]['iface_static_gateway'] = ''
                        return_interface[interface_name]['iface_lan_ip'] = ''
                        return_interface[interface_name]['iface_lan_mask'] = ''
                        return_interface[interface_name]['iface_lan_default_gw'] = ''
                        return_interface[interface_name]['iface_mgmt_ip'] = ''
                        return_interface[interface_name]['iface_mgmt_netmask'] = ''
                        return_interface[interface_name]['iface_mgmt_default_gw'] = ''
                        return_interface[interface_name]['iface_vlan_tag'] = ''
                        return_interface[interface_name]['portShutdown'] = ''
                        index += 1
                        comment = root.find(
                            interface_base + '/' + interface_type.tag + '/entry[@name="' + interface_name + '"]/comment')
                        if comment != None: return_interface[interface_name]['iface_comment'] = comment.text
                        for interface in root.findall(
                                interface_base + '/' + interface_type.tag + '/entry[@name="' + interface_name + '"]'):
                            for interface_attribs in interface:
                                if interface_type.tag in ['ethernet',
                                                          'aggregate-ethernet'] and interface_attribs.tag.lower() == 'layer3':
                                    ip = root.find(
                                        interface_base + '/' + interface_type.tag + '/entry[@name="' + interface_name + '"]/' + interface_attribs.tag + '/ip/entry[@name]')
                                    if ip != None:
                                        if ip.get('name') in return_variables:
                                            ipname = return_variables[ip.get('name')]
                                        else:
                                            ipname = ip.get('name')
                                        if re.findall('/', ipname):
                                            return_interface[interface_name]['iface_static_ip'], \
                                            return_interface[interface_name]['iface_static_mask'] = ipname.split('/')
                                            return_interface[interface_name]['iface_static_mask'] = self.service.cidr_to_netmask(
                                                return_interface[interface_name]['iface_static_mask'])
                                        else:
                                            return_interface[interface_name]['iface_static_ip'], \
                                            return_interface[interface_name]['iface_static_mask'] = '0.0.0.0', '0'
                                    if interface_type.tag == 'aggregate-ethernet':  # get ip addresses for sub-interfaces
                                        for sub_interfaces in root.findall(
                                                interface_base + '/' + interface_type.tag + '/entry[@name="' + interface_name + '"]/layer3/units/entry[@name]'):
                                            sub_interface = sub_interfaces.get('name')
                                            return_interface[sub_interface] = OrderedDict()
                                            return_interface[sub_interface]['iface_ifnum'] = str(index)
                                            return_interface[sub_interface]['iface_type'] = interface_type.tag
                                            return_interface[sub_interface]['iface_name'] = sub_interface
                                            return_interface[sub_interface][
                                                'interface_Zone'] = ''  # this would get set when reading zones
                                            return_interface[sub_interface]['iface_comment'] = ''
                                            return_interface[sub_interface]['iface_static_ip'] = ''
                                            return_interface[sub_interface]['iface_static_mask'] = ''
                                            return_interface[sub_interface]['iface_static_gateway'] = ''
                                            return_interface[sub_interface]['iface_lan_ip'] = ''
                                            return_interface[sub_interface]['iface_lan_mask'] = ''
                                            return_interface[sub_interface]['iface_lan_default_gw'] = ''
                                            return_interface[sub_interface]['iface_mgmt_ip'] = ''
                                            return_interface[sub_interface]['iface_mgmt_netmask'] = ''
                                            return_interface[sub_interface]['iface_mgmt_default_gw'] = ''
                                            return_interface[sub_interface]['iface_vlan_tag'] = ''
                                            return_interface[sub_interface]['portShutdown'] = ''
                                            index += 1
                                            ip = root.find(
                                                interface_base + '/' + interface_type.tag + '/entry[@name="' + interface_name + '"]/' + interface_attribs.tag + '/units/entry[@name="' + sub_interface + '"]/ip/entry[@name]')
                                            tag = root.find(
                                                interface_base + '/' + interface_type.tag + '/entry[@name="' + interface_name + '"]/' + interface_attribs.tag + '/units/entry[@name="' + sub_interface + '"]/tag')
                                            comment = root.find(
                                                interface_base + '/' + interface_type.tag + '/entry[@name="' + interface_name + '"]/' + interface_attribs.tag + '/units/entry[@name="' + sub_interface + '"]/comment')
                                            if ip != None:
                                                if ip.get('name') in return_variables:
                                                    ipname = return_variables[ip.get('name')]
                                                else:
                                                    ipname = ip.get('name')
                                                if re.findall('/', ipname):
                                                    return_interface[sub_interface]['iface_static_ip'], \
                                                    return_interface[sub_interface]['iface_static_mask'] = ipname.split(
                                                        '/')
                                                    return_interface[sub_interface][
                                                        'iface_static_mask'] = self.service.cidr_to_netmask(
                                                        return_interface[sub_interface]['iface_static_mask'])
                                                else:
                                                    return_interface[sub_interface]['iface_static_ip'], \
                                                    return_interface[sub_interface][
                                                        'iface_static_mask'] = '0.0.0.0', '0'
                                            if tag != None: return_interface[sub_interface]['iface_vlan_tag'] = tag.text
                                            if comment != None: return_interface[sub_interface][
                                                'iface_comment'] = comment.text

            return return_interface

        def load_interface2(interface_base):

            return_interface = OrderedDict()

            index = 0
            if root.findall(interface_base) != None:
                for interface_type in root.find(interface_base):
                    print(interface_type)
                    for interface_names in root.findall(interface_base + '/' + interface_type.tag + '/entry'):
                        interface_name = interface_names.get('name')
                        print(interface_name)
                        return_interface[interface_name] = OrderedDict()
                        return_interface[interface_name]['iface_ifnum'] = str(index)
                        return_interface[interface_name]['iface_type'] = interface_type.tag
                        return_interface[interface_name]['iface_name'] = interface_name
                        return_interface[interface_name]['interface_Zone'] = ''  # this would get set when reading zones
                        return_interface[interface_name]['iface_comment'] = ''
                        return_interface[interface_name]['iface_static_ip'] = ''
                        return_interface[interface_name]['iface_static_mask'] = ''
                        return_interface[interface_name]['iface_static_gateway'] = ''
                        return_interface[interface_name]['iface_lan_ip'] = ''
                        return_interface[interface_name]['iface_lan_mask'] = ''
                        return_interface[interface_name]['iface_lan_default_gw'] = ''
                        return_interface[interface_name]['iface_mgmt_ip'] = ''
                        return_interface[interface_name]['iface_mgmt_netmask'] = ''
                        return_interface[interface_name]['iface_mgmt_default_gw'] = ''
                        return_interface[interface_name]['iface_vlan_tag'] = ''
                        return_interface[interface_name]['portShutdown'] = ''
                        index += 1
                        comment = root.find(
                            interface_base + '/' + interface_type.tag + '/entry[@name="' + interface_name + '"]/comment')
                        if comment != None: return_interface[interface_name]['iface_comment'] = comment.text
                        for interface in root.findall(
                                interface_base + '/' + interface_type.tag + '/entry[@name="' + interface_name + '"]'):
                            for interface_attribs in interface:
                                if interface_type.tag in ['ethernet',
                                                          'aggregate-ethernet'] and interface_attribs.tag == 'layer3':
                                    ip = root.find(
                                        interface_base + '/' + interface_type.tag + '/entry[@name="' + interface_name + '"]/' + interface_attribs.tag + '/ip/entry[@name]')
                                    if ip != None:
                                        if re.findall('/', ip.get('name')):
                                            return_interface[interface_name]['iface_static_ip'], \
                                            return_interface[interface_name]['iface_static_mask'] = ip.get(
                                                'name').split('/')
                                        else:
                                            return_interface[sub_interface]['iface_static_ip'], \
                                            return_interface[sub_interface]['iface_static_mask'] = '0.0.0.0', '0'
                                    if interface_type.tag == 'aggregate-ethernet':  # get ip addresses for sub-interfaces
                                        for sub_interfaces in root.findall(
                                                interface_base + '/' + interface_type.tag + '/entry[@name="' + interface_name + '"]/layer3/units/entry[@name]'):
                                            sub_interface = sub_interfaces.get('name')
                                            return_interface[sub_interface] = OrderedDict()
                                            return_interface[sub_interface]['iface_ifnum'] = str(index)
                                            return_interface[sub_interface]['iface_type'] = interface_type.tag
                                            return_interface[sub_interface]['iface_name'] = sub_interface
                                            return_interface[sub_interface][
                                                'interface_Zone'] = ''  # this would get set when reading zones
                                            return_interface[sub_interface]['iface_comment'] = ''
                                            return_interface[sub_interface]['iface_static_ip'] = ''
                                            return_interface[sub_interface]['iface_static_mask'] = ''
                                            return_interface[sub_interface]['iface_static_gateway'] = ''
                                            return_interface[sub_interface]['iface_lan_ip'] = ''
                                            return_interface[sub_interface]['iface_lan_mask'] = ''
                                            return_interface[sub_interface]['iface_lan_default_gw'] = ''
                                            return_interface[sub_interface]['iface_mgmt_ip'] = ''
                                            return_interface[sub_interface]['iface_mgmt_netmask'] = ''
                                            return_interface[sub_interface]['iface_mgmt_default_gw'] = ''
                                            return_interface[sub_interface]['iface_vlan_tag'] = ''
                                            return_interface[sub_interface]['portShutdown'] = ''
                                            index += 1
                                            ip = root.find(
                                                interface_base + '/' + interface_type.tag + '/entry[@name="' + interface_name + '"]/' + interface_attribs.tag + '/units/entry[@name="' + sub_interface + '"]/ip/entry[@name]')
                                            tag = root.find(
                                                interface_base + '/' + interface_type.tag + '/entry[@name="' + interface_name + '"]/' + interface_attribs.tag + '/units/entry[@name="' + sub_interface + '"]/tag')
                                            comment = root.find(
                                                interface_base + '/' + interface_type.tag + '/entry[@name="' + interface_name + '"]/' + interface_attribs.tag + '/units/entry[@name="' + sub_interface + '"]/comment')
                                            if ip != None:
                                                if ip.get('name') in return_addresses:
                                                    return_interface[sub_interface]['iface_static_ip'], \
                                                    return_interface[sub_interface]['iface_static_mask']
                                                     #   return_address[ip.get('name')]['addrObjIp1'], \
                                                     #   return_address[ip.get('name')]['addrObjIp2']
                                                else:
                                                    if re.findall('/', ip.get('name')):
                                                        return_interface[sub_interface]['iface_static_ip'], \
                                                        return_interface[sub_interface]['iface_static_mask'] = ip.get(
                                                            'name').split('/')
                                                    else:
                                                        return_interface[sub_interface]['iface_static_ip'], \
                                                        return_interface[sub_interface][
                                                            'iface_static_mask'] = '0.0.0.0', '0'
                                            if tag != None: return_interface[sub_interface]['iface_vlan_tag'] = tag.text
                                            if comment != None: return_interface[sub_interface][
                                                'iface_comment'] = comment.text
            else:
                print('no interfaces found')
                print('')

            return return_interface

        def load_vrouters(vrouter_base):

            return_vrouter = OrderedDict()

            if root.find(vrouter_base) != None:
                for vrouter in root.find(vrouter_base):
                    vrouter_name = vrouter.get('name')
                    return_vrouter[vrouter_name] = OrderedDict()
                    if root.find(vrouter_base + '/entry[@name="' + vrouter_name + '"]/routing-table/ip/static-route'):
                        for static_routes in root.find(
                                vrouter_base + '/entry[@name="' + vrouter_name + '"]/routing-table/ip/static-route'):
                            static_name = static_routes.get('name')
                            return_vrouter[vrouter_name][static_name] = OrderedDict()
                            # return_vrouter[vrouter_name][static_name]['nexthop']=''
                            return_vrouter[vrouter_name][static_name]['destination'] = ''
                            return_vrouter[vrouter_name][static_name]['metric'] = ''
                            return_vrouter[vrouter_name][static_name]['bfd'] = ''

                            for vrouter_attribs in root.find(
                                    vrouter_base + '/entry[@name="' + vrouter_name + '"]/routing-table/ip/static-route/entry[@name="' + static_name + '"]'):
                                # debug(vrouter_attribs.tag)
                                if vrouter_attribs.tag.lower() == 'nexthop':
                                    return_vrouter[vrouter_name][static_name]['nexthops'] = []
                                    for nexthop in root.find(
                                            vrouter_base + '/entry[@name="' + vrouter_name + '"]/routing-table/ip/static-route/entry[@name="' + static_name + '"]/nexthop'):
                                        return_vrouter[vrouter_name][static_name]['nexthops'].append(nexthop.text)
                                elif vrouter_attribs.tag.lower() == 'destination':
                                    return_vrouter[vrouter_name][static_name]['destination'] = vrouter_attribs.text
                                elif vrouter_attribs.tag.lower() == 'bfd':
                                    return_vrouter[vrouter_name][static_name]['bfd'] = vrouter_attribs.text
                                elif vrouter_attribs.tag.lower() == 'metric':
                                    return_vrouter[vrouter_name][static_name]['metric'] = vrouter_attribs.text

            return return_vrouter

        import xml.etree.ElementTree as et
        from collections import OrderedDict
        import ipaddress
        import re

        return_config = OrderedDict()

        addr_mappings = OrderedDict()
        svc_mappings = OrderedDict()

        if memoryconfig:
            root = et.fromstring(memoryconfig)
            # exit(1)
        else:
            panorama = et.parse(infile)
            root = panorama.getroot()

        if root.findall('./mgt-config/devices') != []:
            pan_config = True
            self.log('!-- Loading Panorama XML file')
        else:
            pan_config = False
            self.log('!-- Loading Palo Alto XML file')

        if pan_config == True:  # loop through all device groups for Panorama
            for templates in root.findall('./devices/entry/template/entry'):

                template = templates.get('name')

                return_config[template] = OrderedDict()
                self.log('!-- Reading Template : ' + template)

                ##      LOAD VARIABLES FROM XML
                self.log('  |-- Variable Objects             ', end='')
                variable_list = root.findall(
                    './devices/entry[@name="localhost.localdomain"]/template/entry[@name=\'' + template + '\']/variable/entry')
                if variable_list:
                    return_variables = load_variables(variable_list)

                ##      LOAD VROUTERS FROM XML
                self.log('  |-- Loading VRouters', end='')
                return_vrouters = load_vrouters(
                    './devices/entry[@name="localhost.localdomain"]/template/entry[@name="' + template + '"]/config/devices/entry[@name="localhost.localdomain"]/network/virtual-router')
                # self.log(return_vrouters)

                ##      LOAD INTERFACES FROM XML
                self.log('  |-- Interface Objects             ', end='')
                return_interface = load_interface(
                    './devices/entry[@name="localhost.localdomain"]/template/entry[@name=\'' + template + '\']/config/devices/entry[@name=\'localhost.localdomain\']/network/interface')
                # debug(root.findall('./devices/entry[@name="localhost.localdomain"]/template/entry[@name="' + current_group +  '"]/config/devices/entry[@name="localhost.localdomain"]/network/interface'))
                # self.log(return_interface)

                ##      LOAD ZONES FROM XML
                self.log('  |-- Zone Objects             ', end='')
                zone_list = root.findall(
                    './devices/entry[@name="localhost.localdomain"]/template/entry[@name=\'' + template + '\']/config/devices/entry[@name=\'localhost.localdomain\']/vsys/entry[@name=\'vsys1\']/zone/entry')
                return_zones = load_zones(zone_list)

                ##      ASSIGN ZONES TO INTERFACES
                self.log('!-- Assigning Zones')
                if return_zones:
                    for zone in return_zones:
                        # print('Zone: ', zone)
                        for zone_member in return_zones[zone]['zoneObjMembers']:
                            for interface in return_interface:
                                # self.log('return interface: ', interface)
                                if return_interface[interface]['iface_name'] == zone_member:
                                    return_interface[interface]['interface_Zone'] = zone

                return_config[template]['config'] = defaultdict()
                return_config[template]['config']['name'] = template
                return_config[template]['config']['fw_type'] = 'panorama'
                return_config[template]['config']['version'] = ''
                if self.options.panoramaip:
                    return_config[template]['config']['mgmtip'] = self.options.panoramaip
                else:
                    return_config[template]['config']['mgmtip'] = None
                return_config[template]['interfaces'] = return_interface
                return_config[template]['zones'] = return_zones
                return_config[template]['vrouters'] = return_vrouters
                return_config[template]['addresses'] = {}

            for device_groups in root.findall('./devices/entry/device-group/entry'):

                return_addresses = OrderedDict()
                return_service = OrderedDict()
                return_policy = OrderedDict()
                return_nat = OrderedDict()

                current_group = device_groups.get('name')
                return_addresses = OrderedDict()

                addr_mappings = OrderedDict()
                svc_mappings = OrderedDict()

                self.log('!-- Reading Device-Group : ' + current_group)

                logprofiles = []
                for logs in root.findall(
                        './devices/entry/device-group/entry[@name=\'' + current_group + '\']/log-settings/profiles/entry'):
                    logprofiles.append(logs.get('name'))

                ##      LOAD ADDRESSES FROM XML
                self.log('  |-- Address Objects        \r', end=' ')
                address_list = root.findall(
                    './devices/entry/device-group/entry[@name=\'' + current_group + '\']/address/entry')
                return_addresses = load_addresses(address_list)

                ##      LOAD ADDRESS GROUPS FROM XML
                self.log('  |-- Address-Group Objects  \r', end=' ')
                address_list = root.findall(
                    './devices/entry/device-group/entry[@name=\'' + current_group + '\']/address-group/entry')
                tmp_addresses = OrderedDict()
                if address_list != []:
                    tmp_addresses, addr_mappings = load_address_groups(address_list)
                return_addresses.update(tmp_addresses)

                ##      LOAD SERVICES FROM XML
                self.log('  |-- Service Objects        \r', end=' ')
                service_list = root.findall(
                    './devices/entry/device-group/entry[@name=\'' + current_group + '\']/service/entry')
                return_service = load_services(service_list)

                ##      LOAD SERVICES GROUPS FROM XML
                self.log('  |-- Service Group Objects  \r', end=' ')
                service_list = root.findall(
                    './devices/entry/device-group/entry[@name=\'' + current_group + '\']/service-group/entry')
                tmp_services = OrderedDict()
                if service_list != []:
                    tmp_services, svc_mappings = load_service_groups(service_list)
                return_service.update(tmp_services)

                ##      LOAD POLICIES FROM XML
                self.log('  |-- Policy Objects         \r', end='')
                policy_list = root.findall(
                    './devices/entry/device-group/entry[@name=\'' + current_group + '\']/pre-rulebase/security/rules/entry')
                return_policy = load_policies(policy_list)

                ##      LOAD NAT POLICIES FROM XML
                self.log('  |-- NAT Objects             \r', end='')
                policy_list = root.findall(
                    './devices/entry/device-group/entry[@name=\'' + current_group + '\']/rulebase/nat/rules/entry')
                return_nat = load_nat(policy_list, return_interface)

                ## Assign loaded values to return variables

                if current_group not in return_config:
                    return_config[current_group] = OrderedDict()
                return_config[current_group]['config'] = defaultdict()
                return_config[current_group]['config']['name'] = current_group
                return_config[current_group]['config']['fw_type'] = 'panorama'
                return_config[current_group]['config']['version'] = ''
                if self.options.panoramaip:
                    return_config[current_group]['config']['mgmtip'] = self.options.panoramaip
                else:
                    return_config[current_group]['config']['mgmtip'] = None

                return_config[current_group]['addresses'] = return_addresses
                return_config[current_group]['services'] = return_service
                return_config[current_group]['policies'] = return_policy
                return_config[current_group]['nat'] = return_nat
                return_config[current_group]['apps'] = {}
                return_config[current_group]['addressmappings'] = addr_mappings
                return_config[current_group]['servicemappings'] = svc_mappings

                ## Placeholder keys for future use
                return_config[current_group]['zones'] = {}

                return_config[current_group]['routing'] = OrderedDict()
                return_config[current_group]['logprofiles'] = logprofiles

            ## READ SHARED OBJECTS (panorama only)

            ## Re-initialize variables used above

            return_addresses = OrderedDict()
            return_service = OrderedDict()
            return_policy = OrderedDict()
            addr_mappings = OrderedDict()

            self.log('!-- Reading Shared Objects : ')
            self.log('  |-- Address Objects  \r', end=' ')

            logprofiles = []

            for logs in root.findall('./shared/log-settings/profiles/entry'):
                logprofiles.append(logs.get('name'))

            ##  READ SHARED ADDRESS OBJECTS
            address_list = root.findall('./shared/address/entry')
            return_addresses = load_addresses(address_list)

            ##  LOAD SHARED ADDRESS GROUPS FROM XML
            self.log('  |-- Address-Group Objects  \r', end=' ')
            addr_mappings = OrderedDict()
            address_list = root.findall('./shared/address-group/entry')
            tmp_addresses = OrderedDict()

            if address_list != []:
                tmp_addresses, addr_mappings = load_address_groups(address_list)
            return_addresses.update(tmp_addresses)

            ##  LOAD SHARED SERVICE FROM XML
            self.log('  |-- Service Objects        \r', end=' ')
            service_list = root.findall('./shared/service/entry')
            return_service = load_services(service_list)

            ##  LOAD SHARED SERVICE GROUPS FROM XML
            self.log('  |-- Service Group Objects  \r', end=' ')
            svc_mappings = OrderedDict()
            service_list = root.findall('./shared/service-group/entry')
            tmp_services = OrderedDict()

            if service_list != []:
                tmp_services, svc_mappings = load_service_groups(service_list)
            return_service.update(tmp_services)

            return_config['shared'] = OrderedDict()
            return_config['shared']['config'] = defaultdict()
            return_config['shared']['config']['name'] = 'shared'
            return_config['shared']['config']['fw_type'] = 'panorama'
            return_config['shared']['config']['version'] = ''
            if self.options.panoramaip:
                return_config['shared']['config']['mgmtip'] = self.options.panoramaip
            else:
                return_config['shared']['config']['mgmtip'] = None
            # debug('return_addresses')
            return_config['shared']['addresses'] = return_addresses
            return_config['shared']['services'] = return_service
            return_config['shared']['policies'] = OrderedDict()  # return_policy
            return_config['shared']['nat'] = OrderedDict()
            return_config['shared']['apps'] = {}
            return_config['shared']['addressmappings'] = addr_mappings
            return_config['shared']['servicemappings'] = svc_mappings
            return_config['shared']['logprofiles'] = logprofiles  # move this to 'config'
            return_config['shared']['vrouters'] = {}

            ## This is a search for "temp" objects - these are IP addresses directly input into policies without referencing an address object
            '''    
            for c in return_config: # context
                for p in return_config[c]['policies']: # policy 
                    for s in return_config[c]['policies'][p]['policySrcNet']:
                        if s not in return_config[c]['addresses'] and s not in return_config['shared']['addresses'] and s.lower()!='any':
                            debug(c + ':' + return_config[c]['policies'][p]['policyName'] + ':' + s + ' not found')    
                    for d in return_config[c]['policies'][p]['policyDstNet']:
                        if d not in return_config[c]['addresses'] and d not in return_config['shared']['addresses'] and d.lower()!='any':
                            debug(c + ':' + return_config[c]['policies'][p]['policyName'] + ':' + d + ' not found')  
            '''

            return return_config

        else:  # load Palo Alto Config
            return_addresses = OrderedDict()
            return_service = OrderedDict()
            return_policy = OrderedDict()
            return_interface = OrderedDict()
            return_variables = []

            current_group = 'paloalto'
            return_addresses = OrderedDict()

            addr_mappings = OrderedDict()
            svc_mappings = OrderedDict()

            self.log('!-- Reading Device-Group : ' + current_group)
            logprofiles = []
            for logs in root.findall('./shared/log-settings/profiles/entry'):
                # self.log(logs.get('name'))
                logprofiles.append(logs.get('name'))

            ## interfaces
            interface_list = root.findall('./devices/entry[@name="localhost.localdomain"]/network/interface/ethernet')
            ##      LOAD VROUTERS FROM XML
            self.log('  |-- Loading VRouters\r', end='')
            return_vrouters = load_vrouters('./devices/entry[@name="localhost.localdomain"]/network/virtual-router')

            ##      LOAD ADDRESSES FROM XML
            self.log('  |-- Address Objects        \r', end=' ')
            address_list = root.findall(
                './devices/entry[@name="localhost.localdomain"]/vsys/entry[@name="vsys1"]/address/entry')
            return_addresses = load_addresses(address_list)
            # print(return_addresses)

            ##      LOAD ADDRESS GROUPS FROM XML
            self.log('  |-- Address-Group Objects  \r', end=' ')
            address_list = root.findall(
                './devices/entry[@name="localhost.localdomain"]/vsys/entry[@name="vsys1"]/address-group/entry')
            tmp_addresses = OrderedDict()
            if address_list != []:
                tmp_addresses, addr_mappings = load_address_groups(address_list)
            return_addresses.update(tmp_addresses)

            ##      LOAD INTERFACE OBJECTS FROM XML
            self.log('  |-- Interface Objects             \r', end='')
            return_interface = load_interface('./devices/entry[@name="localhost.localdomain"]/network/interface')
            # self.log(return_interface)

            ##      LOAD ZONES FROM XML
            self.log('  |-- Zone Objects             \r', end='')
            zone_list = root.findall(
                './devices/entry[@name="localhost.localdomain"]/vsys/entry[@name=\'vsys1\']/zone/entry')
            return_zones = load_zones(zone_list)

            ##      ASSIGN ZONES TO INTERFACES
            self.log('!-- Assigning Zones')
            if return_zones:
                for zone in return_zones:
                    # print('Zone: ', zone)
                    for zone_member in return_zones[zone]['zoneObjMembers']:
                        for interface in return_interface:
                            # self.log('return interface: ', interface)
                            if return_interface[interface]['iface_name'] == zone_member:
                                return_interface[interface]['interface_Zone'] = zone

            ##      LOAD SERVICES FROM XML
            self.log('  |-- Service Objects        \r', end=' ')
            service_list = root.findall(
                './devices/entry[@name="localhost.localdomain"]/vsys/entry[@name="vsys1"]/service/entry')
            return_service = load_services(service_list)

            ##      LOAD SERVICES GROUPS FROM XML
            self.log('  |-- Service Group Objects  \r', end=' ')
            service_list = root.findall(
                './devices/entry[@name="localhost.localdomain"]/vsys/entry[@name="vsys1"]/service-group/entry')
            tmp_services = OrderedDict()
            if service_list != []:
                tmp_services, svc_mappings = load_service_groups(service_list)
            return_service.update(tmp_services)

            ##      LOAD POLICIES FROM XML
            self.log('  |-- Policy Objects         \r', end='')
            policy_list = root.findall(
                './devices/entry[@name="localhost.localdomain"]/vsys/entry[@name="vsys1"]/rulebase/security/rules/entry')
            return_policy = load_policies(policy_list)

            ##      LOAD NAT POLICIES FROM XML
            self.self.log('  |-- NAT Objects             \r', end='')
            policy_list = root.findall(
                './devices/entry[@name="localhost.localdomain"]/vsys/entry[@name="vsys1"]/rulebase/nat/rules/entry')
            return_nat = load_nat(policy_list, return_interface)

            ## Assign loaded values to return variables

            return_config[current_group] = OrderedDict()
            return_config[current_group]['config'] = defaultdict()
            return_config[current_group]['config']['name'] = 'paloalto'  # get name of actual firewall from config
            return_config[current_group]['config']['fw_type'] = 'paloalto'
            return_config[current_group]['config']['version'] = ''
            if self.options.panoramaip:
                return_config[current_group]['config']['mgmtip'] = self.options.panoramaip
            else:
                return_config[current_group]['config']['mgmtip'] = None
            return_config[current_group]['addresses'] = return_addresses
            return_config[current_group]['services'] = return_service
            return_config[current_group]['policies'] = return_policy
            return_config[current_group]['nat'] = return_nat
            return_config[current_group]['apps'] = {}
            return_config[current_group]['addressmappings'] = addr_mappings
            return_config[current_group]['servicemappings'] = svc_mappings

            ## Placeholder keys for future use
            return_config[current_group]['zones'] = return_zones
            return_config[current_group]['interfaces'] = return_interface
            return_config[current_group]['vrouters'] = return_vrouters
            return_config[current_group]['routing'] = OrderedDict()
            return_config[current_group]['logprofiles'] = logprofiles

            return_config['shared'] = OrderedDict()  # set shared to empty
            return_config['shared']['config'] = defaultdict()
            return_config['shared']['config']['name'] = 'shared'
            return_config['shared']['config']['fw_type'] = 'paloalto'
            return_config['shared']['config']['version'] = ''
            return_config['shared']['config']['mgmtip'] = 'None'
            return_config['shared']['addresses'] = OrderedDict()
            return_config['shared']['services'] = OrderedDict()
            return_config['shared']['policies'] = OrderedDict()  # return_policy
            return_config['shared']['nat'] = OrderedDict()
            return_config['shared']['apps'] = OrderedDict()
            return_config['shared']['addressmappings'] = OrderedDict()
            return_config['shared']['servicemappings'] = OrderedDict()
            return_config['shared']['logprofiles'] = OrderedDict()

            return return_config

    def load_interface_mappings(self, mapfile):

        mappings = OrderedDict()

        for mapping in mapfile:
            if len(os.path.basename(mapping)) > 0:
                if os.path.basename(mapping[0]) == '@':
                    for line in self.service.file_to_list(mapping[1:]):
                        sw, pa = line.strip('\n').split(',')
                        mappings[sw] = pa
                else:
                    sw, pa = mapping.strip('\n').split(',')
                    mappings[sw] = pa

        return mappings

    def load_devicegroups(self, infile):

        import xml.etree.ElementTree as et

        panorama = et.parse(infile)
        root = panorama.getroot()
        devicegroups = ['shared']
        for dg in root.findall('./devices/entry/device-group/entry'):
            devicegroups.append(dg.get('name'))

        return devicegroups;

    def show_devicegroups(self, infile):

        devicegroups = self.load_devicegroups(infile)
        for dg in devicegroups:
            self.log(dg)

    def load_templates(self, infile):

        import xml.etree.ElementTree as et

        panorama = et.parse(infile)
        root = panorama.getroot()
        templates = ['shared']
        for t in root.findall('./devices/entry/template/entry'):
            templates.append(t.get('name'))

        return templates;
