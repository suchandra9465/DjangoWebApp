import re
import os
import base64

import json
import urllib3
import sys

from collections import defaultdict
from collections import OrderedDict

from netaddr import IPSet, IPNetwork
from ...generator import NetworkLogs
from ...generator import Logging
from ...generator import Tree
from ...generator.network import Service

import  CreateService as CS
import GetService as GS
import Zone as Z
import EditService as ES
from .sonicwall import LoadService as SW


class Service:

    def _init_(self, options, config, contexts):
        self.log = NetworkLogs().log
        self.sc = NetworkLogs().sc
        self.ss = NetworkLogs().ss
        self.loggin = Logging().loggin
        self.debug = NetworkLogs().debug
        self.options = options
        self.contexts = contexts
        self.service = Service(self.options)
        self.editNetworkService = ES.EditNetworkService(options)
        self.createNetworkService = CS.CreateNetworkService(options)
        self.getNetworkService = GS.GetNetworkService(config)
        self.zone = Z.zones(options, config)
        self.sonicwall = SW.SonicWallService(options, config)
    # Convert CIDR notation to netmask /## --> ###.###.###.###
    def cidr_to_netmask(self, prefix):
        return '.'.join([str((0xffffffff << (32 - int(prefix)) >> i) & 0xff) for i in [24, 16, 8, 0]])

    # Convert netmask to CIDR notation ###.###.###.### --> /##
    def netmask_to_cidr(self, netmask):
        return sum([bin(int(x)).count("1") for x in netmask.split(".")])

    # This converts a sonicwall .exp file to a plain textfile
    def convert_exp_file(self, infile, outfile, encoded=None):

        if os.path.isfile(infile) or encoded:
            if not encoded:
                encoded_file = open(infile, 'rb')
                encoded = encoded_file.read()
            decoded = base64.decodestring(encoded)
            decoded_with_newline = re.sub(r'&', '\n', decoded.decode('utf-8', errors='ignore'))
            decoded_space_removed = re.sub(r'%20$', '', decoded_with_newline)
            if outfile:
                decoded_file = open(outfile, 'wb')
                for line in decoded_space_removed.splitlines():
                    decoded_space_removed = re.sub(r'%20$', '', line)
                    decoded_file.write(decoded_space_removed.encode())
                    decoded_file.write('\n'.encode())
                decoded_file.close()
        else:
            return False
        # with open (configfilename) as working_file:
        #        config = working_file.read()
        return re.sub(r'&', '\n', decoded.decode('utf-8', errors='ignore'))

    # Used for Sonicwall configuration, this generates a dictionary of Groupname --> [ List of Group Members ]
    def generate_group_mappings(self, tmp_config, group_type):

        group_mappings = defaultdict(list)
        search_string = r'^' + group_type + '_.*'

        tmp_mappings = re.findall(search_string, tmp_config, flags=re.MULTILINE)
        for index, object in enumerate(tmp_mappings[::2]):
            junk, member = object.split('=', 1)
            junk, group = tmp_mappings[(index * 2) + 1].split('=', 1)
            group_mappings[group].append(member)
        # working_file.close()
        return group_mappings;

    # Used to read the various configuration elements of Sonicwall configurations.
    def migrate_orig(self, objectname, config, property_list, skipdisabled=False):

        regexpattern = r'^interface.*_.*=.*|^' + objectname + '.*_.*=.*'
        regexpattern0 = r'^' + objectname + '.*_0=.*'
        config_dict = OrderedDict()

        # with open (infile) as working_file:
        #    config = working_file.read()
        matched = re.findall(regexpattern, config, flags=re.MULTILINE)

        for line in matched:

            object_beg, object_property = line.split('=', 1)
            object_key, object_num = object_beg.rsplit('_', 1)
            object_index = int(object_num)

            if object_key in property_list:
                if not object_index in config_dict:
                    config_dict[object_index] = OrderedDict()

                config_dict[object_index][object_key] = object_property
                ## insert empty policyDstApps / natPolicyName values for Sonicwalls
                if object_key == 'policyDstSvc':
                    config_dict[object_index]['policyDstApps'] = []
                if object_key == 'natPolicyOrigSrc':
                    config_dict[object_index]['natPolicyName'] = ''

        ## REMOVED DISABLED RULES IF skip-disabled set
        if self.options.skip_disabled:
            skipped_dict = OrderedDict()
            for index in config_dict:
                if config_dict[index]['policyEnabled'] == '1':
                    skipped_dict[index] = config_dict[index]
            return skipped_dict

        return config_dict

    # Used to read the various configuration elements of Sonicwall configurations.
    # New version that no longer uses numerical index (which later gets stripped with remove_index)
    def migrate(self, objectname, config, property_list):

        regexpattern = r'^portShutdown.*_.*=.*|^interface.*_.*=.*|^' + objectname + '.*_.*=.*'
        config_dict = OrderedDict()

        # with open (infile) as working_file:
        #    config = working_file.read()
        matched = re.findall(regexpattern, config, flags=re.MULTILINE)

        for line in matched:

            object_beg, object_property = line.split('=', 1)
            object_key, object_num = object_beg.rsplit('_', 1)

            if object_key == property_list[0]:
                object_name = object_property.rstrip().lstrip()
            if object_key in property_list:
                if not object_name in config_dict:
                    config_dict[object_name] = OrderedDict()
                config_dict[object_name][object_key] = object_property.rstrip().lstrip()
                prev_object_num = object_num

        return config_dict;

    # Given an address or service object name, this will build a tree from this object to the groups it is a member of.
    # The root of the tree is a member object, not the parent object, so it builds the tree opposite of what might be expected.
    def build_tree(self, mappings, children, parent=None, tree=Tree()):

        for child in [children]:
            tree.add_node(child, parent)

        # Get list of children (
        for child in [children]:
            for group in mappings:
                if child in mappings[group]:
                    tree = Service.build_tree(mappings, group, child, tree)
        return tree

    # Will create a list of all possible tuples for a policy.  This can be used for testing purposes with another script
    # For network address objects, it will only output the network address, not every possible combination of addresses in
    # that network.  If it were to expand the entire network, the resulting list of addresses would likely exceed billions
    # of possibilities.
    # It also currently only includes traffic from the WAN zone.
    # Exclude Multicast?
    def create_tuples(self, config, outfile, tuplezone, contexts, policyname=''):


        srctuplezone, dsttuplezone = tuplezone.split(',')

        out = open(outfile, 'w')
        stdout = sys.stdout
        sys.stdout = out
        for context in contexts:
            # self.log(context)
            if context in config:
                # if zones are empty for first policy, assume this is a checkpoint policy and compute src/dst zones for each rule.
                # self.log('policylen', len(config[context]['policies']))
                if len(config[context]['policies']) > 0:
                    # self.log('policylen', len(config[context]['policies']))
                    if config[context]['policies'][1]['policySrcZone'] == []:
                        self.debug('Build zone information for each rule')
                        for policy_index in config[context]['policies']:
                            if config[context]['policies'][policy_index]['policyName'] in policyname or policyname == [
                                '']:
                                for src_addr in config[context]['policies'][policy_index]['policySrcNet']:
                                    if src_addr in config[context]['addresses']:
                                        tmp_zone = None
                                        ## def expand_address(address_dict, address_object, address_map, inc_group=False):
                                        if src_addr.lower() == 'any':
                                            addr_list = []
                                            self.log('Any source addr')
                                        elif config[context]['addresses'][src_addr]['addrObjType'] == '8':
                                            addr_list = self.expand_address(config[context]['addresses'], src_addr,
                                                                       config[context]['addressmappings'])
                                        else:
                                            self.debug(src_addr, config[context]['addresses'][src_addr]['addrObjZone'])
                                            addr_list = [src_addr]
                                        self.debug(addr_list)
                                        for addr in addr_list:
                                            if config[context]['addresses'][addr]['addrObjZone'] == '':
                                                if config[context]['addresses'][addr]['addrObjType'] == '98':
                                                    self.debug('Group with exception', config[context]['addresses'][addr])
                                                    if config[context]['addresses'][addr]['include'].lower() == 'any':
                                                        ip1 = '0.0.0.0'
                                                        self.debug('Group with exception - any', ip1)
                                                    else:
                                                        ip1 = '{}'.format(config[context]['addresses'][
                                                                              config[context]['addresses'][addr][
                                                                                  'include']]['IPSet'].iter_cidrs()[0][
                                                                              1])
                                                        self.debug('Group with exception - not any', ip1)
                                                else:
                                                    ip1, ip2 = self.getNetworkService.get_address_of(config[context]['addresses'], addr)
                                                self.debug('{}-{}-{}'.format('addr', addr, ip1))
                                                if ip1 not in ['', None]:
                                                    tmp_zone = self.zone.get_zone_old(context, '{}'.format(ip1))
                                                    config[context]['addresses'][addr]['addrObjZone'] = tmp_zone
                                                    self.debug('Assigning zone {} to object {}'.format(tmp_zone, addr))
                                                else:
                                                    self.debug('Unknown IP1 {} for object {}'.format(ip1, addr))
                                            else:
                                                tmp_zone = config[context]['addresses'][addr]['addrObjZone']
                                            if tmp_zone not in config[context]['policies'][policy_index][
                                                'policySrcZone'] and tmp_zone:
                                                self.debug(
                                                    'Adding zone {} to policy index {}'.format(tmp_zone, policy_index))
                                                config[context]['policies'][policy_index]['policySrcZone'].append(
                                                    tmp_zone)
                                self.debug('sourcezones:', config[context]['policies'][policy_index]['policySrcZone'])
                                for dst_addr in config[context]['policies'][policy_index]['policyDstNet']:
                                    if dst_addr in config[context]['addresses']:
                                        tmp_zone = None
                                        ## def expand_address(address_dict, address_object, address_map, inc_group=False):
                                        if dst_addr.lower() == 'any':
                                            addr_list = []
                                        elif config[context]['addresses'][dst_addr]['addrObjType'] == '8':
                                            addr_list = self.createNetworkService.expand_address(config[context]['addresses'], dst_addr,
                                                                       config[context]['addressmappings'])
                                        else:
                                            addr_list = [dst_addr]
                                        for addr in addr_list:
                                            if config[context]['addresses'][addr]['addrObjZone'] == '':
                                                if config[context]['addresses'][addr]['addrObjType'] == '98':
                                                    self.debug('Group with exception', config[context]['addresses'][addr])
                                                    if config[context]['addresses'][addr]['include'].lower() == 'any':
                                                        ip1 = '0.0.0.0'
                                                        self.debug('Group with exception - any', ip1)
                                                    else:
                                                        ip1 = '{}'.format(config[context]['addresses'][
                                                                              config[context]['addresses'][addr][
                                                                                  'include']]['IPSet'].iter_cidrs()[0][
                                                                              1])
                                                        self.debug('Group with exception - not any', ip1)
                                                else:
                                                    ip1, ip2 = self.getNetworkService.get_address_of(config[context]['addresses'], addr)
                                                # self.debug('{}-{}-{}'.format('addr', addr, ip1))
                                                if ip1 not in ['', None]:
                                                    tmp_zone = self.zone.get_zone_old(context, '{}'.format(ip1))
                                                    config[context]['addresses'][addr]['addrObjZone'] = tmp_zone
                                            else:
                                                tmp_zone = config[context]['addresses'][addr]['addrObjZone']
                                            if tmp_zone not in config[context]['policies'][policy_index][
                                                'policyDstZone'] and tmp_zone:
                                                self.debug(
                                                    'Adding zone {} to policy index {}'.format(tmp_zone, policy_index))
                                                config[context]['policies'][policy_index]['policyDstZone'].append(
                                                    tmp_zone)
                            # self.debug(config[context]['policies'][policy_index]['policySrcZone'])
                            self.debug('destzones:', config[context]['policies'][policy_index]['policyDstZone'])
                            if config[context]['policies'][policy_index]['policySrcZone'] == [] and \
                                    config[context]['policies'][policy_index]['policyDstZone'] == []:
                                self.debug('Unable to determine source and dest zones for rule index : {}'.format(
                                    policy_index))
                                self.debug(config[context]['policies'][policy_index])
                            elif config[context]['policies'][policy_index]['policySrcZone'] == []:
                                config[context]['policies'][policy_index]['policySrcZone'] = [
                                    config[context]['zones']['default']]
                            elif config[context]['policies'][policy_index]['policyDstZone'] == []:
                                config[context]['policies'][policy_index]['policyDstZone'] = [
                                    config[context]['zones']['default']]
                    else:
                        pass
                        # self.log(config[context]['policies'][1]['policySrcZone'])

                for policy_index in config[context]['policies']:  # range(0, len(config[context]['policies'])):
                    negate_source = config[context]['policies'][policy_index]['policySrcNegate']
                    negate_dest = config[context]['policies'][policy_index]['policyDstNegate']

                    if config[context]['policies'][policy_index]['policyName'] in policyname or policyname == ['']:
                        if (srctuplezone in config[context]['policies'][policy_index][
                            'policySrcZone'] or srctuplezone.lower() == 'all') and (
                                dsttuplezone in config[context]['policies'][policy_index][
                            'policyDstZone'] or dsttuplezone.lower() == 'all') and \
                                config[context]['policies'][policy_index]['policyProps'] == '0' and \
                                config[context]['policies'][policy_index]['policyEnabled'] == '1':
                            if negate_source:  ## this will break tuple creation for palo and sonicwall until the Negate values are added to configs.
                                source_set = IPSet()
                                for source in config[context]['policies'][policy_index]['policySrcNet']:
                                    if config[context]['addresses'][source]['addrObjType'] in ['8',
                                                                                               '98']:  ## Address is group, or group with exception, ipset is already calculated
                                        source_set = source_set | config[context]['addresses'][source]['IPSet']

                                    else:
                                        for member in self.createNetworkService.expand_address(config[context]['addresses'], source,
                                                                     config[context]['addressmappings']):
                                            # self.debug('IPSET', member)
                                            # source_set.add([str(addr))
                                            for addr in config[context]['addresses'][member]['IPv4Networks']:
                                                source_set.add(str(addr))
                                negated_set = IPSet(['0.0.0.0/0']) ^ source_set
                                # self.log('NEGATED: ')
                                policy_source = []
                                for network in negated_set.iter_cidrs():
                                    if len(network) > 8:

                                        if '{}'.format(network).split('/')[0] != '0.0.0.0':
                                            if IPNetwork(network) < IPNetwork('224.0.0.0/3'):
                                                policy_source.append('{}'.format(network[4]))
                                                # self.log('ADDING NEGATED: {}'.format(network[4]))
                                        else:
                                            policy_source.append('0.0.0.0')
                            elif config[context]['policies'][policy_index]['policySrcNet'] == [''] or \
                                    config[context]['policies'][policy_index]['policySrcNet'] in [['any'], ['Any']] or \
                                    config[context]['policies'][policy_index]['policySrcNet'] == []:
                                policy_source = ['0.0.0.0']
                            else:
                                policy_source = []
                                for source in config[context]['policies'][policy_index]['policySrcNet']:
                                    for member in self.createNetworkService.expand_address(config[context]['addresses'], source,
                                                                 config[context]['addressmappings']):
                                        policy_source.append(member)

                            if negate_dest:  ## this will break tuple creation for palo and sonicwall until the Negate values are added to configs.
                                dest_set = IPSet()
                                for dest in config[context]['policies'][policy_index]['policyDstNet']:
                                    if config[context]['addresses'][dest]['addrObjType'] in ['8',
                                                                                             '98']:  ## Address is group, or group with exception, ipset is already calculated
                                        dest_set = dest_set | config[context]['addresses'][dest]['IPSet']
                                    else:
                                        for member in self.createNetworkService.expand_address(config[context]['addresses'], dest,
                                                                     config[context]['addressmappings']):
                                            # [dest_set.add(str(addr)) for addr in config[context]['addresses'][member]['IPv4Networks'] ]
                                            for addr in config[context]['addresses'][member]['IPv4Networks']:
                                                dest_set.add(str(addr))
                                # for network in IPSet(['0.0.0.0/0']) ^ dest_set:
                                #    self.log('network:', network)
                                self.debug('negate_set policy index', policy_index)
                                self.debug('dest_set before negated', dest_set)
                                negated_set = IPSet(['0.0.0.0/0']) ^ dest_set
                                self.debug('negated_set after negated', negated_set)
                                policy_dest = []
                                for network in negated_set.iter_cidrs():
                                    if len(network) > 8:
                                        if '{}'.format(network).split('/')[0] != '0.0.0.0':
                                            if IPNetwork(network) < IPNetwork('224.0.0.0/3'):
                                                # self.log('negated', network, '{}'.format(network[4]))
                                                policy_dest.append('{}'.format(network[4]))
                                        else:
                                            policy_dest.append('0.0.0.0')


                            elif config[context]['policies'][policy_index]['policyDstNet'] == [''] or \
                                    config[context]['policies'][policy_index]['policyDstNet'] in [['any'], ['Any']] or \
                                    config[context]['policies'][policy_index]['policyDstNet'] == []:
                                policy_dest = ['0.0.0.0']
                            else:
                                policy_dest = []
                                for dest in config[context]['policies'][policy_index]['policyDstNet']:
                                    for member in self.createNetworkService.expand_address(config[context]['addresses'], dest,
                                                                 config[context]['addressmappings']):
                                        policy_dest.append(member)
                            if config[context]['policies'][policy_index]['policyDstSvc'] == [''] or \
                                    config[context]['policies'][policy_index]['policyDstSvc'] in [['any'], ['Any']] or \
                                    config[context]['policies'][policy_index]['policyDstSvc'] == []:
                                policy_services = ['0']
                            else:
                                policy_services = []
                                for svc in config[context]['policies'][policy_index]['policyDstSvc']:
                                    if svc != 'application-default':
                                        for member in self.createNetworkService.expand_service(config[context]['services'], svc,
                                                                     config[context]['servicemappings']):
                                            policy_services.append(member)
                            for source_index in policy_source:
                                # self.log(source_index)
                                if negate_source:
                                    source = '{}'.format(source_index)
                                    srcmask = '32'
                                    # self.log('source', source)
                                else:
                                    source, srcmask = self.getNetworkService.get_address_of(config[context]['addresses'], source_index)
                                if source != None and source != '':
                                    if config[context]['policies'][policy_index]['policySrcZone'] != '':
                                        src_zone = config[context]['policies'][policy_index]['policySrcZone'][0]
                                    else:
                                        src_zone = str(self.zone.get_zone_old(context, '{}'.format(source)))
                                    for dest_index in policy_dest:
                                        if negate_dest:
                                            dest = '{}'.format(
                                                dest_index)  ## shouldnt be needed, when building dest_index above, just add it in correctly as a string, or a set (objectname, address) - may be difficult to include names of negated objects, or will need to update routines
                                            destmask = '32'
                                        else:
                                            dest, destmask = self.getNetworkService.get_address_of(config[context]['addresses'],
                                                                            dest_index)  # look into updating routines above to do the lookup directly, and add as a set of (objectname, address)
                                        if dest != None and dest != '':
                                            if config[context]['policies'][policy_index]['policyDstZone'] != '':
                                                dst_zone = config[context]['policies'][policy_index]['policyDstZone'][0]
                                            else:
                                                dst_zone = str(self.zone.get_zone_old(context, '{}'.format(dest)))
                                            if IPNetwork(source) < IPNetwork('224.0.0.0/3') and IPNetwork(
                                                    dest) < IPNetwork('224.0.0.0/3'):
                                                for service_index in policy_services:
                                                    prot = self.get_prot_of(config[context]['services'], service_index)
                                                    port = self.get_ports_of(config[context]['services'], service_index)
                                                    # src_port=get_src_ports_of(config[context]['services'],service_index)
                                                    # self.log('service idx', service_index, prot, port)
                                                    if len(port) > 0:
                                                        port = str(port[0])
                                                    else:
                                                        port = '0'

                                                    try:
                                                        # self.log(config[context]['services'][service_index])
                                                        if (
                                                                srctuplezone.lower() == src_zone.lower() or srctuplezone.lower() == 'all') and (
                                                                dsttuplezone.lower() == dst_zone.lower() or dsttuplezone.lower() == 'all'):
                                                            self.log(source + '/' + srcmask + ',' + dest + '/' + destmask + ',' + prot + ',' + port + ',' +
                                                                config[context]['policies'][policy_index][
                                                                    'policyAction'] + ',' + str(
                                                                config[context]['policies'][policy_index][
                                                                    'policyNum']) + ',' + source_index + ',' + dest_index + ',' + service_index,
                                                                src_zone, dst_zone)
                                                            ## + ',' + str(config[context]['policies'][policy_index]['policyUiNum']) + ',' + str(config[context]['policies'][policy_index]['policyNum']) + ',' + str(config[context]['policies'][policy_index]['policySrcZone']) + ',' + str(config[context]['policies'][policy_index]['policyDstZone']) )
                                                        elif src_zone == "None" or dst_zone == "None":
                                                            self.log('NONE: src_zone {} src {} dst_zone {} dst {}'.format(
                                                                src_zone, source, dst_zone, dest))
                                                    except Exception as e:
                                                        # self.log(e)
                                                        self.log('EXCEPTION {}: {}'.format(e, config[context]['services'][
                                                            service_index]))
        out.close()
        sys.stdout = stdout

        return

    # This converts elements in a sonicwall policy dictionary to a list, to match how it is stored by Palo Alto.
    # Sonicwall policies can only have a single object per element, but the Palo Alto can have several, so these
    # items are now stored as a list.
    def policy_objects_to_list(self, policy_dict, prop_list):

        tmp_dict = policy_dict
        for index in policy_dict:
            for prop in prop_list:
                tmp_dict[index][prop] = [policy_dict[index][prop]]
            if 'policyUUID' not in policy_dict[index]:
                tmp_dict[index]['policyUUID'] = None
                tmp_dict[index]['policySrcNegate'] = False
                tmp_dict[index]['policyDstNegate'] = False
                tmp_dict[index]['policySvcNegate'] = False
        return tmp_dict

    def add_IPv4Network(self, addresses):

        # This adds a IPv4Network dictionary entry for Sonicwall configurations after the configuration is read

        import ipaddress
        from netaddr import IPSet

        for address in addresses:
            self.debug(addresses[address])
            addresses[address]['IPSet'] = IPSet([])
            try:
                if addresses[address]['addrObjType'] == '1':  ## host
                    addresses[address]['IPv4Networks'] = [
                        ipaddress.IPv4Network(addresses[address]['addrObjIp1'] + '/32')]
                if addresses[address]['addrObjType'] == '2':  ## range
                    addresses[address]['IPv4Networks'] = [ipaddr for ipaddr in ipaddress.summarize_address_range(
                        ipaddress.IPv4Address(addresses[address]['addrObjIp1']),
                        ipaddress.IPv4Address(addresses[address]['addrObjIp2']))]
                if addresses[address]['addrObjType'] == '4':
                    bitmask = sum([bin(int(x)).count("1") for x in addresses[address]['addrObjIp2'].split(".")])
                    addresses[address]['IPv4Networks'] = [
                        ipaddress.IPv4Network(addresses[address]['addrObjIp1'] + '/' + str(bitmask))]
                if addresses[address]['addrObjType'] == '8':
                    addresses[address]['IPv4Networks'] = []
                    pass
                    # cant do anything with the group at this point
            except:
                pass
            for network in addresses[address]['IPv4Networks']:
                addresses[address]['IPSet'].add('{}'.format(network))
                pass
        return addresses;

    def dump_config(self, config, contexts):

        # Not complete?  There might be cases in with shared objects are not handled correctly?
        # Dynamic column widths by tracking longest length item and calling set_column after data is written?

        import xlsxwriter

        sh_addr = []
        sh_svc = []

        ## Output to XLSX
        path = ''

        for context in contexts:
            self.log('\r!-- Dumping ' + context + ' to Excel                                                 ')
            workbook = xlsxwriter.Workbook(path + context + '.xlsx')

            xl_policies = workbook.add_worksheet('Policies')
            xl_policies.set_column('A:I', 50)
            xl_policies.set_column('B:B', 15)
            xl_addresses = workbook.add_worksheet('Addresses')
            xl_addresses.set_column('A:H', 50)
            xl_addresses.set_column('C:C', 12)
            xl_addresses.set_column('D:D', 12)
            xl_addresses.set_column('E:E', 20)
            xl_addresses.set_column('F:F', 20)
            xl_addresses.set_column('G:G', 20)
            xl_addressgroups = workbook.add_worksheet('Address Groups')
            xl_addressgroups.set_column('A:H', 50)
            xl_services = workbook.add_worksheet('Services')
            xl_services.set_column('A:H', 50)
            xl_services.set_column('B:B', 15)
            xl_services.set_column('C:C', 15)
            xl_services.set_column('D:D', 15)
            xl_services.set_column('E:E', 12)
            xl_services.set_column('F:F', 12)

            xl_servicegroups = workbook.add_worksheet('Service Groups')
            xl_servicegroups.set_column('A:H', 50)
            xl_networking = workbook.add_worksheet('Networking')
            xl_networking.set_column('A:H', 50)

            ## print headers for each worksheet
            if len(list(config[context]['policies'].keys())) > 0:
                for col, key in enumerate(config[context]['policies'][list(config[context]['policies'].keys())[0]]):
                    xl_policies.write(0, col, key)
            xl_addressgroups.write(0, 0, 'Address Mappings')
            xl_servicegroups.write(0, 0, 'Service Mappings')

            xl_addresses.write(0, 0, 'Addresses')
            if len(list(config[context]['addresses'].keys())) > 0:
                for col, key in enumerate(config[context]['addresses'][list(config[context]['addresses'].keys())[0]]):
                    xl_addresses.write(0, col, key)
            xl_services.write(0, 0, 'Services')
            row = 1
            if len(list(config[context]['services'].keys())) > 0:
                for col, key in enumerate(config[context]['services'][list(config[context]['services'].keys())[0]]):
                    xl_services.write(0, col, key)

            row = 1
            for policy in config[context]['policies']:
                # build list of address and service objects that might be in shared
                for src in config[context]['policies'][policy]['policySrcNet']:
                    if src not in config[context]['addresses'] and src in config['shared']['addresses']:
                        if src not in sh_addr:
                            sh_addr.append(src)
                for dst in config[context]['policies'][policy]['policyDstNet']:
                    if dst not in config[context]['addresses'] and dst in config['shared']['addresses']:
                        if dst not in sh_addr:
                            sh_addr.append(dst)
                for svc in config[context]['policies'][policy]['policyDstSvc']:
                    if svc not in config[context]['services'] and svc in config['shared']['services']:
                        if svc not in sh_svc:
                            sh_svc.append(svc)

                for col, key in enumerate(config[context]['policies'][policy]):
                    output = ''
                    if type(config[context]['policies'][policy][key]) == list:
                        for index, item in enumerate(config[context]['policies'][policy][key]):
                            # output += item
                            if key in ['policySrcNet', 'policyDstNet', 'policyDstSvc'] and item in ['']:
                                output += 'any'
                            else:
                                output += item
                            if index < len(config[context]['policies'][policy][key]) - 1:
                                output += '\n'
                    elif key == 'policyAction':
                        if config[context]['policies'][policy][key] == '0':
                            output = 'Deny'
                        elif config[context]['policies'][policy][key] == '1':
                            output = 'Discard'
                        elif config[context]['policies'][policy][key] == '2':
                            output = 'Allow'
                        else:
                            output = config[context]['policies'][policy][key]
                    elif key == 'policyEnabled':
                        if config[context]['policies'][policy][key] == '1':
                            output = 'Enabled'
                        else:
                            output = 'Disabled'
                    else:
                        output = str(config[context]['policies'][policy][key])
                    if row % 2 == 1:
                        cell_format = workbook.add_format({'bg_color': '#DDDDDD', 'text_wrap': True})
                    else:
                        cell_format = workbook.add_format({'bg_color': '#BBBBBB', 'text_wrap': True})
                    xl_policies.write(row, col, self.ss(output), cell_format)
                row += 1

            row = 1
            for map in config[context]['addressmappings']:
                if row % 2 == 1:
                    cell_format = workbook.add_format({'bg_color': '#DDDDDD', 'text_wrap': True})
                else:
                    cell_format = workbook.add_format({'bg_color': '#BBBBBB', 'text_wrap': True})
                xl_addressgroups.write(row, 0, self.ss(map), cell_format)
                output = ''
                for index, item in enumerate(config[context]['addressmappings'][map]):
                    output += item
                    if index < len(config[context]['addressmappings'][map]) - 1:
                        output += '\n'
                xl_addressgroups.write(row, 1, self.ss(output), cell_format)
                row += 1
            if 'shared' in config:
                for map in config['shared']['addressmappings']:
                    if map in sh_addr:
                        if row % 2 == 1:
                            cell_format = workbook.add_format({'bg_color': '#AAAAAA', 'text_wrap': True})
                        else:
                            cell_format = workbook.add_format({'bg_color': '#999999', 'text_wrap': True})
                        xl_addressgroups.write(row, 0, self.ss(map), cell_format)
                        output = ''
                        for index, item in enumerate(config['shared']['addressmappings'][map]):
                            output += item
                            if index < len(config['shared']['addressmappings'][map]) - 1:
                                output += '\n'

                        xl_addressgroups.write(row, 1, self.ss(output), cell_format)
                        row += 1

            row = 1
            for map in config[context]['servicemappings']:
                if row % 2 == 1:
                    cell_format = workbook.add_format({'bg_color': '#DDDDDD', 'text_wrap': True})
                else:
                    cell_format = workbook.add_format({'bg_color': '#BBBBBB', 'text_wrap': True})
                xl_servicegroups.write(row, 0, self.ss(map), cell_format)
                output = ''
                for index, item in enumerate(config[context]['servicemappings'][map]):
                    output += item
                    if index < len(config[context]['servicemappings'][map]) - 1:
                        output += '\n'
                xl_servicegroups.write(row, 1, self.ss(output), cell_format)
                row += 1
            if 'shared' in config:
                for map in config['shared']['servicemappings']:
                    if map in sh_svc:
                        xl_servicegroups.write(row, 0, map)
                        output = ''
                        for index, item in enumerate(config['shared']['servicemappings'][map]):
                            output += item
                            if index < len(config['shared']['servicemappings'][map]) - 1:
                                output += '\n'
                        if row % 2 == 1:
                            cell_format = workbook.add_format({'bg_color': '#AAAAAA', 'text_wrap': True})
                        else:
                            cell_format = workbook.add_format({'bg_color': '#999999', 'text_wrap': True})
                        xl_servicegroups.write(row, 1, self.ss(output), cell_format)
                        row += 1
            row = 1
            for address in config[context]['addresses']:
                for col, key in enumerate(config[context]['addresses'][address]):
                    if key == 'addrObjType':
                        if config[context]['addresses'][address][key] == '1':
                            output = 'Host'
                        elif config[context]['addresses'][address][key] == '2':
                            output = 'Range'
                        elif config[context]['addresses'][address][key] == '4':
                            output = 'Network'
                        elif config[context]['addresses'][address][key] == '8':
                            output = 'Group'
                        else:
                            output = config[context]['addresses'][address][key]
                    elif key == 'addrObjProperties':
                        if config[context]['addresses'][address][key] == '14':
                            output = 'User Defined'
                        else:
                            output = config[context]['addresses'][address][key]
                    else:
                        output = str(config[context]['addresses'][address][key])
                    if row % 2 == 1:
                        cell_format = workbook.add_format({'bg_color': '#DDDDDD', 'text_wrap': True})
                    else:
                        cell_format = workbook.add_format({'bg_color': '#BBBBBB', 'text_wrap': True})
                    xl_addresses.write(row, col, self.ss(output), cell_format)
                row += 1
            if 'shared' in config:
                for address in sh_addr:
                    if address in config['shared']['addresses']:
                        for col, key in enumerate(config['shared']['addresses'][address]):
                            if key == 'addrObjType':
                                if config['shared']['addresses'][address][key] == '1':
                                    output = 'Host'
                                elif config['shared']['addresses'][address][key] == '2':
                                    output = 'Range'
                                elif config['shared']['addresses'][address][key] == '4':
                                    output = 'Network'
                                elif config['shared']['addresses'][address][key] == '8':
                                    output = 'Group'
                                else:
                                    output = config['shared']['addresses'][address][key]
                            elif key == 'addrObjProperties':
                                if config['shared']['addresses'][address][key] == '14':
                                    output = 'User Defined'
                                else:
                                    output = config['shared']['addresses'][address][key]
                            else:
                                output = str(config['shared']['addresses'][address][key])
                            if row % 2 == 1:
                                cell_format = workbook.add_format({'bg_color': '#AAAAAA', 'text_wrap': True})
                            else:
                                cell_format = workbook.add_format({'bg_color': '#999999', 'text_wrap': True})
                            xl_addresses.write(row, col, self.ss(output), cell_format)
                        row += 1
            row = 1

            for service in config[context]['services']:
                for col, key in enumerate(config[context]['services'][service]):
                    if key == 'svcObjType':
                        if config[context]['services'][service][key] == '1':
                            output = 'Service'
                        elif config[context]['services'][service][key] == '2':
                            output = 'Service Group'
                        else:
                            output = config[context]['services'][service][key]
                    elif key == 'svcObjProperties':
                        if config[context]['services'][service][key] == '14':
                            output = 'User Defined'
                        else:
                            output = config[context]['services'][service][key]
                    elif key == 'svcObjIpType':
                        if config[context]['services'][service][key] == '6':
                            output = 'TCP'
                        elif config[context]['services'][service][key] == '17':
                            output = 'UDP'
                        elif config[context]['services'][service][key] == '0':
                            output = 'Service Group'
                        else:
                            output = 'Other'
                    else:
                        # self.debug('col:' + str(col))
                        # self.debug('key: ' + str(key))
                        # self.debug(config[context]['services'][service])
                        # self.debug(config[context]['services'][service][key])
                        if key in config[context]['services'][service]:
                            output = str(config[context]['services'][service][key])
                        pass
                    if row % 2 == 1:
                        cell_format = workbook.add_format({'bg_color': '#DDDDDD', 'text_wrap': True})
                    else:
                        cell_format = workbook.add_format({'bg_color': '#BBBBBB', 'text_wrap': True})
                    xl_services.write(row, col, self.ss(output), cell_format)
                row += 1
            if 'shared' in config:
                for service in sh_svc:
                    if service in config['shared']['services']:
                        for col, key in enumerate(config['shared']['services'][service]):
                            if key == 'svcObjType':
                                if config['shared']['services'][service][key] == '1':
                                    output = 'Service'
                                elif config['shared']['services'][service][key] == '2':
                                    output = 'Service Group'
                                else:
                                    output = config['shared']['services'][service][key]
                            elif key == 'svcObjProperties':
                                if config['shared']['services'][service][key] == '14':
                                    output = 'User Defined'
                                else:
                                    output = config['shared']['services'][service][key]
                            elif key == 'svcObjIpType':
                                if config['shared']['services'][service][key] == '6':
                                    output = 'TCP'
                                elif config['shared']['services'][service][key] == '17':
                                    output = 'UDP'
                                elif config['shared']['services'][service][key] == '0':
                                    output = 'Service Group'
                                else:
                                    output = 'Other'
                            else:
                                output = str(config['shared']['services'][service][key])
                            if row % 2 == 1:
                                cell_format = workbook.add_format({'bg_color': '#AAAAAA', 'text_wrap': True})
                            else:
                                cell_format = workbook.add_format({'bg_color': '#999999', 'text_wrap': True})
                            xl_services.write(row, col, self.ss(output), cell_format)
                        row += 1

            workbook.close()

    def ckpt_api_call(self, ip_addr, port, command, json_payload, sid):

        import requests, json

        url = 'https://' + ip_addr + ':' + str(port) + '/web_api/' + command
        if sid == '':
            request_headers = {'Content-Type': 'application/json'}
        else:
            request_headers = {'Content-Type': 'application/json', 'X-chkp-sid': sid}
        r = requests.post(url, data=json.dumps(json_payload), headers=request_headers, verify=False)
        return r

    def ckpt_login(self, ip_addr, domain, user, password):

        import requests, json

        payload = {'user': user, 'password': password, "domain": domain}
        response = self.ckpt_api_call(ip_addr, 443, 'login', payload, '')
        # self.debug(response)
        if "sid" in json.loads(response.text):
            return json.loads(response.text)["sid"], json.loads(response.text)["uid"], 'Success'
        elif "message" in response:
            return False, response["message"], None
        else:
            return False, 'Unknown', None

    def ckpt_logout(self, ip_addr, domain, sid):

        # payload = {'user': user, 'password' : password, "domain": domain }
        response = self.ckpt_api_call(ip_addr, 443, 'login', {}, sid)
        # print(response)
        # if "sid" in response:
        #    return response["sid"], 'Success'
        # elif "message" in response:
        #    return False, response["message"]
        # else:
        #    return False, 'Unknown'
        return response

    def show_templates(self, infile):

        templates = self.load_templates(infile)
        for t in templates:
            self.log(t)

    def get_creds(self):

        import getpass

        username = input("  Username : ")
        password = getpass.getpass("  Password : ")

        return username, password;

    def search_address(self, search_addresses, contexts):

        ## (DONE) - Do this for specified contexts
        ## (DONE) - Now just returns a list for post-processing outside this routine -- Output for this should be better.  Perhaps printing a tree, or at least if each object is an address or group
        ## (FIXED) Return results for ranges and groups not correct

        return_list = []
        for address in search_addresses:
            for context in contexts:
                if 'addressmappings' in  self.config[context]:
                    addresses = self.createNetworkService.expand_address(self.config[context]['addresses'], address,
                                               self.config[context]['addressmappings'], False)
                    if addresses:
                        for item in addresses:
                            if item in self.config[context]['addresses']:
                                addr_obj = self.config[context]['addresses'][item]
                            elif item in self.config['shared']['addresses']:
                                addr_obj = self.config['shared']['addresses'][item]
                            if item in self.config[context]['addresses'] or item in self.config['shared']['addresses']:
                                if addr_obj['addrObjType'] == '1':
                                    addrmask = 32
                                    return_list.append(
                                        (context, address, item, str(addr_obj['addrObjIp1']) + '/' + str(addrmask)))
                                elif addr_obj['addrObjType'] == '2':
                                    return_list.append((context, address, item, str(addr_obj['addrObjIp1']) + '-' + str(
                                        addr_obj['addrObjIp2'])))
                                elif addr_obj['addrObjType'] == '8':
                                    return_list.append((context, address, item, 'GROUP'))
                                elif addr_obj['addrObjType'] == '4':
                                    addrmask = self.netmask_to_cidr(addr_obj['addrObjIp2'])
                                    return_list.append(
                                        (context, address, item, str(addr_obj['addrObjIp1']) + '/' + str(addrmask)))
                                else:
                                    # addrmask=netmask_to_cidr(addr_obj['addrObjIp2'])
                                    # return_list.append((item,str(addr_obj['addrObjIp1']) + '/' + str(addrmask)))
                                    return_list.append((context, address, item, addr_obj['addrObjType']))
        return return_list;

    def search_ip(self, search_ips, contexts):

        import re
        import ipaddress
        from netaddr import IPSet, IPRange

        ## (DONE) - Do this for specified contexts
        ## (DONE) - Now just returns a list for post-processing outside this routine -- Output for this should be better.  Perhaps printing a tree, or at least if each object is an address or group
        ## (FIXED) Return results for ranges and groups not correct

        return_list = []
        ip_to_find = IPSet([])

        for ip in search_ips:
            self.log(ip)
            if len(re.findall('/', ip)) == 1:
                # network, netmask = ip.split('/')
                ip_to_find.add('{}'.format(ip))
                ipv4_to_find = ipaddress.IPv4Network(ip)
            elif len(re.findall('/', ip)) == 0:
                # network=ip
                # netmask='32'
                ip_to_find.add('{}/{}'.format(ip, '32'))
                ipv4_to_find = ipaddress.IPv4Network('{}/{}'.format(ip, '32'))
            else:
                pass
                # invalid address format

            # ipv4_to_find=ipaddress.IPv4Network(ip_to_find)
            for context in contexts:
                # self.log(self.config[context]['addresses'][1])
                self.log(context)
                if 'addressmappings' in self.config[context]:
                    # addresses = expand_address(self.config[context]['addresses'], ip, self.config[context]['addressmappings'], False)
                    for address in self.config[context]['addresses']:
                        # self.log(address)
                        for address_member in self.createNetworkService.expand_address(self.config[context]['addresses'], address,
                                                             self.config[context]['addressmappings'], False):
                            address_ipset = IPSet([])

                            # if 'IPv4Networks' in self.config[context]['addresses'][address_member]:
                            if ipv4_to_find in self.config[context]['addresses'][address_member]['IPv4Networks']:
                                return_list.append((context, address_member, address, ip))

                            elif 'IPSet' in self.config[context]['addresses'][address_member]:
                                if ip_to_find & self.config[context]['addresses'][address_member]['IPSet']:
                                    return_list.append((context, address_member, address, ip))
                                    pass
                            else:
                                if self.config[context]['addresses'][address_member]['addrObjType'] == '1':
                                    address_ipset.add(
                                        '{}/32'.format(self.config[context]['addresses'][address_member]['addrObjIp1']))
                                    # self.log('Success network')
                                    if ip_to_find & address_ipset:
                                        return_list.append((context, address_member, address, ip))
                                elif self.config[context]['addresses'][address_member]['addrObjType'] == '4':
                                    address_ipset.add(
                                        '{}/{}'.format(self.config[context]['addresses'][address_member]['addrObjIp1'],
                                                       self.netmask_to_cidr(
                                                           self.config[context]['addresses'][address_member]['addrObjIp2'])))
                                    # self.log('Success network')
                                    if ip_to_find & address_ipset:
                                        return_list.append((context, address_member, address, ip))
                                elif self.config[context]['addresses'][address_member]['addrObjType'] == '2':
                                    try:
                                        # self.log(self.config[context]['addresses'][address_member]['addrObjIp1'], self.config[context]['addresses'][address_member]['addrObjIp2'])
                                        address_ipset.add(
                                            IPRange(self.config[context]['addresses'][address_member]['addrObjIp1'],
                                                    self.config[context]['addresses'][address_member]['addrObjIp2']))
                                        # self.log('Success range')
                                        if ip_to_find & address_ipset:
                                            return_list.append((context, address_member, address, ip))

                                    except Exception as e:
                                        self.log('Exception {}'.format(e))
                                        pass

            for items in return_list:
                self.log(items)
        return return_list

    def exec_fw_command(self, target, fw_type, commands, syntax='cli', policylens=None, delay=None, use_session=True,
                        use_apikey=False, dryrun=False,
                        sw_objects=None):  # add sw_sesssion, enable_api and commit options -- what is policy lens for?

        ## in theory, for checkpoint, commands could include multiple CMAs.  We should build a list of all the CMAs in a set of commands, then generate a sid and uid for each

        import requests
        import re
        import sonicwall as sw
        from urllib.parse import quote
        import time
        import json
        import base64

        valid_commands = ['create_address',
                          'modify_address',
                          'create_rule',
                          'modify_rule',
                          'create_service',
                          'modify_service',
                          'raw_command']
        # all_params=['context', 'ip1', 'ip2', 'name', 'members', 'comment', 'color', 'type', 'props', 'zone', 'srczone', 'dstzone', 'service', 'app', 'cmdtype', 'rulename', 'rulenum']

        retries = 3
        result = True
        # sw_objects={'address_objects': {'ipv4': [], 'ipv6': [], 'fqdn': []}, 'address_groups': {'ipv4': [], 'ipv6': [], 'fqdn': []}, 'service_objects': [], 'service_groups': [] }
        sw_objects = None
        if fw_type.lower() in ['sonicwall', 'palo', 'paloalto', 'pano', 'sw65', 'checkpoint'] and syntax != 'cli':
            session = requests.Session()
            session.mount('https://' + target, sw.DESAdapter())
            urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
            if not self.options.web and (self.options.username == None or self.options.password == None):
                self.options.username, self.options.password = self.get_creds()
            if fw_type.lower() == 'sonicwall':
                response = sw.do_login(session, self.options.username, self.options.password, target, True)
                apikey = None
            elif fw_type.lower() in ['sw65']:
                tries = 0
                success = False
                while tries < retries and not success:
                    tries += 1
                    try:
                        url = 'https://{}/api/sonicos/auth'.format(target)
                        session.headers = OrderedDict([('User-Agent', 'python-requests/2.18.4'), ('Accept', '*/*'),
                                                       ('Accept-Encoding', 'gzip, deflate'),
                                                       ('Connection', 'keep-alive')])
                        post_data = None
                        # auth = requests.auth.HTTPBasicAuth(self.options.username, self.options.password) -- replaced with manually setting headers myself since python requests basic auth was not handling special characters correctly
                        response_code = None
                        login_tries = 0
                        apikey = None
                        while response_code != 200 and login_tries < 1:
                            login_tries += 1
                            response = session.post(url=url, headers={'authorization': "Basic " + base64.b64encode(
                                '{}:{}'.format(self.options.username, self.options.password).encode()).decode()}, verify=False,
                                                    timeout=self.options.timeout_sw_webui_login)
                            response_code = response.status_code
                            # self.log('LOGIN RESULT', response.text)
                            apikey = True
                        if response_code != 200:
                            session = None
                            apikey = None
                            self.log('!-- Login failed')
                        else:
                            if not sw_objects:
                                ## build sonicwall objects list - this is needed to determine object type for when they need to be added to other objects
                                ## get addresses_objects, address_groups, address_fqdn, services_objects, service_groups for ipv4, ipv6, fqdn
                                ## verify we are in self.config mode
                                # self.log('building sw_objects')
                                sw_objects = self.sonicwall.get_sw_objects(target, self.options.username, self.options.password, fw_type,
                                                            session)
                        success = True
                    except Exception as e:
                        self.log('An exception occured when trying to log in to Sonicwall : {}'.format(e))

            elif fw_type.lower() in ['palo', 'pano', 'paloalto'] and use_session:
                try:
                    key = session.get(
                        'https://' + target + '/api/?type=keygen&user=' + self.options.username + '&password=' + quote(
                            self.options.password), verify=False, stream=True, timeout=self.options.timeout_palo_api)
                    if len(re.findall("status = 'success'", key.text)) == 0:
                        self.log('Unable to execute configuration commands - Login Failed')
                        self.debug(key.text)
                        return False
                    apikey = re.sub(r'.*<key>(.*)</key>.*', r'\1', key.text)
                except:
                    apikey = None
            elif fw_type.lower() in ['checkpoint']:
                self.debug('!-- Logging into Checkpoint R80 API to get SID and UID')
                apikey, session, message = self.ckpt_login(target, self.options.context[0], self.options.username, self.options.password)
                if not apikey:
                    self.debug('!-- Login to Checkpoint R80 API failed')
                    session = None
                    apikey = None
                else:
                    self.debug('!-- Login to Checkpoint R80 API successful - Retreived SID {} and UID {}'.format(apikey,
                                                                                                            session))
                    pass
                    # session=self.options.context[0]

            else:  # what is this here for?
                session = None
                apikey = True

        else:
            session = None
            apikey = None
        # self.debug(apikey)
        # self.debug(session)

        if apikey or fw_type.lower() not in ['palo', 'paloalto', 'pano', 'sw65'] or syntax.lower() == 'cli':
            #
            tries = 0
            success = False
            self.debug('COMMANDS', commands)

            ## the retries loop below should be for each command, not the entire set of commands...
            successful_commands = 0
            while tries < retries and not success:
                tries += 1
                # self.log('starting push -- try : {}'.format(tries))
                try:
                    successful_commands = 0
                    for command, params in commands:
                        self.debug('COMMAND', command)
                        self.debug('PARAMS', params)
                        #        for param in all_params: #set defalt value for all unset params - no validation is done at this time that the right params are passed for each cmdtype
                        #            if param not in command:
                        #                if param=='members':
                        #                    command[param]=[]
                        #                elif param=='color':
                        #                    command['color']='black'
                        #                else:
                        #                    command[param]=None

                        if 'comment' not in params:  # should provide proper handling of missing comment in functions below instead of setting this for everything CHANGE_ME
                            params['comment'] = ''
                        if command == 'create_address':
                            result = self.createNetworkService.create_address_obj(target, session, apikey, fw_type, syntax, params, sw_objects)
                        elif command == 'modify_address':
                            result = self.editNetworkService.modify_address_obj(target, session, apikey, fw_type, syntax, params, sw_objects)
                        elif command == 'modify_address_group':
                            result = self.editNetworkService.modify_address_obj(target, session, apikey, fw_type, syntax, params, sw_objects)
                        elif command == 'create_rule':
                            result = self.createNetworkService.create_rule_obj(target, session, apikey, fw_type, syntax, params, sw_objects)
                        elif command == 'modify_rule':
                            result = self.editNetworkService.modify_rule_obj(target, session, apikey, fw_type, syntax, params, sw_objects)
                        elif command == 'create_service':
                            result = self.createNetworkService.create_service_obj(target, session, apikey, fw_type, syntax, params, sw_objects)
                        elif command == 'modify_service':
                            result = self.editNetworkService.modify_service_obj(target, session, apikey, fw_type, syntax, params, sw_objects)
                        else:
                            return 'Unknown Command'
                        if syntax.lower != 'cli':
                            self.debug('{},{},{},"{}",{}'.format(target, fw_type, command, params, result))
                        if delay:
                            self.debug('Sleeping for {} seconds'.format(delay))
                            time.sleep(delay)
                        success=result==True
                        if success:
                            successful_commands += 1
                            debug('command success')
                        else:
                            debug('command failed')
                except Exception as e:
                    self.log('An exception occured when trying to perform exec_fw_command : {}'.format(e))

            ## Add sonicwall log-out / commit routines
            tries = 0
            success = False
            if successful_commands > 0:
                # self.log('attempting commit')
                if fw_type.lower() in ['sw65']:
                    while tries < retries and not success:
                        tries += 1
                        try:
                            commit_result = session.get('https://{}/api/sonicos/config/pending'.format(target),
                                                        data=None, verify=False, timeout=self.options.timeout_sw_webui)
                            self.debug(commit_result.text)
                            if json.loads(commit_result.text) != {}:
                                self.debug('!-- Commiting pending changes')
                                commit_result = session.post('https://{}/api/sonicos/config/pending'.format(target),
                                                             data=None, verify=False,
                                                             timeout=self.options.timeout_sw_webui_post)
                                self.debug(commit_result.text)
                                if 'status' in json.loads(commit_result.text):
                                    success = True
                                if not json.loads(commit_result.text)['status']['success']:
                                    result = False, json.loads(commit_result.text)['status']['info'][0]['message']
                            else:
                                self.debug('!-- No Changes made - Skipping commit')
                                success = True
                            self.debug('!-- Logging out of API')
                            url = 'https://{}/api/sonicos/auth'.format(target)
                            session.delete(url=url, verify=False, timeout=self.options.timeout_sw_webui)
                        except Exception as e:
                            self.log('An exception occured when trying to commit Sonicwall config : {}'.format(e))
                elif fw_type.lower() == 'checkpoint' and syntax.lower() == 'api':
                    if result == True:
                        self.debug('result before publish', result)
                        publish_result = self.ckpt_api_call(target, 443, "publish", {}, apikey)
                        self.debug("publish result: " + json.dumps(publish_result.text))
                        if 'task-id' not in json.loads(publish_result.text):
                            result = False, 'Publish Failed'
                            self.debug('!-- Changes failed -- discarding changes')
                            discard_result = self.ckpt_api_call(target, 443, "discard", {'uid': session}, apikey)
                            self.debug('discard result', discard_result)
                    else:
                        self.debug('!-- Changes failed -- discarding changes')
                        discard_result = self.ckpt_api_call(target, 443, "discard", {'uid': session}, apikey)
                        self.debug('discard result', discard_result)
                    self.debug('!-- Logging out of Checkpoint API')
                    logout_result = self.ckpt_api_call(target, 443, "logout", {}, apikey)
                    self.debug("logout result: " + json.dumps(logout_result.text))
        else:
            return False, 'no API key'
        # self.log('result', result)
        return result

    def inverse_match(self, subnets):

        ## address match results should not be just the first address object of the policy "[0]".. It should be changed to a tuple, containing the address object and object type.  The match type would be nice, but currently the matching is done on all the addresses in the policy at once, so this would be difficult to implement as it is currently written.
        ## this is only for reporting purposes.  the logic should be sound for matching as it currently is.  the problem is that when generating the matching report for policies, only the first address object is returned.
        from netaddr import IPSet
        import os
        from urllib.parse import unquote as url_unquote

        searchnets = IPSet([])
        sourcenets = IPSet([])
        destnets = IPSet([])
        inverse = OrderedDict()

        for network in subnets:
            searchnets.add(network)
        '''
            if len(os.path.basename(network))>0:
                if os.path.basename(network[0]) == '@':
                    for i in file_to_list(network[1:]):
                        searchnets.add(i)
                else:
                    searchnets.add(network)
        '''

        # print(searchnets)

        for context in self.contexts:

            inverse[context] = OrderedDict()
            inverse[context]['stats'] = {}
            inverse[context]['policies'] = []
            inverse[context]['effected_policies'] = []
            inverse[context]['addresses'] = []
            inverse[context]['addr_stats'] = [0, 0, 0]
            inverse[context]['policy_stats'] = [0, 0, 0]
            inverse[context]['stats'] = {'match': {'rules': {'total': 0, 'complete': 0, 'partial': 0},
                                                   'addresses': {'total': 0, 'complete': 0, 'partial': 0}
                                                   },
                                         'cleanup': {'rules': {'disabled': 0, 'deleted': 0, 'skipped_not_allow_rule': 0,
                                                               'skipped_notdisabled': 0},
                                                     'addresses': {'rem_rules': 0, 'rem_groups': 0, 'rem_dg': 0}
                                                     },

                                         'exec': {'rules': {'disabled': {'pass': 0, 'fail': 0, 'skipped': 0},
                                                            'deleted': {'pass': 0, 'fail': 0, 'skipped': 0}},
                                                  'addresses': {'rem_rules': {'pass': 0, 'fail': 0, 'skipped': 0},
                                                                'rem_groups': {'pass': 0, 'fail': 0, 'skipped': 0},
                                                                'rem_dg': {'pass': 0, 'fail': 0, 'skipped': 0}}
                                                  }}
            complete_matches = []  # CHANGEME - not sure what these were used for and I believe they can be removed
            partial_matches = []
            for policy in self.config[context]['policies']:
                rulematch = False
                source_match = 'none'
                dest_match = 'none'
                source_addr = ''  ###+ bcolors.OKGREEN
                dest_addr = ''  ###+ bcolors.OKGREEN
                sourcenets = IPSet([])
                destnets = IPSet([])
                if self.config[context]['policies'][policy]['policyProps'] == '0':  ## Only perform matching for custom rules
                    for source in self.config[context]['policies'][policy]['policySrcNet']:
                        for member in self.createNetworkService.expand_address(self.config[context]['addresses'], source,
                                                     self.config[context]['addressmappings']):
                            if member in self.config[context]['addresses']:
                                for network in self.config[context]['addresses'][member]['IPv4Networks']:
                                    if network.prefixlen > 8:
                                        sourcenets.add(str(network))
                            elif member in self.config['shared']['addresses']:
                                for network in self.config['shared']['addresses'][member]['IPv4Networks']:
                                    if network.prefixlen > 8:
                                        sourcenets.add(str(network))
                    for dest in self.config[context]['policies'][policy]['policyDstNet']:
                        for member in self.createNetworkService.expand_address(self.config[context]['addresses'], dest,
                                                     self.config[context]['addressmappings']):
                            if member in self.config[context]['addresses']:
                                for network in self.config[context]['addresses'][member]['IPv4Networks']:
                                    if network.prefixlen > 8:
                                        destnets.add(str(network))
                            elif member in self.config['shared']['addresses']:
                                for network in self.config['shared']['addresses'][member]['IPv4Networks']:
                                    if network.prefixlen > 8:
                                        destnets.add(str(network))

                    if sourcenets and ((sourcenets & searchnets) == sourcenets):  ## Don't match empty sourcenets
                        source_match = 'complete'
                        for member in self.config[context]['policies'][policy]['policySrcNet']:
                            if member not in partial_matches: partial_matches.append(member)

                        rulematch = True
                    elif (sourcenets & searchnets):
                        source_match = 'partial'
                        for member in self.config[context]['policies'][policy]['policySrcNet']:
                            if member not in complete_matches: complete_matches.append(member)
                        rulematch = True
                    if destnets and ((destnets & searchnets) == destnets):  ## Don't match empty destnets
                        dest_match = 'complete'
                        for member in self.config[context]['policies'][policy]['policyDstNet']:
                            if member not in partial_matches: partial_matches.append(member)
                        rulematch = True
                    elif (destnets & searchnets):
                        dest_match = 'partial'
                        for member in self.config[context]['policies'][policy]['policyDstNet']:
                            if member not in complete_matches: complete_matches.append(member)
                        rulematch = True

                    if rulematch:
                        self.debug('RULEMATCH!!')
                        if self.config[context]['policies'][policy]['policyName'] not in inverse[context][
                            'effected_policies']:  # build a list of effected policies
                            # self.log('adding: ', self.config[context]['policies'][policy]['policyName'])
                            inverse[context]['effected_policies'].append(
                                self.config[context]['policies'][policy]['policyName'])
                        # else:
                        #    self.log('new : ', self.config[context]['policies'][policy]['policyName'])

                        if self.config[context]['policies'][policy]['policyEnabled'] == '0':
                            enabled = False
                        elif self.config[context]['policies'][policy]['policyEnabled'] == '1':
                            enabled = True

                        if self.config[context]['policies'][policy]['policyAction'] == '0':
                            action = 'deny'
                        elif self.config[context]['policies'][policy]['policyAction'] == '1':
                            action = 'discard'
                        elif self.config[context]['policies'][policy]['policyAction'] == '2':
                            action = 'allow'
                        elif self.config[context]['policies'][policy]['policyAction'] == '3':
                            action = 'CltAuth'

                        name = self.config[context]['policies'][policy]['policyName']
                        comment = url_unquote(self.config[context]['policies'][policy]['policyComment'])

                        if self.config[context]['policies'][policy]['policySrcZone'] == []:
                            source_zone = 'any'
                        else:
                            source_zone = self.config[context]['policies'][policy]['policySrcZone'][0]

                        if self.config[context]['policies'][policy]['policyDstZone'] == []:
                            dest_zone = 'any'
                        else:
                            dest_zone = self.config[context]['policies'][policy]['policyDstZone'][0]
                        if len(self.config[context]['policies'][policy]['policySrcNet']) > 0: source_addr += \
                        self.config[context]['policies'][policy]['policySrcNet'][0]  ###+ bcolors.ENDC
                        if len(self.config[context]['policies'][policy]['policyDstNet']) > 0: dest_addr += \
                        self.config[context]['policies'][policy]['policyDstNet'][0]  ###+ bcolors.ENDC
                        if len(self.config[context]['policies'][policy]['policyDstSvc']) > 0: dest_service = \
                        self.config[context]['policies'][policy]['policyDstSvc'][0]
                        if dest_service == '' or self.config[context]['policies'][policy][
                            'policyDstSvc'] == []: dest_service = 'any'

                        if source_addr == '' or source_addr.lower() == 'any':
                            source_type = 'any'
                        else:
                            if source_addr in self.config[context]['addresses']:
                                tmp_type = self.config[context]['addresses'][source_addr]['addrObjType']
                            elif 'shared' in self.config:
                                if source_addr in self.config['shared']['addresses']:
                                    tmp_type = self.config['shared']['addresses'][source_addr]['addrObjType']
                                else:
                                    tmp_type = '0'
                            else:
                                tmp_type = '0'

                            if tmp_type == '1':
                                source_type = 'host'
                            elif tmp_type == '2':
                                source_type = 'range'
                            elif tmp_type == '4':
                                source_type = 'network'
                            elif tmp_type == '0':
                                source_type = 'ERROR'
                            else:
                                source_type = 'group'

                        if dest_addr == '' or dest_addr.lower() == 'any':
                            dest_type = 'any'
                        else:
                            if dest_addr in self.config[context]['addresses']:
                                tmp_type = self.config[context]['addresses'][dest_addr]['addrObjType']
                            elif 'shared' in self.config:
                                if dest_addr in self.config['shared']['addresses']:
                                    tmp_type = self.config['shared']['addresses'][dest_addr]['addrObjType']
                            else:
                                tmp_type = '0'

                            if tmp_type == '1':
                                dest_type = 'host'
                            elif tmp_type == '2':
                                dest_type = 'range'
                            elif tmp_type == '4':
                                dest_type = 'network'
                            elif tmp_type == '91':
                                dest_type = 'special'
                            elif tmp_type == '0':
                                dest_type = 'ERROR'
                            else:
                                dest_type = 'group'

                        if dest_service == '' or dest_service.lower() == 'any':
                            service_type = 'any'
                        else:
                            if dest_service in self.config[context]['services']:
                                tmp_type = self.config[context]['services'][dest_service]['svcObjType']
                            elif 'shared' in self.config:
                                if dest_service in self.config['shared']['services']:
                                    tmp_type = self.config['shared']['services'][dest_service]['svcObjType']
                            else:
                                tmp_type = '0'

                            if tmp_type == '1':
                                service_type = 'name'
                            elif tmp_type == '2':
                                service_type = 'group'
                            elif tmp_type == '4':
                                service_type = 'portset'
                            elif tmp_type == '0':
                                service_type = 'ERROR'
                            else:
                                service_type = 'group'

                        inverse[context]['stats']['match']['rules']['total'] += 1
                        if source_match == 'complete' or dest_match == 'complete':
                            inverse[context]['stats']['match']['rules']['complete'] += 1
                        else:
                            inverse[context]['stats']['match']['rules']['partial'] += 1

                        if self.config[context]['config']['fw_type'].lower() == 'checkpoint':
                            rule_num = self.config[context]['policies'][policy]['policyNum']
                            ui_num = self.config[context]['policies'][policy]['policyUiNum']
                        else:
                            rule_num = 0
                            ui_num = 0
                        inverse[context]['policies'].append({'devname': self.config[context]['config']['name'],
                                                             'rule_num': rule_num,
                                                             'fw_type': self.config[context]['config']['fw_type'],
                                                             'fw_version': self.config[context]['config']['version'],
                                                             'enabled': enabled,
                                                             'action': action,
                                                             'name': name,
                                                             'source_zone': source_zone,
                                                             'dest_zone': dest_zone,
                                                             'source_type': source_type,
                                                             'source_addr': source_addr,
                                                             'source_match': source_match,
                                                             'dest_type': dest_type,
                                                             'dest_addr': dest_addr,
                                                             'dest_match': dest_match,
                                                             'service_type': service_type,
                                                             'dest_service': dest_service,
                                                             'comment': comment,
                                                             'rule_num': self.config[context]['policies'][policy][
                                                                 'policyNum'],
                                                             'ui_num': self.config[context]['policies'][policy][
                                                                 'policyUiNum'],
                                                             'source_list': self.config[context]['policies'][policy][
                                                                 'policySrcNet'],
                                                             'dest_list': self.config[context]['policies'][policy][
                                                                 'policyDstNet']})

            for address in self.config[context]['addresses']:

                addressnets = IPSet([])
                for member in self.createNetworkService.expand_address(self.config[context]['addresses'], address, self.config[context]['addressmappings']):
                    if member in self.config[context]['addresses']:
                        for network in self.config[context]['addresses'][member]['IPv4Networks']:
                            if network.prefixlen > 8:
                                addressnets.add(str(network))
                    elif member in self.config['shared']['addresses']:
                        for network in self.config['shared']['addresses'][member]['IPv4Networks']:
                            if network.prefixlen > 8:
                                addressnets.add(str(network))
                try:
                    if self.config[context]['addresses'][address]['addrObjType'] == '1':
                        addr_type = 'host'
                    elif self.config[context]['addresses'][address]['addrObjType'] == '2':
                        addr_type = 'range'
                    elif self.config[context]['addresses'][address]['addrObjType'] == '4':
                        addr_type = 'network'
                    elif self.config[context]['addresses'][address]['addrObjType'] == '8':
                        addr_type = 'group'
                    else:
                        addr_type = self.config[context]['addresses'][address]['addrObjType']
                except:
                    if self.config['shared']['addresses'][address]['addrObjType'] == '1':
                        addr_type = 'host'
                    elif self.config['shared']['addresses'][address]['addrObjType'] == '2':
                        addr_type = 'range'
                    elif self.config['shared']['addresses'][address]['addrObjType'] == '4':
                        addr_type = 'network'
                    elif self.config['shared']['addresses'][address]['addrObjType'] == '8':
                        addr_type = 'group'
                    else:
                        addr_type = self.config['shared']['addresses'][address]['addrObjType']

                if addressnets and ((addressnets & searchnets) == addressnets):  ## Don't match empty destnets
                    self.log('complete', address, level=self.logging.DEBUG)
                    inverse[context]['addresses'].append(
                        {'devname': self.config[context]['config']['name'], 'fw_type': self.config[context]['config']['fw_type'],
                         'fw_version': self.config[context]['config']['version'], 'match': 'complete', 'type': addr_type,
                         'mapping': 'root', 'address': address})
                elif (addressnets & searchnets):
                    self.log('partial', address, level=self.logging.DEBUG)
                    inverse[context]['addresses'].append(
                        {'devname': self.config[context]['config']['name'], 'fw_type': self.config[context]['config']['fw_type'],
                         'fw_version': self.config[context]['config']['version'], 'match': 'partial', 'type': addr_type,
                         'mapping': 'root', 'address': address})

                if self.config[context]['addresses'][address]['addrObjType'] == '8' and not (addressnets and (
                        (addressnets & searchnets) == addressnets)):  # what is being excluded here with the NOT?
                    for mapping in self.config[context]['addressmappings'][address]:
                        addressnets = IPSet([])
                        for member in self.createNetworkService.expand_address(self.config[context]['addresses'], mapping,
                                                     self.config[context]['addressmappings']):
                            if 'member' in self.config[context]['addresses']:
                                for network in self.config[context]['addresses'][member]['IPv4Networks']:
                                    if network.prefixlen > 8:
                                        addressnets.add(str(network))
                            elif 'member' in self.config['shared']['addresses']:
                                for network in self.config['shared']['addresses'][member]['IPv4Networks']:
                                    if network.prefixlen > 8:
                                        addressnets.add(str(network))
                        try:
                            if self.config[context]['addresses'][mapping]['addrObjType'] == '1':
                                addr_type = 'host'
                            elif self.config[context]['addresses'][mapping]['addrObjType'] == '2':
                                addr_type = 'range'
                            elif self.config[context]['addresses'][mapping]['addrObjType'] == '4':
                                addr_type = 'network'
                            elif self.config[context]['addresses'][mapping]['addrObjType'] == '8':
                                addr_type = 'group'
                            else:
                                addr_type = self.config[context]['addresses'][mapping]['addrObjType']
                            # location='context'
                        except:
                            if 'shared' in self.config:
                                if mapping in self.config['shared']['addresses']:
                                    if self.config['shared']['addresses'][mapping]['addrObjType'] == '1':
                                        addr_type = 'host'
                                    elif self.config['shared']['addresses'][mapping]['addrObjType'] == '2':
                                        addr_type = 'range'
                                    elif self.config['shared']['addresses'][mapping]['addrObjType'] == '4':
                                        addr_type = 'network'
                                    elif self.config['shared']['addresses'][mapping]['addrObjType'] == '8':
                                        addr_type = 'group'
                                    else:
                                        addr_type = self.config['shared']['addresses'][mapping]['addrObjType']
                            else:
                                addr_type = 'GMS'  # WHY GMS???
                        if addressnets and ((addressnets & searchnets) == addressnets):  ## Don't match empty destnets
                            inverse[context]['addresses'].append({'devname': self.config[context]['config']['name'],
                                                                  'fw_type': self.config[context]['config']['fw_type'],
                                                                  'fw_version': self.config[context]['config']['version'],
                                                                  'match': 'complete', 'type': addr_type,
                                                                  'address': mapping, 'mapping': address})
                            inverse[context]['addr_stats'][0] += 1
                            inverse[context]['addr_stats'][1] += 1
                            inverse[context]['stats']['match']['addresses']['total'] += 1
                            inverse[context]['stats']['match']['addresses']['complete'] += 1
                        elif (addressnets & searchnets):
                            inverse[context]['addresses'].append({'devname': self.config[context]['config']['name'],
                                                                  'fw_type': self.config[context]['config']['fw_type'],
                                                                  'fw_version': self.config[context]['config']['version'],
                                                                  'match': 'partial', 'type': addr_type,
                                                                  'address': mapping, 'mapping': address})
                            inverse[context]['addr_stats'][0] += 1
                            inverse[context]['addr_stats'][2] += 1
                            inverse[context]['stats']['match']['addresses']['total'] += 1
                            inverse[context]['stats']['match']['addresses']['partial'] += 1
        self.debug(inverse)
        return inverse;

    def cip_match4(self, subnets):

        ## this differs from inverse_match in that each ip address passed in as a member of the subnets list is checked individually
        ## This first method has an outer loop of each address object and an inner loop of each ip address being searched - a second routine will be added to iterate through the ip address search list first, then network objects.
        ## I anticipate method 1 to be faster because the addressnets variable would need to be created far less.

        ## time to search 379 networks across all "internet" objects takes just under 17 minutes

        from netaddr import IPSet
        import os
        from urllib.parse import unquote as url_unquote
        import ipaddress

        searchnets = []
        sourcenets = IPSet([])
        destnets = IPSet([])
        change = OrderedDict()

        for network in subnets:
            if len(os.path.basename(network)) > 0:
                if os.path.basename(network[0]) == '@':
                    for i in self.file_to_list(network[1:]):
                        if i[0] != '#':
                            searchnets.append(i.rstrip().split(','))
                else:
                    searchnets.append(network.split(','))
        for searchnet, newnet in searchnets:
            if ipaddress.IPv4Network(searchnet).prefixlen < ipaddress.IPv4Network(newnet).prefixlen:
                self.log('Replacement of {} with smaller network {} requested - exact network matches will be replaced only'.format(
                    searchnet, newnet))
        for searchnet, newnet in searchnets:
            try:
                ipaddress.IPv4Network(searchnet)
            except:
                self.log('Bad Old Network Given - ABORTING : {}'.format(ipaddress.IPv4Network(searchnet)))
                exit(1)
            try:
                ipaddress.IPv4Network(newnet)
            except:
                self.log('Bad New Network Given - ABORTING : {}'.format(ipaddress.IPv4Network(newnet)))
                exit(1)
        tmpindex = 0
        for searchnet, newnet in searchnets:
            tmpindex += 1
            for searchnet2, newnet2 in searchnets[tmpindex:]:
                self.debug('Checking if New network {} overlaps with new network {}'.format(newnet, newnet2))
                # self.log(newnet,newnet2)
                if IPSet([newnet]) & IPSet([newnet2]) != IPSet([]):
                    self.log('WARNING! New network {} overlaps with new network {}'.format(newnet, newnet2))
        match_id = 0

        for context in self.contexts:
            if 'version' not in self.config[context]['config']: self.config[context]['config']['version'] = ''
            change[context] = OrderedDict()
            change[context]['fw_type'] = self.config[context]['config']['fw_type']
            change[context]['groups'] = OrderedDict()
            change[context]['addresses'] = OrderedDict()
            change[context]['sources'] = OrderedDict()
            change[context]['dests'] = OrderedDict()
            change[context]['nat'] = OrderedDict()
            change[context]['colors'] = OrderedDict()
            change[context]['group_policies'] = OrderedDict()
            expanded = {'groups': OrderedDict(),
                        'policy_src': OrderedDict(),
                        'policy_dst': OrderedDict(),
                        'nat_orig_src': OrderedDict(),
                        'nat_orig_dst': OrderedDict(),
                        'nat_trans_src': OrderedDict(),
                        'nat_trans_dst': OrderedDict(),
                        'all': []}

            expanded['all'] = []
            for group in self.config[context]['addresses']:
                if self.config[context]['addresses'][group]['addrObjType'] == '8':
                    tmplist = self.createNetworkService.expand_address(self.config[context]['addresses'], group, self.config[context]['addressmappings'],
                                             inc_group=True)
                    expanded['groups'][group] = tmplist

            for policy in self.config[context]['policies']:
                expanded['policy_src'][policy] = []
                expanded['policy_dst'][policy] = []

                for pol_src in self.config[context]['policies'][policy]['policySrcNet']:
                    tmplist = self.createNetworkService.expand_address(self.config[context]['addresses'], pol_src, self.config[context]['addressmappings'],
                                             inc_group=True)
                    expanded['policy_src'][policy].extend(tmplist)
                    expanded['all'].extend(tmplist)

                for pol_dst in self.config[context]['policies'][policy]['policyDstNet']:
                    tmplist = self.createNetworkService.expand_address(self.config[context]['addresses'], pol_dst, self.config[context]['addressmappings'],
                                             inc_group=True)
                    expanded['policy_dst'][policy].extend(tmplist)
                    expanded['all'].extend(tmplist)

            if 'nat' in self.config[context]:
                for policy in self.config[context]['nat']:
                    expanded['nat_orig_src'][policy] = []
                    expanded['nat_orig_dst'][policy] = []
                    expanded['nat_trans_src'][policy] = []
                    expanded['nat_trans_dst'][policy] = []

                    for nat_src in self.config[context]['nat'][policy]['natPolicyOrigSrc']:
                        tmplist = self.createNetworkService.expand_address(self.config[context]['addresses'], nat_src,
                                                 self.config[context]['addressmappings'], inc_group=True)
                        expanded['nat_orig_src'][policy].extend(tmplist)
                        expanded['all'].extend(tmplist)
                    for nat_dst in self.config[context]['nat'][policy]['natPolicyOrigDst']:
                        tmplist = self.createNetworkService.expand_address(self.config[context]['addresses'], nat_dst,
                                                 self.config[context]['addressmappings'], inc_group=True)
                        expanded['nat_orig_dst'][policy].extend(tmplist)
                        expanded['all'].extend(tmplist)
                    for nat_src in self.config[context]['nat'][policy]['natPolicyTransSrc']:
                        tmplist = self.createNetworkService.expand_address(self.config[context]['addresses'], nat_src,
                                                 self.config[context]['addressmappings'], inc_group=True)
                        expanded['nat_trans_src'][policy].extend(tmplist)
                        expanded['all'].extend(tmplist)
                    for nat_dst in self.config[context]['nat'][policy]['natPolicyTransDst']:
                        tmplist = self.createNetworkService.expand_address(self.config[context]['addresses'], nat_dst,
                                                 self.config[context]['addressmappings'], inc_group=True)
                        expanded['nat_trans_dst'][policy].extend(tmplist)
                        expanded['all'].extend(tmplist)

            complete_matches = []  # CHANGEME - not sure what these were used for and I believe they can be removed
            partial_matches = []

            addresses_to_add = []
            for idx, address in enumerate(self.config[context]['addresses']):
                ## only perform matching for hosts, ranges and networks
                if self.config[context]['addresses'][address]['addrObjType'] in ['1', '2', '4', '91']:
                    addressnets = IPSet([])
                    for member in self.createNetworkService.expand_address(self.config[context]['addresses'], address, self.config[context][
                        'addressmappings']):  ## why is this being done for addr types 1,2,4,91??
                        for network in self.config[context]['addresses'][member]['IPv4Networks']:
                            if network.prefixlen > 8:
                                addressnets.add(str(network))
                    tmp_addr = None
                    if address in self.config[context]['addresses']:
                        tmp_addr = self.config[context]['addresses'][address]
                    elif address in self.config['shared']['addresses'] and self.config[context]['config'][
                        'fw_type'] == 'panorama':
                        tmp_addr = self.config['shared']['addresses'][address]
                    if tmp_addr != None:
                        if tmp_addr['addrObjType'] == '1':
                            addr_type = 'host'
                        elif tmp_addr['addrObjType'] == '2':
                            addr_type = 'range'
                        elif tmp_addr['addrObjType'] == '4':
                            addr_type = 'network'
                        elif tmp_addr['addrObjType'] == '8':
                            addr_type = 'group'
                        elif tmp_addr['addrObjType'] == '91':
                            addr_type = 'cluster_member'
                        else:
                            addr_type = tmp_addr['addrObjType']

                    for searchnet, newnet in searchnets:
                        if ipaddress.IPv4Network(searchnet).prefixlen >= ipaddress.IPv4Network(
                                newnet).prefixlen or addressnets == IPSet(
                                [searchnet]):  ## allow for replacement of larger to smaller for exact matches
                            newaddr = None
                            search = IPSet([searchnet])
                            if addr_type in ['host', 'range', 'network', 'cluster_member']:
                                addr_matches = addressnets & search
                            else:
                                addr_matches = ''
                            if addressnets and ((addressnets & search) == addressnets) or (
                                    addressnets & search):  ### if its a complete or partial match...
                                if addressnets == search:
                                    match_type = 'exact'
                                elif addressnets and ((addressnets & search) == addressnets):
                                    match_type = 'complete'
                                else:
                                    match_type = 'partial'
                                ## determine new object information
                                if match_type != 'partial' or self.options.exclude_partial == False:
                                    if self.config[context]['addresses'][address]['addrObjType'] == '1':  ## host
                                        try:
                                            hidx = list(ipaddress.IPv4Network(searchnet)).index(ipaddress.IPv4Address(
                                                self.config[context]['addresses'][address]['IPv4Networks'][0][0]))
                                            newip1 = str(list(ipaddress.IPv4Network(newnet))[hidx])
                                            newip2 = '255.255.255.255'
                                            newaddr = "H-" + str(newip1)
                                        except:
                                            self.log('ERROR')

                                    elif self.config[context]['addresses'][address]['addrObjType'] == '2':  ## range
                                        if match_type == 'complete':
                                            # self.log('Complete Range Match')
                                            if ipaddress.IPv4Address(
                                                    self.config[context]['addresses'][address]['IPv4Networks'][0][
                                                        0]) in list(ipaddress.IPv4Network(searchnet)):
                                                rfidx = list(ipaddress.IPv4Network(searchnet)).index(
                                                    ipaddress.IPv4Address(
                                                        self.config[context]['addresses'][address]['IPv4Networks'][0][0]))
                                            else:
                                                rfidx = 0
                                            if ipaddress.IPv4Address(
                                                    self.config[context]['addresses'][address]['IPv4Networks'][-1][
                                                        -1]) in list(ipaddress.IPv4Network(searchnet)):
                                                rlidx = list(ipaddress.IPv4Network(searchnet)).index(
                                                    ipaddress.IPv4Address(
                                                        self.config[context]['addresses'][address]['IPv4Networks'][-1][-1]))
                                            else:
                                                rlidx = -1
                                            newip1 = str(list(ipaddress.IPv4Network(newnet))[rfidx])
                                            newip2 = str(list(ipaddress.IPv4Network(newnet))[rlidx])
                                            newaddr = "R-" + str(newip1) + '-' + str(newip2)
                                        else:
                                            ## if searchnet is entirely contained within the range, do the same thing as we do for networks and just create a new network object
                                            self.log('WARNING -- range object with a partial match - this needs to be handled manually')
                                            self.log('DETAILS -- Search Network : {search}  Range Start: {rstart} Range End: {rend}'.format(
                                                search=searchnet,
                                                rstart=self.config[context]['addresses'][address]['addrObjIp1'],
                                                rend=self.config[context]['addresses'][address]['addrObjIp2']))
                                            if ipaddress.IPv4Address(
                                                    self.config[context]['addresses'][address]['IPv4Networks'][0][
                                                        0]) in list(ipaddress.IPv4Network(searchnet)):
                                                rfidx = list(ipaddress.IPv4Network(searchnet)).index(
                                                    ipaddress.IPv4Address(
                                                        self.config[context]['addresses'][address]['IPv4Networks'][0][0]))
                                            else:
                                                rfidx = 0
                                            if ipaddress.IPv4Address(
                                                    self.config[context]['addresses'][address]['IPv4Networks'][-1][
                                                        -1]) in list(ipaddress.IPv4Network(searchnet)):
                                                rlidx = list(ipaddress.IPv4Network(searchnet)).index(
                                                    ipaddress.IPv4Address(
                                                        self.config[context]['addresses'][address]['IPv4Networks'][-1][-1]))
                                                if rlidx > len(list(ipaddress.IPv4Network(newnet))):
                                                    rlidx = -1
                                            else:
                                                rlidx = -1
                                            # self.log(rfidx, rlidx)
                                            newip1 = str(list(ipaddress.IPv4Network(newnet))[rfidx])
                                            newip2 = str(list(ipaddress.IPv4Network(newnet))[rlidx])
                                            newaddr = "R-" + str(newip1) + '-' + str(newip1).split('.')[3]
                                            newaddr = "R-" + str(newip1) + '-' + str(newip2)
                                    elif self.config[context]['addresses'][address]['addrObjType'] == '4':  ## network
                                        if match_type == 'complete':
                                            nidx = list(ipaddress.IPv4Network(searchnet)).index(ipaddress.IPv4Address(
                                                self.config[context]['addresses'][address]['IPv4Networks'][0][
                                                    0]))  # complete match index - searched network is a superset of the current address object
                                            nlen = self.config[context]['addresses'][address]['IPv4Networks'][0].prefixlen
                                            newip1 = str(list(ipaddress.IPv4Network(newnet))[nidx])
                                            newip2 = str(self.cidr_to_netmask(nlen))
                                            newaddr = 'N-' + newip1 + '-' + str(self.netmask_to_cidr(newip2))
                                        else:
                                            if len(re.findall('/', newnet)) > 0:
                                                newip1, newip2 = newnet.split('/')
                                                newip2 = self.cidr_to_netmask(newip2)
                                            else:
                                                newip1 = newnet
                                                newip2 = '255.255.255.255'
                                            newaddr = 'N-' + newip1 + '-' + str(self.netmask_to_cidr(newip2))
                                    if newaddr != None:
                                        if newaddr in self.config[context]['addresses']:
                                            while newaddr in self.config[context]['addresses']:
                                                newaddr = newaddr + '_DUPE'
                                            self.log('WARNING -- existing address already exists with the proposed new name, renaming to : ' + newaddr,
                                                level=self.logging.INFO)

                                        if searchnet not in change[context]['addresses']:
                                            change[context]['addresses'][searchnet] = []

                                        ## consider changing new addresses to include list of tuple searchaddress,oldaddress
                                        ## consider keeping track of the number of matches
                                        if expanded['all'].count(address) == 0:
                                            self.debug('Object {} not found in any policy'.format(address))
                                        if match_type.lower() != 'partial':
                                            skip_address = 'no'
                                        else:
                                            skip_address = 'yes'
                                        change[context]['addresses'][searchnet].append(
                                            {'devname': self.config[context]['config']['name'],
                                             'fw_type': self.config[context]['config']['fw_type'],
                                             'fw_version': self.config[context]['config']['version'],
                                             'context': context,
                                             'match': match_type,
                                             'match_id': match_id,
                                             'type': addr_type,
                                             'mapping': 'root',
                                             'searchaddress': searchnet,
                                             'oldaddress': address,
                                             'old_ip1': self.config[context]['addresses'][address]['addrObjIp1'],
                                             'old_ip2': self.config[context]['addresses'][address]['addrObjIp2'],
                                             'zone': self.config[context]['addresses'][address]['addrObjZone'],
                                             'new_addr': newaddr,
                                             'new_ip1': newip1,
                                             'new_ip2': newip2,
                                             'matchlen': int(
                                                 self.netmask_to_cidr(self.config[context]['addresses'][address]['addrObjIp2'])),
                                             'comment': 'WAS: ' + address + ' - ' +
                                                        self.config[context]['addresses'][address]['addrObjComment'],
                                             'oldcolor': self.config[context]['addresses'][address]['addrObjColor'],
                                             'color': self.config[context]['addresses'][address]['addrObjColor'],
                                             'skip': skip_address,
                                             'inuse': expanded['all'].count(address)

                                             })
                                        match_id += 1
                                        if newaddr not in change[context]['colors']:
                                            change[context]['colors'][newaddr] = {}
                                            change[context]['colors'][newaddr]['color'] = \
                                            self.config[context]['addresses'][address]['addrObjColor']
                                            change[context]['colors'][newaddr]['matchlen'] = int(
                                                self.netmask_to_cidr(self.config[context]['addresses'][address]['addrObjIp2']))
                                        if int(self.netmask_to_cidr(self.config[context]['addresses'][address]['addrObjIp2'])) > \
                                                change[context]['colors'][newaddr]['matchlen'] and expanded[
                                            'all'].count(address) > 0:
                                            change[context]['colors'][newaddr]['color'] = \
                                            self.config[context]['addresses'][address]['addrObjColor']
                                            change[context]['colors'][newaddr]['matchlen'] = int(
                                                self.netmask_to_cidr(self.config[context]['addresses'][address]['addrObjIp2']))
                                        addresses_to_add.append(newaddr)
                                        for group in self.config[context]['addressmappings']:
                                            if address in self.config[context]['addressmappings'][
                                                group]:  # and (self.options.cipskippartial and match_type !='partial'): ## added condition for 152.62.0.0 because of the time it was taking to process, and this replacement is not happning
                                                if address not in change[context]['groups']: change[context]['groups'][
                                                    address] = []
                                                change[context]['groups'][address].append(
                                                    {'devname': self.config[context]['config']['name'],
                                                     'fw_type': self.config[context]['config']['fw_type'],
                                                     'fw_version': self.config[context]['config']['version'],
                                                     'type': 'group',
                                                     'searchaddress': searchnet,
                                                     'oldmember': member,
                                                     'newmember': newaddr,
                                                     'group': group
                                                     })
                                                ## move matched_policies routing from report to here -- this is needed since it relies on having "self.config" available

                                                matched_policies = {}
                                                for p in self.config[context]['policies']:
                                                    if self.config[context]['policies'][p][
                                                        'policyName'] not in self.options.cipblacklist:
                                                        policy_addresses = []
                                                        for s in self.config[context]['policies'][p]['policySrcNet']:
                                                            policy_addresses.extend(
                                                                self.createNetworkService.expand_address(self.config[context]['addresses'], s,
                                                                               self.config[context]['addressmappings'],
                                                                               inc_group=True))
                                                            policy_addresses.extend([s])
                                                        for d in self.config[context]['policies'][p]['policyDstNet']:
                                                            policy_addresses.extend(
                                                                self.createNetworkService.expand_address(self.config[context]['addresses'], s,
                                                                               self.config[context]['addressmappings'],
                                                                               inc_group=True))
                                                            policy_addresses.extend([d])
                                                        if group in policy_addresses:
                                                            if self.config[context]['policies'][p][
                                                                'policyName'] not in matched_policies:
                                                                # matched_policies.append(self.config[context]['policies'][p]['policyName'])
                                                                matched_policies[
                                                                    self.config[context]['policies'][p]['policyName']] = [(
                                                                                                                     self.config[
                                                                                                                         context][
                                                                                                                         'policies'][
                                                                                                                         p][
                                                                                                                         'policyUiNum'],
                                                                                                                     self.config[
                                                                                                                         context][
                                                                                                                         'policies'][
                                                                                                                         p][
                                                                                                                         'policyNum'])]
                                                            else:
                                                                matched_policies[self.config[context]['policies'][p][
                                                                    'policyName']].append((self.config[context]['policies'][
                                                                                               p]['policyUiNum'],
                                                                                           self.config[context]['policies'][
                                                                                               p]['policyNum']))

                                                change[context]['group_policies'][group] = matched_policies
                                        for policy in self.config[context]['policies']:
                                            if self.config[context]['policies'][policy][
                                                'policyName'] not in self.options.cipblacklist:
                                                if address in self.config[context]['policies'][policy]['policySrcNet']:
                                                    if address not in change[context]['sources']:
                                                        change[context]['sources'][address] = []
                                                        change[context]['sources'][address].append(
                                                        {'devname': self.config[context]['config']['name'],
                                                         'fw_type': self.config[context]['config']['fw_type'],
                                                         'fw_version': self.config[context]['config']['version'],
                                                         'type': 'policy_source',
                                                         'policy_name': self.config[context]['policies'][policy][
                                                             'policyName'],
                                                         'policy_num': self.config[context]['policies'][policy]['policyNum'],
                                                         'policy_uinum': self.config[context]['policies'][policy][
                                                             'policyUiNum'],
                                                         'src_zone': self.config[context]['policies'][policy][
                                                             'policySrcZone'],
                                                         'dst_zone': self.config[context]['policies'][policy][
                                                             'policyDstZone'],
                                                         'orig_policy': self.config[context]['policies'][policy],
                                                         'searchaddress': searchnet,
                                                         'oldaddress': address,
                                                         'newaddress': newaddr})
                                        for policy in self.config[context]['policies']:
                                            if self.config[context]['policies'][policy][
                                                'policyName'] not in self.options.cipblacklist:
                                                if address in self.config[context]['policies'][policy]['policyDstNet']:
                                                    if address not in change[context]['dests']:
                                                        change[context]['dests'][address] = []
                                                    change[context]['dests'][address].append(
                                                        {'devname': self.config[context]['config']['name'],
                                                         'fw_type': self.config[context]['config']['fw_type'],
                                                         'fw_version': self.config[context]['config']['version'],
                                                         'type': 'policy_dest',
                                                         'policy_name': self.config[context]['policies'][policy][
                                                             'policyName'],
                                                         'policy_num': self.config[context]['policies'][policy]['policyNum'],
                                                         'policy_uinum': self.config[context]['policies'][policy][
                                                             'policyUiNum'],
                                                         'src_zone': self.config[context]['policies'][policy][
                                                             'policySrcZone'],
                                                         'dst_zone': self.config[context]['policies'][policy][
                                                             'policyDstZone'],
                                                         'orig_policy': self.config[context]['policies'][policy],
                                                         'searchaddress': searchnet,
                                                         'oldaddress': address,
                                                         'newaddress': newaddr})

                                        for policy in self.config[context]['nat']:
                                            if self.config[context]['nat'][policy][
                                                'natPolicyName'] not in self.options.cipblacklist:
                                                if address in self.config[context]['nat'][policy]['natPolicyOrigSrc']:
                                                    if address not in change[context]['nat']: change[context]['nat'][
                                                        address] = []
                                                    change[context]['nat'][address].append(
                                                        {'devname': self.config[context]['config']['name'],
                                                         'fw_type': self.config[context]['config']['fw_type'],
                                                         'fw_version': self.config[context]['config']['version'],
                                                         'searchaddress': searchnet,
                                                         'type': 'natPolicyOrigSrc',
                                                         'policy_name': self.config[context]['nat'][policy]['natPolicyName'],
                                                         'policy_num': self.config[context]['nat'][policy]['natPolicyNum'],
                                                         'policy_uinum': self.config[context]['nat'][policy][
                                                             'natPolicyUiNum'],
                                                         'searchaddress': searchnet,
                                                         'oldaddress': address,
                                                         'newaddress': newaddr})
                                                if address in self.config[context]['nat'][policy]['natPolicyOrigDst']:
                                                    if address not in change[context]['nat']: change[context]['nat'][
                                                        address] = []
                                                    change[context]['nat'][address].append(
                                                        {'devname': self.config[context]['config']['name'],
                                                         'fw_type': self.config[context]['config']['fw_type'],
                                                         'fw_version': self.config[context]['config']['version'],
                                                         'type': 'natPolicyOrigDst',
                                                         'policy_name': self.config[context]['nat'][policy]['natPolicyName'],
                                                         'policy_num': self.config[context]['nat'][policy]['natPolicyNum'],
                                                         'policy_uinum': self.config[context]['nat'][policy][
                                                             'natPolicyUiNum'],
                                                         'oldaddress': address,
                                                         'newaddress': newaddr})
                                                if address in self.config[context]['nat'][policy]['natPolicyTransSrc']:
                                                    if address not in change[context]['nat']: change[context]['nat'][
                                                        address] = []
                                                    change[context]['nat'][address].append(
                                                        {'devname': self.config[context]['config']['name'],
                                                         'fw_type': self.config[context]['config']['fw_type'],
                                                         'fw_version': self.config[context]['config']['version'],
                                                         'type': 'natPolicyTransSrc',
                                                         'policy_name': self.config[context]['nat'][policy]['natPolicyName'],
                                                         'policy_num': self.config[context]['nat'][policy]['natPolicyNum'],
                                                         'policy_uinum': self.config[context]['nat'][policy][
                                                             'natPolicyUiNum'],
                                                         'searchaddress': searchnet,
                                                         'oldaddress': address,
                                                         'newaddress': newaddr})
                                                if address in self.config[context]['nat'][policy]['natPolicyTransDst']:
                                                    if address not in change[context]['nat']: change[context]['nat'][
                                                        address] = []
                                                    change[context]['nat'][address].append(
                                                        {'devname': self.config[context]['config']['name'],
                                                         'fw_type': self.config[context]['config']['fw_type'],
                                                         'fw_version': self.config[context]['config']['version'],
                                                         'type': 'natPolicyTransDst',
                                                         'policy_name': self.config[context]['nat'][policy]['natPolicyName'],
                                                         'policy_num': self.config[context]['nat'][policy]['natPolicyNum'],
                                                         'policy_uinum': self.config[context]['nat'][policy][
                                                             'natPolicyUiNum'],
                                                         'searchaddress': searchnet,
                                                         'oldaddress': address,
                                                         'newaddress': newaddr})
        # print(change)
        return change

    def cip_audit(self, subnets):

        from netaddr import IPSet
        import os
        from urllib.parse import unquote as url_unquote
        import ipaddress

        searchnets = []
        sourcenets = IPSet([])
        destnets = IPSet([])
        # change = OrderedDict()

        for network in subnets:
            if len(os.path.basename(network)) > 0:
                if os.path.basename(network[0]) == '@':
                    for i in self.file_to_list(network[1:]):
                        if i[0] != '#':
                            searchnets.append(i.rstrip().split(','))
                else:
                    searchnets.append(network.split(','))

        match_id = 0

        for context in self.contexts:
            for policy in self.config[context]['policies']:
                srcmatches = 0
                dstmatches = 0
                src_match_list_old = []
                src_match_list_new = []
                dst_match_list_old = []
                dst_match_list_new = []
                for source in self.config[context]['policies'][policy]['policySrcNet']:
                    for address in self.createNetworkService.expand_address(self.config[context]['addresses'], source,
                                                  self.config[context]['addressmappings'], inc_group=False):
                        if self.config[context]['addresses'][address]['IPv4Networks'][0].prefixlen > 8:
                            for searchnet, newnet in searchnets:
                                if IPSet([str(x) for x in
                                          self.config[context]['addresses'][address]['IPv4Networks']]) & IPSet([searchnet]):
                                    if (address, self.config[context]['addresses'][address][
                                        'IPv4Networks']) not in src_match_list_old:
                                        src_match_list_old.append((address, self.config[context]['addresses'][address][
                                            'addrObjIp1'] + ' - ' + self.config[context]['addresses'][address][
                                                                       'addrObjIp2']))
                                if IPSet([str(x) for x in
                                          self.config[context]['addresses'][address]['IPv4Networks']]) & IPSet([newnet]):
                                    if (address, self.config[context]['addresses'][address][
                                        'IPv4Networks']) not in src_match_list_new:
                                        src_match_list_new.append((address, self.config[context]['addresses'][address][
                                            'addrObjIp1'] + ' - ' + self.config[context]['addresses'][address][
                                                                       'addrObjIp2']))

                for dest in self.config[context]['policies'][policy]['policyDstNet']:
                    for address in self.createNetworkService.expand_address(self.config[context]['addresses'], dest,
                                                  self.config[context]['addressmappings'], inc_group=False):
                        if self.config[context]['addresses'][address]['IPv4Networks'][0].prefixlen > 8:
                            for searchnet, newnet in searchnets:
                                if IPSet([str(x) for x in
                                          self.config[context]['addresses'][address]['IPv4Networks']]) & IPSet([searchnet]):
                                    if (address, self.config[context]['addresses'][address][
                                        'IPv4Networks']) not in dst_match_list_old:
                                        dst_match_list_old.append((address, self.config[context]['addresses'][address][
                                            'addrObjIp1'] + ' - ' + self.config[context]['addresses'][address][
                                                                       'addrObjIp2']))
                                if IPSet([str(x) for x in
                                          self.config[context]['addresses'][address]['IPv4Networks']]) & IPSet([newnet]):
                                    if (address, self.config[context]['addresses'][address][
                                        'IPv4Networks']) not in dst_match_list_new:
                                        dst_match_list_new.append((address, self.config[context]['addresses'][address][
                                            'addrObjIp1'] + ' - ' + self.config[context]['addresses'][address][
                                                                       'addrObjIp2']))

                if src_match_list_old != [] or src_match_list_new != [] or dst_match_list_old != [] or dst_match_list_new != []:
                    self.log(policy, self.config[context]['policies'][policy]['policyName'])
                    self.log('-' * 180)
                    if src_match_list_old != [] or src_match_list_new != []:
                        self.log('Sources')
                        self.log('-' * 180)
                        for match in src_match_list_old:
                            self.log('oldnet:', match)
                        for match in src_match_list_new:
                            self.log('newnet:', match)
                    if dst_match_list_old != [] or dst_match_list_new != []:
                        self.log('Destinations')
                        self.log('-' * 180)
                        for match in dst_match_list_old:
                            self.log('oldnet:', match)
                        for match in dst_match_list_new:
                            self.log('newnet:', match)

    def cip_report2(self, change, showskipped=True):

        ## BEGIN REPORT
        report_width = 100
        if self.options.web: set_web_tab('report')
        policy_matches = OrderedDict()
        for context in self.contexts:
            # policy_matches=OrderedDict()
            for saddr in change[context]['addresses']:
                self.log('++' + '=' * report_width + '++')
                self.log('++   Searched Network Object : {:25.25s}{:45.45s} ++'.format(saddr, ''))
                self.log('++' + '=' * report_width + '++')
                self.log('')
                for faddr in change[context]['addresses'][saddr]:
                    skip_address = faddr['skip'].lower()[0]
                    if skip_address != 'y' or showskipped:
                        oldaddr = faddr['oldaddress']
                        newaddr = faddr['new_addr']
                        self.log('||' + '=' * report_width + '||')
                        self.log('|| Address Match : {:50.50s}{:33.33s}||'.format(url_unquote(oldaddr), ''))
                        self.log('||' + '=' * report_width + '||')
                        self.log('|| {:12.12s} : {:33.33s} {:50.50s}||'.format('Context', faddr['context'], ''))
                        self.log('|| {:12.12s} : {:33.33s} {:50.50s}||'.format('Address Type', faddr['type'], ''))
                        self.log('|| {:12.12s} : {:33.33s} {:50.50s}||'.format('Match Type', faddr['match'], ''))
                        self.log('|| {:12.12s} : {:33.33s} {:50.50s}||'.format('Skipped', str(skip_address == 'y'), ''))
                        self.log('|| {:12.12s} : {:33.33s} {:50.50s}||'.format('In Use Count', str(faddr['inuse']), ''))
                        self.log('|| {:12.12s} : {:49.49s} {:15.15s} - {:15.15s} ||'.format('Old Address',
                                                                                       url_unquote(oldaddr),
                                                                                       faddr['old_ip1'],
                                                                                       faddr['old_ip2']))
                        self.log('|| {:12.12s} : {:49.49s} {:15.15s} - {:15.15s} ||'.format('New Address', newaddr,
                                                                                       faddr['new_ip1'],
                                                                                       faddr['new_ip2']))
                        self.log('||' + '=' * report_width + '||')

                        if oldaddr in change[context]['groups']:
                            self.log('|| Group Matches' + ' ' * (report_width - 14) + '||')
                            self.log('||' + '=' * report_width + '||')
                            for fgaddr in change[context]['groups'][oldaddr]:
                                if newaddr == fgaddr['newmember']:
                                    for match in change[context]['group_policies'][fgaddr['group']]:
                                        self.log('|| {:30.30s} {:30.30s} {:30.30s}{:7.7s}||'.format(
                                            url_unquote(fgaddr['group']),
                                            fgaddr['newmember'],
                                            match,
                                            ''
                                            ))
                                if skip_address != 'y' and fgaddr['fw_type'] == 'checkpoint':
                                    for policy in change[context]['group_policies'][fgaddr['group']]:
                                        if policy not in policy_matches:
                                            policy_matches[policy] = change[context]['group_policies'][fgaddr['group']][
                                                policy]
                            self.log('||' + '=' * report_width + '||')
                        else:
                            self.log('|| No Group Matches' + ' ' * (report_width - 17) + '||')
                            self.log('||' + '=' * report_width + '||')
                        if oldaddr in change[context]['sources'] or oldaddr in change[context]['dests']:
                            self.log('|| Security Policy Matches' + ' ' * (report_width - 24) + '||')
                            self.log('||' + '=' * report_width + '||')
                            if oldaddr in change[context]['sources']:
                                for fpaddr in change[context]['sources'][oldaddr]:
                                    if newaddr == fpaddr['newaddress']:
                                        self.log('|| {:20.20s} {:50.50s} {:7.7s} {:7.7s} {:11.11s}||'.format(fpaddr['type'],
                                                                                                        fpaddr[
                                                                                                            'policy_name'],
                                                                                                        str(fpaddr[
                                                                                                                'policy_num']),
                                                                                                        str(fpaddr[
                                                                                                                'policy_uinum']),
                                                                                                        ''
                                                                                                        ))
                                        if (skip_address != 'y' or showskipped) and fpaddr['fw_type'] == 'checkpoint':
                                            if fpaddr['policy_name'] not in policy_matches:
                                                policy_matches[fpaddr['policy_name']] = [
                                                    (fpaddr['policy_uinum'], fpaddr['policy_num'])]
                                            elif (fpaddr['policy_uinum'], fpaddr['policy_num']) not in policy_matches[
                                                fpaddr['policy_name']]:
                                                policy_matches[fpaddr['policy_name']].append(
                                                    (fpaddr['policy_uinum'], fpaddr['policy_num']))
                            if oldaddr in change[context]['dests']:
                                for fpaddr in change[context]['dests'][oldaddr]:
                                    if newaddr == fpaddr['newaddress']:
                                        self.log('|| {:20.20s} {:50.50s} {:7.7s} {:7.7s} {:11.11s}||'.format(fpaddr['type'],
                                                                                                        fpaddr[
                                                                                                            'policy_name'],
                                                                                                        str(fpaddr[
                                                                                                                'policy_num']),
                                                                                                        str(fpaddr[
                                                                                                                'policy_uinum']),
                                                                                                        ''
                                                                                                        ))
                                        if (skip_address != 'y' or showskipped) and fpaddr['fw_type'] == 'checkpoint':
                                            if fpaddr['policy_name'] not in policy_matches:
                                                policy_matches[fpaddr['policy_name']] = [
                                                    (fpaddr['policy_uinum'], fpaddr['policy_num'])]
                                            elif (fpaddr['policy_uinum'], fpaddr['policy_num']) not in policy_matches[
                                                fpaddr['policy_name']]:
                                                policy_matches[fpaddr['policy_name']].append(
                                                    (fpaddr['policy_uinum'], fpaddr['policy_num']))
                            self.log('||' + '=' * report_width + '||')
                        else:
                            self.log('|| NO Security Policy Matches' + ' ' * (report_width - 27) + '||')
                            self.log('||' + '=' * report_width + '||')
                        if oldaddr in change[context]['nat']:
                            self.log('|| NAT Policy Matches' + ' ' * (report_width - 19) + '||')
                            self.log('||' + '=' * report_width + '||')
                            for fnaddr in change[context]['nat'][oldaddr]:
                                if newaddr == fnaddr['newaddress']:
                                    self.log('|| {:20.20s} {:50.50s} {:7.7s} {:7.7s} {:11.11s}||'.format(fnaddr['type'],
                                                                                                    fnaddr[
                                                                                                        'policy_name'],
                                                                                                    str(fnaddr[
                                                                                                            'policy_num']),
                                                                                                    str(fnaddr[
                                                                                                            'policy_uinum']),
                                                                                                    ''
                                                                                                    ))
                                    if (skip_address != 'y' or showskipped) and fnaddr['fw_type'] == 'checkpoint':
                                        if fnaddr['policy_name'] not in policy_matches:
                                            policy_matches[fnaddr['policy_name']] = [
                                                (fnaddr['policy_uinum'], fnaddr['policy_num'])]
                                        elif (fnaddr['policy_uinum'], fnaddr['policy_num']) not in policy_matches[
                                            fnaddr['policy_name']]:
                                            policy_matches[fnaddr['policy_name']].append(
                                                (fnaddr['policy_uinum'], fnaddr['policy_num']))
                            self.log('||' + '=' * report_width + '||')
                        else:
                            self.log('|| NO NAT Policy Matches' + ' ' * (report_width - 22) + '||')
                            self.log('||' + '=' * report_width + '||')
                        self.log('')
        self.log('||' + '=' * (report_width + 40) + '||')
        self.log('|| Effected Policies' + ' ' * (report_width + 22) + '||')
        self.log('||' + '=' * (report_width + 40) + '||')

        if len(policy_matches) > 0:
            # self.log('|| Policy Nums' + ' ' * (report_width+28) + '||')
            col1_size = len(max(policy_matches, key=len))
            col2_size = 136 - col1_size
            for match in policy_matches:
                self.log('|| {:<{col1_size}} : {:<{col2_size}}||'.format(match, ', '.join(
                    [str(num) for uinum, num in policy_matches[match]]), col1_size=col1_size, col2_size=col2_size))
            self.log('||' + '=' * (report_width + 40) + '||')
            self.log('|| Policy UI Nums' + ' ' * (report_width + 25) + '||')
            for match in policy_matches:
                self.log('|| {:<{col1_size}} : {:<{col2_size}}||'.format(match, ', '.join(
                    [str(uinum) for uinum, num in policy_matches[match]]), col1_size=col1_size, col2_size=col2_size))
        else:
            self.log('|| NONE' + ' ' * (report_width + 35) + '||')
        self.log('||' + '=' * (report_width + 40) + '||')
        return

    def cip_match_reviewout(self, change, filename=''):
        if self.options.web: set_web_tab('reviewout')
        self.log('#context,type,matchtype,mID,searchaddress,oldaddress,old_addr1,old_addr2,new_addr,new_ip1,new_ip2,old_color,new_color,comment,use_count,skip,DO_NOT_CHANGE')
        if self.options.web: self.log('## https://10.215.19.133/lab/cgi-bin/migrate.py?Submit=true&cipsubmit=' + timestr)
        for context in change:
            for saddr in change[context]['addresses']:
                for index, faddr in enumerate(change[context]['addresses'][saddr]):
                    self.log('{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{}'.format(
                        context,
                        faddr['type'],
                        faddr['match'],
                        faddr['match_id'],
                        faddr['searchaddress'],
                        faddr['oldaddress'],
                        faddr['old_ip1'],
                        faddr['old_ip2'],
                        faddr['new_addr'],
                        faddr['new_ip1'],
                        faddr['new_ip2'],
                        faddr['oldcolor'],
                        change[context]['colors'][faddr['new_addr']]['color'],
                        faddr['comment'],
                        faddr['inuse'],
                        faddr['skip'],
                        str(index)))
        return

    def cip_match_reviewin(self, filename, change, matchesonly=False):

        ## consider updating routines to
        import copy
        # newchanges=copy.deepcopy(changes)

        with open(filename, 'r') as infile:
            for line in infile:
                if line[0] != '#':
                    try:
                        context, addrtype, match, mID, searchaddress, oldaddress, old_ip1, old_ip2, new_addr, new_ip1, new_ip2, oldcolor, color, comment, usecount, skip, index = line.strip().split(
                            ',')
                    except:
                        try:
                            context, addrtype, match, mID, searchaddress, oldaddress, old_ip1, old_ip2, new_addr, new_ip1, new_ip2, oldcolor, color, comment, usecount, skip, index = line.strip().split(
                                '\t')
                        except:
                            self.log('Error parsing infile')
                            return False
                    self.log('{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{}'.format(context, addrtype, match, mID,
                                                                                    searchaddress, oldaddress, old_ip1,
                                                                                    old_ip2, new_addr, new_ip1, new_ip2,
                                                                                    oldcolor, color, comment, usecount,
                                                                                    skip, index))

                    if context != None:
                        if searchaddress in change[context]['addresses']:
                            if change[context]['addresses'][searchaddress][int(index)]['comment'] != comment:
                                self.log('Replacing Comment {} with {}'.format(
                                    change[context]['addresses'][searchaddress][int(index)]['comment'], comment))
                                change[context]['addresses'][searchaddress][int(index)]['comment'] = comment
                            if change[context]['addresses'][searchaddress][int(index)]['skip'] != skip:
                                self.log('Replacing Skip {} with {}'.format(
                                    change[context]['addresses'][searchaddress][int(index)]['skip'], skip))
                                change[context]['addresses'][searchaddress][int(index)]['skip'] = skip
                            if change[context]['addresses'][searchaddress][int(index)]['color'] != color:
                                self.log('Replacing Color {} with {}'.format(
                                    change[context]['addresses'][searchaddress][int(index)]['color'], color))
                                change[context]['addresses'][searchaddress][int(index)]['color'] = color

                            if int(index) < len(change[context]['addresses'][searchaddress]):
                                if change[context]['addresses'][searchaddress][int(index)]['new_addr'] != new_addr:
                                    self.log('Replacing New Address Name {} with {}'.format(
                                        change[context]['addresses'][searchaddress][int(index)]['new_addr'], new_addr))
                                    change[context]['addresses'][searchaddress][int(index)]['new_addr'] = new_addr
                                    ## update polices and groups
                                    for oldaddr in change[context]['groups']:
                                        for index, match in enumerate(change[context]['groups'][oldaddr]):
                                            if match['oldmember'] == oldaddress:
                                                change[context]['groups'][oldaddr][index]['newmember'] = new_addr
                                                self.log('Updating group {} with address {}'.format(match['group'],
                                                                                               new_addr))
                                    for oldaddr in change[context]['sources']:
                                        for index, match in enumerate(change[context]['sources'][oldaddr]):
                                            if match['oldaddress'] == oldaddress:
                                                change[context]['sources'][oldaddr][index]['newaddress'] = new_addr
                                                self.log('Updating rule {} in policy {} with address {}'.format(
                                                    match['policy_name'], match['policy_num'], new_addr))
                                    for oldaddr in change[context]['dests']:
                                        for index, match in enumerate(change[context]['dests'][oldaddr]):
                                            if match['oldaddress'] == oldaddress:
                                                change[context]['dests'][oldaddr][index]['newaddress'] = new_addr
                                                self.log('Updating rule {} in policy {} with address {}'.format(
                                                    match['policy_name'], match['policy_num'], new_addr))
                                    for oldaddr in change[context]['nat']:
                                        for index, match in enumerate(change[context]['nat'][oldaddr]):
                                            if match['oldaddress'] == oldaddress:
                                                change[context]['nat'][oldaddr][index]['newaddress'] = new_addr
                                                self.log('Updating rule {} in policy {} with address {}'.format(
                                                    match['policy_name'], match['policy_num'], new_addr))
            return change

    def get_fw_type(self, ipaddress):

        import requests
        import re

        session = requests.Session()
        session.mount(ipaddress, DESAdapter())
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
        try:
            response = session.get('https://' + ipaddress, verify=False, stream=True, timeout=self.options.timeout_sw_webui,
                                   allow_redirects=False)
            if response.status_code == 302:
                # print('302 returned')
                if response.headers['Location'].lower() == '/php/login.php':
                    # unable to distinguish between palo and pano via login.php content
                    fw_type = 'palo'
                else:
                    fw_type = 'unknown'
            elif len(re.findall('SonicWALL', response.text)) > 0:
                fw_type = 'sonicwall'
            elif len(re.findall('<TITLE>Gaia</TITLE>', response.text)) > 0:
                fw_type = 'checkpoint'
            else:
                fw_type = 'unknown'
            # if fw_type=='unknown':
            #    print(response.text)
        except Exception as e:
            # print(e)
            fw_type = 'unknown'

        return fw_type

    def cip_match_dbedit(self, change, target='', syntax='cli', showresults=False):

        import copy
        import urllib

        for context in change:
            if len(change[context]['addresses']) > 0:
                self.log('#### Context: ' + context)
                self.debug(len(change[context]['addresses']))
            change[context]['colors'] = OrderedDict()
            for saddr in change[context]['addresses']:  ## these routines are to update the color dictionary
                for faddr in change[context]['addresses'][saddr]:
                    if faddr['skip'].lower()[0] != 'y':
                        naddr = faddr['new_addr']
                        if naddr not in change[context]['colors']:
                            change[context]['colors'][naddr] = {}
                            change[context]['colors'][naddr]['color'] = faddr['color']
                            change[context]['colors'][naddr]['matchlen'] = faddr['matchlen']
                        if int(self.netmask_to_cidr(faddr['old_ip2'])) > change[context]['colors'][naddr]['matchlen'] and \
                                faddr['inuse'] > 0:
                            change[context]['colors'][naddr]['color'] = faddr['color']
                            change[context]['colors'][naddr]['matchlen'] = int(self.netmask_to_cidr(faddr['old_ip2']))

            dbedit = []
            added_addresses = []

            for saddr in change[context]['addresses']:
                for foundaddr in change[context]['addresses'][saddr]:
                    faddr_copy = copy.deepcopy(foundaddr)
                    faddr_copy.pop('oldmember', None)
                    if foundaddr['skip'][0].lower() != 'y' and faddr_copy not in dbedit:
                        oldaddr = foundaddr['oldaddress']
                        newaddr = foundaddr['new_addr']
                        dbcolor = change[context]['colors'][newaddr]['color']
                        if str(foundaddr['new_ip1']) == '255.255.255.255':
                            self.debug('Skipping found address of {}'.format(oldaddr))
                        else:
                            if foundaddr['new_addr'] not in added_addresses:
                                self.debug(change[context]['fw_type'])
                                result = self.exec_fw_command(target, change[context]['fw_type'], [('create_address', {
                                    'addressname': foundaddr['new_addr'], 'ip1': str(foundaddr['new_ip1']),
                                    'ip2': str(foundaddr['new_ip2']), 'addresstype': foundaddr['type'],
                                    'zone': foundaddr['zone'], 'color': dbcolor, 'comment': foundaddr['comment']})],
                                                         syntax=syntax)
                                added_addresses.append(foundaddr['new_addr'])
                                if showresults: self.log('Create Address {}: {}'.format(foundaddr['new_addr'], result))
                            # if len (change[context]['groups'][oldaddr])>0:
                            if oldaddr in change[context]['groups']:
                                for faddr in change[context]['groups'][oldaddr]:
                                    faddr_copy = copy.deepcopy(faddr)
                                    faddr_copy.pop('oldmember', None)
                                    if newaddr == faddr['newmember']:
                                        if faddr_copy not in dbedit:
                                            dbedit.append(faddr_copy)
                                            # result=modify_rule_obj(target, session, apikey, fw_type, syntax, params)
                                            result = self.exec_fw_command(target, change[context]['fw_type'], [(
                                                                                                          'modify_address',
                                                                                                          {
                                                                                                              'action': 'addmembers',
                                                                                                              'addressname':
                                                                                                                  faddr[
                                                                                                                      'group'],
                                                                                                              'members': [
                                                                                                                  faddr[
                                                                                                                      'newmember']]})],
                                                                     syntax=syntax)
                                            if showresults: self.log(
                                                'Add Address {} to group {}: {}'.format(faddr['newmember'],
                                                                                        faddr['group'], result))

                            if oldaddr in change[context]['sources'] or oldaddr in change[context]['dests']:
                                if oldaddr in change[context]['sources']:
                                    for faddr in change[context]['sources'][oldaddr]:
                                        faddr_copy = copy.deepcopy(faddr)
                                        faddr_copy.pop('searchaddress', None)
                                        if newaddr == faddr['newaddress']:
                                            if faddr_copy not in dbedit:
                                                dbedit.append(faddr_copy)
                                                # exec_fw_command(target, change[context]['fw_type'], [('modify_address', {'action': 'addmember', 'addressname': 'test_group', 'members': [faddr['newmember']]})], syntax='cli')
                                                result = self.exec_fw_command(target, change[context]['fw_type'], [(
                                                                                                              'modify_rule',
                                                                                                              {
                                                                                                                  'context': context,
                                                                                                                  'policyname':
                                                                                                                      faddr[
                                                                                                                          'policy_name'],
                                                                                                                  'policynum': str(
                                                                                                                      faddr[
                                                                                                                          'policy_num']),
                                                                                                                  'action': 'addmembers',
                                                                                                                  'sources': [
                                                                                                                      faddr[
                                                                                                                          'newaddress']]})],
                                                                         syntax=syntax)
                                                if showresults: self.log('Add Address {} to Source in Rule {}: {}'.format(
                                                    faddr['newaddress'], str(faddr['policy_num']), result))
                                                # modify_rule_obj(target, session, apikey, fw_type, syntax, params)
                                if oldaddr in change[context]['dests']:
                                    for faddr in change[context]['dests'][oldaddr]:
                                        faddr_copy = copy.deepcopy(faddr)
                                        faddr_copy.pop('searchaddress', None)
                                        if newaddr == faddr['newaddress']:
                                            if faddr_copy not in dbedit:
                                                dbedit.append(faddr_copy)
                                                result = self.exec_fw_command(target, change[context]['fw_type'], [(
                                                                                                              'modify_rule',
                                                                                                              {
                                                                                                                  'context': context,
                                                                                                                  'policyname':
                                                                                                                      faddr[
                                                                                                                          'policy_name'],
                                                                                                                  'policynum': str(
                                                                                                                      faddr[
                                                                                                                          'policy_num']),
                                                                                                                  'action': 'addmembers',
                                                                                                                  'dests': [
                                                                                                                      faddr[
                                                                                                                          'newaddress']]})],
                                                                         syntax=syntax)
                                                if showresults: self.log(
                                                    'Add Address {} to Destination in Rule {}: {}'.format(
                                                        faddr['newaddress'], str(faddr['policy_num']), result))

                            if oldaddr in change[context]['nat']:
                                for faddr in change[context]['nat'][oldaddr]:
                                    faddr_copy = copy.deepcopy(faddr)
                                    faddr_copy.pop('oldaddress', None)
                                    if newaddr == faddr['newaddress']:
                                        if faddr_copy not in dbedit:
                                            dbedit.append(faddr_copy)
                                            if faddr['type'] == 'natPolicyOrigSrc':
                                                if change[context]['fw_type'] == 'checkpoint':
                                                    ## for this just remove the old element and add the new one
                                                    self.log("#rmelement fw_policies {} rule_adtr:{}:src_adtr network_objects:{}".format(
                                                        faddr['policy_name'], str(faddr['policy_num']), oldaddr))
                                                    self.log("#addelement fw_policies {} rule_adtr:{}:src_adtr network_objects:{}".format(
                                                        faddr['policy_name'], str(faddr['policy_num']),
                                                        faddr['newaddress']))
                                                    # self.log("modify fw_policies " + faddr['policy_name'] + " rule_adtr:" + str(faddr['policy_num']) + ":src_adtr:'' network_objects:" + faddr['newaddress'])
                                                elif change[context]['fw_type'] == 'sonicwall':
                                                    self.log('change nat policy placeholder')
                                                elif change[context]['fw_type'] == 'panorama':
                                                    self.log('change nat policy placeholder')
                                            if faddr['type'] == 'natPolicyOrigDst':
                                                if change[context]['fw_type'] == 'checkpoint':
                                                    ## for this just remove the old element and add the new one
                                                    self.log("#rmelement fw_policies {} rule_adtr:{}:dst_adtr network_objects:{}".format(
                                                        faddr['policy_name'], str(faddr['policy_num']), oldaddr))
                                                    self.log("#addelement fw_policies {} rule_adtr:{}:dst_adtr network_objects:{}".format(
                                                        faddr['policy_name'], str(faddr['policy_num']),
                                                        faddr['newaddress']))
                                                    # self.log("modify fw_policies " + faddr['policy_name'] + " rule_adtr:" + str(faddr['policy_num']) + ":dst_adtr:'' network_objects:" + faddr['newaddress'])
                                                elif change[context]['fw_type'] == 'sonicwall':
                                                    self.log('change nat policy placeholder')
                                                elif change[context]['fw_type'] == 'panorama':
                                                    self.log('change nat policy placeholder')
                                            if faddr['type'] == 'natPolicyNewSrc':
                                                if change[context]['fw_type'] == 'checkpoint':
                                                    ## for this, a temp object needs to be created..
                                                    ## https://www.mail-archive.com/fw-1-mailinglist@amadeus.us.checkpoint.com/msg22701.html
                                                    '''
                                                    I also need to get the address translation type...
                                                    create $type tmp_name
                                                    modify owned tmp_name '' $valuenetwork:objects:faddr['newaddress']
                                                    add_owned_remove_name fw_policies faddr['policy_name']  rule_adtr:str(faddr['policy_num']):dst|src_adtr_translated owned:tmp_name
                                                    delete owned tmp_name

                                                    Where $type is obviously the type of the owned object, these are one of:
                                                            service_translate
                                                            translate_hide
                                                            translate_static

                                                    So you essentially chose the translation method by the "type" of the owned
                                                    object (for src or dst. service is always service_translate).

                                                    $field - Well, in my code $field is always \'\' (ie. two quoted
                                                    apostrophies, though you may well not need to quote them (so just '').

                                                    $value is the actual either a service (service:foo) which is of course only
                                                    valid if the type is service_translate, a network object
                                                    (network_objects:foo) for the other two or a global, like global:Any, which
                                                    works in all of them.

                                                    $prefix is what you're adding it to, and would be *one* of:
                                                            fw_policies ##New rule_adtr:0:service_adtr_translated
                                                            fw_policies ##New rule_adtr:0:dst_adtr_translated
                                                            fw_policies ##New rule_adtr:0:src_adtr_translated
                                                    '''
                                                    self.log("modify fw_policies " + faddr[
                                                        'policy_name'] + " rule_adtr:" + str(faddr[
                                                                                                 'policy_num']) + ":src_adtr_translated:'' network_objects:" +
                                                        faddr['newaddress'])
                                                elif change[context]['fw_type'] == 'sonicwall':
                                                    self.log('change nat policy placeholder')
                                                elif change[context]['fw_type'] == 'panorama':
                                                    self.log('change nat policy placeholder')
                                            if faddr['type'] == 'natPolicyNewDst':
                                                if change[context]['fw_type'] == 'checkpoint':
                                                    self.log("modify fw_policies " + faddr[
                                                        'policy_name'] + " rule_adtr:" + str(faddr[
                                                                                                 'policy_num']) + ":dst_adtr_translated:'' network_objects:" +
                                                        faddr['newaddress'])
                                                elif change[context]['fw_type'] == 'sonicwall':
                                                    self.log('change nat policy placeholder')
                                                elif change[context]['fw_type'] == 'panorama':
                                                    self.log('change nat policy placeholder')
        return

    def remove_dupes(self, duplicates, context):  ## pass in context name

        replacements = 0
        exist_count = 0

        self.log("!-- Renaming Duplicate Objects in Policies")

        for index in self.config[context]['policies']:
            for dupe in duplicates['addresses']:
                if dupe in self.config[context]['policies'][index]['policySrcNet']:
                    replacements += 1
                    self.config[context]['policies'][index]['policySrcNet'].remove(dupe)
                    self.config[context]['policies'][index]['policySrcNet'].append(duplicates['addresses'][dupe])
                if dupe in self.config[context]['policies'][index]['policyDstNet']:
                    replacements += 1
                    self.config[context]['policies'][index]['policyDstNet'].remove(dupe)
                    self.config[context]['policies'][index]['policyDstNet'].append(duplicates['addresses'][dupe])
            for dupe in duplicates['services']:

                if dupe in self.config[context]['policies'][index]['policyDstSvc']:
                    replacements += 1
                    self.config[context]['policies'][index]['policyDstSvc'].remove(dupe)
                    self.config[context]['policies'][index]['policyDstSvc'].append(duplicates['services'][dupe])

        self.log("!-- Renaming Duplicate Objects in Address Mappings")

        for map in self.config[context]['addressmappings']:
            for dupe in duplicates['addresses']:
                if dupe in self.config[context]['addressmappings'][map]:
                    replacements += 1
                    self.log('ADDRMAP: Replacing {:30.30s} with {:30.30s}'.format(dupe, duplicates['addresses'][dupe],
                                                                             level=self.logging.INFO))
                    self.config[context]['addressmappings'][map].remove(dupe)
                    self.config[context]['addressmappings'][map].append(duplicates['addresses'][dupe])

        self.log("!-- Renaming Duplicate Objects in Service Mappings")

        for map in self.config[context]['servicemappings']:
            for dupe in duplicates['services']:
                if dupe in self.config[context]['servicemappings'][map]:
                    replacements += 1
                    self.log('SVCMAP: Replacing {:30.30s} with {:30.30s} in {:30.30s}'.format(dupe,
                                                                                         duplicates['services'][dupe],
                                                                                         map), level=self.logging.INFO)
                    self.config[context]['servicemappings'][map].remove(dupe)
                    self.config[context]['servicemappings'][map].append(duplicates['services'][dupe])

        self.log("!-- Renaming Duplicate Objects in Routing Objects")

        ## Routing policy Src/Dst is not currently a list, do I need to change this? CHANGEME
        for index in self.config[context]['routing']:
            for dupe in duplicates['addresses']:
                if dupe in self.config[context]['routing'][index]['pbrObjSrc']:
                    replacements += 1
                    self.config[context]['routing'][index]['pbrObjSrc'].remove(dupe)
                    self.config[context]['routing'][index]['pbrObjSrc'].append(duplicates['addresses'][dupe])
                if dupe in self.config[context]['routing'][index]['pbrObjDst']:
                    replacements += 1
                    self.config[context]['routing'][index]['pbrObjDst'].remove(dupe)
                    self.config[context]['routing'][index]['pbrObjDst'].append(duplicates['addresses'][dupe])
                if dupe in self.config[context]['routing'][index]['pbrObjGw']:
                    replacements += 1
                    self.config[context]['routing'][index]['pbrObjGw'].remove(dupe)
                    self.config[context]['routing'][index]['pbrObjGw'].append(duplicates['addresses'][dupe])

        # Remove duplicates from address and service objects and mappings

        self.log("!-- Removing Duplicate Address and Service Objects")

        tmpaddr = OrderedDict()
        tmpaddrmap = OrderedDict()

        for index in self.config[context]['addresses']:
            dupefound = False
            for dupe in duplicates['addresses']:
                if dupe == index:
                    dupefound = True;
                    break;
            if not dupefound:
                tmpaddr[index] = self.config[context]['addresses'][index]
        self.config[context]['addresses'] = tmpaddr

        for index in self.config[context]['addressmappings']:
            dupefound = False
            for dupe in duplicates['addresses']:
                if dupe == index:
                    dupefound = True;
                    break;
            if not dupefound:
                tmpaddrmap[index] = self.config[context]['addressmappings'][index]
        self.config[context]['addressmappings'] = tmpaddrmap

        tmpsvc = OrderedDict()
        tmpsvcmap = OrderedDict()

        for index in self.config[context]['services']:
            dupefound = False
            for dupe in duplicates['services']:
                if dupe == index:
                    dupefound = True;
                    break;
            if not dupefound:
                tmpsvc[index] = self.config[context]['services'][index]
        self.config[context]['services'] = tmpsvc

        for index in self.config[context]['servicemappings']:
            dupefound = False
            for dupe in duplicates['services']:
                if dupe == index:
                    dupefound = True;
                    break;
            if not dupefound:
                tmpsvcmap[index] = self.config[context]['servicemappings'][index]
        self.config[context]['servicmappings'] = tmpsvcmap

        return replacements;

    def inverse_rule_cleanup(self, inverse_results, matching='complete'):

        from urllib.parse import quote as url_quote, unquote as url_unquote
        import re

        panohostip = '%PANOIP%'
        userkey = '%APIKEY%'
        inverse_stats = OrderedDict()

        inverse_cmds = ([])
        inverse_newcmds = ([])
        if self.options.inversedisable:
            if self.options.web: set_web_tab('disable')
            self.log('!-- Disabling Inverse Policy Matches')
        if self.options.inversedelete:
            if self.options.web: set_web_tab('delete')
            self.log('!-- Deleting Inverse Policy Matches')

        for context in self.contexts:
            self.log('-' * 150)
            inverse_stats[context] = [0, 0, 0, 0]  # disabled, deleted, skipped-notall, skipped-notdisablde
            self.log('Context  : ' + context)
            self.log('Firewall : ' + self.config[context]['config']['name'])
            self.log('Mgmt IP  : ' + str(self.config[context]['config']['mgmtip']))
            num = 0
            for match in inverse_results[context]['policies']:
                if match['action'].lower() != 'allow': inverse_stats[context][2] += 1
                if match['enabled'] == False: inverse_stats[context][3] += 1
                if (match['action'].lower() == 'allow' or self.options.inverseallrules) and (self.options.inversedisable or match[
                    'enabled'] == False):  # perform checking only for "allow" rules, for all objects in disable mode, enabled rules only in delete mode
                    if match['source_match'] == 'complete' or match[
                        'dest_match'] == 'complete' or self.options.inversepartial:
                        self.log('-' * 150)
                        self.log('Context      : ' + context)
                        if match['fw_type'] == 'checkpoint':
                            self.log('Policy Name  : ' + match['name'])
                        else:
                            self.log('Rule Name    : ' + match['name'])
                        self.log('Rule Comment : ' + match['comment'])
                        self.log('Rule Enabled : ' + str(match['enabled']))
                        self.log('{:15.15s} {:60.60s} {:60.60s}'.format('', 'Source', 'Destination'))
                        self.log('{:15.15s} {:60.60s} {:60.60s}'.format('Match Type', match['source_match'],
                                                                   match['dest_match']))
                        self.log('{:15.15s} {:60.60s} {:60.60s}'.format('Zone', match['source_zone'], match['dest_zone']))
                        if match['fw_type'] == 'sonicwall': self.log(
                            '{:15.15s} {:60.60s} {:60.60s}'.format('Address Type', match['source_type'],
                                                                   match['dest_type']))
                        if len(match['source_list']) > len(match['dest_list']):
                            num_obj = len(match['source_list'])
                        else:
                            num_obj = len(match['dest_list'])
                        for idx in range(num_obj):
                            src = ''
                            dst = ''
                            if idx < len(match['source_list']): src = match['source_list'][idx]
                            if idx < len(match['dest_list']): dst = match['dest_list'][idx]
                            if idx == 0:
                                self.log('{:15.15s} {:60.60s} {:60.60s}'.format('Address', src, dst))
                            else:
                                self.log('{:15.15s} {:60.60s} {:60.60s}'.format('', src, dst))
                        self.log('{:15.15s} {:60.60s}'.format('Service', url_unquote(match['dest_service']), ''))

                        if match['source_type'].lower() == 'any':
                            src_str = 'any'
                        elif match['source_type'].lower() in ['range', 'network',
                                                              'host']:  # despite "range" and "network" being keywords in the CLI, these objects seem to use the "name" keyword instead (in 6.1.1.7 anyhow)
                            src_str = 'name "' + self.ss(match['source_addr']) + '"'
                        else:
                            src_str = match['source_type'] + ' "' + url_unquote(match['source_addr']) + '"'

                        if match['dest_type'].lower() == 'any':
                            dst_str = 'any'
                        elif match['dest_type'].lower() in ['range', 'network',
                                                            'host']:  # despite "range" and "network" being keywords in the CLI, these objects seem to use the "name" keyword instead (in 6.1.1.7 anyhow)
                            dst_str = 'name "' + self.ss(match['dest_addr']) + '"'
                        else:
                            dst_str = match['dest_type'] + ' "' + url_unquote(match['dest_addr']) + '"'

                        if match['service_type'].lower() == 'any':
                            svc_str = 'any'
                        else:
                            svc_str = match['service_type'] + ' "' + url_unquote(match['dest_service']) + '"'

                        if match['source_match'] != 'none':
                            for addr in match['source_list']:
                                self.log('-' * 150)
                                self.log('Source Address Object : ' + addr)
                                self.log('-' * 150)
                                for context, parent, name, address in self.search_address([addr], [context]):
                                    self.log('{:60.60s} {:60.60s}'.format(name, address))
                        if match['dest_match'] != 'none':
                            self.log('-' * 150)
                            self.log('Destination Address Object : ' + match['dest_addr'])
                            self.log('-' * 150)
                            for context, parent, name, address in self.search_address([match['dest_addr']], [context]):
                                self.log('{:60.60s} {:60.60s}'.format(name, address))
                        self.log('-' * 150)

                        if match['fw_type'].lower() == 'sonicwall':  ## changeme - use config/context/config/fw_type
                            if len(match['source_addr']) > 38 or len(match[
                                                                         'dest_addr']) > 38:  # sonicwall has an issue with address name params >38 chars long on CLI
                                self.log('**', end='')
                            if self.options.inversedisable:
                                inverse_newcmds.append(
                                    {'num': num, 'fw_type': 'sonicwall', 'fw_ip': self.config[context]['config']['mgmtip'],
                                     'fw_version': match['fw_version'], 'rule-action': 'disable', 'matchtype': 'rule',
                                     'srczone': match['source_zone'], 'dstzone': match['dest_zone'],
                                     'action': match['action'], 'source': src_str, 'dest': dst_str, 'service': svc_str,
                                     'device_group': context, 'rule_num': match['rule_num'], 'ui_num': match['ui_num'],
                                     'policy_name': match['name']})
                                num += 1
                                inverse_stats[context][0] += 1
                            else:
                                inverse_newcmds.append(
                                    {'num': num, 'fw_type': 'sonicwall', 'fw_ip': self.config[context]['config']['mgmtip'],
                                     'fw_version': match['fw_version'], 'rule-action': 'delete', 'matchtype': 'rule',
                                     'srczone': match['source_zone'], 'dstzone': match['dest_zone'],
                                     'action': match['action'], 'source': src_str, 'dest': dst_str, 'service': svc_str,
                                     'device_group': context, 'rule_num': match['rule_num'], 'ui_num': match['ui_num'],
                                     'policy_name': match['name']})
                                num += 1
                                inverse_stats[context][1] += 1
                        elif match['fw_type'].lower() == 'checkpoint':
                            if self.options.inversedisable:
                                inverse_newcmds.append(
                                    {'num': num, 'fw_type': 'checkpoint', 'fw_ip': self.config[context]['config']['mgmtip'],
                                     'fw_version': match['fw_version'], 'rule-action': 'disable', 'matchtype': 'rule',
                                     'srczone': match['source_zone'], 'dstzone': match['dest_zone'],
                                     'action': match['action'], 'source': src_str, 'dest': dst_str, 'service': svc_str,
                                     'device_group': context, 'rule_num': match['rule_num'], 'ui_num': match['ui_num'],
                                     'policy_name': match['name']})
                                num += 1
                                inverse_stats[context][0] += 1
                            else:
                                inverse_newcmds.append(
                                    {'num': num, 'fw_type': 'checkpoint', 'fw_ip': self.config[context]['config']['mgmtip'],
                                     'fw_version': match['fw_version'], 'rule-action': 'delete', 'matchtype': 'rule',
                                     'srczone': match['source_zone'], 'dstzone': match['dest_zone'],
                                     'action': match['action'], 'source': src_str, 'dest': dst_str, 'service': svc_str,
                                     'device_group': context, 'rule_num': match['rule_num'], 'ui_num': match['ui_num'],
                                     'policy_name': match['name']})
                                num += 1
                                inverse_stats[context][1] += 1
                        elif match['fw_type'].lower() == 'panorama':  ## assume firewall type is panorama
                            if self.options.inversedisable:
                                inverse_stats[context][0] += 1
                                num += 1
                                inverse_newcmds.append(
                                    {'num': num, 'fw_type': 'panorama', 'fw_ip': self.config[context]['config']['mgmtip'],
                                     'fw_version': match['fw_version'], 'rule-action': 'disable', 'matchtype': 'rule',
                                     'srczone': match['source_zone'], 'dstzone': match['dest_zone'],
                                     'action': match['action'], 'source': url_unquote(match['source_addr']),
                                     'dest': url_unquote(match['dest_addr']),
                                     'service': url_unquote(match['dest_service']), 'device_group': context,
                                     'rule_name': match['name'], 'rule_num': match['rule_num']})
                            else:
                                inverse_stats[context][1] += 1
                                num += 1
                                inverse_newcmds.append(
                                    {'num': num, 'fw_type': 'panorama', 'fw_ip': self.config[context]['config']['mgmtip'],
                                     'fw_version': match['fw_version'], 'rule-action': 'delete', 'matchtype': 'rule',
                                     'srczone': match['source_zone'], 'dstzone': match['dest_zone'],
                                     'action': match['action'], 'source': url_unquote(match['source_addr']),
                                     'dest': url_unquote(match['dest_addr']),
                                     'service': url_unquote(match['dest_service']), 'device_group': context,
                                     'rule_name': match['name'], 'rule_num': match['rule_num']})
                        elif match['fw_type'].lower() == 'paloalto':
                            if self.options.inversedisable:
                                inverse_stats[context][0] += 1
                                num += 1
                                inverse_newcmds.append(
                                    {'num': num, 'fw_type': 'paloalto', 'fw_ip': self.config[context]['config']['mgmtip'],
                                     'fw_version': match['fw_version'], 'rule-action': 'disable', 'matchtype': 'rule',
                                     'srczone': match['source_zone'], 'dstzone': match['dest_zone'],
                                     'action': match['action'], 'source': url_unquote(match['source_addr']),
                                     'dest': url_unquote(match['dest_addr']),
                                     'service': url_unquote(match['dest_service']), 'device_group': context,
                                     'rule_name': match['name'], 'rule_num': match['rule_num']})
                            else:
                                inverse_stats[context][1] += 1
                                num += 1
                                inverse_newcmds.append(
                                    {'num': num, 'fw_type': 'paloalto', 'fw_ip': self.config[context]['config']['mgmtip'],
                                     'fw_version': match['fw_version'], 'rule-action': 'delete', 'matchtype': 'rule',
                                     'srczone': match['source_zone'], 'dstzone': match['dest_zone'],
                                     'action': match['action'], 'source': url_unquote(match['source_addr']),
                                     'dest': url_unquote(match['dest_addr']),
                                     'service': url_unquote(match['dest_service']), 'device_group': context,
                                     'rule_name': match['name'], 'rule_num': match['rule_num']})
                        elif context.lower() == 'shared':  # SHOULD NO LONGER BE NEEDED - REMOVE
                            pass
                            self.log(re.sub(r'&key=.*', '%APIKEY%', request), level=self.logging.INFO)
                            if self.options.inversedisable:
                                pass
                            else:
                                pass
                        self.log('\r\n')
        return inverse_newcmds, inverse_stats

    def inverse_address_cleanup(self, inverse_results, matching='complete', skipshared=True):

        from urllib.parse import quote as url_quote, unquote as url_unquote
        import re

        if self.options.web: set_web_tab('address')
        panohostip = '%PANOIP%'
        userkey = '%APIKEY%'
        inverse_stats = OrderedDict()

        inverse_cmds = ([])
        inverse_newcmds = ([])
        inverse_revcmds = ([])
        self.log('!-- Deleting Inverse Address Matches')
        num = 0
        for context in self.contexts:

            inverse_stats[context] = OrderedDict(
                [('addresses', 0), ('policies', 0), ('groups', 0)])  # address,policy,groups
            self.log('=' * 180)
            self.log('Context  : ' + context)
            self.log('Firewall : ' + self.config[context]['config']['name'])
            self.log('Mgmt IP  : ' + str(self.config[context]['config']['mgmtip']))
            for match in inverse_results[context]['addresses']:
                inverse_stats[context]['addresses'] += 1
                if (match['match'].lower() == 'complete' or self.options.inversepartial) and match['mapping'] == 'root' and (
                        context.lower() != 'shared' or skipshared == False):  # match is complete, a host object, and at the root level (not an entry with group membership listed)

                    self.log('=' * 180)
                    if match['fw_type'].lower() != 'checkpoint':
                        self.log('Context      : ' + context)
                    self.log('Address      : ' + match['address'])
                    self.log('Address Type : ' + match['type'])
                    if match['type'] == 'host':
                        addr_str = self.config[context]['addresses'][match['address']]['addrObjIp1'] + '/32'
                    elif match['type'] == 'network':
                        addr_str = self.config[context]['addresses'][match['address']]['addrObjIp1'] + '/' + str(
                            self.netmask_to_cidr(self.config[context]['addresses'][match['address']]['addrObjIp2']))
                    elif match['type'] == 'range:':
                        addr_str = self.config[context]['addresses'][match['address']]['addrObjIp1'] + '-' + \
                                   self.config[context]['addresses'][match['address']]['addrObjIp2']
                    else:
                        addr_str = 'Details Below'
                    self.log('Address Def  : ' + addr_str)
                    self.log('Match Type   : ' + match['match'])
                    self.log('Parent       : ' + match['mapping'])

                    if context.lower() == 'sonicwall':
                        self.log('sonicwall', match['address'])
                    else:
                        if context.lower() != 'shared':
                            if match['address'] in self.config[context]['addresses']:
                                shared = False
                            else:
                                shared = True
                        else:  # context is shared
                            shared = False
                        self.log('-' * 180)
                        self.log('Group Membership')
                        self.log('-' * 180)
                        found = False
                        for address in self.config[context]['addressmappings']:
                            if match['address'] in self.config[context]['addressmappings'][address]:
                                found = True
                                self.log(str(address))
                                if match['fw_type'].lower() == 'sonicwall':
                                    inverse_newcmds.append(
                                        {'fw_type': 'sonicwall', 'fw_ip': self.config[context]['config']['mgmtip'],
                                         'device_group': context, 'match_type': 'address', 'cleanup_type': 'group',
                                         'group': str(address), 'member': match['address']})
                                else:
                                    inverse_newcmds.append(
                                        {'fw_type': match['fw_type'], 'fw_ip': self.config[context]['config']['mgmtip'],
                                         'device_group': context, 'match_type': 'address', 'cleanup_type': 'group',
                                         'group': str(address), 'member': match['address']})

                                num += 1
                                inverse_stats[context]['groups'] += 1
                        if not found:
                            self.log('None')

                        if match['type'].lower() == 'group':
                            self.log('-' * 180)
                            self.log('Group Members')
                            self.log('-' * 180)
                            for member in self.createNetworkService.expand_address(self.config[context]['addresses'], match['address'],
                                                         self.config[context]['addressmappings']):
                                tmpaddr = None
                                if member in self.config[context]['addresses']:
                                    tmpaddr = self.config[context]['addresses'][member]
                                elif member in self.config['shared']['addresses']:
                                    tmpaddr = self.config['shared']['addresses'][member]
                                if tmpaddr['addrObjType'] == '1':
                                    addr_str = tmpaddr['addrObjIp1'] + '/32'
                                elif tmpaddr['addrObjType'] == '4':
                                    addr_str = tmpaddr['addrObjIp1'] + '/' + str(self.netmask_to_cidr(tmpaddr['addrObjIp2']))
                                elif tmpaddr['addrObjType'] == '2:':
                                    addr_str = tmpaddr['addrObjIp1'] + '-' + tmpaddr['addrObjIp2']
                                else:
                                    addr_str = 'Group Object'
                                self.log('  {:30.30s} {:30.30s}'.format(member, addr_str))

                        ## check to see if address is used in any policies -- Ideally the policies using the object would already be disabled & deleted

                        ## check if shared address is  in the match list for each context - if so it has already been removed from the context rules and can be skipped
                        self.log('-' * 180)
                        self.log('Rule Membership')
                        self.log('-' * 180)
                        if context == 'shared':
                            polcontexts = self.contexts
                        else:
                            polcontexts = [context]
                        found = False
                        for polcontext in polcontexts:
                            for policy in self.config[polcontext]['policies']:
                                if match['address'] in self.config[polcontext]['policies'][policy]['policySrcNet']:
                                    found = True
                                    inverse_stats[context]['policies'] += 1
                                    if match['fw_type'].lower() == 'sonicwall':
                                        self.log('Source       :  {:20.20s} {:20.20s} {:40.40s} {:40.40s} {:40.40s}'.format(
                                            self.config[polcontext]['policies'][policy]['policySrcZone'][0],
                                            self.config[polcontext]['policies'][policy]['policyDstZone'][0],
                                            self.config[polcontext]['policies'][policy]['policySrcNet'][0],
                                            self.config[polcontext]['policies'][policy]['policyDstNet'][0],
                                            self.config[polcontext]['policies'][policy]['policyDstSvc'][0]))
                                        inverse_newcmds.append(
                                            {'fw_type': 'sonicwall', 'fw_ip': self.config[context]['config']['mgmtip'],
                                             'device_group': polcontext, 'match_type': 'address',
                                             'cleanup_type': 'policy-source',
                                             'policy_name': self.config[polcontext]['policies'][policy]['policyName'],
                                             'member': match['address']})
                                    elif match['fw_type'].lower() == 'checkpoint':
                                        self.log('Source       : ' + self.config[polcontext]['policies'][policy][
                                            'policyName'] + ':rule:' + str(
                                            self.config[polcontext]['policies'][policy]['policyNum']) + '  (UI#: ' + str(
                                            self.config[polcontext]['policies'][policy]['policyUiNum']) + ')')
                                        inverse_newcmds.append(
                                            {'fw_type': match['fw_type'], 'fw_ip': self.config[context]['config']['mgmtip'],
                                             'device_group': polcontext, 'match_type': 'address',
                                             'cleanup_type': 'policy-source',
                                             'policy_name': self.config[polcontext]['policies'][policy]['policyName'],
                                             'member': match['address'],
                                             'rule_num': self.config[polcontext]['policies'][policy]['policyNum']})
                                    else:
                                        self.log('Source       : ' + self.config[polcontext]['policies'][policy]['policyName'])
                                        inverse_newcmds.append(
                                            {'fw_type': match['fw_type'], 'fw_ip': self.config[context]['config']['mgmtip'],
                                             'device_group': polcontext, 'match_type': 'address',
                                             'cleanup_type': 'policy-source',
                                             'policy_name': self.config[polcontext]['policies'][policy]['policyName'],
                                             'member': match['address'],
                                             'rule_num': self.config[polcontext]['policies'][policy]['policyNum']})
                                    num += 1

                                if match['address'] in self.config[polcontext]['policies'][policy]['policyDstNet']:
                                    found = True
                                    inverse_stats[context]['policies'] += 1
                                    if match['fw_type'].lower() == 'sonicwall':
                                        self.log('Destination  :  {:20.20s} {:20.20s} {:40.40s} {:40.40s} {:40.40s}'.format(
                                            self.config[polcontext]['policies'][policy]['policySrcZone'][0],
                                            self.config[polcontext]['policies'][policy]['policyDstZone'][0],
                                            self.config[polcontext]['policies'][policy]['policySrcNet'][0],
                                            self.config[polcontext]['policies'][policy]['policyDstNet'][0],
                                            self.config[polcontext]['policies'][policy]['policyDstSvc'][0]))
                                        inverse_newcmds.append(
                                            {'fw_type': 'sonicwall', 'fw_ip': self.config[context]['config']['mgmtip'],
                                             'device_group': polcontext, 'match_type': 'address',
                                             'cleanup_type': 'policy-dest',
                                             'policy_name': self.config[polcontext]['policies'][policy]['policyName'],
                                             'member': match['address']})
                                    elif match['fw_type'].lower() == 'checkpoint':
                                        self.log('Destination  : ' + self.config[polcontext]['policies'][policy][
                                            'policyName'] + ':rule:' + str(
                                            self.config[polcontext]['policies'][policy]['policyNum']) + '  (UI#: ' + str(
                                            self.config[polcontext]['policies'][policy]['policyUiNum']) + ')')
                                        inverse_newcmds.append(
                                            {'fw_type': match['fw_type'], 'fw_ip': self.config[context]['config']['mgmtip'],
                                             'device_group': polcontext, 'match_type': 'address',
                                             'cleanup_type': 'policy-dest',
                                             'policy_name': self.config[polcontext]['policies'][policy]['policyName'],
                                             'member': match['address'],
                                             'rule_num': self.config[polcontext]['policies'][policy]['policyNum']})
                                    else:
                                        self.log('Destination  : ' + self.config[polcontext]['policies'][policy]['policyName'])
                                        inverse_newcmds.append(
                                            {'fw_type': match['fw_type'], 'fw_ip': self.config[context]['config']['mgmtip'],
                                             'device_group': polcontext, 'match_type': 'address',
                                             'cleanup_type': 'policy-dest',
                                             'policy_name': self.config[polcontext]['policies'][policy]['policyName'],
                                             'member': match['address'],
                                             'rule_num': self.config[polcontext]['policies'][policy]['policyNum']})
                                    num += 1

                        ## check to see if address is used in any shared policies (not likely, as we currently do not have any shared pre-rules)

                        if not found:
                            self.log('NONE')

                        ## remove address from context
                        if not shared:  # only remove if address is not a shared object in a context other than shared
                            if match['type'] == 'group':
                                if match['fw_type'].lower() == 'sonicwall':
                                    inverse_newcmds.append(
                                        {'fw_type': 'sonicwall', 'fw_ip': self.config[context]['config']['mgmtip'],
                                         'device_group': context, 'match_type': 'address',
                                         'cleanup_type': 'address-group', 'address': match['address']})
                                else:
                                    inverse_newcmds.append(
                                        {'fw_type': match['fw_type'], 'fw_ip': self.config[context]['config']['mgmtip'],
                                         'device_group': context, 'match_type': 'address',
                                         'cleanup_type': 'address-group', 'address': match['address']})
                            else:
                                if match['fw_type'].lower() == 'sonicwall':
                                    inverse_newcmds.append(
                                        {'fw_type': 'sonicwall', 'fw_ip': self.config[context]['config']['mgmtip'],
                                         'device_group': context, 'match_type': 'address', 'cleanup_type': 'address',
                                         'address': match['address']})
                                else:
                                    inverse_newcmds.append(
                                        {'fw_type': match['fw_type'], 'fw_ip': self.config[context]['config']['mgmtip'],
                                         'device_group': context, 'match_type': 'address', 'cleanup_type': 'address',
                                         'address': match['address']})
                            num += 1
                    self.log('\r\n')

        return inverse_newcmds, inverse_stats

    def inverse_showcommands(self, commands):

        if 'rules' in commands:
            for i in commands['rules']:
                self.log(i)
        if 'addresses' in commands:
            for i in commands['addresses']:
                self.log(i)

        return

    def address_to_ipset(self, address, context):

        from netaddr import IPSet, IPRange, IPNetwork, IPAddress
        import ipaddress

        returnset = None

        ## return none for unsupported address types
        pass
        if address.lower() in ['', 'any']:
            returnset = IPSet(['0.0.0.0/0'])
        elif address in self.config[context]['addresses']:
            if self.config[context]['addresses'][address]['addrObjType'] in ['1', '99']:
                returnset = IPSet([IPAddress(self.config[context]['addresses'][address]['addrObjIp1'])])
            elif self.config[context]['addresses'][address]['addrObjType'] == '2':
                returnset = IPSet(IPRange(self.config[context]['addresses'][address]['addrObjIp1'],
                                          self.config[context]['addresses'][address]['addrObjIp2']))
            elif self.config[context]['addresses'][address]['addrObjType'] == '4':
                returnset = IPSet([IPNetwork(self.config[context]['addresses'][address]['addrObjIp1'] + '/' + str(
                    self.netmask_to_cidr(self.config[context]['addresses'][address]['addrObjIp2'])))])
            elif self.config[context]['addresses'][address]['addrObjType'] == '8':  # group
                returnset = IPSet([])
                #  def expand_address(address_dict, address_object, address_map, inc_group=False):
                for member in self.createNetworkService.expand_address(self.config[context]['addresses'], address, self.config[context]['addressmappings']):
                    if member.lower() in ['', 'any']:
                        returnset = IPSet(['0.0.0.0/0'])
                    elif member in self.config[context]['addresses']:
                        if self.config[context]['addresses'][member]['addrObjType'] in ['1', '99']:
                            returnset.add(IPAddress(self.config[context]['addresses'][member]['addrObjIp1']))
                        elif self.config[context]['addresses'][member]['addrObjType'] == '2':
                            returnset.add(IPRange(self.config[context]['addresses'][member]['addrObjIp1'],
                                                  self.config[context]['addresses'][member]['addrObjIp2']))
                        elif self.config[context]['addresses'][member]['addrObjType'] == '4':
                            # returnset.add(IPSet([IPNetwork(self.config[context]['addresses'][member]['addrObjIp1'] + '/' + str(netmask_to_cidr(self.config[context]['addresses'][member]['addrObjIp2'])))]))
                            # debug('adding network to ipset' + self.config[context]['addresses'][member]['addrObjIp1'] + '/' + str(netmask_to_cidr(self.config[context]['addresses'][member]['addrObjIp2'])))
                            returnset.add(IPNetwork(self.config[context]['addresses'][member]['addrObjIp1'] + '/' + str(
                                self.netmask_to_cidr(self.config[context]['addresses'][member]['addrObjIp2']))))
                        else:
                            self.debug(self.config[context]['addresses'][member]['addrObjType'])

                    # print('MEMBER : ' + member)
            else:
                returnset = 'address type : ' + self.config[context]['addresses'][address]['addrObjType']


        elif self.config[context]['config']['fw_type'].lower() in ['paloalto', 'panorama']:
            if address in self.config['shared']['addresses']:
                returnset = 'None'
        else:
            returnset = address

        ## does address exist in given context?
        ## if not, and its a palo/pano device, does it exist in shared?
        ## if address is host/network/range - return ipset value or object
        ## if address is group loop through expand_address_object
        ## does address exist in given context?
        ## if not, and its a palo/pano device, does it exist in shared?
        ## if address is host/network/range - return ipset value or object

        return returnset

    def file_to_list(filename):
        filelist = []
        if os.path.isfile(filename):
            with open(filename, 'r') as infile:
                for line in infile:
                    if line[0] != '#':
                        filelist.append(line)

        return filelist

    def bulk_create_rules(self, target, config=None):

        try:

            if self.options.fwtype in ['sw', 'sonicwall']:  ## not really supported as I need to read in routing table
                config = self.get_sonicwall_exp(target)
            elif self.options.fwtype in ['sw65']:
                config = {}
                config['sonicwall'] = self.load_sonicwall_api(target, self.options.username, self.options.password)
                if not self.options.context:
                    self.options.context = ['sonicwall']
                for context in self.options.context:
                    self.contexts.append(context)
            elif self.options.fwtype in ['palo', 'panorama', 'pano']:
                palo_xml = get_palo_config_https(target, 'config.panorama.temp', self.options.username, self.options.password)
                if palo_xml:
                    config = load_xml('', palo_xml)
                    palo_xml = None
            elif self.options.fwtype in ['cp', 'checkpoint']:  ## config needs to be loaded and passed to routines
                pass
            # self.log(self.options.nexposerule)
            # self.log('-' *180)
            return_status = []
            for ruleitems in self.options.nexposerule:
                # self.log('processing ruleitem', ruleitems)
                # self.log(ruleitems.split(','))
                # self.log(len(ruleitems.split(',')))
                # self.log(self.options.context[0])
                if len(ruleitems.split(',')) >= 8:  # rule_name, src_zone, src_net, dst_zone, dst_net, action, comment
                    # for context in config:
                    #    self.log(context)
                    #    for item in config[context]:
                    #        self.log(item)
                    rule_name, src_zones, src_address, dst_zones, dst_address, dst_service, action, *comment = ruleitems.split(
                        ',')
                    comment = ','.join(comment)
                    # self.log(src_zones)
                    if src_zones == '':
                        if self.options.fwtype.lower() in ['sw', 'sw65', 'sonicwall']:
                            try:
                                src_zones = [config[self.options.context[0]]['addresses'][
                                                 self.createNetworkService.expand_address(config[self.options.context[0]]['addresses'], src_address,
                                                                config[self.options.context[0]]['addressmappings'])[0]][
                                                 'addrObjZone']]
                            except:
                                src_zones = []
                        else:
                            src_zones = self.zone.get_zones2(self.options.context[0], src_address, config)
                    elif src_zones[0] == '%':
                        src_zones = [self.zone.get_zone(self.options.context[0], src_zones[1:], config)]
                    else:
                        src_zones = [src_zones]
                    if dst_zones == '':
                        if self.options.fwtype.lower() in ['sw', 'sw65', 'sonicwall']:
                            # self.log(expand_address(config[self.options.context[0]]['addresses'], dst_address, config[self.options.context[0]]['addressmappings']))
                            try:
                                dst_zones = [config[self.options.context[0]]['addresses'][
                                                 self.createNetworkService.expand_address(config[self.options.context[0]]['addresses'], dst_address,
                                                                config[self.options.context[0]]['addressmappings'])[0]][
                                                 'addrObjZone']]
                            except:
                                dst_zones = []
                        else:
                            dst_zones = self.zone.get_zones2(self.options.context[0], dst_address, config)
                    elif dst_zones[0] == '%':
                        # self.log(dst_zones[1:])
                        dst_zones = [self.zone.get_zone(self.options.context[0], dst_zones[1:], config)]
                        # self.log('JEFF!!!!')
                        # self.log(dst_zones)
                    else:
                        dst_zones = [dst_zones]
                    # self.log(self.options.context[0], src_zones, dst_zones, dst_service)
                    if src_zones != [] and dst_zones != []:
                        if (len(src_zones) == 1 and len(dst_zones) == 1):
                            for src_zone in src_zones:
                                if src_zone != '':
                                    for dst_zone in dst_zones:
                                        if dst_zone != '':
                                            # self.log(src_zone, dst_zone)
                                            result = 'Read-Only'
                                            if not self.options.readonly:
                                                if src_zone != 'MGMT' and dst_zone != 'MGMT':
                                                    result = self.service.exec_fw_command(target, self.options.fwtype, [('create_rule',
                                                                                                       {
                                                                                                           'rulename': rule_name,
                                                                                                           'polaction': '2',
                                                                                                           'enabled': '1',
                                                                                                           'srczones': [
                                                                                                               src_zone],
                                                                                                           'dstzones': [
                                                                                                               dst_zone],
                                                                                                           'sources': [
                                                                                                               src_address],
                                                                                                           'dests': [
                                                                                                               dst_address],
                                                                                                           'services': [
                                                                                                               dst_service],
                                                                                                           'comment': comment, })],
                                                                             syntax='api')
                                            # self.log('{},{},{},{},{},{},{},{},{},{}'.format(target, result, rule_name, action, src_zone, src_address, dst_zone, dst_address, dst_service, comment))
                                            return_status.append((target, result, rule_name, action, src_zone,
                                                                  src_address, dst_zone, dst_address, dst_service,
                                                                  comment))
                        else:
                            return_status.append((target,
                                                  (False, 'Src and/or Dst zones did not contain a single member'),
                                                  rule_name, action, src_zones, src_address, dst_zones, dst_address,
                                                  dst_service, comment))
                    else:
                        return_status.append((target, (False, 'Missing Zone(s)'), rule_name, action, src_zones,
                                              src_address, dst_zones, dst_address, dst_service, comment))
                else:
                    self.log('{},{},{}'.format(target, (False, 'Invalid Ruleitems Length'), ruleitems))
            # self.log('-' *180)
            return return_status
        except Exception as e:
            return [(target, 'Exception', e, '', '', '', '', '', '', '')]

    def bulk_create_addresses(self, target, config=None):

        try:
            members_added = []
            members_existed = []
            new_addresses = []
            existing_addresses = []

            if target == None:
                if self.options.panoramaip:
                    target = self.options.panoramaip
                elif self.options.sonicwallip:
                    target = self.options.sonicwallip
                elif self.options.sonicwall_api_ip:
                    target = self.options.sonicwall_api_ip
                elif self.options.checkpoint_api:
                    target = self.options.checkpoint_api
                elif self.options.checkpoint:
                    target = ''
                else:
                    target = ''
            else:
                self.log(target)
                if self.options.fwtype in ['sw', 'sonicwall']:  ## not really supported as I need to read in routing table
                    config = self.get_sonicwall_exp(target)


                elif self.options.fwtype in ['sw65']:
                    config = {}
                    config['sonicwall'] = self.load_sonicwall_api(target, self.options.username, self.options.password)
                    if not self.options.context:
                        self.options.context = ['sonicwall']
                    for context in self.options.context:
                        self.contexts.append(context)
                elif self.options.fwtype in ['palo', 'panorama', 'pano']:
                    palo_xml = get_palo_config_https(target, 'config.panorama.temp', self.options.username, self.options.password)
                    if palo_xml:
                        config = load_xml('', palo_xml)
                        palo_xml = None
                    # not much advantage for multiprocessing here, can just perform this by loading config files per cma
                    # and generating dbedit commands.
                elif self.options.fwtype in ['cp', 'checkpoint']:
                    pass
            # should probably allow the use of self.options.grouptargets
            # self.log(config['sonicwall']['addressmappings'])

            comment = self.options.comment

            nexpose_delay = 0
            # Create Nexpose group

            # if self.options.nexpose.lower() not in [x.lower() for x in config['shared']['addresses']]:  ## create address group if needed
            #    if not self.options.readonly:
            #        self.log('Creating Address Group : {}'.format(self.options.nexpose))
            #        result=exec_fw_command(target, 'pano', [('create_address', {'addressname': self.options.nexpose, 'addresstype': '8', 'zone': 'LAN', 'color': 'black', 'comment': comment, 'members': [], 'context': 'shared'})], syntax='api', delay=10)
            # else:
            #    self.log('Using existing Address Group : {}'.format(self.options.nexpose))

            # Create rules with group - this was removed as it is now added as a shared policy
            # if self.options.context != ['all']:
            target_context = None
            for context in self.options.context:
                target_zone = None
                group_length = len(self.options.groupaddresses)
                # self.log(context)
                address_group_members = self.createNetworkService.expand_address(config[context]['addresses'], self.options.nexpose,
                                                       config[context]['addressmappings'])
                # if len(address_group_members) >= group_length:
                #    self.log('{} contains {} members, no action needed (STEP1)'.format(self.options.nexpose, len(address_group_members)))
                # else:
                # self.log('{} only contains {} members, creating address objects (STEP1)'.format(self.options.nexpose, len(address_group_members)))
                if len(config[context][
                           'addresses']) > 1:  # at least one address must exist to continue, otherwise loading config likely failed.
                    sw_objects = {'address_objects': {'ipv4': [], 'ipv6': [], 'fqdn': []},
                                  'address_groups': {'ipv4': [], 'ipv6': [], 'fqdn': []}, 'service_objects': [],
                                  'service_groups': []}
                    if context in config:
                        fw_type = config[context]['config']['fw_type']
                        if fw_type in ["sw65", "palo", "pano", "R80", 'paloalto', 'panorama']:
                            api_type = 'api'
                        elif fw_type == "sonicwall":
                            api_type = 'webui'
                        elif fw_type == "checkpoint":
                            api_type = 'cli'
                        if fw_type in ['pano', 'panorama']:
                            fw_type = 'pano'
                            target_zone = True
                            target_context = 'shared'
                            if self.options.nexpose.lower() not in [x.lower() for x in config['shared'][
                                'addresses']] and not self.options.readonly:  ## create address group if needed
                                self.log('Creating Shared Address Group : {}'.format(self.options.nexpose))
                                result = self.service.exec_fw_command(target, fw_type, [('create_address',
                                                                            {'addressname': self.options.nexpose,
                                                                             'addresstype': '8', 'zone': 'LAN',
                                                                             'color': 'black', 'comment': comment,
                                                                             'members': [],
                                                                             'context': target_context})],
                                                         syntax=api_type, delay=nexpose_delay)
                            elif self.options.nexpose.lower() in [x.lower() for x in config['shared']['addresses']]:
                                for address in config[context]['addresses']:
                                    if address.lower() == self.options.nexpose.lower():
                                        self.options.nexpose = address
                                        break
                                self.log('!-- Using existing Address Group : {}'.format(self.options.nexpose))
                        elif fw_type not in ['pano', 'panorama']:
                            target_context = context
                            if fw_type in ['sonicwall', 'sw65']:
                                # self.log(self.options.groupaddresses[0].split(',')[0])
                                if not self.options.skipzone:
                                    for address in self.options.groupaddresses:
                                        if len(address.split('%')) == 2:
                                            target_zone = self.zone.get_zone(target_context, address.split(',')[0].split('%')[1],
                                                                   config)
                                        else:
                                            target_zone = self.zone.get_zone(target_context, address.split(',')[0], config)
                                        if target_zone != None:
                                            # self.log('target_zone', target_zone, address)
                                            break
                                    if target_zone == None:
                                        try:
                                            self.log('Trying to determine zone for {}'.format(
                                                self.options.groupaddresses[0].split(',')[0]))
                                            target_zone = \
                                                self.zone.get_zones2(target_context, self.options.groupaddresses[0].split(',')[0],
                                                           config)[0]
                                        except:
                                            target_zone = None

                                    self.log('!-- Zone for newly created objects : {}'.format(target_zone))
                                else:
                                    self.log('!-- Skipping zone detection for adding address objects to group')
                                    target_zone = True
                                self.log('!-- Building lists for address and service objects')
                                orig_api = True
                                # orig_api=self.sw_get_api_status(target, self.options.username, self.options.password)
                                # sw_enable_api(target, self.options.username, self.options.password)
                                sw_objects = self.get_sw_objects(target, self.options.username, self.options.password, fw_type)
                            else:
                                # self.log('Zone for newly created objects : {}'.format(target_zone))
                                target_zone = 'LAN'
                                orig_api = None

                            # if self.options.nexpose.lower() not in [x.lower() for x in config[context]['addresses']] and not self.options.readonly:
                            # self.log('!-- Original API status {}'.format(orig_api))
                            # if api_type=='api' and orig_api==False:  ## only enable if needed -- enabling API will log you out of box
                            #    sw_enable_api(target, self.options.username, self.options.password)
                            # self.log('!-- Creating Temp Address Object for Sonicwalls ')
                            # result=exec_fw_command(target, fw_type, [('create_address', {'addressname': 'temp_address_object', 'ip1': '1.1.1.1', 'ip2' : '255.255.255.255', 'addresstype': '1', 'zone': target_zone, 'color': 'black', 'comment': 'DELETE_ME', 'context': target_context})], syntax=api_type, delay=nexpose_delay)
                            # self.log('!-- Creating Address Group : {}'.format(self.options.nexpose))
                            # result=exec_fw_command(target, fw_type, [('create_address', {'addressname': self.options.nexpose, 'addresstype': '8', 'zone': target_zone, 'color': 'black', 'comment': comment, 'members': ['temp_address_object'], 'context': target_context})], syntax=api_type, delay=nexpose_delay)
                            # self.log(result)
                            # elif self.options.nexpose.lower() in [x.lower() for x in config[context]['addresses']]:
                            if self.options.nexpose.lower() in [x.lower() for x in config[context]['addressmappings']]:
                                for address in config[context]['addresses']:
                                    if address.lower() == self.options.nexpose.lower():
                                        self.options.nexpose = address
                                        break
                                self.log('!-- Using existing Address Group : {}'.format(self.options.nexpose))

                                # result=exec_fw_command(target, fw_type, [('create_rule', {'rulename': 'test_rule', 'policyname': context, 'policynum': '1', 'polaction': '1', 'srczones': [target_zone], 'dstzones': ['WAN'], 'sources': ['test_host'], 'dests': ['test_group'], 'services': ['any'], 'comment': 'testing', 'context': context})], syntax='api')
                            # result=exec_fw_command(target, fw_type, [('create_rule', {'rulename': 'NEXPOSE', 'policyname': context, 'policynum': '1', 'polaction': '2', 'srczones': [target_zone], 'dstzones': ['any'], 'sources': [self.options.nexpose], 'dests': ['any'], 'services': ['any'], 'applications': ['any'], 'comment': comment, 'disabled': 'True', 'context': context})], syntax='api', delay=10)
                            # result=exec_fw_command(target, 'pano', [('modify_rule', {'action': 'disable', 'comment': 'Modified Comment', 'rulename': 'NEXPOSE', 'policyname': context, 'policynum': '1', 'polaction': '1', 'srczones': ['LAN'], 'dstzones': ['WAN'], 'sources': ['test_host'], 'dests': ['test_group'], 'services': ['any'], 'context': context})], syntax='api')
            # if len(address_group_members) >= group_length:
            #    self.log('{} contains {} members, no action needed (STEP2)'.format(self.options.nexpose, len(address_group_members)))
            # else:
            # target_zone='WAN'
            # self.log(target_zone, target_context)

            members_added = []
            members_existed = []
            new_addresses = []
            existing_addresses = []

            if target_context:
                if target_zone and len(config[target_context]['addresses']) > 1:

                    addresses_to_add = []  # list of sets containing (network, mask, address_name)
                    address_cmds = []
                    group_members = []

                    for address_to_add in self.options.groupaddresses:  ## build addresses_to_add
                        fqdn = None
                        if address_to_add in config[target_context]['addresses']:
                            group_members.append(address_to_add)
                            self.log('Using existing object name with exact name match {}'.format(address_to_add))
                            existing_addresses.append(address_to_add)
                        elif len(address_to_add.split(',')) == 2:

                            address_obj, address_name = address_to_add.split(',')
                            if len(address_obj.split('/')) == 2:
                                network, mask = address_obj.split('/')
                            elif len(address_obj.split('%')) == 2:
                                fqdn, fqdn_ip = address_obj.split('%')
                            elif len(address_obj.split('-')) == 2:
                                range_start, range_end = address_obj.split('-')
                                network, mask = (None, None)
                            else:
                                network, mask = (address_obj, '32')
                            if fqdn != None:
                                addresses_to_add.append((fqdn, fqdn_ip, address_name, 'fqdn'))
                                # target_zone=get_zone(target_context, fqdn_ip, config)
                            else:
                                try:
                                    tmpaddr = IPNetwork(network + '/' + str(mask))
                                    addresses_to_add.append((network, mask, address_name, 'network'))
                                except:
                                    try:
                                        tmpaddr = IPRange(range_start, range_end)
                                        addresses_to_add.append((range_start, range_end, address_name, 'range'))
                                    except:
                                        # pass
                                        self.log('!-- Skipping entry {} - Invalid format'.format(address_to_add))

                        else:
                            self.log('!-- Skipping entry {} - Invalid format - Expected network/mask,address_name'.format(
                                address_to_add))

                    ## for sonicwalls, if we are adding objects to a group, I need to add routines to ensure addresses being added do not overlap!

                    # for address_to_add in addresses_to_add: ## now perform action on each address object to add
                    matches = {}

                    # for addr in addresslist: self.log(addr)
                    # log ('-'*100)
                    # for first, address_name in groupaddresses: self.log(address_name)

                    ###result=exec_fw_command(fwip, fw, [('create_address', {'addressname': 'test_fqdn', 'domain': 'www.deleteme.com', 'ttl': '120', 'addresstype': 'fqdn', 'zone': 'LAN', 'color': 'black' })], syntax=syntax)

                    for network, mask, address_name, address_type in addresses_to_add:  ## build a list of existing address objects that match each object that needs to be created
                        if address_type == 'network':
                            network_mask = '{}/{}'.format(network, mask)
                            fqdn_name = address_name
                            try:
                                host_name = address_name.split('.')[0]
                            except:
                                host_name = address_name
                            matches[network_mask] = {'address_ip': None, 'fqdn': None, 'hostname': None, 'other': None}
                            # self.log('new address : ', address_name)
                            for config_address in config[target_context][
                                'addresses']:  ## build a list of existing address objects that match the object we want to add
                                if config[target_context]['addresses'][config_address]['IPv4Networks'] == [
                                    ipaddress.IPv4Network(
                                        network_mask)]:  # or ( config[target_context]['addresses'][config_address]['addrObjIp1'] == network and config[target_context]['addresses'][config_address]['addrObjIp2']==cidr_to_netmask(mask)):
                                    # self.log(config[target_context]['addresses'][address])
                                    if config_address not in matches[network_mask]:
                                        if re.findall(r'{}.*{}'.format(host_name, network), config_address.lower(),
                                                      flags=re.IGNORECASE):
                                            matches[network_mask]['address_ip'] = config_address
                                            existing_addresses.append(config_address)
                                        elif config_address.lower() == fqdn_name.lower():
                                            matches[network_mask]['fqdn'] = config_address
                                            existing_addresses.append(config_address)
                                        elif config_address.lower() == host_name.lower():
                                            if not matches[network_mask]['hostname']:
                                                matches[network_mask]['hostname'] = config_address
                                                existing_addresses.append(config_address)
                                        else:
                                            if not matches[network_mask]['other']:
                                                matches[network_mask]['other'] = config_address
                                                existing_addresses.append(config_address)

                            # if len(matches[network_mask]) == 0: ## no address object exists with same definition - create new address object and add it to group
                            # result=exec_fw_command(target, fw_type, [('create_address', {'addressname': new_address_name, 'ip1': network, 'ip2' : cidr_to_netmask(mask), 'addresstype': '1', 'zone': target_zone, 'color': 'black', 'comment': 'NEXPOSE_SCANNERS', 'context': target_context})], syntax='cli')
                            # result=exec_fw_command(target, fw_type, [('modify_address', {'action': 'addmembers', 'addressname': self.options.nexpose, 'members': [new_address_name], 'comment': 'NEXPOSE_GROUP', 'addresstype': '8', 'zone': target_zone, 'color': 'black', 'context': target_context})], syntax='cli')
                            # else: # figure out what address object to use and add it to group
                            # address_name
                            new_address_name = address_name
                            if len(address_name.split('.')) > 0:
                                new_address_name = address_name.split('.')[0]
                            new_address_name = '{}-{}'.format(new_address_name, network)

                            if matches[network_mask]['address_ip']:
                                self.log('Using existing object name with address_ip match {} instead of requested name {}'.format(
                                    matches[network_mask]['address_ip'], address_name))
                                group_members.append(matches[network_mask]['address_ip'])
                            elif matches[network_mask]['fqdn']:
                                self.log('Using existing object name with fqdn match {} instead of requested name {}'.format(
                                    matches[network_mask]['fqdn'], address_name))
                                group_members.append(matches[network_mask]['fqdn'])
                            elif matches[network_mask]['hostname']:
                                self.log('Using existing object name with hostname match {} instead of requested name {}'.format(
                                    matches[network_mask]['hostname'], address_name))
                                group_members.append(matches[network_mask]['hostname'])
                            elif matches[network_mask]['other']:
                                self.log('Using existing object name with first match {} instead of requested name {}'.format(
                                    matches[network_mask]['other'], address_name))
                                group_members.append(matches[network_mask]['other'])
                            else:  ## no matches found
                                self.log('Creating new address object {} defined as {}'.format(new_address_name,
                                                                                          network_mask))
                                new_addresses.append(new_address_name)
                                group_members.append(new_address_name)
                                if mask == '32':
                                    address_cmds.append(
                                        ('create_address', {'addressname': new_address_name, 'ip1': network,
                                                            'ip2': self.service.cidr_to_netmask(mask),
                                                            'addresstype': '1', 'zone': target_zone,
                                                            'color': 'black', 'comment': comment,
                                                            'context': target_context}))
                                else:
                                    address_cmds.append(
                                        ('create_address', {'addressname': new_address_name, 'ip1': network,
                                                            'ip2': self.service.cidr_to_netmask(mask),
                                                            'addresstype': '4', 'zone': target_zone,
                                                            'color': 'black', 'comment': comment,
                                                            'context': target_context}))
                        elif address_type == 'range':
                            new_address_name = address_name
                            # for range_start, range_end, address_name, address_type in addresses_to_add: ## build a list of existing address objects that match each object that needs to be created
                            address_cmds.append(('create_address',
                                                 {'addressname': new_address_name, 'ip1': network, 'ip2': mask,
                                                  'addresstype': '2', 'zone': target_zone, 'color': 'black',
                                                  'comment': comment, 'context': target_context}))
                            group_members.append(new_address_name)
                        elif address_type == 'fqdn':  # [('create_address', {'addressname': 'test_fqdn', 'domain': 'www.deleteme.com', 'ttl': '120', 'addresstype': 'fqdn', 'zone': 'LAN', 'color': 'black' })]
                            # self.log('Creating fqdn object {}'.format(address_name))
                            # self.log(config[target_context]['addressesfqdn'])
                            # for x in config[target_context]['addressesfqdn']:
                            #    self.log(x)
                            #    pass
                            #    self.log(config[target_context]['addressesfqdn'][x])
                            # if address_name in config[target_context]['addresses'] or address_name in config[target_context]['addressesV6']:# or address_name in config[target_context]['addressesfqdn']:
                            #    existing_addresses.append(address_name)
                            #    self.log('Using existing fqdn object with name {}'.format(address_name))

                            ## Sonicwall 6.5.4.8 has a problem where sometimes the JSON returned for FQDN objects is mixed-up.  an FQDN match will only happen if both the Name of the object and the
                            ## FQDN definition of the object are the same.  This is not ideal, as it should only match on FQDN definition.  Our use of FQDNs is limited, so no major concerns here.

                            if network in [config[target_context]['addressesfqdn'][x]['addrObjFqdn'] for x in
                                           config[target_context]['addressesfqdn']] and address_name in [
                                config[target_context]['addressesfqdn'][y]['addrObjFqdnId'] for y in
                                config[target_context]['addressesfqdn']]:
                                for y in config[target_context]['addressesfqdn']:
                                    self.log('{} -- {} -- {} -- {}'.format(network,
                                                                      config[target_context]['addressesfqdn'][y][
                                                                          'addrObjFqdn'], address_name,
                                                                      config[target_context]['addressesfqdn'][y][
                                                                          'addrObjFqdnId']))
                                    if network in config[target_context]['addressesfqdn'][y][
                                        'addrObjFqdn'] and address_name == config[target_context]['addressesfqdn'][y][
                                        'addrObjFqdnId']:
                                        group_members.append(
                                            config[target_context]['addressesfqdn'][y]['addrObjFqdnId'])
                                        existing_addresses.append(
                                            config[target_context]['addressesfqdn'][y]['addrObjFqdnId'])
                                        self.log('Using existing fqdn object {} with name {}'.format(y,
                                                                                                config[target_context][
                                                                                                    'addressesfqdn'][y][
                                                                                                    'addrObjFqdnId']))
                                        break
                                # existing_addresses.append(address_name)
                                # group_members.append(new_address_name)

                            else:
                                self.log('Creating new fqdn object {}'.format(address_name))
                                new_address_name = address_name
                                address_cmds.append(
                                    ('create_address', {'addressname': new_address_name, 'domain': network,
                                                        'addresstype': 'fqdn', 'zone': target_zone,
                                                        'color': 'black', 'comment': comment,
                                                        'context': target_context}))
                                group_members.append(new_address_name)
                    if not self.options.readonly:
                        if address_cmds != []:
                            # self.log(target, fw_type)
                            result = self.service.exec_fw_command(target, fw_type, address_cmds, syntax=api_type,
                                                     delay=nexpose_delay,
                                                     sw_objects=sw_objects)
                            self.log('Creating Address objects', result)

                        else:
                            self.log('No new addresses need to be created')
                        members_added = []
                        members_existed = []
                        group_created = False
                        for sublist in [group_members[i:i + 50] for i in range(0, len(group_members),
                                                                               50)]:  ## only add a max of 50 group members at a time (limit is 100) -- should likely move this to the create/modify address group routines instead
                            result = False
                            if fw_type in ['sonicwall', 'sw65']:
                                sw_objects = self.get_sw_objects(target, self.options.username, self.options.password, fw_type)
                            for member in [x for x in sublist]:  # cant use sublist and then change it in the loop.
                                if self.options.nexpose in config[target_context]['addressmappings']:
                                    if member in config[target_context]['addressmappings'][self.options.nexpose]:
                                        sublist.remove(member)
                                        members_existed.append(member)
                                        self.log('Removing {} from sublist'.format(member))

                            if self.options.nexpose.lower() != 'none':
                                # self.log('sublist', sublist)
                                tries = 0
                                while sublist != [] and result != True and tries < len(sublist):
                                    tries += 1
                                    self.log('subgroup members : ', sublist)
                                    if self.options.nexpose.lower() in [x.lower() for x in config[target_context][
                                        'addresses']] or self.options.nexpose.lower() in [x.lower() for x in
                                                                                     config[target_context][
                                                                                         'addressesV6']] or group_created:
                                        result = self.service.exec_fw_command(target, fw_type, [('modify_address',
                                                                                    {'action': 'addmembers',
                                                                                     'addressname': self.options.nexpose,
                                                                                     'addresstype': '8',
                                                                                     'zone': target_zone,
                                                                                     'color': 'black',
                                                                                     'comment': comment,
                                                                                     'members': sublist,
                                                                                     'context': target_context})],
                                                                 syntax=api_type, delay=nexpose_delay,
                                                                 sw_objects=sw_objects)
                                        self.log('Adding members to existing group :', result)
                                    else:
                                        result = self.service.exec_fw_command(target, fw_type, [('create_address',
                                                                                    {'addressname': self.options.nexpose,
                                                                                     'addresstype': '8',
                                                                                     'zone': target_zone,
                                                                                     'color': 'black',
                                                                                     'comment': comment,
                                                                                     'members': sublist,
                                                                                     'context': target_context})],
                                                                 syntax=api_type, delay=nexpose_delay,
                                                                 sw_objects=sw_objects)
                                        self.log('Creating group and adding members :', result)
                                        if result == True:
                                            group_created = True

                                    if result != True:
                                        bad_object = ''
                                        if fw_type == 'sw65':
                                            try:
                                                bad_object = result[1].split(' ')[5]
                                                sublist.remove(bad_object)
                                                self.log('Removing {} from group members'.format(bad_object))
                                                self.log('Group members {}'.format(sublist))
                                            except:
                                                self.log('Removing {} from group failed'.format(bad_object))
                                        else:
                                            # self.log(result)
                                            result = True
                                    else:
                                        for x in sublist:
                                            members_added.append(x)

                        if members_added != []:
                            self.log('The following group members were successfully added : ', members_added)
                    #    if not orig_api:
                    #        sw_disable_api(target, self.options.username, self.options.password)
                else:
                    self.log('!-- Unable to determine Address object zone - skipping')
            return (target, new_addresses, existing_addresses, members_added, members_existed)
        except Exception as e:
            # self.log(e)
            return (target, 'Exception', e, '', '')

    def bulk_create_services(self, target):
        # self.log(config)
        try:
            target_context = None

            if target == None:
                if self.options.panoramaip:
                    target = self.options.panoramaip
                elif self.options.sonicwallip:
                    target = self.options.sonicwallip
                elif self.options.sonicwall_api_ip:
                    target = self.options.sonicwall_api_ip
                elif self.options.checkpoint_api:
                    target = self.options.checkpoint_api
                elif self.options.checkpoint:
                    global config
                    target = ''
                else:
                    target = ''
            else:
                self.log(target)
                if self.options.fwtype in ['sw', 'sonicwall']:  ## not really supported as I need to read in routing table
                    config = self.get_sonicwall_exp(target)

                elif self.options.fwtype in ['sw65']:
                    config = {}
                    config['sonicwall'] = self.load_sonicwall_api(target, self.options.username, self.options.password)
                    if not self.options.context:
                        self.options.context = ['sonicwall']
                    for context in self.options.context:
                        self.contexts.append(context)
                elif self.options.fwtype in ['palo', 'panorama', 'pano']:
                    palo_xml = get_palo_config_https(target, 'config.panorama.temp', self.options.username, self.options.password)
                    if palo_xml:
                        config = load_xml('', palo_xml)
                        palo_xml = None
                elif self.options.fwtype in ['cp',
                                        'checkpoint']:  ## not much advantage for multiprocessing here, can just perform this by loading config files per cma and generating dbedit commands.
                    pass

            comment = 'RITM5363965 - TASK5953822'
            comment = 'RITM5284122 - TASK5885697'

            nexpose_delay = 0

            for context in self.options.context:
                self.log('context: ', context)
                group_length = len(self.options.groupservices)
                if context in config:  # and context!='shared':
                    service_group_members = self.createNetworkService.expand_service(config[context]['services'], self.options.nexposesvc,
                                                           config[context]['servicemappings'], inc_group=False)

                    if len(config[context]['services']) > 1:
                        sw_objects = {'address_objects': {'ipv4': [], 'ipv6': [], 'fqdn': []},
                                      'address_groups': {'ipv4': [], 'ipv6': [], 'fqdn': []}, 'service_objects': [],
                                      'service_groups': []}
                        fw_type = config[context]['config']['fw_type']
                        if fw_type == 'panorama': fw_type = 'pano'
                        if fw_type == 'paloalto': fw_type = 'palo'
                        if fw_type in ["sw65", "palo", "pano", "R80", 'paloalto', 'panorama']:
                            api_type = 'api'
                        elif fw_type == "sonicwall":
                            api_type = 'webui'
                        elif fw_type == "checkpoint":
                            api_type = 'cli'
                        if fw_type in ['pano', 'panorama']:
                            # self.log(context)
                            target_context = 'shared'
                            if self.options.nexposesvc.lower() not in [x.lower() for x in config['shared'][
                                'services']]:  ## create address group if needed
                                if context == 'shared':
                                    self.log('Creating Shared Service Group : {}'.format(self.options.nexposesvc))
                                    if not self.options.readonly:
                                        result = self.service.exec_fw_command(target, fw_type, [('create_service',
                                                                                    {'servicename': self.options.nexposesvc,
                                                                                     'servicetype': '2', 'zone': 'LAN',
                                                                                     'color': 'black',
                                                                                     'comment': comment,
                                                                                     'members': [],
                                                                                     'context': target_context})],
                                                                 syntax=api_type, delay=nexpose_delay)
                            else:
                                if context == 'shared':
                                    self.log('Using existing shared Service Group : {}'.format(self.options.nexposesvc))
                        elif fw_type not in ['pano', 'panorama']:
                            target_context = context
                            if fw_type in ['sonicwall', 'sw65']:
                                self.log('!-- Building lists for address and service objects')
                                orig_api = True
                                sw_objects = self.get_sw_objects(target, self.options.username, self.options.password, fw_type)
                            if self.options.nexposesvc.lower() in [x.lower() for x in config[context]['services']]:
                                for service in config[context]['services']:
                                    if service.lower() == self.options.nexposesvc.lower():
                                        self.options.nexposesvc = service
                                        break
                                self.log('Using existing Service Group : {}'.format(self.options.nexposesvc))

            new_services, existing_services, members_added, members_existed = ([], [], [], [])

            if target_context:
                if len(config[target_context]['services']) > 1:
                    services_to_add = []  # list of sets containing (protocol, port1, port2, service_name)

                    for service_to_add in self.options.groupservices:  ## build services_to_add
                        if len(service_to_add.split(',')) == 2:
                            service_prot, service_ports = service_to_add.split(',')[0].split('/')
                            service_name = service_to_add.split(',')[1]
                            if len(service_ports.split('-')) == 2:
                                service_port1, service_port2 = service_ports.split('-')
                            else:
                                service_port1, service_port2 = (service_ports, '')

                            try:
                                if service_prot.lower() in ['tcp', 'udp']:
                                    if service_prot.lower() == 'tcp':
                                        service_prot_num = '6'
                                    elif service_prot.lower() == 'udp':
                                        service_prot_num = '17'
                                    services_to_add.append((service_prot.lower(), service_prot_num, service_port1,
                                                            service_port2, service_name))
                                else:
                                    self.log('Skipping entry {} - Protocol must be tcp or udp'.format(service_to_add))
                            except Exception as e:
                                self.log(e)
                                self.log('Skipping entry {} - Invalid format'.format(service_to_add))
                        else:
                            self.log('Skipping entry {} - Invalid format - Expected protocol/ports,service_object_name'.format(
                                service_to_add))

                    matches = {}
                    service_cmds = []
                    group_members = []

                    for service_prot, service_prot_num, service_port1, service_port2, service_name in services_to_add:  ## build a list of existing address objects that match each object that needs to be created
                        if service_port2 != '':
                            service_def = '{}/{}-{}'.format(service_prot, service_port1, service_port2)
                        else:
                            service_def = '{}/{}'.format(service_prot, service_port1)

                        matches[service_def] = {'exact': None, 'underscore': None, 'dash': None, 'other': None}
                        # self.log('new address : ', address_name)
                        # build a list of existing address objects that match the object we want to add
                        for config_service in config[target_context]['services']:
                            if 'svcObjIpType' in config[target_context]['services'][config_service]:
                                if config[target_context]['services'][config_service]['svcObjIpType'].lower() in \
                                        [service_prot, service_prot_num]:
                                    if service_port1 == config[target_context]['services'][config_service][
                                        'svcObjPort1'] and (
                                            service_port2 == config[target_context]['services'][config_service][
                                        'svcObjPort2'] or (
                                                    config[target_context]['services'][config_service]['svcObjPort2'] ==
                                                    config[target_context]['services'][config_service][
                                                        'svcObjPort1'] and service_port2) == ''):
                                        if config_service not in matches[service_def]:
                                            if re.findall(r'^{}$'.format(service_name), config_service.lower(),
                                                          flags=re.IGNORECASE) or re.findall(
                                                r'{}_{}-{}$'.format(service_prot, service_port1, service_port2),
                                                config_service.lower(), flags=re.IGNORECASE):
                                                matches[service_def]['exact'] = config_service
                                            if re.findall(r'{}_{}$'.format(service_prot, service_port1),
                                                          config_service.lower(), flags=re.IGNORECASE) or re.findall(
                                                r'{}_{}-{}$'.format(service_prot, service_port1, service_port2),
                                                config_service.lower(), flags=re.IGNORECASE):
                                                matches[service_def]['underscore'] = config_service
                                            elif re.findall(r'{}-{}$'.format(service_prot, service_port1),
                                                            config_service.lower(), flags=re.IGNORECASE) or re.findall(
                                                r'{}-{}-{}$'.format(service_prot, service_port1, service_port2),
                                                config_service.lower(), flags=re.IGNORECASE):
                                                matches[service_def]['dash'] = config_service
                                            else:
                                                if not matches[service_def]['other']:
                                                    matches[service_def]['other'] = config_service

                        new_service_name = service_name
                        index = 0
                        while new_service_name.lower() in [x.lower() for x in config[target_context]['services']]:
                            # self.log(config[target_context]['services'])
                            new_service_name = '{}_{}'.format(service_name, index)
                            index += 1
                        if matches[service_def]['exact']:
                            self.log('Using existing object name with exact name match {}'.format(
                                matches[service_def]['exact']))
                            existing_services.append(matches[service_def]['exact'])
                            # if not self.options.readonly:
                            group_members.append(matches[service_def]['exact'])
                        elif matches[service_def]['other']:
                            self.log('Using existing object name with other match {} instead of requested name {}'.format(
                                matches[service_def]['other'], service_name))
                            existing_services.append(matches[service_def]['other'])
                            # if not self.options.readonly:
                            group_members.append(matches[service_def]['other'])
                        elif matches[service_def]['underscore']:
                            self.log('Using existing object name with underscore match {} instead of requested name {}'.format(
                                matches[service_def]['underscore'], service_name))
                            existing_services.append(matches[service_def]['underscore'])
                            # if not self.options.readonly:
                            group_members.append(matches[service_def]['underscore'])
                        elif matches[service_def]['dash']:
                            self.log('Using existing object name with dash match {} instead of requested name {}'.format(
                                matches[service_def]['dash'], service_name))
                            existing_services.append(matches[service_def]['dash'])
                            # if not self.options.readonly:
                            group_members.append(matches[service_def]['dash'])
                        else:  ## no matches found
                            self.log('Creating new service object {} defined as {}'.format(new_service_name, service_def))
                            group_members.append(new_service_name)
                            new_services.append(new_service_name)
                            # if not self.options.readonly:
                            if service_port2 == '':
                                service_port2 = service_port1
                            service_cmds.append(('create_service',
                                                 {'servicename': new_service_name, 'protocol': service_prot,
                                                  'port1': service_port1, 'port2': service_port2, 'servicetype': '1',
                                                  'color': 'black', 'comment': comment, 'context': target_context}))

                    ###############################################

                    if not self.options.readonly:
                        if service_cmds != []:
                            # self.log(target, fw_type)
                            result = self.service.exec_fw_command(target, fw_type, service_cmds, syntax=api_type,
                                                     delay=nexpose_delay,
                                                     sw_objects=sw_objects)
                            self.log('Creating Service objects', result)
                        else:
                            self.log('No new services need to be created')
                        members_added = []
                        group_created = False
                        for sublist in [group_members[i:i + 50] for i in range(0, len(group_members),
                                                                               50)]:  ## only add a max of 50 group members at a time (limit is 100) -- should likely move this to the create/modify address group routines instead
                            result = False
                            if fw_type in ['sonicwall', 'sw65']:
                                sw_objects = self.get_sw_objects(target, self.options.username, self.options.password, fw_type)
                            for member in [x for x in sublist]:  # cant use sublist and then change it in the loop.
                                if self.options.nexposesvc in config[target_context]['servicemappings']:
                                    if member in config[target_context]['servicemappings'][self.options.nexposesvc]:
                                        sublist.remove(member)
                                        members_existed.append(member)
                                        self.log('Removing {} from sublist'.format(member))
                            if self.options.nexposesvc.lower() != 'none':
                                while sublist != [] and result != True:
                                    # self.log('-----------------JEFF------------------------------')
                                    # if sublist != []:
                                    self.log('subgroup members : ', sublist)
                                    if self.options.nexposesvc.lower() in [x.lower() for x in
                                                                      config[target_context][
                                                                          'services']] or group_created:
                                        self.log('Adding members to existing group')
                                        result = self.service.exec_fw_command(target, fw_type, [('modify_service',
                                                                                    {'action': 'addmembers',
                                                                                     'servicename': self.options.nexposesvc,
                                                                                     'servicetype': '2',
                                                                                     'color': 'black',
                                                                                     'comment': comment,
                                                                                     'members': sublist,
                                                                                     'context': target_context})],
                                                                 syntax=api_type, delay=nexpose_delay,
                                                                 sw_objects=sw_objects)
                                    else:
                                        self.log('Creating group and adding members')
                                        result = self.service.exec_fw_command(target, fw_type, [('create_service',
                                                                                    {'servicename': self.options.nexposesvc,
                                                                                     'servicetype': '2',
                                                                                     'color': 'black',
                                                                                     'comment': comment,
                                                                                     'members': sublist,
                                                                                     'context': target_context})],
                                                                 syntax=api_type, delay=nexpose_delay,
                                                                 sw_objects=sw_objects)
                                        self.log(result)
                                        if result == True:
                                            group_created = True

                                    # result=exec_fw_command(target, fw_type, [('modify_address', {'action': 'addmembers', 'addressname': self.options.nexposesvc, 'members': [sublist], 'addresstype': '8', 'zone': target_zone, 'color': 'black', 'context': target_context})], syntax=api_type, delay=nexpose_delay, sw_objects=sw_objects)
                                    # maximum of 100 objects at a time

                                    self.log('Adding Members to group', result)
                                    if result != True:
                                        if fw_type == 'sw65':
                                            bad_object = ''
                                            try:
                                                bad_object = result[1].split(' ')[5]
                                                sublist.remove(bad_object)
                                                self.log('Removing {} from group members'.format(bad_object))
                                                self.log('Group members {}'.format(sublist))
                                            except:
                                                self.log('Removing {} from group failed'.format(bad_object))
                                        else:
                                            # self.log(result)
                                            result = True
                                    else:
                                        for x in sublist:
                                            members_added.append(x)
                        if members_added != []:
                            self.log('The following group members were successfully added : ', members_added)

                    # if  fw_type != 'pano' and not self.options.readonly:
                    # result=exec_fw_command(target, fw_type, [('modify_service', {'action': 'delete', 'servicename': 'temp_service_object', 'servicetype': '1', 'context': target_context})], syntax=api_type, delay=nexpose_delay)

                    # if not orig_api:
                    #    sw_disable_api(target, self.options.username, self.options.password)
            return (target, new_services, existing_services, members_added, members_existed)

        except Exception as e:
            self.log(e)
            return (target, 'Exception', e, '', '')
