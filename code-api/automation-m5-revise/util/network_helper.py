import os
import re
import base64
from collections import defaultdict, OrderedDict
from copy import deepcopy
from urllib.parse import unquote
from logger import debug, log
from helper import sc, ss

# Network related helper


def cidr_to_netmask(prefix):

    # Convert CIDR notation to netmask /## --> ###.###.###.###
    return '.'.join([str((0xffffffff << (32 - int(prefix)) >> i) & 0xff) for i in [24, 16, 8, 0]])


def netmask_to_cidr(netmask):

    # Convert netmask to CIDR notation ###.###.###.### --> /##
    return sum([bin(int(x)).count("1") for x in netmask.split(".")])


# TODO: Move to sonic wall utility
def convert_exp_file(infile, outfile, encoded=None):

    # This converts a sonicwall .exp file to a plain textfile

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
        '''
        return_lines=''
        for line in decoded_space_removed.splitlines():
                return_space_removed = re.sub(r'%20$','',line)
                return_lines+=decoded_space_removed+'\n'
                #decoded_file.write('\n'.encode())
        '''
    else:
        return False
    # with open (configfilename) as working_file:
    # config = working_file.read()
    return re.sub(r'&', '\n', decoded.decode('utf-8', errors='ignore'))


def generate_group_mappings(tmp_config, group_type):
    # Used for Sonicwall configuration, this generates a dictionary of Groupname --> [ List of Group Members ]

    group_mappings = defaultdict(list)
    search_string = r'^' + group_type + '_.*'

    # with open (infile) as working_file:
    #    tmp_config = working_file.read()

    tmp_mappings = re.findall(search_string, tmp_config, flags=re.MULTILINE)
    for index, item in enumerate(tmp_mappings[::2]):
        junk, member = item.split('=', 1)
        junk, group = tmp_mappings[(index * 2) + 1].split('=', 1)
        group_mappings[group].append(member)
    # working_file.close()

    return group_mappings


def migrate_orig(objectname, config, property_list, skipdisabled=False):
    # Used to read the various configuration elements of Sonicwall configurations.

    regex_pattern = r'^interface.*_.*=.*|^' + objectname + '.*_.*=.*'
    # regexpattern0 = r'^' + objectname + '.*_0=.*'
    config_dict = OrderedDict()

    # with open (infile) as working_file:
    #    config = working_file.read()
    matched = re.findall(regex_pattern, config, flags=re.MULTILINE)

    for line in matched:

        object_beg, object_property = line.split('=', 1)
        object_key, object_num = object_beg.rsplit('_', 1)
        object_index = int(object_num)

        if object_key in property_list:
            if object_index not in config_dict:
                config_dict[object_index] = OrderedDict()

            config_dict[object_index][object_key] = object_property
            # insert empty policyDstApps / natPolicyName values for Sonicwalls
            if object_key == 'policyDstSvc':
                config_dict[object_index]['policyDstApps'] = []
            if object_key == 'natPolicyOrigSrc':
                config_dict[object_index]['natPolicyName'] = ''

    # REMOVED DISABLED RULES IF skip-disabled set
    if options.skip_disabled:
        skipped_dict = OrderedDict()
        for index in config_dict:
            if config_dict[index]['policyEnabled'] == '1':
                skipped_dict[index] = config_dict[index]
        return skipped_dict

    return config_dict


def migrate(name, config, property_list):
    # Used to read the various configuration elements of Sonicwall configurations.
    # New version that no longer uses numerical index (which later gets stripped with remove_index)
    regex_pattern = r'^portShutdown.*_.*=.*|^interface.*_.*=.*|^' + name + '.*_.*=.*'
    config_dict = OrderedDict()

    # with open (infile) as working_file:
    #    config = working_file.read()
    matched = re.findall(regex_pattern, config, flags=re.MULTILINE)

    for line in matched:

        object_beg, object_property = line.split('=', 1)
        object_key, object_num = object_beg.rsplit('_', 1)
        object_name = None

        if object_key == property_list[0]:
            object_name = object_property.rstrip().lstrip()

        if object_key in property_list:
            if object_name not in config_dict:
                config_dict[object_name] = OrderedDict()
            config_dict[object_name][object_key] = object_property.rstrip().lstrip()
            # prev_object_num = object_num

    return config_dict


def find_dupes(config):
    # First entry will be kept.  All subsequent duplicates should point to the original/first item

    duplicates = OrderedDict()

    # Find Dupe Addresses

    # total = len(config['addresses'])
    count = 0
    tmp_addresses = deepcopy(config['addresses'])

    for address in tmp_addresses:
        del tmp_addresses[address]['addrObjId']
        del tmp_addresses[address]['addrObjIdDisp']

    duplicates['addresses'] = OrderedDict()

    for masterindex in tmp_addresses:
        masterobject = tmp_addresses[masterindex]
        # If master object is already marked as a duplicate object, skip it
        if masterindex not in duplicates['addresses']:
            # Only find dupes if address object is not a group (8)
            if masterobject['addrObjType'] != '8':  # and masterobject['addrObjProperties'] == '14':
                for candidate in tmp_addresses:
                    if masterindex != candidate:  # don't compare master with itself
                        candidateobject = tmp_addresses[candidate]
                        if masterobject == candidateobject \
                                and candidateobject['addrObjProperties'] == '14':
                            # only remove candidates that are a user-defined object
                            if candidate not in duplicates['addresses']:
                                # Only add the candidate if its not already in the dupe list
                                duplicates['addresses'][candidate] = masterindex
                            # break;  # break removed, as it would stop searching for candidate in address1
                            # after first match (not desired)
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
            if masterobject['svcObjType'] == '1':
                # master object can be any type, and masterobject['svcObjProperties'] == '14':
                for candidate in tmpservices:
                    if masterindex != candidate:  # don't compare master with itself
                        candidateobject = tmpservices[candidate]
                        if masterobject == candidateobject and candidateobject['svcObjProperties'] == '14':
                            # only remove candidates that are a user-defined object
                            if candidate not in duplicates['services']:
                                # Only add the candidate if its not already in the dupe list
                                duplicates['services'][candidate] = masterindex
            # svcPortSet FIX
        count = count + 1

    # Find duplicate service groups - very low priority.  duplicates of entire groups not likely and would be slow
    return duplicates


def expand_address(address_dict, address_object, address_map, inc_group=False):
    # Takes an address group object (by name) and expands it into a list of all of its individual address objects

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
                        for group_member in expand_address(address_dict, group_members, address_map, inc_group):
                            expanded_addresses.append(group_member)
    elif 'addresses' in config['shared']:
        if address_object in config['shared']['addresses']:
            if 'addrObjType' in config['shared']['addresses'][address_object]:
                if config['shared']['addresses'][address_object]['addrObjType'] != '8':
                    expanded_addresses.append(address_object)
                else:
                    if inc_group:
                        expanded_addresses.append(address_object)
                    if address_object in address_map:
                        for group_members in config['shared']['addressesmappings'][config['shared']['addresses'][address_object]['addrObjId']]:
                            for group_member in expand_address(config['shared']['addresses'], group_members,
                                                               config['shared']['addressesmappings'], inc_group):
                                expanded_addresses.append(group_member)

    return expanded_addresses


def expand_service(service_dict, service_object, service_map, inc_group=False):

    # Takes a service group object (by name) and expands it into a list of all of its individual service objects

    expanded_services = []
    if service_object.lower() in [name.lower() for name in service_dict]: # do case insensitive match
        if service_object in service_dict:
            if service_dict[service_object]['svcObjIpType'] != '0':
                expanded_services.append(service_object)
            else:
                if inc_group:
                    expanded_services.append(service_object)
                if service_object in service_map:
                    for member in service_map[service_dict[service_object]['svcObjId']]:
                        for members in expand_service(service_dict, member, service_map, inc_group):
                            expanded_services.append(members)
        elif service_object in config['shared']['services']:
            if config['shared']['services'][service_object]['svcObjIpType'] != '0':
                expanded_services.append(service_object)
            else:
                if inc_group:
                    expanded_services.append(service_object)
                if service_object in config['shared']['servicemappings']:
                    for member in config['shared']['servicemappings'][config['shared']['services'][service_object]['svcObjId']]:
                        for members in expand_service(config['shared']['services'], member, config['shared']['servicemappings'], inc_group):
                            expanded_services.append(members)
    return expanded_services


# Original script does de-dupe before find_unused, so at the moment, this script returns too many results

def find_unused2(config, context):
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
    log('!-- Building set of address group members')
    for address in config['addresses']:
        if config['addresses'][address]['addrObjType'] == '8':
            expanded_addrgroup[address] = expand_address(config['addresses'], config['addresses'][address]['addrObjId'],
                                                         config['addressmappings'], True)
            for member in expanded_addrgroup[address]:
                all_address_group_members.add(member)
    log('!-- Building set of service group members')
    for service in config['services']:
        if config['services'][service]['svcObjType'] == '2':
            expanded_svcgroup[service] = expand_service(config['services'], config['services'][service]['svcObjId'],
                                                        config['servicemappings'], True)
            for member in expanded_svcgroup[service]:
                all_service_group_members.add(member)
    log('!-- Building sets for policy sources, destinations and services')
    for policy in config['policies']:
        for src in config['policies'][policy]['policySrcNet']:
            # debug(config['policies'][policy]['policyName'], config['policies'][policy]['policyUiNum'], 'SRC:',src)
            all_policy_address_members.add(src)
        for dst in config['policies'][policy]['policyDstNet']:
            # debug(config['policies'][policy]['policyName'], config['policies'][policy]['policyUiNum'], 'DST:',dst)
            all_policy_address_members.add(dst)
        for svc in config['policies'][policy]['policyDstSvc']:
            # debug(config['policies'][policy]['policyName'], config['policies'][policy]['policyUiNum'], 'DST:',dst)
            all_policy_service_members.add(svc)

    for policy in config['nat']:
        # 'natPolicyOrigSrc', 'natPolicyOrigDst', 'natPolicyOrigSvc', 'natPolicyTransSrc',
        # 'natPolicyTransDst', 'natPolicyTransSvc'
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
        debug(len(unused['addresses']) + len(unused['addressgroups']), unused_count)
        debug('looping addresses')
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
                            debug('removing {} from pol set'.format(address))
                            all_policy_address_members.remove(address)
                        if address in all_address_group_members:
                            debug('removing {} from address set'.format(address))
                            all_address_group_members.remove(address)
    debug(len(unused['addresses']) + len(unused['addressgroups']), unused_count)

    unused_count = -1
    while len(unused['services']) > unused_count:
        debug(len(unused['services']) + len(unused['servicegroups']), unused_count)
        debug('looping services')
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
                            debug('removing {} from pol set'.format(service))
                            all_policy_service_members.remove(service)
                        if service in all_service_group_members:
                            debug('removing {} from service set'.format(service))
                            all_service_group_members.remove(service)
    debug(len(unused['services']) + len(unused['servicegroups']), unused_count)
    # print(expanded_svcgroup)

    '''for category in unused:
        print ('-' * 180)
        print(category, len(unused[category]))
        print ('-' * 180)
        for item in unused[category]:
            print('{},{}'.format(category,item))
    '''

    return unused


def find_unused(config, context):
    # WARNING :  This routine only checks for unused objects in areas that are loaded from the config for migration.
    # For example an address object could be used for a NAT rule, but since NAT rules are not currently migrated, NAT
    # rules are not searched.  This find_unused function should only be used for migration script purposes, and updated
    # if/when new migration functionality is added.  A second function should be created to count the number of
    # occurrences an object name exists in the entire configuration file, if broader support for unused object detection
    # is needed.

    # Fix logic of this routine, as it is fairly slow.
    # Loop over every address object
    # Check if object is an address or group (Does this really matter?)
    # Check to see if it is used in an address group object, a policy source/dest or routing object

    unused = defaultdict(dict)
    expanded_addrgroup = defaultdict(dict)

    total = len(config['addresses'])
    count = 0
    loopcount = 0

    unused['addressgroups'] = []
    unused['addresses'] = []

    # FIND UNUSED ADDRESS GROUPS

    addr_list = list(config['addresses'].keys())  # create list of all address objects

    # build expanded address list for all address groups  # improves speed by about 6x

    for address in config['addresses']:
        if config['addresses'][address]['addrObjType'] == '8':
            expanded_addrgroup[address] = expand_address(config['addresses'], config['addresses'][address]['addrObjId'],
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
                    # expand_address(config['addresses'], source, config['addressmappings'], True):
                    found_in_policy = True
                    break
            # CHECK EACH DESTINATION ADDRESS OBJECT IN POLICY
            for dest in config['policies'][policy]['policyDstNet']:
                if config['addresses'][address1]['addrObjId'] == dest:
                    found_in_policy = True
                    break
                if config['addresses'][address1]['addrObjId'] in expanded_addrgroup[source]:
                    # expand_address(config['addresses'], dest, config['addressmappings'], True):
                    # if config['addresses'][address1][-'addrObjId']
                    # in expand_address(config['addresses'], dest, config['addressmappings'], True):
                    found_in_policy = True
                    break
        # CHECK IF THE ADDRESS IS PART OF AN ADDRESS GROUP
        if found_in_policy is False:  # check to see if address is used in a group, somewhere
            found_in_group = False

            for address2 in addr_list:
                if address1 != address2:
                    # Check to see if address is part of an adress group mapping
                    if config['addresses'][address1]['addrObjId'] \
                            in expanded_addrgroup[config['addresses'][address2]['addrObjId']]:
                        # expand_address(config['addresses'], config['addresses'][address2]['addrObjId'],
                        # config['addressmappings'], True):
                        found_in_group = True
                        break

            if found_in_group is False:
                found_in_route = False
                for route in config['routing']:
                    if address1 == config['routing'][route]['pbrObjSrc'] \
                            or address1 == config['routing'][route]['pbrObjDst'] \
                            or address1 == config['routing'][route]['pbrObjGw']:
                        found_in_route = True
                        break
                    if address1 in expanded_addrgroup[config['routing'][route]['pbrObjSrc']] \
                            or address1 in expanded_addrgroup[config['routing'][route]['pbrObjDst']] \
                            or address1 in expanded_addrgroup[config['routing'][route]['pbrObjGw']]:
                        found_in_route = True
                        break
                if found_in_route is False:
                    if config['addresses'][address1]['addrObjType'] == '8':
                        unused['addressgroups'].append(address1)
                    else:
                        unused['addresses'].append(address1)
        count = count + 1
        if not options.web: log('[' + str(count) + '/' + str(total) + ']   ', end='\r')

    # FIND UNUSED SERVICE OBJECTS

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
                    if config['services'][service1]['svcObjId'] \
                            in expand_service(config['services'], service, config['servicemappings'], True):
                        found_in_policy = True
                        break
                    # DOES THE SERVICE MATCH THE SOURCE EXACTLY?
                    if config['services'][service1]['svcObjId'] == service:
                        found_in_policy = True
                        break

            # CHECK IF THE SERVICE IS PART OF A SERVICE GROUP
            # (DONE) CHANGEME - expand_service needs to be updated to include service groups  (inc_group=True param now passed to function)

            if found_in_policy is False:  # check to see if service is used in a group, somewhere
                found_in_group = False
                for service2 in config['services']:
                    loopcount = loopcount + 1
                    if service1 != service2:
                        # Check to see if service is in an expanded service object
                        # (should not need to perform this check for service groups)
                        # WHY NOT?
                        if config['services'][service1]['svcObjId'] \
                                in expand_service(config['services'], config['services'][service2]['svcObjId'],
                                                  config['servicemappings'], True):
                            found_in_group = True
                            break
                if found_in_group is False:
                    found_in_route = False
                    for route in config['routing']:
                        if service1 == config['routing'][route]['pbrObjSvc']:
                            found_in_route = True
                    if found_in_route is False:
                        unused['servicegroups'].append(service1)
        count = count + 1
        if not options.web: log('[' + str(count) + '/' + str(total) + ']   ', end='\r')

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
                            if config['services'][service1]['svcObjId'] in expand_service(config['services'], service,
                                                                                          context, True):
                                found_in_policy = True
                                break
                    if config['services'][service1]['svcObjId'] == service:
                        found_in_policy = True
                        break
            if found_in_policy is False:  # check to see if service is used in a group, somewhere
                found_in_group = False
                for service2 in config['services']:
                    if service1 != service2 and config['services'][service2]['svcObjType'] == "2":
                        if config['services'][service1]['svcObjId'] \
                                in expand_service(config['services'], config['services'][service2]['svcObjId'],
                                                  config['servicemappings'], True):
                            found_in_group = True
                            break
                if found_in_group is False:
                    unused['services'].append(service1)
        count = count + 1
        if not options.web: log('[' + str(count) + '/' + str(total) + ']    ', end='\r')
    return unused


def get_address_of(addresses, address_object):

    # Given an address object name, it will return the IP address object of it.
    # (DONE) Should be modified to also return netmask

    if address_object not in addresses:  # this should be handled better
        addresses = config['shared']['addresses']
    if address_object == '0.0.0.0' or address_object=='':
        return '0.0.0.0','0'
    elif addresses[address_object]['addrObjType'] in ['1', '99', '91']:
        return addresses[address_object]['addrObjIp1'], '32'
    elif addresses[address_object]['addrObjType'] == '89':  #Palo FQDN object
        return addresses[address_object]['fqdn'], 'fqdn'
    elif addresses[address_object]['addrObjType'] == '2':
        return addresses[address_object]['addrObjIp1'], addresses[address_object]['addrObjIp2']
    elif addresses[address_object]['addrObjType'] == '98': # group with exception
        return None, None
        # return addresses[address_object]['addrObjIp1'], addresses[address_object]['addrObjIp2']
        # return addresses[address_object]['addrObjIp1'], addresses[address_object]['addrObjIp2']
    else:
        try:
            #log(addresses[address_object]['addrObjIp1'], addresses[address_object]['addrObjIp2'])
            return addresses[address_object]['addrObjIp1'], str(sum([bin(int(x)).count("1") for x in addresses[address_object]['addrObjIp2'].split(".")]));
        except:
            #log(address_object, addresses[address_object]['addrObjIp1'], addresses[address_object]['addrObjIp2'])
            return None, None

def get_prot_of(services, service_object):

    # Given a service object name, will return the IP protocol number of it.

    if service_object not in services:
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


def get_port_of(services, service_object):
    ## Given a service object name, will return the L4 protocol number of it.

    if service_object not in services:
        services = config['shared']['services']
    if service_object == '0':
        return 'any', 'any'
    else:
        return services[service_object]['svcObjPort1'], services[service_object]['svcObjPort2']


def get_ports_of(services, service_object):
    ## Given a service object name, will return the L4 protocol number of it.

    import re
    portlist = []
    if service_object == '0':
        return ['any']  # list(range(1))
    if service_object not in services:
        services = config['shared']['services']
    if service_object in services:
        if services[service_object]['svcObjType'] == '1':
            if services[service_object]['svcObjPort1'] == '':
                # debug(services[service_object])
                services[service_object]['svcObjPort1'] = '0'
            if services[service_object]['svcObjPort2'] == '':
                services[service_object]['svcObjPort2'] = services[service_object]['svcObjPort1']
            # log(services[service_object]['svcObjPort1'])
            # log(services[service_object]['svcObjPort2'])
            if services[service_object]['svcObjPort1'] == 'echo-request':
                services[service_object]['svcObjPort1'] = '8'
            elif services[service_object]['svcObjPort1'] == 'echo-reply':
                services[service_object]['svcObjPort1'] = '0'
            elif services[service_object]['svcObjPort1'] == 'alternative-host':
                services[service_object]['svcObjPort1'] = '6'
            elif services[service_object]['svcObjPort1'] == 'mobile-registration-reply':
                services[service_object]['svcObjPort1'] = '36'
            elif services[service_object]['svcObjPort1'] in ['mobile-registration-request', 'mobile-host-redirect',
                                                             'datagram-error', 'traceroute', 'address-mask-reply',
                                                             'address-mask-request', 'info-reply', 'info-request',
                                                             'timestamp-reply', 'timestamp', 'parameter-problem']:
                services[service_object]['svcObjPort1'] = '99'
                services[service_object]['svcObjPort2'] = '99'

            if services[service_object]['svcObjPort2'] == 'echo-request':
                # needed to fix Port2 value for icmp objects read in via sonicwall API
                services[service_object]['svcObjPort2'] = '8'
            elif services[service_object]['svcObjPort2'] == 'echo-reply':
                services[service_object]['svcObjPort2'] = '0'
            elif services[service_object]['svcObjPort2'] == 'alternative-host':
                services[service_object]['svcObjPort2'] = '6'
            elif services[service_object]['svcObjPort2'] == 'mobile-registration-reply':
                services[service_object]['svcObjPort2'] = '36'
            elif services[service_object]['svcObjPort2'] in ['mobile-registration-request', 'mobile-host-redirect',
                                                             'datagram-error', 'traceroute']:
                services[service_object]['svcObjPort2'] = '99'
            try:
                tmp = int(services[service_object]['svcObjPort1'])
            except:
                services[service_object]['svcObjPort1'] = '99'
                services[service_object]['svcObjPort2'] = '99'

            return list(
                range(int(services[service_object]['svcObjPort1']), int(services[service_object]['svcObjPort2']) + 1))
        elif services[service_object]['svcObjType'] == '4':
            for ports in services[service_object]['svcObjPortSet']:
                if re.findall('-', ports) != []:
                    first, last = ports.split('-')
                    portlist.extend(list(range(int(first), int(last) + 1)))
                else:
                    portlist.extend([int(ports)])
        elif services[service_object]['svcObjType'] == '4':  ## add support to get port list for service group
            pass
        return portlist

    return []


def get_src_ports_of(services, service_object):
    ## Given a service object name, will return the L4 protocol number of it.

    import re
    portlist = []
    if service_object == '0':
        return ['any']  # list(range(1))
    if service_object not in services:
        services = config['shared']['services']
    if service_object in services:
        if services[service_object]['svcObjType'] == '1':
            if services[service_object]['svcObjPort1'] == '':
                # debug(services[service_object])
                services[service_object]['svcObjPort1'] = '0'
            if services[service_object]['svcObjPort2'] == '':
                services[service_object]['svcObjPort2'] = services[service_object]['svcObjPort1']
            # log(services[service_object]['svcObjPort1'])
            # log(services[service_object]['svcObjPort2'])
            return list(
                range(int(services[service_object]['svcObjPort1']), int(services[service_object]['svcObjPort2']) + 1))
        elif services[service_object]['svcObjType'] == '4':
            for ports in services[service_object]['svcObjPortSet']:
                if re.findall('-', ports) != []:
                    first, last = ports.split('-')
                    portlist.extend(list(range(int(first), int(last) + 1)))
                else:
                    portlist.extend([int(ports)])
        elif services[service_object]['svcObjType'] == '4':  ## add support to get port list for service group
            pass
        return portlist

    return []


def create_addresses(addresses, addressesfqdn, address_map, builtin_map):
    # Generate address and address-group portions of Palo Alto .xml configuration

    log('          <address>')
    for index in addresses:
        # if addresses[index]['addrObjProperties'] != '14':
        #      debug(addresses[index]['addrObjId'])
        # nat_index=1
        # if addresses[index]['addrObjProperties'] == '14' and addresses[index]['addrObjType'] != '8':
        if addresses[index]['addrObjType'] != '8':
            # and ( addresses[index]['addrObjProperties'] == '14' or addresses[index]['addrObjId'] in builtin_map):
            # if addresses[index]['addrObjProperties'] != '14':
            # check to see if address object is used in a NAT rule -- If so, create new NAT address object
            #    pass
            '''
                #tmp_address=None
                for policy in nat_policies:
                    if nat_policies[policy]['natPolicyProperties'] not in ['1023', '17407']:
                        tmp_address=None
                        #nat_props = [ 'natPolicyOrigSrc', 'natPolicyOrigDst', 'natPolicyOrigSvc', 'natPolicyTransSrc', 'natPolicyTransDst', 'natPolicyTransSvc', 'natPolicySrcIface', 'natPolicyDstIface', 'natPolicyEnabled', 'natPolicyComment', 'natPolicyProperties', 'natPolicyName' ]
                        if addresses[index]['addrObjId'] in nat_policies[policy]['natPolicyOrigSrc']:
                            tmp_address='NAT_OrigSrc_{}'.format(int(policy)+1)
                        elif addresses[index]['addrObjId'] in nat_policies[policy]['natPolicyOrigDst']:
                            tmp_address='NAT_OrigDst_{}'.format(int(policy)+1)
                        elif addresses[index]['addrObjId'] in nat_policies[policy]['natPolicyTransSrc']:
                            tmp_address='NAT_TransSrc_{}'.format(int(policy)+1)
                        elif addresses[index]['addrObjId'] in nat_policies[policy]['natPolicyTransDst']:
                            tmp_address='NAT_TransDst_{}'.format(int(policy)+1)
                        if tmp_address:
                            log('            <entry name="' + sc(tmp_address) + '">')
                            if addresses[index]['addrObjType'] == '1':
                                log('              <ip-netmask>' + addresses[index]['addrObjIp1'] + '/32</ip-netmask>')
                            elif addresses[index]['addrObjType'] == '2':
                                log('              <ip-range>' + addresses[index]['addrObjIp1'] + '-' + addresses[index]['addrObjIp2'] + '</ip-range>')
                            elif addresses[index]['addrObjType'] == '4':
                                bitmask = sum([bin(int(x)).count("1") for x in addresses[index]['addrObjIp2'].split(".")])
                                log('              <ip-netmask>' + addresses[index]['addrObjIp1'] + '/' + str(bitmask) + '</ip-netmask>')
                            log('              <description>' + ss(addresses[index]['addrObjIdDisp']) + '</description>')
                            log('            </entry>')
            '''
            # else:
            if addresses[index]['addrObjProperties'] == '14':
                tmp_addr = sc(addresses[index]['addrObjId'])
            else:
                tmp_addr = "BUILTIN_" + sc(
                    addresses[index]['addrObjId'])  # placeholder name, eventually use the builtin map name
            log('            <entry name="' + tmp_addr + '">')
            if addresses[index]['addrObjType'] == '1':
                log('              <ip-netmask>' + addresses[index]['addrObjIp1'] + '/32</ip-netmask>')
            elif addresses[index]['addrObjType'] == '2':
                log('              <ip-range>' + addresses[index]['addrObjIp1'] + '-' + addresses[index][
                    'addrObjIp2'] + '</ip-range>')
            elif addresses[index]['addrObjType'] == '4':
                bitmask = sum([bin(int(x)).count("1") for x in addresses[index]['addrObjIp2'].split(".")])
                log('              <ip-netmask>' + addresses[index]['addrObjIp1'] + '/' + str(
                    bitmask) + '</ip-netmask>')
            log('              <description>' + ss(addresses[index]['addrObjIdDisp']) + '</description>')
            log('            </entry>')
            # addressfqdn_props = ['addrObjFqdnId', 'addrObjFqdnType', 'addrObjFqdnZone', 'addrObjFqdnProperties',
            # 'addrObjFqdn']

    for index in addressesfqdn:
        log('            <entry name="' + sc(addressesfqdn[index]['addrObjFqdnId']) + '">')
        log('              <fqdn>{}</fqdn>'.format(addressesfqdn[index]['addrObjFqdn']))
        log('              <disable-override>no</disable-override>')
        log('              <description>{}</description>'.format(addressesfqdn[index]['addrObjFqdnId']))
        log('            </entry>')

    # log('            <entry name="' + 'Address_Object_Placeholder' + '">')
    # log('              <ip-netmask>' + '255.255.255.255/32</ip-netmask>')
    # log('            </entry>')

    log('          </address>')
    log('          <address-group>')
    for index in addresses:
        if addresses[index]['addrObjType'] is '8':
            # and ( addresses[index]['addrObjProperties'] == '14' or addresses[index]['addrObjId'] in builtin_map):
            if addresses[index]['addrObjProperties'] == '14':
                tmp_addr = sc(addresses[index]['addrObjId'])
            else:
                tmp_addr = "BUILTIN_" + sc(addresses[index]['addrObjId'])

            # log('            <entry name="' +  tmp_addr + '">')

            if index in address_map:
                if len(address_map[index]) > 0:
                    log('            <entry name="' + tmp_addr + '">')
                    log('              <static>')
                    for member in address_map[index]:
                        if member in addresses:
                            if addresses[member]['addrObjProperties'] != '14':  # in builtin_map:
                                log('                <member>' + "BUILTIN_" + sc(member) + '</member>')
                            else:

                                log('                <member>' + sc(member) + '</member>')
                        else:  # member is likely addressfqdn
                            log('                <member>' + sc(member) + '</member>')
                    log('              </static>')
                    log('            <description>"' + ss(addresses[index]['addrObjId']) + '"</description>')
                    log('            </entry>')
            # else:
            #    log('<member>Address_Object_Placeholder</member>')

            # log('            <description>"' + ss(addresses[index]['addrObjId']) + '"</description>')
            # log('            </entry>')
    log('          </address-group>')


def create_services(services, service_map):
    # Generate service and service-group portions of Palo Alto .xml configuration
    log("          <service>")
    for index in services:
        if services[index]['svcObjIpType'] in ['6', '17']:
            log('            <entry name="' + sc(services[index]['svcObjId']) + '">')
            log('              <description>"' + ss(services[index]['svcObjId']) + '"</description>')
            log('              <protocol>')
            if services[index]['svcObjIpType'] == '6':
                log('                <tcp>')
            elif services[index]['svcObjIpType'] == '17':
                log('                <udp>')
            log('                  <port>' + services[index]['svcObjPort1'], end='')
            if services[index]['svcObjPort1'] != services[index]['svcObjPort2']:
                log('-' + services[index]['svcObjPort2'], end='')
            log('</port>')
            if services[index]['svcObjIpType'] == '6':
                log('                </tcp>')
            elif services[index]['svcObjIpType'] == '17':
                log('                </udp>')
            log('              </protocol>')
            log('            </entry>')

    log('            <entry name="' + 'Service_Object_Placeholder' + '">')
    log('              <description>"' + 'Service Object Placeholder for empty groups' + '"</description>')
    log('              <protocol>')
    log('                <tcp>')
    log('                  <port>0</port>')
    log('                </tcp>')
    log('              </protocol>')
    log('            </entry>')

    log('          </service>')

    log('          <service-group>')
    for index in services:
        if services[index]['svcObjIpType'] == '0':
            log('            <entry name="' + sc(services[index]['svcObjId']) + '">')
            log('              <members>')
            member_found = False
            if index in service_map:
                if len(service_map[index]) > 0:
                    for member in service_map[index]:
                        if services[member]['svcObjIpType'] in ['6', '17', '0']:
                            log('                <member>' + sc(member) + '</member>')
                            member_found = True
            if member_found == False:
                log('<member>Service_Object_Placeholder</member>')
            log('              </members>')
            log('            </entry>')
    log('          </service-group>')


def create_network(interfaces, interface_map, zones, routes, context, zone_map):

    # Create Network, Interface and Zone portions of Palo Alto .xml configuration

    log('      <vsys>')
    log('        <entry name=\'vsys1\'>')
    log('          <zone>')
    for zone_index in zones:
        member_found = False
        if zones[zone_index]['zoneObjId'].lower() in zone_map:
            out_zone = zone_map[zones[zone_index]['zoneObjId'].lower()]
            # else:
            # out_zone=zones[zone_index]['zoneObjId']
            log('            <entry name="' + out_zone + '">')
            log('              <network>')
            for interface_index in interfaces:
                if interfaces[interface_index]['interface_Zone'].lower() == zones[zone_index]['zoneObjId'].lower() and \
                        zones[zone_index]['zoneObjId'] != 'MGMT' and interface_index in interface_map:
                    if member_found is False:
                        log('                <layer3>')
                        member_found = 1
                    log('                  <member>' + interface_map[
                        unquote(interfaces[interface_index]['iface_name'])] + '</member>')
            if member_found is False:
                log('                <layer3/>')
            else:
                log('                </layer3>')
            log('              </network>')
            if zones[zone_index]['zoneObjId'].lower() == 'lan' and options.userid:
                log('              <enable-user-identification>yes</enable-user-identification>')
            log('            </entry>')
    log('          </zone>')
    if options.userid:
        log('          <user-id-agent>')
        log('            <entry name="Admin-UserID">')
        log('              <host>10.58.90.53</host>')
        log('              <port>5007</port>')
        log('              <ldap-proxy>yes</ldap-proxy>')
        log('              <collectorname>Admin-UserID</collectorname>')
        log('              <secret>-AQ==bsiEbjhCKN6u/kaJRdoALKqdudY=CvD+ExaF9qHBrdQejLQD7g==</secret>')
        log('            </entry>')
        log('          </user-id-agent>')
    log('          <import>')
    log('            <network>')
    log('              <interface>')
    # for zone_index in zones:
    log(interface_map)
    log(interfaces)
    for interface_index in interfaces:
        # if interfaces[interface_index]['interface_Zone'].lower() in zone_map and interface_map[interfaces[interface_index]['iface_name']] != 'MGMT' and interface_index in interface_map:
        if interfaces[interface_index]['interface_Zone'].lower() in zone_map and unquote(
                interface_index) in interface_map:
            if interface_map[unquote(interfaces[interface_index]['iface_name'])] != 'MGMT':
                log('                <member>' + interface_map[
                    unquote(interfaces[interface_index]['iface_name'])] + '</member>')
    log('              </interface>')
    log('              <virtual-router>')
    log('                <member>' + options.vrouter + '</member>')
    log('              </virtual-router>')
    log('            </network>')
    log('          </import>')
    log('        </entry>')
    log('</vsys>')

    # Missing config elements

    log("      <network>")

    # create interface-management-profile
    # TODO Some of the networks below should be removed as they now belong to NTT

    log("        <profiles>")
    log("          <interface-management-profile>")
    log("            <entry name=\"" + customops.int_mgmt_profile + "\">")
    log("              <https>yes</https>")
    log("              <ssh>yes</ssh>")
    log("              <ping>yes</ping>")
    log("              <permitted-ip>")
    log("                <entry name=\"10.0.0.0/8\"/>")
    log("                <entry name=\"143.166.0.0/16\"/>")
    log("                <entry name=\"163.244.0.0/16\"/>")
    log("                <entry name=\"155.16.0.0/15\"/>")
    log("                <entry name=\"160.110.0.0/16\"/>")
    log("                <entry name=\"165.136.0.0/16\"/>")
    log("                <entry name=\"148.9.32.0/20\"/>")
    log("              </permitted-ip>")
    log("              <snmp>yes</snmp>")
    log("              <userid-service>yes</userid-service>")
    log("              <userid-syslog-listener-ssl>yes</userid-syslog-listener-ssl>")
    log("              <userid-syslog-listener-udp>yes</userid-syslog-listener-udp>")
    log("            </entry>")
    log("          </interface-management-profile>")
    log("        </profiles>")

    # create interfaces

    log("        <interface>")
    log("          <ethernet>")
    #  need to get interface mappings

    for interface_index in interfaces:
        if interfaces[interface_index]['iface_type'] in ['1', '6', '7'] \
                and interfaces[interface_index]['interface_Zone'].lower() in zone_map and interface_index in interface_map:
            log("          <entry name=\"" + interface_map[unquote(interfaces[interface_index]['iface_name'])] + "\">")
            log("            <layer3>")
            log("              <ipv6>")
            log("                <neighbor-discovery>")
            log("                  <router-advertisement>")
            log("                    <enable>no</enable>")
            log("                  </router-advertisement>")
            log("                </neighbor-discovery>")
            log("              </ipv6>")
            # Add lines here for VLAN subinterfaces
            subint_found = False
            import re
            for sub_interface in interfaces:
                if re.findall(interface_map[unquote(interfaces[interface_index]['iface_name'])] + "\.",
                              interface_map[unquote(interfaces[sub_interface]['iface_name'])]) \
                        and interface_map[unquote(interfaces[interface_index]['iface_name'])] \
                        != interface_map[unquote(interfaces[sub_interface]['iface_name'])] \
                        and sub_interface in interface_map:
                    if not subint_found:
                        log("              <untagged-sub-interface>no</untagged-sub-interface>")
                        log("              <units>")
                        subint_found = True
                    log('                <entry name="' + interface_map[
                        unquote(interfaces[sub_interface]['iface_name'])] + '">')
                    log('                  <ipv6>')
                    log('                    <neighbor-discovery>')
                    log('                      <enable-dad>no</enable-dad>')
                    log('                      <dad-attempts>1</dad-attempts>')
                    log('                      <ns-interval>1</ns-interval>')
                    log('                      <reachable-time>30</reachable-time>')
                    log('                    </neighbor-discovery>')
                    log('                    <enabled>no</enabled>')
                    log('                    <interface-id>EUI-64</interface-id>')
                    log('                  </ipv6>')
                    log('                  <ip>')
                    ip = interfaces[sub_interface]['iface_lan_ip']
                    mask = str(
                        sum([bin(int(x)).count("1") for x in interfaces[sub_interface]['iface_lan_mask'].split(".")]))

                    log('                    <entry name="' + ip + '/' + mask + '"/>')
                    log('                  </ip>')
                    log('                  <adjust-tcp-mss>')
                    log('                    <enable>no</enable>')
                    log('                    <ipv4-mss-adjustment>40</ipv4-mss-adjustment>')
                    log('                    <ipv6-mss-adjustment>60</ipv6-mss-adjustment>')
                    log('                  </adjust-tcp-mss>')
                    log('                  <tag>' + interfaces[sub_interface]['iface_vlan_tag'] + '</tag>')
                    # CHANGEME - use customops.int_mgmt_profile if interface zone is LAN
                    if interfaces[sub_interface]['interface_Zone'] == "LAN":
                        log('                  <interface-management-profile>' + customops.int_mgmt_profile + '</interface-management-profile>')
                    else:
                        log('                  <interface-management-profile>Allow ping</interface-management-profile>')
                    log('                </entry>')
            if subint_found:
                log("              </units>")
            log("              <ndp-proxy>")
            log("                <enabled>no</enabled>")
            log("              </ndp-proxy>")
            log("              <lldp>")
            log("                <enable>no</enable>")
            log("              </lldp>")
            log("              <ip>")

            if interfaces[interface_index]['iface_type'] == '1' \
                    and interfaces[interface_index]['interface_Zone'].lower() in zone_map \
                    and interface_index in interface_map:
                ip = interfaces[interface_index]['iface_static_ip']
                mask = str(
                    sum([bin(int(x)).count("1") for x in interfaces[interface_index]['iface_static_mask'].split(".")]))
                log("                <entry name=\"" + ip + "/" + mask + "\"/>")
                log("              </ip>")
                if interfaces[interface_index]['interface_Zone'].lower() == "lan":
                    log("              <interface-management-profile>" + customops.int_mgmt_profile + "</interface-management-profile>")
                log("            </layer3>")
                log("          </entry>")

            if interfaces[interface_index]['iface_type'] in ['6', '7'] \
                    and interfaces[interface_index]['interface_Zone'].lower() in zone_map \
                    and interface_index in interface_map:
                ip = interfaces[interface_index]['iface_lan_ip']
                mask = str(
                    sum([bin(int(x)).count("1") for x in interfaces[interface_index]['iface_lan_mask'].split(".")]))
                log("                <entry name=\"" + ip + "/" + mask + "\"/>")
                log("             </ip>")
                if interfaces[interface_index]['interface_Zone'].lower() == "lan":
                    log("             <interface-management-profile>" + customops.int_mgmt_profile + "</interface-management-profile>")
                log("           </layer3>")
                log("          </entry>")
    log("          </ethernet>")
    log("        </interface>")

    # Add virtual router

    log("        <virtual-router>")
    log("          <entry name=\"" + options.vrouter + "\">")
    log("            <routing-table>")
    log("              <ip>")
    log("                <static-route>")
    routecounter = 1

    defroute = False

    for route_index in routes:
        if routes[route_index]['pbrObjGw'] != '':
            nexthop, mask = get_address_of(config[context]['addresses'], routes[route_index]['pbrObjGw'])
            ## CHANGEME -- Use expand_address instead of address_mappings for dest, as dest can be any address type, not just a group
            if routes[route_index]['pbrObjSrc'] == '':  ## only add routes without a source specified
                if routes[route_index]['pbrObjSrc'] == '' and routes[route_index]['pbrObjDst'] == '' and \
                        routes[route_index]['pbrObjSvc'] == '':  # default route
                    log("                <entry name=\"Default Route\">")
                    log("                  <nexthop>")
                    log("                    <ip-address>" + nexthop + "</ip-address>")
                    log("                  </nexthop>")
                    log("                  <destination>0.0.0.0/0</destination>")
                    log("                </entry>")
                    defroute = True
                for dest in expand_address(config[context]['addresses'], routes[route_index]['pbrObjDst'],
                                           config[context]['addressmappings']):
                    if config[context]['addresses'][dest]['addrObjType'] in ['1', '4']:
                        address, mask = get_address_of(config[context]['addresses'], dest)
                        log("                  <entry name=\"Route " + str(routecounter) + "\">")
                        log("                    <nexthop>")
                        log("                      <ip-address>" + nexthop + "</ip-address>")
                        log("                    </nexthop>")
                        log("                    <destination>" + address + "/" + mask + "</destination>")
                        log("                  </entry>")
                        routecounter = routecounter + 1

    # Add Default Route
    # Is this a valid assumption?? CHANGEME
    if not defroute:
        defgateway = False
        for defgateway_index in interfaces:
            if interfaces[defgateway_index]['iface_static_gateway'] != '0.0.0.0' \
                    and interfaces[defgateway_index]['iface_static_gateway'] != '0.0.0.1':
                defgateway = interfaces[defgateway_index]['iface_static_gateway']

        if defgateway:
            log("                <entry name=\"Default Route\">")
            log("                  <nexthop>")
            log("                    <ip-address>" + defgateway + "</ip-address>")
            log("                  </nexthop>")
            log("                  <destination>0.0.0.0/0</destination>")
            log("                </entry>")

    log("              </static-route>")
    log("            </ip>")
    log("          </routing-table>")

    # Add Network Interfaces to VRouter

    log("          <interface>")
    for interface_index in interfaces:
        if interfaces[interface_index]['iface_type'] in ['1', '6', '7'] \
                and interfaces[interface_index]['interface_Zone'].lower() in zone_map \
                and interface_index in interface_map:
            log("            <member>" + interface_map[
                unquote(interfaces[interface_index]['iface_name'])] + "</member>")
    log("            </interface>")
    log("          </entry>")
    log("        </virtual-router>")
    log("      </network>")

    log("      <deviceconfig>")
    log("        <system>")
    log(
        '''          <domain>''' + customops.domain + '''</domain>
          <dns-setting>
            <servers>
              <primary>''' + customops.dnsservers[0] + '''</primary>
              <secondary>''' + customops.dnsservers[1] + '''</secondary>
            </servers>
          </dns-setting>
          <secure-proxy-server>''' + customops.secureproxy['host'] + '''</secure-proxy-server>
          <secure-proxy-port>''' + customops.secureproxy['port'] + '''</secure-proxy-port>
          <timezone>''' + customops.timezone + '''</timezone>
          <ntp-servers>
            <primary-ntp-server>
              <ntp-server-address>''' + customops.ntpservers[0] + '''</ntp-server-address>
              <authentication-type>
                <none/>
              </authentication-type>
            </primary-ntp-server>
            <secondary-ntp-server>
              <ntp-server-address>''' + customops.ntpservers[1] + '''</ntp-server-address>
              <authentication-type>
                <none/>
              </authentication-type>
            </secondary-ntp-server>
          </ntp-servers>
          <update-server>''' + customops.updateserver + '''</update-server>
          <snmp-setting>
            <access-setting>
              <version>
                <v2c>
                  <snmp-community-string>''' + customops.snmpsettings['community'] + '''</snmp-community-string>
                </v2c>
              </version>
            </access-setting>
            <snmp-system>
              <contact>''' + customops.snmpsettings['contact'] + '''</contact>
              <location>''' + customops.snmpsettings['location'] + '''</location>
            </snmp-system>
          </snmp-setting>
          <login-banner>''' + customops.loginbanner + '''</login-banner>
''')
    # Add mgmt interface ip

    for interface_index in interfaces:
        # this needs to go somewhere else....
        if interfaces[interface_index]['iface_type'] == '12':
            ip = interfaces[interface_index]['iface_mgmt_ip']
            mask = sum([bin(int(x)).count("1") for x in interfaces[interface_index]['iface_mgmt_netmask'].split(".")])
            log("          <ip-address>" + ip + "</ip-address>")
            log("          <netmask>" + interfaces[interface_index]['iface_mgmt_netmask'] + "</netmask>")
            log("         <default-gateway>" + interfaces[interface_index][
                'iface_mgmt_default_gw'] + "</default-gateway>")

    log("        </system>")
    log("      </deviceconfig>")
    return


def create_policies(policy_object, context, zone_map):
    # Create Policy portion of Palo Alto .xml configuration

    count = 1

    log('            <security>')
    log('              <rules>')
    # log(zone_map)
    for policy_index in policy_object:

        tmp_srcnet = policy_object[policy_index]['policySrcNet']
        tmp_dstnet = policy_object[policy_index]['policyDstNet']
        tmp_dstsvc = policy_object[policy_index]['policyDstSvc']
        if tmp_srcnet == [''] or tmp_srcnet == []:
            tmp_srcnet = ['any']
        if tmp_dstnet == [''] or tmp_dstnet == []:
            tmp_dstnet = ['any']
        if tmp_dstsvc == [''] or tmp_dstsvc == []:
            tmp_dstsvc = ['any']

        if policy_object[policy_index]['policyProps'] == '0'\
                and 'MULTICAST' not in policy_object[policy_index]['policySrcZone'] \
                and 'MULTICAST' not in policy_object[policy_index]['policyDstZone']:

            # if dstzone.lower() in zone_map and srczone.lower() in zone_map:
            if (list(set([x.lower() for x in policy_object[policy_index]['policySrcZone']]) & set(
                    [y.lower() for y in zone_map])) != []) and (
                    list(set([xx.lower() for xx in policy_object[policy_index]['policyDstZone']]) & set(
                            [yy.lower() for yy in zone_map])) != []):  ##m3 line
                # if list(set([x.lower() for x in policy_object[policy_index]['policySrcZone']])
                # & set([y.lower() for y in zone_map])) != [] and list(set([xx.lower()
                # for xx in policy_object[policy_index]['policyDstZone']])
                # & set([yy.lower() for yy in zone_map])) != []:
                log('                <entry name="' + customops.base_rule_name + '%04d' % count + '_' + sc(
                    tmp_dstsvc[0]) + '">')
                log('                  <target>')
                log('                    <negate>no</negate>')
                log('                  </target>')
                log('                  <to>')
                for dstzone in policy_object[policy_index]['policyDstZone']:
                    if dstzone.lower() in zone_map:
                        out_zone = zone_map[dstzone.lower()]
                    else:
                        out_zone = dstzone

                    log('                    <member>' + out_zone + '</member>')
                log('                  </to>')
                log('                  <from>')
                for srczone in policy_object[policy_index]['policySrcZone']:
                    if srczone.lower() in zone_map:
                        out_zone = zone_map[srczone.lower()]
                    else:
                        out_zone = srczone
                    log('                    <member>' + out_zone + '</member>')
                log('                  </from>')
                log('                  <source>')
                for srcnet in tmp_srcnet:
                    if srcnet.lower() == 'any':
                        tmp_src = srcnet
                    elif srcnet in config[context]['addresses']:
                        if config[context]['addresses'][srcnet]['addrObjProperties'] == '14':
                            tmp_src = srcnet
                        else:
                            tmp_src = "BUILTIN_" + sc(srcnet)
                    elif srcnet in config[context]['addressesfqdn']:
                        tmp_src = srcnet
                    log('                    <member>' + sc(tmp_src) + '</member>')
                log('                  </source>')
                log('                  <destination>')
                for dstnet in tmp_dstnet:
                    if dstnet.lower() == 'any':
                        tmp_dst = dstnet
                    elif dstnet in config[context]['addresses']:
                        if config[context]['addresses'][dstnet]['addrObjProperties'] == '14':
                            tmp_dst = dstnet
                        else:
                            tmp_dst = "BUILTIN_" + sc(dstnet)
                    elif dstnet in config[context]['addressesfqdn']:
                        tmp_dst = dstnet
                    log('                    <member>' + sc(tmp_dst) + '</member>')
                log('                  </destination>')
                log('                            <source-user>')
                log('                    <member>any</member>')
                log('                  </source-user>')
                log('                  <category>')
                log('                    <member>any</member>')
                log('                  </category>')
                log('                  <application>')
                log('                    <member>any</member>')
                log('                  </application>')
                log('                 <service>')
                for dstsvc in tmp_dstsvc:
                    log('                    <member>' + sc(dstsvc) + '</member>')
                log('                  </service>')
                log('                  <hip-profiles>')
                log('                    <member>any</member>')
                log('                  </hip-profiles>')
                log('                  <description>' + ss(policy_object[policy_index]['policyComment']))
                log('')
                if policy_object[policy_index]['policySrcZone'][0].lower() in zone_map:
                    out_srczone = zone_map[policy_object[policy_index]['policySrcZone'][0].lower()]
                else:
                    out_srczone = policy_object[policy_index]['policySrcZone'][0]
                if policy_object[policy_index]['policyDstZone'][0].lower() in zone_map:
                    out_dstzone = zone_map[policy_object[policy_index]['policyDstZone'][0].lower()]
                else:
                    out_dstzone = policy_object[policy_index]['policyDstZone'][0]
                log(out_srczone + '__' + out_dstzone + '__' + sc(tmp_srcnet[0]) + '__' + sc(tmp_dstnet[0]) + '__' + sc(
                    tmp_dstsvc[0]))
                log('                  </description>')
                if policy_object[policy_index]['policyAction'] == '0':
                    log('                  <action>deny</action>')
                if policy_object[policy_index]['policyAction'] == '1':
                    log('                  <action>drop</action>')
                if policy_object[policy_index]['policyAction'] == '2':
                    log('                  <action>allow</action>')
                if policy_object[policy_index]['policyEnabled'] != '1':
                    log('<disabled>yes</disabled>')
                log('                  <log-setting>' + customops.log_forward_profile_name + '</log-setting>')
                log('                  <profile-setting>')
                log('                    <group>')
                log('                      <member>' + customops.rule_profile_setting + '</member>')
                log('                    </group>')
                log('                  </profile-setting>')
                log('                </entry>')

        # Get a list of ICMP services used in this rule
        icmp_ports = []
        for dstsvc in tmp_dstsvc:
            for svc in expand_service(config[context]['services'], dstsvc, config[context]['servicemappings'],
                                      inc_group=False):
                if str.lower(get_prot_of(config[context]['services'], svc)) == 'icmp':
                    icmp_ports.append(get_port_of(config[context]['services'], svc))

        # If ICMP is defined in this rule, add a new icmp rule using application

        if icmp_ports != []:
            if policy_object[policy_index]['policyProps'] == '0' \
                    and 'MULTICAST' not in policy_object[policy_index]['policySrcZone'] \
                    and 'MULTICAST' not in policy_object[policy_index]['policyDstZone']:
                if list(set([x.lower() for x in policy_object[policy_index]['policySrcZone']]) & set(
                        [y.lower() for y in zone_map])) != [] and list(
                        set([xx.lower() for xx in policy_object[policy_index]['policyDstZone']]) & set(
                                [yy.lower() for yy in zone_map])) != []:
                    log('                <entry name="' + customops.base_rule_name + '%04d-icmp">' % count)
                    log('                  <target>')
                    log('                    <negate>no</negate>')
                    log('                  </target>')
                    log('                  <to>')
                    for dstzone in policy_object[policy_index]['policyDstZone']:
                        if dstzone.lower() in zone_map:
                            out_zone = zone_map[dstzone.lower()]
                        else:
                            out_zone = dstzone
                        log('                    <member>' + out_zone + '</member>')
                    log('                  </to>')
                    log('                  <from>')
                    for srczone in policy_object[policy_index]['policySrcZone']:
                        if srczone.lower() in zone_map:
                            out_zone = zone_map[srczone.lower()]
                        else:
                            out_zone = srczone
                        log('                    <member>' + out_zone + '</member>')
                    log('                  </from>')
                    log('                  <source>')
                    for srcnet in tmp_srcnet:
                        log('                    <member>' + sc(srcnet) + '</member>')
                    log('                  </source>')
                    log('                  <destination>')
                    for dstnet in tmp_dstnet:
                        log('                    <member>' + sc(dstnet) + '</member>')
                    log('                  </destination>')
                    log('                            <source-user>')
                    log('                    <member>any</member>')
                    log('                  </source-user>')
                    log('                  <category>')
                    log('                    <member>any</member>')
                    log('                  </category>')

                    log('                  <application>')
                    '''if sorted(icmp_ports) == ['0','8']:
                        icmp_svc = 'ping'
                    else:
                        icmp_svc = 'icmp'
                    log('                    <member>' + icmp_svc + '</member>')
                    '''
                    log('                    <member>' + 'ping' + '</member>')
                    log('                    <member>' + 'icmp' + '</member>')
                    log('                    <member>' + 'traceroute' + '</member>')

                    log('                  </application>')
                    log('                 <service>')
                    log('                    <member>application-default</member>')
                    log('                  </service>')
                    log('                  <hip-profiles>')
                    log('                    <member>any</member>')
                    log('                  </hip-profiles>')
                    log('                  <description>' + ss(policy_object[policy_index]['policyComment']))
                    log('')
                    if policy_object[policy_index]['policySrcZone'][0].lower() in zone_map:
                        out_srczone = zone_map[policy_object[policy_index]['policySrcZone'][0].lower()]
                    else:
                        out_srczone = policy_object[policy_index]['policySrcZone'][0]
                    if policy_object[policy_index]['policyDstZone'][0].lower() in zone_map:
                        out_dstzone = zone_map[policy_object[policy_index]['policyDstZone'][0].lower()]
                    else:
                        out_dstzone = policy_object[policy_index]['policyDstZone'][0]
                    log(out_srczone + '__' + out_dstzone + '__' + sc(tmp_srcnet[0]) + '__' + sc(
                        tmp_dstnet[0]) + '__' + sc(tmp_dstsvc[0]))
                    log('                  </description>')
                    if policy_object[policy_index]['policyAction'] == '0':
                        log('                  <action>deny</action>')
                    if policy_object[policy_index]['policyAction'] == '1':
                        log('                  <action>drop</action>')
                    if policy_object[policy_index]['policyAction'] == '2':
                        log('                  <action>allow</action>')
                    if policy_object[policy_index]['policyEnabled'] != '1':
                        log('<disabled>yes</disabled>')
                    log('                  <log-setting>' + customops.log_forward_profile_name + '</log-setting>')
                    log('                  <profile-setting>')
                    log('                    <group>')
                    log('                      <member>' + customops.rule_profile_setting + '</member>')
                    log('                    </group>')
                    log('                  </profile-setting>')
                    log('                </entry>')

        if 'MULTICAST' not in policy_object[policy_index]['policySrcZone'] and 'MULTICAST' not in \
                policy_object[policy_index]['policyDstZone']:
            count = count + 1
    log('              </rules>')
    log('            </security>')

    return



