import sys
from logger import log
from helper import sc, ss
from network_helper import expand_address, create_network, create_addresses, create_services
from nat import create_nat
from network_helper import create_policies


def create_config(config, interface_map, outfile, context):
    ## Create a Palo Alto configuration file.  Intended to be used with a Sonicwall source input file.
    ## Not intended to be used for Palo Alto to Palo Alto use.

    if options.zonemaps:
        zone_map = {}
        for zonemap in options.zonemaps:
            old_zone, new_zone = zonemap.split(',')
            zone_map[old_zone.lower()] = new_zone

    out = open(outfile, 'w')
    stdout = sys.stdout
    sys.stdout = out

    # zone_map={}

    '''
    if options.zonemaps:
        for zonemap in options.zonemaps:
            if len(re.findall(',', zonemap))==1:
                zonemap=zonemap.replace(', ',',').replace(' ,',',')
                old_zone, new_zone=zonemap.split(',')
                zone_map[old_zone.lower()]=new_zone
                #zone_map[xls.lower()]['fwzone']=fwzone
                #zone_map[xls.lower()]['policytext']=policytext
                #debug(xls, fwzone, policytext)
    '''

    ## build list of built-in objects that are in use by nat policies
    builtin_map = {}
    builtin_index = 0
    for policy in config['nat']:
        if config['nat'][policy]['natPolicyProperties'] not in ['1023', '17407']:
            for obj_type in ['natPolicyOrigSrc', 'natPolicyOrigDst', 'natPolicyTransSrc', 'natPolicyTransDst']:
                if config['nat'][policy][obj_type][0] != '':
                    if config['addresses'][config['nat'][policy][obj_type][0]]['addrObjProperties'] != '14':
                        if config['nat'][policy][obj_type][0] not in builtin_map:
                            builtin_map[config['nat'][policy][obj_type][0]] = 'BUILTIN_' + sc(
                                config['nat'][policy][obj_type][0])
                            # debug('built-in object {}'.format(config['nat'][policy][obj_type][0]))
                            # debug('built-in object {}'.format(sc(config['nat'][policy][obj_type][0])))
                        if config['addresses'][config['nat'][policy][obj_type][0]]['addrObjType'] == '8':
                            ## def expand_address(address_dict, address_object, address_map, inc_group=False):
                            for addr in expand_address(config['addresses'],
                                                       config['addresses'][config['nat'][policy][obj_type][0]][
                                                           'addrObjId'], config['addressmappings']):
                                if config['addresses'][addr]['addrObjProperties'] != '14':
                                    if addr not in builtin_map:
                                        # debug('built-in group member {}'.format(ss(addr)))
                                        builtin_map[addr] = 'BUILTIN_' + sc(addr)

        '''
        if config['nat'][policy]['natPolicyOrigDst'][0]!='':
            if config['addresses'][config['nat'][policy]['natPolicyOrigDst'][0]]['addrObjProperties'] != '14':
                debug('built-in object {}'.format(config['nat'][policy]['natPolicyOrigDst']))
                if config['nat'][policy]['natPolicyOrigDst'][0] not in builtin_map:
                    builtin_map[config['nat'][policy]['natPolicyOrigDst'][0]]='Temp'
        if config['nat'][policy]['natPolicyTransSrc'][0]!='':
            if config['addresses'][config['nat'][policy]['natPolicyTransSrc'][0]]['addrObjProperties'] != '14':
                debug('built-in object {}'.format(config['nat'][policy]['natPolicyTransSrc']))
                if config['nat'][policy]['natPolicyTransSrc'][0] not in builtin_map:
                    builtin_map[config['nat'][policy]['natPolicyTransSrc'][0]]='Temp'
        if config['nat'][policy]['natPolicyTransDst'][0]!='':
            if config['addresses'][config['nat'][policy]['natPolicyTransDst'][0]]['addrObjProperties'] != '14':
                debug('built-in object {}'.format(config['nat'][policy]['natPolicyTransDst']))
                if config['nat'][policy]['natPolicyTransDst'][0] not in builtin_map:
                    builtin_map[config['nat'][policy]['natPolicyTransDst'][0]]='Temp'
        '''

    log('<config version=\"7.1.0\" urldb=\"paloaltonetworks\">')
    create_logging()
    log('  <devices>')
    log('    <entry name=\"localhost.localdomain\">')
    create_network(config['interfaces'], interface_map, config['zones'], config['routing'], context, zone_map)
    log('      <device-group>')
    log('        <entry name="' + customops.devicegroup_name + '">')
    create_addresses(config['addresses'], config['addressesfqdn'], config['addressmappings'], builtin_map)
    create_services(config['services'], config['servicemappings'])
    log('          <pre-rulebase>')

    create_policies(config['policies'], context, zone_map)
    create_nat(config['nat'], context, zone_map, interface_map, config['interfaces'], builtin_map)
    log('          </pre-rulebase>')
    log('          <profile-group>')
    log('            <entry name="' + customops.rule_profile_setting + '"/>')
    log('          </profile-group>')
    log('        <devices/>')
    log('        </entry>')
    log('      </device-group>')
    log('    </entry>')
    log('  </devices>')
    log('</config>')
    sys.stdout = stdout
    out.close
    return;


def dump_config(config, contexts):
    # Not complete?  There might be cases in with shared objects are not handled correctly?
    # Dynamic column widths by tracking longest length item and calling set_column after data is written?

    import xlsxwriter

    sh_addr = []
    sh_svc = []

    ## Output to XLSX
    path = ''

    for context in contexts:
        log('\r!-- Dumping ' + context + ' to Excel                                                 ')
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
                xl_policies.write(row, col, ss(output), cell_format)
            row += 1

        row = 1
        for map in config[context]['addressmappings']:
            if row % 2 == 1:
                cell_format = workbook.add_format({'bg_color': '#DDDDDD', 'text_wrap': True})
            else:
                cell_format = workbook.add_format({'bg_color': '#BBBBBB', 'text_wrap': True})
            xl_addressgroups.write(row, 0, ss(map), cell_format)
            output = ''
            for index, item in enumerate(config[context]['addressmappings'][map]):
                output += item
                if index < len(config[context]['addressmappings'][map]) - 1:
                    output += '\n'
            xl_addressgroups.write(row, 1, ss(output), cell_format)
            row += 1
        if 'shared' in config:
            for map in config['shared']['addressmappings']:
                if map in sh_addr:
                    if row % 2 == 1:
                        cell_format = workbook.add_format({'bg_color': '#AAAAAA', 'text_wrap': True})
                    else:
                        cell_format = workbook.add_format({'bg_color': '#999999', 'text_wrap': True})
                    xl_addressgroups.write(row, 0, ss(map), cell_format)
                    output = ''
                    for index, item in enumerate(config['shared']['addressmappings'][map]):
                        output += item
                        if index < len(config['shared']['addressmappings'][map]) - 1:
                            output += '\n'

                    xl_addressgroups.write(row, 1, ss(output), cell_format)
                    row += 1

        row = 1
        for map in config[context]['servicemappings']:
            if row % 2 == 1:
                cell_format = workbook.add_format({'bg_color': '#DDDDDD', 'text_wrap': True})
            else:
                cell_format = workbook.add_format({'bg_color': '#BBBBBB', 'text_wrap': True})
            xl_servicegroups.write(row, 0, ss(map), cell_format)
            output = ''
            for index, item in enumerate(config[context]['servicemappings'][map]):
                output += item
                if index < len(config[context]['servicemappings'][map]) - 1:
                    output += '\n'
            xl_servicegroups.write(row, 1, ss(output), cell_format)
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
                    xl_servicegroups.write(row, 1, ss(output), cell_format)
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
                xl_addresses.write(row, col, ss(output), cell_format)
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
                        xl_addresses.write(row, col, ss(output), cell_format)
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
                    # debug('col:' + str(col))
                    # debug('key: ' + str(key))
                    # debug(config[context]['services'][service])
                    # debug(config[context]['services'][service][key])
                    if key in config[context]['services'][service]:
                        output = str(config[context]['services'][service][key])
                    pass
                if row % 2 == 1:
                    cell_format = workbook.add_format({'bg_color': '#DDDDDD', 'text_wrap': True})
                else:
                    cell_format = workbook.add_format({'bg_color': '#BBBBBB', 'text_wrap': True})
                xl_services.write(row, col, ss(output), cell_format)
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
                        xl_services.write(row, col, ss(output), cell_format)
                    row += 1

        workbook.close()
