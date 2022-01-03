from . import utils
from . import sonicwall_utils
from . import rulesearch_utils
from . import dumpConfig_utils
import xlsxwriter


# todo: check for xlswriter file
def get_creds():
    import getpass
    username = input("  Username : ")
    password = getpass.getpass("  Password : ")
    return username, password


class Services:
    config = {}

    def __init__(self, config) -> None:
        self.config = config

    # todo: not sure how to create config .. so considering it as parameter?
    # consider input as dict 
    # implement try - catch for service nexpose function
    def service_nexpose(self, options):  ## create address objects

        def run_parallel(targets, max_proc=48):

            from multiprocessing import Pool

            pool = Pool(processes=max_proc)
            return pool.map(utils.bulk_create_addresses, targets)

        if options.grouptargets:
            results = run_parallel(options.grouptargets)
            for target, new_addresses, existing_addresses, members_added, members_existed in results:
                if new_addresses != 'Exception':
                    # check for better way 
                    print('{},{},{},{}'.format(target, 'New Addresses', len(new_addresses), new_addresses))
                    print(
                        '{},{},{},{}'.format(target, 'Existing Addresses', len(existing_addresses), existing_addresses))
                    print('{},{},{},{}'.format(target, 'New Group Members', len(members_added), members_added))
                    print('{},{},{},{}'.format(target, 'Existing Group Members', len(members_existed), members_existed))
                else:
                    print('{},{},{}'.format(target, 'Exception', new_addresses))

        else:
            print(options.grouptargets)
            print('Creating bulk objects without target group targets specified')
            utils.bulk_create_addresses(None, self.config, self.params)

    # todo: contexts and config
    def service_ruleSearch(self, options):
        rulesearch_utils.find_matching_rules2(self.config, self.config['shared'], options.rulematch, self.contexts, options, options.rulemodify)

    # dump config
    def dump_config(self, config, contexts):

        sh_addr = []
        sh_svc = []

        #Output to XLSX
        path = ''

        for context in contexts:
            print('\r!-- Dumping ' + context + ' to Excel                                                 ')
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
                    xl_policies.write(row, col, dumpConfig_utils.ss(output), cell_format)
                row += 1

            row = 1
            for map in config[context]['addressmappings']:
                if row % 2 == 1:
                    cell_format = workbook.add_format({'bg_color': '#DDDDDD', 'text_wrap': True})
                else:
                    cell_format = workbook.add_format({'bg_color': '#BBBBBB', 'text_wrap': True})
                xl_addressgroups.write(row, 0, dumpConfig_utils.ss(map), cell_format)
                output = ''
                for index, item in enumerate(config[context]['addressmappings'][map]):
                    output += item
                    if index < len(config[context]['addressmappings'][map]) - 1:
                        output += '\n'
                xl_addressgroups.write(row, 1, utils.ss(output), cell_format)
                row += 1
            if 'shared' in config:
                for map in config['shared']['addressmappings']:
                    if map in sh_addr:
                        if row % 2 == 1:
                            cell_format = workbook.add_format({'bg_color': '#AAAAAA', 'text_wrap': True})
                        else:
                            cell_format = workbook.add_format({'bg_color': '#999999', 'text_wrap': True})
                        xl_addressgroups.write(row, 0, dumpConfig_utils.ss(map), cell_format)
                        output = ''
                        for index, item in enumerate(config['shared']['addressmappings'][map]):
                            output += item
                            if index < len(config['shared']['addressmappings'][map]) - 1:
                                output += '\n'

                        xl_addressgroups.write(row, 1, dumpConfig_utils.ss(output), cell_format)
                        row += 1

            row = 1
            for map in config[context]['servicemappings']:
                if row % 2 == 1:
                    cell_format = workbook.add_format({'bg_color': '#DDDDDD', 'text_wrap': True})
                else:
                    cell_format = workbook.add_format({'bg_color': '#BBBBBB', 'text_wrap': True})
                xl_servicegroups.write(row, 0, dumpConfig_utils.ss(map), cell_format)
                output = ''
                for index, item in enumerate(config[context]['servicemappings'][map]):
                    output += item
                    if index < len(config[context]['servicemappings'][map]) - 1:
                        output += '\n'
                xl_servicegroups.write(row, 1, dumpConfig_utils.ss(output), cell_format)
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
                        xl_servicegroups.write(row, 1, dumpConfig_utils.ss(output), cell_format)
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
                    xl_addresses.write(row, col, dumpConfig_utils.ss(output), cell_format)
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
                            xl_addresses.write(row, col, utils.ss(output), cell_format)
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
                    xl_services.write(row, col, dumpConfig_utils.ss(output), cell_format)
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
                            xl_services.write(row, col, dumpConfig_utils.ss(output), cell_format)
                        row += 1

            workbook.close()

    def service_migration(self, options):
        # log("!-- Retrieving sonicwall config")
        if not options.web and (options.username == None or options.password == None):
            options.username, options.password = get_creds()
        config = sonicwall_utils.get_sonicwall_exp(options.sonicwallip)

        config['shared'] = {}
        config['shared']['config'] = {}
        config['shared']['config']['name'] = ''
        config['shared']['config']['fw_type'] = ''
        config['shared']['config']['version'] = ''
        config['shared']['config']['mgmtip'] = ''
        config['shared']['addresses'] = {}
        config['shared']['services'] = {}
        config['shared']['policies'] = {}  # return_policy
        config['shared']['nat'] = {}
        config['shared']['apps'] = {}
        config['shared']['addressmappings'] = {}
        config['shared']['servicemappings'] = {}
        config['shared']['logprofiles'] = {}
