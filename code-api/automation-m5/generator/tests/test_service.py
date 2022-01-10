import netaddr
import urllib
import sonicwall as sw
import re
from netaddr import IPSet
import re
import ipaddress
import re
import sonicwall as sw
import pandas
from urllib.parse import quote, unquote


# routines to determine address objects defined with a zone that differs from the routing table
def address_routing_table():
    context = None
    for contexts in config:

        if config[contexts]['config']['fw_type'] == 'sonicwall':
            context = contexts
            break
    log(context)
    context = 'checkpoint'
    for address in config[context]['addresses']:
        if config[context]['addresses'][address]['addrObjType'] in ['1', '4']:
            # log('config   : ', config[context]['addresses'][address]['addrObjId'], config[context]['addresses'][address]['addrObjZone'])
            # log('get_zone : ', config[context]['addresses'][address]['addrObjId'], get_zone(context, config[context]['addresses'][address]['addrObjIp1']))
            if config[context]['addresses'][address]['addrObjZone'] != get_zone(context,
                                                                                config[context]['addresses'][address][
                                                                                    'addrObjIp1']) and \
                    config[context]['addresses'][address]['addrObjIp1'] != '0.0.0.0':
                log('ZONEINFO: ', address, get_zone(context, config[context]['addresses'][address]['addrObjIp1']))
                # log('Zone mismatch for object {:40.40} {:20.20} - config: {:10.10} - get_zone: {:10.10}'.format(config[context]['addresses'][address]['addrObjId'], config[context]['addresses'][address]['addrObjIp1'], config[context]['addresses'][address]['addrObjZone'], get_zone(context, config[context]['addresses'][address]['addrObjIp1'])))
    print('-' * 160)
    for route in config[context]['routing']:
        print(route)
        route_dest = config[context]['routing'][route]['pbrObjDst']
        if route_dest == '':
            route_dest = '0.0.0.0'
        for route_dest_addr in expand_address(config[context]['addresses'], route_dest,
                                              config[context]['addressmappings']):
            if route_dest_addr in config[context]['addresses']:
                # print(route_dest_addr)
                # print(dest_ip)
                # if netaddr.IPAddress(dest_ip) in netaddr.IPNetwork('{}/{}'.format(config[context]['addresses'][route_dest_addr]['addrObjIp1'], config[context]['addresses'][route_dest_addr]['addrObjIp2'])):
                # print('{:24.24s} - {:24.24s}'.format(config[context]['routing'][route]['pbrObjDst'], config[context]['routing'][route]['pbrObjGw'] ))
                print('{:>24.24s}/{} - {} - {}'.format(config[context]['addresses'][route_dest_addr]['addrObjIp1'],
                                                       netmask_to_cidr(
                                                           config[context]['addresses'][route_dest_addr]['addrObjIp2']),
                                                       config[context]['addresses'][
                                                           config[context]['routing'][route]['pbrObjGw']]['addrObjIp1'],
                                                       config[context]['addresses'][
                                                           config[context]['routing'][route]['pbrObjGw']][
                                                           'addrObjZone']))
        # routing_props = ['pbrObjId', 'pbrObjProperties', 'pbrObjSrc', 'pbrObjDst', 'pbrObjSvc', 'pbrObjGw', 'pbrObjIface', 'pbrObjIfaceName', 'pbrObjMetric', 'pbrObjPriority', 'pbrObjProbe', 'pbrObjComment']
        # print('{:24.24s} - {:24.24s}'.format(config[context]['routing'][route]['pbrObjDst'], config[context]['routing'][route]['pbrObjGw'] ))
    for interface in config[context]['interfaces']:
        if config[context]['interfaces'][interface]['interface_Zone'] != '':
            if config[context]['interfaces'][interface]['iface_static_ip'] != '0.0.0.0':
                print('{:>24.24s}/{} - {:24.24s} - {:24.24s}'.format(
                    config[context]['interfaces'][interface]['iface_static_ip'],
                    netmask_to_cidr(config[context]['interfaces'][interface]['iface_static_mask']),
                    config[context]['interfaces'][interface]['iface_static_gateway'],
                    config[context]['interfaces'][interface]['interface_Zone']))
            if config[context]['interfaces'][interface]['iface_lan_ip'] != '0.0.0.0':
                print('{:>24.24s}/{} - {:24.24s} - {:24.24s}'.format(
                    config[context]['interfaces'][interface]['iface_lan_ip'],
                    netmask_to_cidr(config[context]['interfaces'][interface]['iface_lan_mask']),
                    config[context]['interfaces'][interface]['iface_lan_default_gw'],
                    config[context]['interfaces'][interface]['interface_Zone']))
            if config[context]['interfaces'][interface]['iface_mgmt_ip'] != '0.0.0.0':
                print('{:>24.24s}/{} - {:24.24s} - {:24.24s}'.format(
                    config[context]['interfaces'][interface]['iface_mgmt_ip'],
                    netmask_to_cidr(config[context]['interfaces'][interface]['iface_mgmt_netmask']),
                    config[context]['interfaces'][interface]['iface_mgmt_default_gw'],
                    config[context]['interfaces'][interface]['interface_Zone']))
    log('INTERFACE', config[context]['interfaces'])
    log('INTERFACE', config[context]['zones'])
    log('INTERFACE', config[context]['routing'])


# routines to get zone of ip address based on routing table/interface info
def get_zone_from_routing_table():
    dest_ip = '132.5.6.9'
    dest_ips = ['10.25.116.3', '10.7.200.1']
    for dest_ip in dest_ips:
        print('-' * 100)

        for context in contexts:
            log('Searching {} for address : {}'.format(context, dest_ip))
            print('-' * 100)

            if 'routing' in config[context]:
                matchlen = 0
                for route in config[context]['routing']:
                    route_dest = config[context]['routing'][route]['pbrObjDst']
                    if route_dest == '':
                        route_dest = '0.0.0.0'
                    # print(route_dest)
                    if route_dest in config[context]['addresses']:
                        # print(config[context]['addresses'][route_dest])
                        if config[context]['addresses'][route_dest]['addrObjType'] == '8':
                            debug('Route Destination is a group, checking each member object')
                            for route_dest_addr in expand_address(config[context]['addresses'], route_dest,
                                                                  config[context]['addressmappings']):
                                if route_dest_addr in config[context]['addresses']:
                                    # print(route_dest_addr)
                                    # print(dest_ip)
                                    if netaddr.IPAddress(dest_ip) in netaddr.IPNetwork(
                                            '{}/{}'.format(config[context]['addresses'][route_dest_addr]['addrObjIp1'],
                                                           config[context]['addresses'][route_dest_addr][
                                                               'addrObjIp2'])):
                                        # if netaddr.IPAddress(dest_ip) in netaddr.IPNetwork('{}/{}'.format(config[config[context]['addresses']['addrObjIp1'], netmask_to_cidr(config[context]['interfaces'][interface]['iface_lan_mask']))):
                                        # config[context]['addresses'][route_dest_addr]['IPSet']:
                                        debug('Searched address found in destination group: "{}"'.format(
                                            urllib.parse.unquote(route_dest)))
                                        if netmask_to_cidr(
                                                config[context]['addresses'][route_dest_addr]['addrObjIp2']) > matchlen:
                                            matchlen = netmask_to_cidr(
                                                config[context]['addresses'][route_dest_addr]['addrObjIp2'])
                                            next_hop = config[context]['routing'][route]['pbrObjGw']
                                            if next_hop in config[context]['addresses']:
                                                next_hop_ip = config[context]['addresses'][next_hop]['addrObjIp1']
                                            else:
                                                next_hop_ip = next_hop
                                        else:
                                            debug('Skipping - not longest match')
                        else:
                            if dest_ip in config[context]['addresses'][route_dest]['IPSet']:
                                debug('Searched address found in destination address')
                                if netmask_to_cidr(
                                        config[context]['addresses'][route_dest_addr]['addrObjIp2']) > matchlen:
                                    matchlen = netmask_to_cidr(
                                        config[context]['addresses'][route_dest_addr]['addrObjIp2'])
                                    next_hop = config[context]['routing'][route]['pbrObjGw']
                                    if next_hop in config[context]['addresses']:
                                        next_hop_ip = config[context]['addresses'][next_hop]['addrObjIp1']
                                    else:
                                        next_hop_ip = next_hop
                                else:
                                    debug('Skipping - not longest match')
                            # print(next_hop)
                            # print(next_hop_ip)
                    # print(config[context]['interfaces'])
                if matchlen != 0:
                    for interface in config[context]['interfaces']:
                        if config[context]['interfaces'][interface]['iface_lan_ip'] != '0.0.0.0':
                            if netaddr.IPAddress(next_hop_ip) in netaddr.IPNetwork(
                                    '{}/{}'.format(config[context]['interfaces'][interface]['iface_lan_ip'],
                                                   netmask_to_cidr(config[context]['interfaces'][interface][
                                                                       'iface_lan_mask']))):
                                # print('{} - {}/{}'.format(config[context]['interfaces'][interface]['iface_name'],config[context]['interfaces'][interface]['iface_lan_ip'],config[context]['interfaces'][interface]['iface_lan_mask']))
                                print(
                                    'ROUTE MATCH - Searched address {} is in Zone : {} Interface Name: {} Interface Address {}/{}'.format(
                                        dest_ip, config[context]['interfaces'][interface]['interface_Zone'],
                                        config[context]['interfaces'][interface]['iface_name'], '', ''))
                        if config[context]['interfaces'][interface]['iface_static_ip'] != '0.0.0.0':
                            if netaddr.IPAddress(next_hop_ip) in netaddr.IPNetwork(
                                    '{}/{}'.format(config[context]['interfaces'][interface]['iface_static_ip'],
                                                   netmask_to_cidr(config[context]['interfaces'][interface][
                                                                       'iface_static_mask']))):
                                # print('{} - {}/{}'.format(config[context]['interfaces'][interface]['iface_name'],config[context]['interfaces'][interface]['iface_static_ip'],config[context]['interfaces'][interface]['iface_static_mask']))
                                print(
                                    'ROUTE MATCH - Searched address {} is in Zone : {} Interface Name: {} Interface Address {}/{}'.format(
                                        dest_ip, config[context]['interfaces'][interface]['interface_Zone'],
                                        config[context]['interfaces'][interface]['iface_name'], '', ''))
                        if config[context]['interfaces'][interface]['iface_mgmt_ip'] != '0.0.0.0':
                            if netaddr.IPAddress(next_hop_ip) in netaddr.IPNetwork(
                                    '{}/{}'.format(config[context]['interfaces'][interface]['iface_mgmt_ip'],
                                                   netmask_to_cidr(config[context]['interfaces'][interface][
                                                                       'iface_mgmt_netmask']))):
                                # print('{} - {}/{}'.format(config[context]['interfaces'][interface]['iface_name'],config[context]['interfaces'][interface]['iface_mgmt_ip'],config[context]['interfaces'][interface]['iface_mgmt_netmask']))
                                print(
                                    'ROUTE MATCH - Searched address {} is in Zone : {} Interface Name: {} Interface Address {}/{}'.format(
                                        dest_ip, config[context]['interfaces'][interface]['interface_Zone'],
                                        config[context]['interfaces'][interface]['iface_name'], '', ''))


def log_content(contexts):
    for context in contexts:
        for address in config[context]['addresses']:
            try:
                log('{},{},{}'.format(config[context]['addresses'][address]['addrObjId'],
                                      config[context]['addresses'][address]['connection_limit'],
                                      config[context]['addresses'][address]['auto_calc_conns']))
            except:
                pass


def bind_password():
    binddn_passwords = {'cn=ServiceFWRWemeaprod,ou=service accounts,dc=emea,dc=dell,dc=com'.lower(): 'password1',
                        'cn=ServiceFWRWamerprod,ou=service accounts,dc=amer,dc=dell,dc=com'.lower(): 'password2',
                        'cn=ServiceFWRWapjprod,ou=service accounts,dc=apac,dc=dell,dc=com'.lower(): 'password3'
                        }
    target = '10.215.16.60'
    target = '10.67.73.13'
    options.username = 'admin'
    options.password = 'admin'
    session = requests.Session()
    session.mount('https://' + target, sw.DESAdapter())
    response = sw.do_login(session, options.username, options.password, target, True)
    url = 'https://' + target + '/main.cgi'
    response = sw.get_url(session, 'https://' + target + '/ldapProps.html')
    print(response.text)
    try:
        loginname = re.findall(r'var loginName.*', response.text)[0].split('"')[1].lower()
        print(binddn_passwords[loginname])
    except Exception as e:
        print('Could not get current Bind DN setting')
        print(e)

    sw.do_logout(session, target)
    print(binddn_passwords)


def log_address_of_ip1():
    for context in contexts:
        for address in config[context]['addresses']:
            log(config[context]['addresses'][address]['addrObjIp1'])


# find bi-directional rules
def find_bi_directional_rules():
    for context in config:
        # log(config[context])
        if 'policies' in config[context]:
            for policy in config[context]['policies']:
                # log(context)

                srcSet = IPSet([])
                dstSet = IPSet([])

                for source_index in config[context]['policies'][policy]['policySrcNet']:
                    if source_index.lower() == 'any' and options.zero_network:
                        found_in_source = True
                        source_addr = ['Any']
                        break
                    policyIPv4_srclist = []
                    if (source_index in config[context]['addresses']):
                        for expanded_index in expand_address(config[context]['addresses'],
                                                             config[context]['addresses'][source_index]['addrObjId'],
                                                             config[context]['addressmappings']):
                            if (expanded_index in config[context]['addresses']):
                                policyIPv4_srclist.extend(config[context]['addresses'][expanded_index]['IPv4Networks'])
                            elif (expanded_index in config['shared']['addresses']):
                                policyIPv4_srclist.extend(config['shared']['addresses'][expanded_index]['IPv4Networks'])
                    elif (source_index in config['shared']['addresses']):
                        for expanded_index in expand_address(config['shared']['addresses'],
                                                             config['shared']['addresses'][source_index]['addrObjId'],
                                                             config['shared']['addressmappings']):
                            policyIPv4_srclist.extend(config['shared']['addresses'][expanded_index]['IPv4Networks'])
                            prefix = '*'
                    else:
                        # if source_index.lower() not in ['any', '']: log('UNKNOWN SOURCE "{}"'.format(source_index))
                        try:
                            if re.findall('-', source_index) != []:
                                first, last = source_index.split('-')
                                for x in ipaddress.summarize_address_range(ipaddress.IPv4Address(first),
                                                                           ipaddress.IPv4Address(last)):
                                    policyIPv4_srclist.extend([x])
                            else:
                                first = source_index
                                last = source_index
                                if re.findall('/', first) == []:
                                    first = first + '/32'
                                policyIPv4_srclist.extend([ipaddress.IPv4Network(first)])
                        except Exception as e:
                            debug(e, 'UNKNOWN SOURCE "{}"'.format(source_index))
                            pass

                    srcSet = IPSet([])
                    for x in policyIPv4_srclist:
                        srcSet.add(str(x))

                for dest_index in config[context]['policies'][policy]['policyDstNet']:
                    if dest_index.lower() == 'any' and options.zero_network:
                        found_in_dest = True
                        dest_addr = ['Any']
                        break
                    policyIPv4_dstlist = []
                    if (dest_index in config[context]['addresses']):
                        for expanded_index in expand_address(config[context]['addresses'],
                                                             config[context]['addresses'][dest_index]['addrObjId'],
                                                             config[context]['addressmappings']):
                            if (expanded_index in config[context]['addresses']):
                                policyIPv4_dstlist.extend(config[context]['addresses'][expanded_index]['IPv4Networks'])
                            elif (expanded_index in config['shared']['addresses']):
                                policyIPv4_dstlist.extend(config['shared']['addresses'][expanded_index]['IPv4Networks'])
                    elif (dest_index in config['shared']['addresses']):
                        for expanded_index in expand_address(config['shared']['addresses'],
                                                             config['shared']['addresses'][dest_index]['addrObjId'],
                                                             config['shared']['addressmappings']):
                            policyIPv4_dstlist.extend(config['shared']['addresses'][expanded_index]['IPv4Networks'])
                            prefix = '*'
                    else:
                        try:
                            if re.findall('-', dest_index) != []:
                                first, last = dest_index.split('-')
                                for x in ipaddress.summarize_address_range(ipaddress.IPv4Address(first),
                                                                           ipaddress.IPv4Address(last)):
                                    policyIPv4_dstlist.extend([x])
                            else:
                                first = dest_index
                                last = dest_index
                                if re.findall('/', first) == []:
                                    first = first + '/32'
                                policyIPv4_dstlist.extend([ipaddress.IPv4Network(first)])
                        except Exception as e:
                            debug(e, 'UNKNOWN DESTINATION "{}"'.format(dest_index))
                            pass
                    dstSet = IPSet([])
                    for x in policyIPv4_dstlist:
                        dstSet.add(str(x))
                searchset = IPSet([])
                searchset.add(str(ipaddress.IPv4Network('10.0.0.0/8')))
                # log(dstSet)
                if (ipaddress.IPv4Network('10.0.0.0/8') in policyIPv4_dstlist) and (
                        ipaddress.IPv4Network('10.0.0.0/8') in policyIPv4_srclist):
                    log('{},{},{},{}'.format(context, config[context]['policies'][policy]['policyName'],
                                             config[context]['policies'][policy]['policySrcNet'],
                                             config[context]['policies'][policy]['policyDstNet']))


# find services using a portlist
def find_service_from_port_list(contexts):
    for context in contexts:
        print(context)
        if 'services' in config[context]:
            for service in config[context]['services']:
                portlist = get_ports_of(config[context]['services'], config[context]['services'][service]['svcObjId'])
                if len(portlist) < 100:
                    pass
                    # print(config[context]['services'][service]['svcObjId'], portlist)
                # print(get_ports_of(config[context]['services'], config[context]['services'][service]['svcObjId']))


# Get Syslog server details
def syslog_details():
    matched_context = None
    matched_object = None

    for context in contexts:
        if context != 'shared':
            matched_context = context
            break
    if matched_context:
        session = requests.Session()
        session.mount('https://' + options.sonicwallip, sw.DESAdapter())
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
        if not options.web and (options.username == None or options.password == None):
            options.username, options.password = get_creds()
        response = sw.do_login(session, options.username, options.password, options.sonicwallip, True)
        if response:
            url = 'https://' + options.sonicwallip + '/logSyslogView.html'
            response = sw.get_url(session, url)
            if response:
                data = response.content
                try:
                    tl = pandas.read_html(data, match='Server Name')
                    df = tl[0]
                    # print (df.to_string(index=False, na_rep='',header=False))
                    for table in tl:
                        # print(table)
                        # print(table[0][1])
                        # print(len(table))
                        for row in range(1, len(table) - 1):
                            pattern = re.compile("\((.+)\)")
                            if pattern.search(table[0][row]):
                                server = pattern.search(table[0][row]).group(0)[1:-1]
                                print('{:40.40s}{:100.100s}{:10.10s}'.format(matched_context, server, table[1][row]))
                                # for context in config['config']:
                                #    print(context)

                                server_lower = quote(server, safe='()').lower()
                                debug('"{}"'.format(server_lower))
                                for address in config[matched_context]['addresses']:
                                    debug('"{}"'.format(address))
                                    if address.lower() == server_lower:
                                        matched_object = ('addresses', address)
                                        break
                                if not matched_object:
                                    for address in config[matched_context]['addressesfqdn']:
                                        debug('"{}"'.format(address))
                                        if address.lower() == server_lower:
                                            matched_object = ('addressesfqdn', address)
                                            break

                                if matched_object:
                                    obj_type, obj_name = matched_object
                                    # print(config[matched_context][obj_type][obj_name])
                                # print('-'*100)
                except Exception as e:
                    print(e)
                    print('{:40.40s}{:100.100s}{:10.10s}'.format(matched_context, "Syslog Table not Found", ""))
            else:
                print('{:40.40s}{:100.100s}{:10.10s}'.format(matched_context, "Get Syslog Page Failed", ""))
            sw.do_logout(session, options.sonicwallip)
        else:
            print('{:40.40s}{:100.100s}{:10.10s}'.format(options.sonicwallip, "Login Failed", ""))


# check if sonicwall has current password
def check_sw_current_password():
    old_password = '$0n'
    import sonicwall as sw

    for target in options.grouptargets:
        session = requests.Session()
        session.mount('https://' + target, sw.DESAdapter())
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
        if not options.web and (options.username == None or options.password == None):
            options.username, options.password = get_creds()

        response = sw.do_login(session, options.username, options.password, target, True)
        if response:
            log(target, 'new')
        else:
            response = sw.do_login(session, options.username, old_password, target, True)
            if response:
                log(target, 'old')
            else:
                log(target, 'unknown')


# modify/fix LDAP user groups in 6.5
def edit_ldap_user_groups():
    import sonicwall as sw
    import json
    import re
    import time
    from collections import OrderedDict

    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    for target in options.grouptargets:
        log(target)
        session = requests.Session()
        session.mount('https://' + target, sw.DESAdapter())
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
        sw.do_login(session, 'admin', 'snowflake', target, preempt=True)
        response = sw.get_url(session, 'https://' + target + '/addUserObjGroupDlg.html')
        csrf = re.findall(r'csrfToken.*"', response.text)[0].split('value=')[1].split('"')[1]
        postdata = {'csrfToken': csrf,
                    'cgiaction': "none",
                    'error_page': 'userObjView.html',
                    'refresh_page': '',
                    'userGroupObjId_-2': 'CS_FIREWALL_RW',
                    'userGroupObjComment_-2': 'Read-Write PAC Group',
                    'userGroupObjType_-2': '2',
                    'userGroupObjProperties_-2': '16398',
                    'userGroupObjPrivMask_-2': '128',
                    'userGroupObjVpnDestNet_-2': '',
                    'userGroupOtpReq_-2': '0',
                    'userGroupObjLdapLocn_-2': 'emea.dell.com/AdmAccounts/PrivilegedGroups/CS_Firewall_RW',

                    'userGroupObjId_1': 'CS_FIREWALL_RW',
                    'userGroupObjComment_1': 'Read-Write PAC Group',
                    'userGroupObjType_1': '2',
                    'userGroupObjProperties_1': '131086',
                    'userGroupObjPrivMask_1': '128',
                    'userGroupObjVpnDestNet_1': '',
                    'userGroupOtpReq_1': '0',
                    'userGroupObjLdapLocn_1': 'emea.dell.com/AdmAccounts/PrivilegedGroups/CS_Firewall_RW',
                    'auditPath': 'MANAGE / Users / Local Users & Groups / Edit Group'}

        url = 'https://' + target + '/main.cgi'
        result = send_sw_webcmd(session, url, postdata)
        log('change group result', result)

        response = sw.get_url(session, 'https://' + target + '/addUserObjGroupDlg.html')
        csrf = re.findall(r'csrfToken.*"', response.text)[0].split('value=')[1].split('"')[1]
        postdata = {'csrfToken': csrf,
                    'cgiaction': "none",
                    'error_page': 'userObjView.html',
                    'refresh_page': '',
                    'userGroupObjId_-1': 'CS_FIREWALL_RO',
                    'userGroupObjComment_-1': 'Read-Only PAC Group',
                    'userGroupObjType_-1': '2',
                    'userGroupObjProperties_-1': '131086',
                    'userGroupObjPrivMask_-1': '0',
                    'userGroupObjVpnDestNet_-1': '',
                    'userGroupObjCfspId_-1': '0',
                    'userGroupOtpReq_-1': '0',
                    'userGroupObjLdapLocn_-1': 'emea.dell.com/AdmAccounts/PrivilegedGroups/CS_Firewall_RO'
                    }
        url = 'https://' + target + '/main.cgi'
        sw.do_logout(session, target)


def test1():
    import sonicwall as sw
    import json
    import re
    import time
    from collections import OrderedDict
    import sonicwall as sw
    import re

    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    for target in options.grouptargets:

        ## Enable API first

        session = requests.Session()
        session.mount('https://' + target, sw.DESAdapter())
        sw.do_login(session, options.username, options.password, target, preempt=True)
        response = sw.get_url(session, 'https://' + target + '/systemAdministrationView.html')
        csrf = re.findall(r'csrfToken.*"', response.text)[0].split('value=')[1].split('"')[1]
        postdata = {'csrfToken': csrf,
                    'cgiaction': "none",
                    'sonicOsApi_enable': "on",
                    'sonicOsApi_basicAuth': "on",
                    'cbox_sonicOsApi_enable': "",
                    'cbox_sonicOsApi_basicAuth': ""}
        url = 'https://' + target + '/main.cgi'
        api_result = send_sw_webcmd(session, url, postdata)
        sw.do_logout(session, target)

        ## Use API to send CLI command for groups
        session = requests.Session()
        session.mount('https://' + target, sw.DESAdapter())
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
        url = 'https://{}/api/sonicos/auth'.format(target)
        session.headers = OrderedDict(
            [('User-Agent', 'python-requests/2.18.4'), ('Accept', '*/*'), ('Accept-Encoding', 'gzip, deflate'),
             ('Connection', 'keep-alive')])
        post_data = None
        # auth = requests.auth.HTTPBasicAuth(options.username, options.password)
        response_code = None
        login_tries = 0
        while response_code != 200 and login_tries < 5:
            login_tries += 1
            response = session.post(url=url, headers={'authorization': "Basic " + base64.b64encode(
                '{}:{}'.format(options.username, options.password).encode()).decode()}, verify=False)
            response_code = response.status_code
            if response_code != 200:
                # session = requests.Session()
                # session.mount('https://' + target, sw.DESAdapter())
                # urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
                # url='https://{}/api/sonicos/auth'.format(target)
                debug('Login failed, retrying in 10 seconds')
                time.sleep(10)

        if response_code == 200:
            url = 'https://{}/api/sonicos/direct/cli'.format(target)
            session.headers.update({'content-type': 'text/plain'})

            post_data = 'show user local groups\n'
            result = session.post(url=url, data=post_data, verify=False)
            groups = json.loads(result.text)
            print(groups)
            for group in groups['user']['local']['group']:
                if re.findall(r'^CS_FIREWALL', group['name'].upper()):
                    group_name = group['name']
                    print(group_name)
                    post_data = 'user local\ngroup "{}"\ndomain any\nno memberships-by-ldap-location\ncommit\n'.format(
                        group_name)
                    result = session.post(url=url, data=post_data, verify=False)
                    su_result = json.loads(result.text)['status']['success']

                    log('{},{},{},{},{},{}'.format(target, login_tries, ro_result, rw_result, su_result, ""))

        else:
            log('{},{},{},{},{},{}'.format(target, login_tries, 'Skipped', 'Skipped', 'Skipped', 'Login Failed'))

        # Log out via DELETE method
        url = 'https://{}/api/sonicos/auth'.format(target)
        post_data = None
        session.delete(url=url, verify=False)


# options.nexpose:  ## create address objects
def create_address_object_nexpose():
    import re
    import ipaddress
    import sonicwall as sw
    from netaddr import IPSet, IPRange, IPNetwork

    # input - group name to create
    # input - address object to create with hostname
    # input - validate that each address is valid and does not overlap with any other address (required for sonicwall)
    # load panorama config
    # check for existence of each ip in shared objects - use object that matches FQDN, hostname or first match in that order
    # make sure given address object name doesnt already exist, otherwise keep appending a number
    # groups should be specified as group/group_name rather than group_name/group

    # options.groupaddresses =['192.168.1.0/24,network1', '192.168.2.0/24,network2', '192.168.3.1,host1', '192.168.3.128,host2', '192.168.3.45,host3', '192.168.3.99/32,host4', '65.115.19.0/24,host5', 'OEM-Agent-access/group']
    groupaddresses = []
    for group_address in options.groupaddresses:
        if len(group_address.split(',')) == 2:
            groupaddresses.append(group_address.split(','))
        elif len(group_address.split('/')) == 2:
            if group_address.split('/')[1].lower() == 'group':
                groupaddresses.append(['group', group_address.split('/')[0]])
            else:
                log('Skipping {} as is must contain IPAddress,hostname or groupname/group'.format(group_address))
        else:
            log('Skipping {} as is must contain IPAddress,hostname or groupname/group'.format(group_address))

    addresslist = []
    addipset = IPSet([])  # IPSet of all the addresses being added to ensure none of them overlap
    target = '1.1.1.1'

    # log(groupaddresses)
    result = True

    result = exec_fw_command(options.panoramaip, 'pano', [('create_address',
                                                           {'addressname': options.nexpose, 'addresstype': '8',
                                                            'zone': 'LAN', 'color': 'black', 'comment': 'NEXPOSE_GROUP',
                                                            'members': [], 'context': 'shared'})], syntax='api')

    if result:

        # go create address groups elsewhere....

        for address_set in groupaddresses:
            address = address_set[0]
            badaddress = False
            if address.lower() == 'group':
                if address_set[1] in config['shared']['addresses']:
                    if config['shared']['addresses'][address_set[1]]['addrObjType'] == '8':
                        log('Adding group {} to new group {}'.format(address_set[1], ''))
                        addresslist.append((address_set[1], 'group'))
                    else:  ## no idea what this is doing
                        badaddress = True  ## not an address group
                        log('Skipping {} as it is not an address group object type'.format(group_address))
                        log(config['shared']['addresses'][address]['addrObjType'])
                else:  ## no idea what this is doing
                    badaddress = True  ## not found in addresses
                    log('Skipping {} as it was not found in shared addresses'.format(group_address))

            else:
                if len(re.findall('/', address)) == 1:
                    network, mask = address.split('/')
                elif len(re.findall('-', address)) == 1:  # address object is a range
                    # log('range found')
                    network, mask = address.split('-')
                elif len(re.findall('/', address)) == 0:
                    network = address
                    mask = '32'
                else:
                    log('!-- Skipping {} - Invalid netmask or address group not found'.format(address))
                    badaddress = True

            if not badaddress:
                try:
                    # tmpaddr=ipaddress.IPv4Network(network+'/'+str(mask))
                    tmpaddr = IPNetwork(network + '/' + str(mask))
                except Exception as e:
                    try:
                        # log(network, mask)
                        tmpaddr = IPRange(network, mask)
                    except:
                        log('!-- Skipping {} - {}'.format(address, e))
                        badaddress = True
            if not badaddress:  ## if addresses dont overlap, add the address to "addresslist"
                # if len(IPSet([network+'/'+str(mask)]) & config[context]['addresses'][groupmaster]['IPSet'])==0:
                # if len(IPSet(list(tmpaddr)) & config[context]['addresses'][groupmaster]['IPSet'])==0:
                # log(network)
                # if len(IPSet([network+'/'+str(mask)]) & addipset)==0:
                if len(IPSet(list(tmpaddr)) & addipset) == 0:
                    addresslist.append((network, mask, address))
                    # addipset.add(network+'/'+str(mask))
                    # log(tmpaddr)
                    addipset.add(tmpaddr)
                else:
                    log('!-- Skipping {} - Overlaps with another new address - Target: {}'.format(address, tmpaddr))
            # else:
            #    log('!-- Skipping {} - Overlaps with existing group member - Target: {}'.format(address, target))
        # print (len(config['shared']['addresses']))

        matches = {}

        for addr in addresslist: log(addr)
        log('-' * 100)
        for first, address_name in groupaddresses: log(address_name)

        for network, mask, address in addresslist:  ## build a list of existing address objects that match each object that needs to be created
            new_address = '{}/{}'.format(network, mask)
            matches[new_address] = []
            # log('new address : ', new_address)
            if mask.lower() != 'group':
                for address in config['shared'][
                    'addresses']:  ## build a list of existing address objects that match the object we want to add
                    if config['shared']['addresses'][address]['IPv4Networks'] == [ipaddress.IPv4Network(new_address)]:
                        # log(config['shared']['addresses'][address])
                        if address not in matches[new_address]: matches[new_address].append(address)

        new_address_name = None
        # debug(matches)

        for address_def, address_name in groupaddresses:  ## groupaddresses is a list of the original options.groupaddresses list split into a set of (address definition, name)
            # if address_def==new_address:
            debug('-' * 100)
            debug('outer loop')
            debug(address_name)
            # new_address_name=None
            if address_name.lower() != 'group':
                new_fqdn = address_name
                try:
                    new_hostname = address.name.split('.')[0]
                except:
                    new_hostname = address_name

                if len(matches[new_address]) == 0 and IPNetwork(address_def) == IPNetwork(
                        new_address):  # if no matching object found, create new object
                    new_address_name = address_name
                    log('Creating new address object {} defined as {}'.format(new_address_name, new_address))
                    base_address_name = new_address_name
                    count = 0
                    while new_address_name in config['shared']['addresses']:
                        debug('NAME CONFLICT!')
                        new_address_name = '{}_{}'.format(base_address_name, count)
                        count = +1
                    network, mask = new_address.split('/')
                    mask = cidr_to_netmask(mask)
                    result = exec_fw_command(options.panoramaip, 'pano', [('create_address',
                                                                           {'addressname': new_address_name,
                                                                            'ip1': network, 'ip2': mask,
                                                                            'addresstype': '1', 'zone': 'LAN',
                                                                            'color': 'black',
                                                                            'comment': 'NEXPOSE_SCANNERS',
                                                                            'context': 'shared'})], syntax='api')
                    if not result: log('Creating address object {} failed'.format(new_address_name))
                elif len(matches[new_address]) != 0:
                    for match in matches[new_address]:
                        debug('inner loop')
                        debug('match: ', match)
                        if new_fqdn.lower() == match.lower():  # matching object found, use object that matches FQDN first
                            new_address_name = new_fqdn
                            log('Using existing object name with fqdn match {} instead of {}'.format(new_address_name,
                                                                                                     address_name))
                            break
                        elif new_hostname.lower() == match.lower():  # matching object found, use object that matches hostname second
                            new_address_name = new_hostname
                            log('Using existing object name with hostname match {} instead of {}'.format(
                                new_address_name, address_name))
                            break
                    if not new_address_name:  # matching object found, use the name of the first matched object
                        debug('new address', new_address)
                        debug('matches', matches[new_address])
                        new_address_name = matches[new_address][0]
                        log('Using existing object name first on list {} instead of {}'.format(new_address_name,
                                                                                               address_name))
            if new_address_name:
                result = exec_fw_command(options.panoramaip, 'pano', [('modify_address', {'action': 'addmembers',
                                                                                          'addressname': options.nexpose,
                                                                                          'members': [new_address_name],
                                                                                          'comment': 'NEXPOSE_GROUP',
                                                                                          'addresstype': '8',
                                                                                          'zone': 'LAN',
                                                                                          'color': 'black',
                                                                                          'context': 'shared'})],
                                         syntax='api')
                if not result: log('Adding {} tp group {} failed'.format(new_address_name, options.nexpose))

        # else:  ## new address is a group, use network as the name
        #    new_address_name=network
        # if new_address_name:  ## add address to group
        #    # def create_address_obj(target, session, apikey, fw_type, syntax, params):
        #    # def exec_fw_command(target, fw_type, commands, syntax='cli', policylens=None, delay=None, use_session=True, use_apikey=False, dryrun=False):
        #    #result=exec_fw_command(options.panoramaip, 'pano', [('modify_address', {'action': 'addmembers', 'addressname': options.nexpose, 'members': ['NEXPOSE_'+new_address_name], 'comment': 'NEXPOSE_GROUP', 'addresstype': '8', 'zone': 'LAN', 'color': 'black', 'context': 'shared'})], syntax='api')
        #    pass
        # else:
        #    log('No matching address object')
        # for addr in config['shared']['addresses']:
        #    log(addr)
    else:
        log('Group Creation Failed')


# compare sonicwall NAT rules between versions 6.2 and 6.5 - both contexts must exist in config
# with _new and _old added to context name
def compare_sw_nat_rules():
    import re
    from urllib.parse import quote, unquote

    print(
        '{:20.20s}{:20.20s}{:20.20s}{:20.20s}{:20.20s}{:20.20s}{:40.40s}{:40.40s}{:20.20s}{:20.20s}{:20.20s}{:20.20s}'.format(
            'mgmtip', 'Note', 'new_rule_index', 'orig_src', 'orig_dst', 'orig_svc', 'trans_src', 'trans_dst',
            'trans_svc', 'iface_src', 'iface_dst', 'pol_enabled'))

    for context in config:

        if re.findall(r'_old', context):
            old = context  # .split('_')[0]
        elif re.findall(r'_new', context):
            new = context  # .split('_')[0]
    # OrderedDict([('natPolicyOrigSrc', ['']), ('natPolicyName', ''), ('natPolicyOrigDst', ['']), ('natPolicyOrigSvc', ['Idle%20HF']), ('natPolicyTransSrc', ['HF%20Backup%20X18%3aV1667%20IP']), ('natPolicyTransDst', ['']), ('natPolicyTransSvc', ['']), ('natPolicySrcIface', '-1'), ('natPolicyDstIface', '268862226'), ('natPolicyEnabled', '0'), ('natPolicyComment', 'Stack%20NAT%20Policy%20For%20HF'), ('natPolicyProperties', '1023'), ('natpolicyName', 'Empty'), ('natPolicyNum', ''), ('natPolicyUiNum', '')])
    # print(old, new)
    # print (len(config[new]['nat']), len(config[old]['nat']))
    for new_rule_index in config[new]['nat']:  # ['config']:
        trans_dst_list = []
        trans_src_list = []
        new_rule = config[new]['nat'][new_rule_index]
        orig_src, orig_dst, orig_svc, trans_src, trans_dst, trans_svc, iface_src, iface_dst, pol_enabled = unquote(
            str(new_rule['natPolicyOrigSrc'][0])), unquote(str(new_rule['natPolicyOrigDst'][0])), unquote(
            str(new_rule['natPolicyOrigSvc'][0])), unquote(str(new_rule['natPolicyTransSrc'][0])), unquote(
            str(new_rule['natPolicyTransDst'][0])), unquote(str(new_rule['natPolicyTransSvc'][0])), new_rule[
                                                                                                               'natPolicySrcIface'], \
                                                                                                           new_rule[
                                                                                                               'natPolicyDstIface'], unquote(
            str(new_rule['natPolicyEnabled'] == '1'))
        if orig_src == '': orig_src = 'Any'
        if orig_dst == '': orig_dst = 'Any'
        if orig_svc == '': orig_svc = 'Any'
        if trans_src == '': trans_src = 'Any'
        if trans_dst == '': trans_dst = 'Any'
        if trans_svc == '': trans_svc = 'Any'
        if int(iface_dst) > 0:
            iface_dst = unquote(config[context]['interfaces'][new_rule['natPolicyDstIface']]['iface_name'])
        else:
            iface_dst = 'Any'
        if int(iface_src) > 0:
            iface_src = unquote(config[context]['interfaces'][new_rule['natPolicySrcIface']]['iface_name'])
        else:
            iface_src = 'Any'
        # if iface_src=='-1': iface_src='Any'
        # if iface_src=='-1': iface_src='Any'
        # print(config[new]['nat'][new_rule])
        old_matched = 0
        new_matched = 0
        for old_rule_index in config[old]['nat']:  # ['config']:
            old_rule = config[old]['nat'][old_rule_index]
            if (new_rule['natPolicyOrigSrc'], new_rule['natPolicyOrigDst'], new_rule['natPolicyOrigSvc'],
                new_rule['natPolicyTransSrc'], new_rule['natPolicyTransDst'], new_rule['natPolicyTransSvc'],
                new_rule['natPolicySrcIface'], new_rule['natPolicyDstIface']) == (
                    old_rule['natPolicyOrigSrc'], old_rule['natPolicyOrigDst'], old_rule['natPolicyOrigSvc'],
                    old_rule['natPolicyTransSrc'], old_rule['natPolicyTransDst'], old_rule['natPolicyTransSvc'],
                    old_rule['natPolicySrcIface'], old_rule['natPolicyDstIface']):
                old_matched = old_matched + 1
        for new_rule_index2 in config[new]['nat']:  # ['config']:
            new_rule2 = config[new]['nat'][new_rule_index2]
            if (new_rule['natPolicyOrigSrc'], new_rule['natPolicyOrigDst'], new_rule['natPolicyOrigSvc'],
                new_rule['natPolicyTransSrc'], new_rule['natPolicyTransDst'], new_rule['natPolicyTransSvc'],
                new_rule['natPolicySrcIface'], new_rule['natPolicyDstIface']) == (
                    new_rule2['natPolicyOrigSrc'], new_rule2['natPolicyOrigDst'], new_rule2['natPolicyOrigSvc'],
                    new_rule2['natPolicyTransSrc'], new_rule2['natPolicyTransDst'], new_rule2['natPolicyTransSvc'],
                    new_rule2['natPolicySrcIface'], new_rule2['natPolicyDstIface']):
                new_matched = new_matched + 1
            elif (new_rule['natPolicyOrigSrc'], new_rule['natPolicyOrigDst'], new_rule['natPolicyOrigSvc'],
                  new_rule['natPolicyTransDst'], new_rule['natPolicyTransSvc'], new_rule['natPolicyDstIface']) == (
                    new_rule2['natPolicyOrigSrc'], new_rule2['natPolicyOrigDst'], new_rule2['natPolicyOrigSvc'],
                    new_rule2['natPolicyTransDst'], new_rule2['natPolicyTransSvc'],
                    new_rule2['natPolicyDstIface']) and orig_svc != 'Idle HF' and str(
                new_rule_index + 1) not in trans_src_list:  # and pol_enabled == 'True':
                trans_src_list.append(str(new_rule_index + 1))

                print(
                    '{:20.20s}{:20.20s}{:20.20s}{:20.20s}{:20.20s}{:20.20s}{:40.40s}{:40.40s}{:20.20s}{:20.20s}{:20.20s}{:20.20s}'.format(
                        config[context]['config']['mgmtip'], 'Diff Trans Source', str(new_rule_index + 1), orig_src,
                        orig_dst, orig_svc, trans_src, trans_dst, trans_svc, iface_src, iface_dst, pol_enabled))
        # print(new_rule_index,old_matched, new_matched)

        if old_matched == 0:
            print(
                '{:20.20s}{:20.20s}{:20.20s}{:20.20s}{:20.20s}{:20.20s}{:40.40s}{:40.40s}{:20.20s}{:20.20s}{:20.20s}{:20.20s}'.format(
                    config[context]['config']['mgmtip'], 'No matches', str(new_rule_index + 1), orig_src, orig_dst,
                    orig_svc, trans_src, trans_dst, trans_svc, iface_src, iface_dst, pol_enabled))
        if new_matched > 1:
            print(
                '{:20.20s}{:20.20s}{:20.20s}{:20.20s}{:20.20s}{:20.20s}{:40.40s}{:40.40s}{:20.20s}{:20.20s}{:20.20s}{:20.20s}'.format(
                    config[context]['config']['mgmtip'], 'Multiple matches', str(new_rule_index + 1), orig_src,
                    orig_dst, orig_svc, trans_src, trans_dst, trans_svc, iface_src, iface_dst, pol_enabled))
        # print('{:20.20s}{:20.20s}{:20.20s}{:20.20s}{:20.20s}{:20.20s}{:40.40s}{:40.40s}{:20.20s}{:20.20s}{:20.20s}{:20.20s}'.format(config[context]['config']['mgmtip'], 'All matches', str(new_rule_index + 1), orig_src, orig_dst, orig_svc, trans_src, trans_dst, trans_svc, iface_src, iface_dst, pol_enabled))
        # print(new_rule)
    print('-' * 280)
    # print(config[context]['interfaces'])


## SonicOS API Testing
def sw_api_test():
    import sonicwall as sw
    import json
    import re
    import time
    from collections import OrderedDict
    import sonicwall as sw
    import re

    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    for target in options.grouptargets:

        ## Enable API first

        session = requests.Session()
        session.mount('https://' + target, sw.DESAdapter())
        sw.do_login(session, options.username, options.password, target, preempt=True)
        response = sw.get_url(session, 'https://' + target + '/systemAdministrationView.html')
        csrf = re.findall(r'csrfToken.*"', response.text)[0].split('value=')[1].split('"')[1]
        postdata = {'csrfToken': csrf,
                    'cgiaction': "none",
                    'sonicOsApi_enable': "on",
                    'sonicOsApi_basicAuth': "on",
                    'cbox_sonicOsApi_enable': "",
                    'cbox_sonicOsApi_basicAuth': ""}
        url = 'https://' + target + '/main.cgi'
        api_result = send_sw_webcmd(session, url, postdata)
        sw.do_logout(session, target)

        ## Use API to send CLI command for groups
        session = requests.Session()
        session.mount('https://' + target, sw.DESAdapter())
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
        url = 'https://{}/api/sonicos/auth'.format(target)
        session.headers = OrderedDict(
            [('User-Agent', 'python-requests/2.18.4'), ('Accept', '*/*'), ('Accept-Encoding', 'gzip, deflate'),
             ('Connection', 'keep-alive')])
        post_data = None
        # auth = requests.auth.HTTPBasicAuth(options.username, options.password)
        response_code = None
        login_tries = 0
        while response_code != 200 and login_tries < 5:
            login_tries += 1
            response = session.post(url=url, headers={'authorization': "Basic " + base64.b64encode(
                '{}:{}'.format(options.username, options.password).encode()).decode()}, verify=False)
            response_code = response.status_code
            if response_code != 200:
                # session = requests.Session()
                # session.mount('https://' + target, sw.DESAdapter())
                # urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
                # url='https://{}/api/sonicos/auth'.format(target)
                debug('Login failed, retrying in 10 seconds')
                time.sleep(10)
        # /api/sonicos/access-rules/ipv4
        if response_code == 200:
            url = 'https://{}/api/sonicos/access-rules/ipv4'.format(target)
            session.headers.update({'content-type': 'text/plain'})
            # Application/JSON
            ''' This section is to retrieve LDAP server config if the BindDN name needs to be changed
            post_data = 'show user ldap'
            result=session.post(url=url, data=post_data, verify=False)
            result=send_sw_webcmd(session, url, post_data)
            log(result.text)
            ldap_config=json.loads(result.text)
            print(json.dumps(ldap_config, sort_keys=True, indent=4))
            for server in ldap_config['user']['ldap']['server']:
                print(server['bind']['distinguished_name'])
            '''

            # post_data = 'show user local groups\n'
            result = session.get(url=url, data=post_data, verify=False)
            response = json.loads(result.text)
            # print(response)
            # print(len(response['access_rules']))
            rule_uuids = []
            for rule in response['access_rules']:
                #    print(rule)
                rule_uuids.append(rule['ipv4']['uuid'])
            # print(rule_uuids)

            # for rule_uuid in rule_uuids[0]:
            print(rule_uuids[0])
            print(response['access_rules'][0])
            session.headers.update({'content-type': 'Application/JSON'})
            post_data = {'access_rule': {'ipv4': {'tcp': {'urgent': True}}}}
            url = 'https://{}/api/sonicos/access-rules/ipv4/uuid/{}'.format(target, rule_uuids[0])
            result = session.put(url=url, json=post_data, verify=False)
            print(result.text)
            post_data = None
            url = 'https://{}/api/sonicos/config/pending'.format(target)
            result = session.post(url=url, json=post_data, verify=False)
            print(result.text)

            # rw_result=json.loads(result.text)['status']['success']
            # for rule_uuid in
            '''
            print(groups)
            for group in groups['user']['local']['group']:
                if re.findall(r'^CS_FIREWALL', group['name'].upper()): 
                    group_name=group['name']
                    print(group_name)
                    post_data = 'user local\ngroup "{}"\ndomain any\nno memberships-by-ldap-location\ncommit\n'.format(group_name)
                    result=session.post(url=url, data=post_data, verify=False)
                    su_result=json.loads(result.text)['status']['success']

                    #post_data = 'user local\ngroup "CS_FIREWALL_RO"\ndomain any\nno memberships-by-ldap-location\ncommit\n'
                    #result=session.post(url=url, data=post_data, verify=False)
                    r#o_result=json.loads(result.text)['status']['success']


                    #post_data = 'user local\ngroup "CS_FIREWALL_RW"\ndomain any\nno memberships-by-ldap-location\ncommit\n'
                    #result=session.post(url=url, data=post_data, verify=False)
                    #rw_result=json.loads(result.text)['status']['success']

                    log('{},{},{},{},{},{}'.format(target, login_tries, ro_result, rw_result, su_result, ""))
            '''
        else:
            log('{},{},{},{},{},{}'.format(target, login_tries, 'Skipped', 'Skipped', 'Skipped', 'Login Failed'))

        ## Log out via DELETE method
        url = 'https://{}/api/sonicos/auth'.format(target)
        post_data = None
        session.delete(url=url, verify=False)


# compare sonicwall 6.2 and 6.5 configs
def compare_sw_configs():
    import pprint
    import sys
    import json

    def get_size(obj, seen=None):
        """Recursively finds size of objects"""
        size = sys.getsizeof(obj)
        if seen is None:
            seen = set()
        obj_id = id(obj)
        if obj_id in seen:
            return 0
        # Important mark as seen *before* entering recursion to gracefully handle
        # self-referential objects
        seen.add(obj_id)
        if isinstance(obj, dict):
            size += sum([get_size(v, seen) for v in obj.values()])
            size += sum([get_size(k, seen) for k in obj.keys()])
        elif hasattr(obj, '__dict__'):
            size += get_size(obj.__dict__, seen)
        elif hasattr(obj, '__iter__') and not isinstance(obj, (str, bytes, bytearray)):
            size += sum([get_size(i, seen) for i in obj])
        return size

    pp = pprint.PrettyPrinter(indent=2)
    # pp.pprint(config)

    # for context in config:
    #    log(context)
    #    if context != 'shared':
    #        for address in config[context]['addresses']:
    #            if config[context]['addresses'][address]['addrObjType'] == '8':
    #                log(pp.pprint(config[context]['addresses'][address]))
    from urllib.parse import unquote as url_unquote
    from urllib.parse import quote as url_quote

    skip_keys = ['addrObjProperties', 'usedzones', 'addressmappings', 'config', 'servicemappings', 'svcObjProperties']
    in_a_not_b = []
    in_b_not_a = []

    config_items = 'addresses'
    for config_item in config['sonicwall']:
        log('config_item', config_item)
        if config_item not in skip_keys:
            for config_key in config['sonicwall'][config_item]:
                config_key_quoted = url_quote(config_key)
                log('     config_key', config_key)
                if config_key_quoted in config['edp2sfwedsvcslab01'][config_item] and config_key not in skip_keys:
                    for key in config['sonicwall'][config_item][config_key]:
                        key = url_quote(key)
                        log('     key', key)
                        if key in config['edp2sfwedsvcslab01'][config_item][config_key_quoted] and key not in skip_keys:
                            if config['sonicwall'][config_item][config_key][key] != \
                                    config['edp2sfwedsvcslab01'][config_item][config_key_quoted][key]:
                                try:
                                    if url_quote(config['sonicwall'][config_item][config_key][key]) != \
                                            config['edp2sfwedsvcslab01'][config_item][config_key_quoted][key]:
                                        log('!-- {:20.20} - {:20.20} - {:50.50} - {:50.50}'.format(str(config_key), key,
                                                                                                   str(config[
                                                                                                           'sonicwall'][
                                                                                                           config_item][
                                                                                                           config_key][
                                                                                                           key]), str(
                                                config['edp2sfwedsvcslab01'][config_item][config_key_quoted][key])))
                                except:
                                    log('!-- {:20.20} - {:20.20} - {:50.50} - {:50.50}'.format(str(config_key), key,
                                                                                               str(config['sonicwall'][
                                                                                                       config_item][
                                                                                                       config_key][
                                                                                                       key]), str(
                                            config['edp2sfwedsvcslab01'][config_item][config_key_quoted][key])))
                        elif key not in config['edp2sfwedsvcslab01'][config_item][config_key_quoted]:
                            if key not in in_a_not_b:
                                in_a_not_b.append(key)
                                log('!-- Key {} in api but not in exp'.format(key))
                elif config_key_quoted not in config['edp2sfwedsvcslab01'][config_item]:
                    log('!-- Config key {} in api but not in exp'.format(config_key))

    # print('total dict size', get_size(config))


def test2():
    from netaddr import IPRange

    for context in config:
        # for p in config[context]['nat']:
        #    if config[context]['nat'][p]['natPolicyName']=='##Hop-Durham-TPA':
        #        log(config[context]['nat'][p])
        for address in config[context]['addresses']:
            if config[context]['addresses'][address]['addrObjType'] == '2':
                try:
                    # log('{:10.10} {:50.50} : {:20.20} : {:20.20}'.format(str(len(IPRange(config[context]['addresses'][address]['addrObjIp1'],config[context]['addresses'][address]['addrObjIp2']))), config[context]['addresses'][address]['addrObjId'],config[context]['addresses'][address]['addrObjIp1'],config[context]['addresses'][address]['addrObjIp2']))
                    log('{},{},{},{}'.format(str(len(IPRange(config[context]['addresses'][address]['addrObjIp1'],
                                                             config[context]['addresses'][address]['addrObjIp2']))),
                                             config[context]['addresses'][address]['addrObjId'],
                                             config[context]['addresses'][address]['addrObjIp1'],
                                             config[context]['addresses'][address]['addrObjIp2']))
                except:
                    # log('{:10.10} {:50.50} : {:20.20} : {:20.20}'.format('error', config[context]['addresses'][address]['addrObjId'],config[context]['addresses'][address]['addrObjIp1'],config[context]['addresses'][address]['addrObjIp2']))
                    log('{},{},{},{}'.format('error', config[context]['addresses'][address]['addrObjId'],
                                             config[context]['addresses'][address]['addrObjIp1'],
                                             config[context]['addresses'][address]['addrObjIp2']))


# troubleshooting zone assignment for create_tuples
def create_tuples_for_zone():
    addr_names = ['glbl-ps3gtm-m.us.dell.com', 'glbl-ps3gtm01.us.dell.com', 'glbl-ps3gtm02.us.dell.com',
                  'glbl-pc1gtm01.us.dell.com', 'glbl-pc1gtm02.us.dell.com']
    for addr in addr_names:
        print(addr, get_zone('checkpoint', config['checkpoint']['addresses'][addr]['addrObjIp1']))

    log(config['checkpoint']['policies'][132])
    for addr in config['checkpoint']['policies'][132]['policySrcNet']:
        print(addr, get_zone('checkpoint', config['checkpoint']['addresses'][addr]['addrObjIp1']))
    for addr in config['checkpoint']['policies'][132]['policyDstNet']:
        print(addr, get_zone('checkpoint', config['checkpoint']['addresses'][addr]['addrObjIp1']))


def test3():
    log(config['checkpoint']['services']['tcp-high-ports'])
    for addr in config['checkpoint']['addresses']:
        if config['checkpoint']['addresses'][addr]['addrObjType'] == '98':
            log(addr, config['checkpoint']['addresses'][addr]['IPSet'])


def test4():
    old_loglevel = options.logging
    options.logging = 0
    for search_ip in options.groupaddresses:
        from netaddr import IPSet, IPNetwork, IPRange

        search_ip = '10.99.5.141'
        log('{:20.20s} | {:20.20s} | {:20.20s} | {:20.20s} | {:20.20s} | {:20.20s}'.format('Source', 'Destination',
                                                                                           'Nexthop', 'Interface',
                                                                                           'Zone', 'Match Length'))
        log('-' * 135)
        bestmatch = {'len': -1, 'zone': None, 'iface': None, 'gateway': None}
        for route in config['sonicwall']['routing']:
            if config['sonicwall']['routing'][route]['pbrObjSrc'] == '':
                source = 'Any'
            else:
                source = config['sonicwall']['routing'][route]['pbrObjSrc']
            gateway = config['sonicwall']['routing'][route]['pbrObjGw']
            if gateway in config['sonicwall']['addresses']:
                gateway = config['sonicwall']['addresses'][gateway]['addrObjIp1']
            elif gateway == '':
                gateway = '0.0.0.0'
            iface = config['sonicwall']['routing'][route]['pbrObjIface']
            zone = ''
            for interface in config['sonicwall']['interfaces']:
                if config['sonicwall']['interfaces'][interface]['iface_name'] == iface:
                    zone = config['sonicwall']['interfaces'][interface]['interface_Zone']
            if config['sonicwall']['routing'][route]['pbrObjDst'] in config['sonicwall']['addresses']:
                for dest in expand_address(config['sonicwall']['addresses'],
                                           config['sonicwall']['routing'][route]['pbrObjDst'], config['sonicwall'][
                                               'addressmappings']):  # def expand_address(address_dict, address_object, address_map, inc_group=False):
                    if config['sonicwall']['addresses'][dest]['addrObjType'] == '2':
                        for range_ip in IPRange(config['sonicwall']['addresses'][dest]['addrObjIp1'],
                                                config['sonicwall']['addresses'][dest]['addrObjIp2']):
                            # log(range_ip)
                            dest_network = '{}/{}'.format(range_ip, '32')
                            if IPNetwork(search_ip) in IPNetwork(dest_network) and source == 'Any':
                                matchlen = 32
                            else:
                                matchlen = -1
                            log('{:20.20s} | {:20.20s} | {:20.20s} | {:20.20s} | {:20.20s} | {:20.20s}'.format(source,
                                                                                                               dest_network,
                                                                                                               gateway,
                                                                                                               iface,
                                                                                                               zone,
                                                                                                               str(matchlen)))
                            if matchlen > bestmatch['len']:
                                bestmatch = {'len': matchlen, 'zone': zone, 'iface': iface, 'gateway': gateway}

                    else:
                        dest_network = '{}/{}'.format(config['sonicwall']['addresses'][dest]['addrObjIp1'],
                                                      netmask_to_cidr(
                                                          config['sonicwall']['addresses'][dest]['addrObjIp2']))
                        if IPNetwork(search_ip) in IPNetwork(dest_network) and source == 'Any':
                            matchlen = netmask_to_cidr(config['sonicwall']['addresses'][dest]['addrObjIp2'])
                        else:
                            matchlen = -1
                        log('{:20.20s} | {:20.20s} | {:20.20s} | {:20.20s} | {:20.20s} | {:20.20s}'.format(source,
                                                                                                           dest_network,
                                                                                                           gateway,
                                                                                                           iface, zone,
                                                                                                           str(matchlen)))
                        if matchlen > bestmatch['len']:
                            bestmatch = {'len': matchlen, 'zone': zone, 'iface': iface, 'gateway': gateway}
            else:
                if config['sonicwall']['routing'][route]['pbrObjDst'] in ['', '0.0.0.0']:
                    dest_network = '0.0.0.0/0'
                else:
                    dest_network = config['sonicwall']['routing'][route]['pbrObjDst']
                if IPNetwork(search_ip) in IPNetwork(dest_network) and source == 'Any':
                    matchlen = int(dest_network.split('/')[
                                       1])  # netmask_to_cidr(config['sonicwall']['addresses'][dest]['addrObjIp2'])
                else:
                    matchlen = -1
                log('{:20.20s} | {:20.20s} | {:20.20s} | {:20.20s} | {:20.20s} | {:20.20s}'.format(source, dest_network,
                                                                                                   gateway, iface, zone,
                                                                                                   str(matchlen)))
                if matchlen > bestmatch['len']:
                    bestmatch = {'len': matchlen, 'zone': zone, 'iface': iface, 'gateway': gateway}

        # log('-' * 135, level=0)
        log(bestmatch, level=0)
    log('-' * 135, level=0)
    options.logging = old_loglevel


def test5():
    for address in config['shared']['addresses']:
        log(address)


def test6():
    for context in config:
        if config[context]['config']['fw_type'].lower() == 'checkpoint':
            log('Showing routing table for {}'.format(context))
            for route in config[context]['routing']:
                log(config[context]['routing'][route])


def test7():
    for context in config:
        if config[context]['config']['fw_type'].lower() == 'checkpoint':
            log('Showing interfaces for {}'.format(context))
            for interface in config[context]['interfaces']:
                log(config[context]['interfaces'][interface])


def test8():
    log(get_zone_old('checkpoint', '{}'.format("143.166.93.175")))


def test9():
    service_list = []
    for policy in config['Extranet_PS3']['policies']:
        if config['Extranet_PS3']['policies'][policy]['policyDstSvc'] == []:
            log(config['Extranet_PS3']['policies'][policy])


# options.testing:
def test_options():
    from netaddr import IPSet, IPNetwork

    for context in config:
        for address in config[context]['addresses']:
            options.groupaddresses = []
            if 'include' in config[context]['addresses'][address]:
                address_name = config[context]['addresses'][address]['addrObjId']
                options.nexpose = address_name + '-PA'
                log('-' * 180)
                log(config[context]['addresses'][address]['include'])
                if config[context]['addresses'][address]['include'].lower() == 'any':
                    include = IPSet(IPNetwork('0.0.0.0/0'))
                else:
                    include = config[context]['addresses'][config[context]['addresses'][address]['include']]['IPSet']
                exclude = config[context]['addresses'][config[context]['addresses'][address]['exclude']]['IPSet']
                result = include - exclude
                log('INCLUDE', config[context]['addresses'][address]['include'], include)
                log('EXCLUDE', config[context]['addresses'][address]['exclude'], exclude)
                log('-' * 180)
                log('RESULT', len(result), result)
                log('-' * 180)
                for iprange in list(result.iter_ipranges()):
                    log('{}'.format(iprange))
                    options.groupaddresses.append('{},R-{}'.format(iprange, iprange))
            if options.groupaddresses != []:
                bulk_create_addresses(None, config)


def test10():
    for context in config:
        log(context)
        log(get_zones2(context, 'SplunkCS_HeavyForwarders', config))
        try:
            for route in config[context]['routing']:
                log(config[context]['routing'][route])
        except:
            pass


# options.testing:
def test11():
    import sonicwall as sw
    import json
    import xmltodict

    # from bs4 import BeautifulSoup
    for target in options.grouptargets:
        session = requests.Session()
        session.mount('https://' + target, sw.DESAdapter())
        loginResult = sw.do_login(session, options.username, options.password, target, preempt=True)
        if loginResult:
            tmp = sw.get_url(session, 'https://' + target + '/getObjectList.json')  # ?type=129')
            allObjects = json.loads(tmp.text)
            for key in allObjects:
                pass
                # log(key)
            tmp = sw.get_url(session, 'https://' + target + '/getPolicies.json')
            allPolicies = json.loads(tmp.text)['ruleArray']
            # log(allPolicies.split('|')[0])
            for index, entry in enumerate(allPolicies.split('|')[1:]):
                name, action, enable, srcIface, dstIface, srcsvc, svc, src, dst, tod, tim, timUdp, frag, tcpUrg, netflow, geoip, perPolicyGeoIpBlock, perPolicyGeoIpBitmap, \
                policyGeoIpBlockUnknown, botnet, enable_sip, enable_h323, pktcap, whomInclType, whomInclStr, whomExclType, whomExclStr, whomInclStr2, whomExclStr2, cmt, \
                log, pri, priType, globalBwmParam, bwmDirStyle, bwmParam, prop, man, tableNum, fromZone, toZone, polConMax, noSSO, noSSOTrafficBlk, noRdrct, connLmtSrcEnable, \
                connLmtDstEnable, connLmtSrcThreshold, connLmtDstThreshold, qosMarkingDscpAction, qosMarkingDscpTagValue, qosMarkingDscpAllow8021pOverride, \
                qosMarking8021pAction, qosMarking8021pTagValue, defaultRule, ipver, bypassDpi, bypassDPISSLClient, bypassDPISSLServer, unusedZone, showEnabled, srcHandle, \
                dstHandle, fromZoneHandle, toZoneHandle, svcHandle, srcsvcHandle, bwUsage, whomInclGrpType, uuid, pdf, timeCreated, timeUpdated, timeCreatedSec, timeUpdatedSec, timeHitSec = entry.split(
                    ',')
                hits = sw.get_url(session,
                                  'https://' + target + '/getRulePolicyStats.xml?srcAddr={}&dstAddr={}&srcZone={}&dstZone={}&srcIface={}&dstIface={}&srcSvc={}&ipType={}&service={}'.format(
                                      srcHandle, dstHandle, fromZoneHandle, toZoneHandle, srcIface, dstIface,
                                      srcsvcHandle, '0', svcHandle))
                # print(hits.text)
                hits_dict = xmltodict.parse(hits.text)
                if not hits_dict['rule-policy-info']['uuid']:
                    print(
                        'Name: {} srcAddr={}&dstAddr={}&srcZone={}&dstZone={}&srcIface={}&dstIface={}&srcSvc={}&ipType={}&service={}'.format(
                            name, srcHandle, dstHandle, fromZoneHandle, toZoneHandle, srcIface, dstIface, srcsvcHandle,
                            '0', svcHandle))
                elif uuid != '"{}"'.format(hits_dict['rule-policy-info']['uuid']):
                    # print('UUID Mismatch', uuid, '"{}"'.format(hits_dict['rule-policy-info']['uuid']))
                    print('*{}'.format(uuid), hits_dict['rule-policy-info']['policyUsage'])
                    # print('Name: {} srcAddr={}&dstAddr={}&srcZone={}&dstZone={}&srcIface={}&dstIface={}&srcSvc={}&ipType={}&service={}'.format(name, 'srcHandle', dstHandle, fromZoneHandle, toZoneHandle, srcIface, dstIface, srcsvcHandle, '0', svcHandle))
                else:
                    # print(hits_dict['rule-policy-info'])
                    print(uuid, hits_dict['rule-policy-info']['policyUsage'])

            tmp = sw.get_url(session, 'https://' + target + '/getRouteList.json?reqType=1')
            allRoutes = json.loads(tmp.text)['pbrPolicies']
            for index, entry in enumerate(allRoutes.split('|')[1:]):
                name, properties, metric, distance, distanceAuto, priority, source, destination, service, applicationID, application, tos, tosMask, nexthopNum, \
                gateway, gatewayVer, iface, ifName, ifaceStatus, gateway2, gatewayVer2, iface2, ifName2, ifaceStatus2, gateway3, gatewayVer3, iface3, ifName3, ifaceStatus3, \
                gateway4, gatewayVer4, iface4, ifName4, ifaceStatus4, comment, probe, ipver, wxaGroup, uuid, rtype, psp, sdwanGroup, entryIndex = entry.split(
                    ',')
                # print(index)
            print(allRoutes)
        sw.do_logout(session, target)


def test12():
    try:

        for policy in config['sonicwall']['policies']:
            # log(config['sonicwall']['policies'][policy]['policyName'])
            if config['sonicwall']['policies'][policy]['policyName'] in ['SplunkCS_Heavy_Forwarders',
                                                                         'SplunkCS_Heavy_ForwarderVIPs',
                                                                         'SplunkCS_Server-to-Server',
                                                                         'SplunkCS_Automation_Servers']:
                # def exec_fw_command(target, fw_type, commands, syntax='cli', policylens=None, delay=None, use_session=True, use_apikey=False, dryrun=False, sw_objects=None):  # add sw_sesssion, enable_api and commit options -- what is policy lens for?
                # result=exec_fw_command(target, change[context]['fw_type'], [('modify_rule', { 'context': context, 'policyname': faddr['policy_name'], 'policynum': str(faddr['policy_num']), 'action': 'addmembers', 'sources': [ faddr['newaddress']] })] ,syntax=syntax)
                exec_fw_command(options.sonicwall_api_ip, 'sw65', [('modify_rule', {'action': 'enable', 'uuid':
                    config['sonicwall']['policies'][policy]['policyUUID']})], syntax='api')
                log(options.sonicwall_api_ip, config['sonicwall']['policies'][policy]['policyName'], 'Enabled')

    except Exception as e:
        log(options.sonicwall_api_ip, 'Exception trying to enable rules')


def test13():
    import json
    from urllib.parse import quote, unquote

    tconfig = {}
    tconfig['routing'] = {}
    target = '10.215.16.61'
    session = requests.Session()
    session.mount('https://' + target, sw.DESAdapter())
    loginResult = sw.do_login(session, options.username, options.password, target, preempt=True)
    result = sw.get_url(session, 'https://' + target + '/getRouteList.json')
    # log(tmp.text)
    sw.do_logout(session, target)
    ## # routing_props = ['pbrObjId', 'pbrObjProperties', 'pbrObjSrc', 'pbrObjDst', 'pbrObjSvc', 'pbrObjGw', 'pbrObjIface', 'pbrObjIfaceName', 'pbrObjMetric', 'pbrObjPriority', 'pbrObjProbe', 'pbrObjComment']
    pbrindex = 0
    for index, entry in enumerate(json.loads(result.text)['pbrPolicies'].split('|')[1:]):
        log(index, entry)
        name, properties, metric, distance, distanceAuto, priority, source, destination, service, applicationID, application, tos, tosMask, nexthopNum, \
        gateway, gatewayVer, iface, ifName, ifaceStatus, gateway2, gatewayVer2, iface2, ifName2, ifaceStatus2, gateway3, gatewayVer3, iface3, ifName3, ifaceStatus3, \
        gateway4, gatewayVer4, iface4, ifName4, ifaceStatus4, comment, probe, ipver, wxaGroup, uuid, rtype, psp, sdwanGroup, entryIndex = entry.split(
            ',')
        if ipver == '0':  ## 0 is IPv4 - do not read IPv6 routes at this time
            # log([x for x in config['sonicwall']['addresses']])
            destination = destination.strip('"')
            source = source.strip('"')
            service = service.strip('"')
            gateway = gateway.strip('"')
            # log('"{}"'.format(destination))
            if source in config['sonicwall']['addresses']:
                source = '{}/{}'.format(config['sonicwall']['addresses'][source]['addrObjIp1'],
                                        netmask_to_cidr(config['sonicwall']['addresses'][source]['addrObjIp2']))
            if gateway in config['sonicwall']['addresses']:
                gateway = '{}'.format(config['sonicwall']['addresses'][gateway]['addrObjIp1'])
            if destination in config['sonicwall']['addresses']:
                log('Destination in Address objects - expand it!')
                log(expand_address(config['sonicwall']['addresses'], destination,
                                   config['sonicwall']['addressmappings'], inc_group=False))
                for each_dest in expand_address(config['sonicwall']['addresses'], destination,
                                                config['sonicwall']['addressmappings'], inc_group=False):
                    log(each_dest, pbrindex)
                    tconfig['routing'][pbrindex] = OrderedDict()
                    tconfig['routing'][pbrindex]['pbrObjId'] = name
                    tconfig['routing'][pbrindex]['pbrObjProperties'] = properties
                    tconfig['routing'][pbrindex]['pbrObjSrc'] = source
                    tconfig['routing'][pbrindex]['pbrObjDst'] = '{}/{}'.format(
                        config['sonicwall']['addresses'][each_dest]['addrObjIp1'],
                        netmask_to_cidr(config['sonicwall']['addresses'][each_dest]['addrObjIp2']))
                    tconfig['routing'][pbrindex]['pbrObjSvc'] = service
                    tconfig['routing'][pbrindex]['pbrObjGw'] = gateway
                    tconfig['routing'][pbrindex]['pbrObjIface'] = iface
                    tconfig['routing'][pbrindex]['pbrObjIfaceName'] = ifName
                    tconfig['routing'][pbrindex]['pbrObjMetric'] = metric
                    tconfig['routing'][pbrindex]['pbrObjPriority'] = priority
                    tconfig['routing'][pbrindex]['pbrObjProbe'] = probe
                    tconfig['routing'][pbrindex]['pbrObjComment'] = comment
                    tconfig['routing'][pbrindex]['pbrObjUUID'] = uuid
                    # log(tconfig['routing'][index]['pbrObjDst'], ipver)
                    pbrindex += 1

            else:
                log('Destination not in Address objects - use as is!')
                log(destination, pbrindex)
                tconfig['routing'][pbrindex] = OrderedDict()
                tconfig['routing'][pbrindex]['pbrObjId'] = name
                tconfig['routing'][pbrindex]['pbrObjProperties'] = properties
                tconfig['routing'][pbrindex]['pbrObjSrc'] = source
                tconfig['routing'][pbrindex]['pbrObjDst'] = destination
                tconfig['routing'][pbrindex]['pbrObjSvc'] = service
                tconfig['routing'][pbrindex]['pbrObjGw'] = gateway
                tconfig['routing'][pbrindex]['pbrObjIface'] = iface
                tconfig['routing'][pbrindex]['pbrObjIfaceName'] = ifName
                tconfig['routing'][pbrindex]['pbrObjMetric'] = metric
                tconfig['routing'][pbrindex]['pbrObjPriority'] = priority
                tconfig['routing'][pbrindex]['pbrObjProbe'] = probe
                tconfig['routing'][pbrindex]['pbrObjComment'] = comment
                tconfig['routing'][pbrindex]['pbrObjUUID'] = uuid
                pbrindex += 1
            # log(config['sonicwall'])
            # log(tconfig['routing'][index]['pbrObjDst'], ipver)
    for route in tconfig['routing']:
        log(tconfig['routing'][route])

    for route in config['sonicwall']['routing']:
        log(config['sonicwall']['routing'][route])

    # for address in config['sonicwall']['addresses']:
    # log(address)

    # https://10.215.16.61/getRouteList.json?reqType=1


def test14():
    config['Durham_Core_FINAL_Zonefix']['routing'], config['Durham_Core_FINAL_Zonefix']['interfaces'], \
    config['Durham_Core_FINAL_Zonefix']['zones'] = load_checkpoint_routing(options.checkpointroute)
    log(get_zones2('Durham_Core_FINAL_Zonefix', 'Durham-DMZ-10.105.0.0-16'))


def test15():
    options.devmap = ['Extranet_PC1,Extranet_Outside']
    options.devmap = ['Extranet_PC1,Pc1_DMZ_Firewalls']

    # for context in config:
    #    log(context)
    for devmap in options.devmap:
        for devgroup, template in [devmap.split(',')]:
            if devgroup in config and template in config:
                # log(config[devgroup]['routing'])
                if 'vrouters' in config[template]:
                    config[devgroup]['routing'] = {}
                    # log(config[context]['vrouters'])
                    for vrouter in config[template]['vrouters']:
                        log('VRouter Name: {}'.format(vrouter))
                        route_num_int = 0

                        for route in config[template]['vrouters'][vrouter]:
                            route_num = str(route_num_int)
                            # log(config[template]['vrouters'][vrouter][route])

                            config[devgroup]['routing'][route_num] = {}
                            config[devgroup]['routing'][route_num]['pbrObjId'] = 'Route {}'.format(route_num)
                            config[devgroup]['routing'][route_num]['pbrObjSrc'] = ''
                            config[devgroup]['routing'][route_num]['pbrObjDst'] = \
                                config[template]['vrouters'][vrouter][route]['destination']
                            config[devgroup]['routing'][route_num]['pbrObjGw'] = \
                                config[template]['vrouters'][vrouter][route]['nexthops'][0]
                            config[devgroup]['routing'][route_num]['pbrObjIface'] = ''
                            config[devgroup]['routing'][route_num]['pbrObjIfaceName'] = ''
                            config[devgroup]['routing'][route_num]['pbrObjMetric'] = ''
                            config[devgroup]['routing'][route_num]['pbrObjPriority'] = ''
                            config[devgroup]['routing'][route_num]['pbrObjProbe'] = ''
                            config[devgroup]['routing'][route_num]['pbrObjComment'] = ''
                            config[devgroup]['routing'][route_num]['pbrObjUUID'] = ''
                            config[devgroup]['routing'][route_num]['pbrObjSvc'] = ''
                            # log(config[devgroup]['routing'][route_num])

                            route_num_int += 1
                if 'interfaces' in config[template]:
                    interfce_num_int = 0
                    config[devgroup]['interfaces'] = {}
                    for interface in config[template]['interfaces']:
                        # interface_num=str(interface_num_int)
                        interface_name = config[template]['interfaces'][interface]['iface_name']
                        config[devgroup]['interfaces'][interface_name] = {}
                        config[devgroup]['interfaces'][interface_name]['iface_ifnum'] = \
                            config[template]['interfaces'][interface]['iface_ifnum']
                        config[devgroup]['interfaces'][interface_name]['iface_type'] = \
                            config[template]['interfaces'][interface]['iface_type']
                        config[devgroup]['interfaces'][interface_name]['iface_name'] = \
                            config[template]['interfaces'][interface]['iface_name']
                        config[devgroup]['interfaces'][interface_name][
                            'interface_Zone'] = ''  ## assign when reading zones
                        config[devgroup]['interfaces'][interface_name]['iface_comment'] = \
                            config[template]['interfaces'][interface]['iface_comment']
                        config[devgroup]['interfaces'][interface_name]['iface_static_ip'] = ''
                        config[devgroup]['interfaces'][interface_name]['iface_static_mask'] = ''
                        config[devgroup]['interfaces'][interface_name]['iface_static_gateway'] = ''
                        config[devgroup]['interfaces'][interface_name]['iface_lan_ip'] = \
                            config[template]['interfaces'][interface]['iface_static_ip']
                        config[devgroup]['interfaces'][interface_name]['iface_lan_mask'] = \
                            config[template]['interfaces'][interface]['iface_static_mask']
                        config[devgroup]['interfaces'][interface_name]['iface_lan_default_gw'] = \
                            config[template]['interfaces'][interface]['iface_static_gateway']
                        config[devgroup]['interfaces'][interface_name]['iface_mgmt_ip'] = ''
                        config[devgroup]['interfaces'][interface_name]['iface_mgmt_netmask'] = ''
                        config[devgroup]['interfaces'][interface_name]['iface_mgmt_default_gw'] = ''
                        config[devgroup]['interfaces'][interface_name]['iface_vlan_tag'] = ''
                        config[devgroup]['interfaces'][interface_name]['iface_http_mgmt'] = ''
                        # config[devgroup]['interfaces'][interface_num]['']=
                        log(config[devgroup]['interfaces'][interface_name])
                        log(config[template]['interfaces'][interface])

                        # interface_num_int += 1

                if 'zones' in config[template]:
                    zone_num_int = 0
                    for zone in config[template]['zones']:
                        zone_num = str(zone_num_int)
                        config[devgroup]['zones'][zone_num] = {}
                        config[devgroup]['zones'][zone_num]['zoneObjId'] = config[template]['zones'][zone]['zoneObjId']
                        config[devgroup]['zones'][zone_num]['zoneObjComment'] = 'Zone Comment'
                        config[devgroup]['zones'][zone_num]['zoneObjMembers'] = config[template]['zones'][zone][
                            'zoneObjMembers']

                        for zone_member in config[template]['zones'][zone]['zoneObjMembers']:
                            for interface in config[devgroup]['interfaces']:
                                if config[devgroup]['interfaces'][interface]['iface_name'] == zone_member:
                                    config[devgroup]['interfaces'][interface]['interface_Zone'] = \
                                        config[template]['zones'][zone]['zoneObjId']
                        log(config[devgroup]['interfaces'][interface]['iface_name'])
                        zone_num_int += 1
                for interface in config[devgroup]['interfaces']:
                    log(config[devgroup]['interfaces'][interface])

                    pass

# options.movecheckpoint:
def move_check_point():

    import copy

    config = {}
    config['source'] = load_checkpoint(secobj=options.checkpointpol, natobj=options.checkpointnat,
                                       svcobj=options.checkpointsvc, netobj=options.checkpointobj)
    # config['dest']=load_checkpoint(secobj=options.destcheckpointpol, natobj=options.destcheckpointnat, svcobj=options.destcheckpointsvc, netobj=options.destcheckpointobj)
    config['dest'] = load_checkpoint(secobj='labs_Security.xml', natobj='labs_NAT.xml', svcobj='labs_services.xml',
                                     netobj='labs_network_objects.xml')
    ## verify that all sources, dests and services have been loaded - some address types are not loaded and can not be moved
    policy_to_move = '##Israel-CoE-AFCC'
    config['shared'] = {}
    config['shared']['addresses'] = {}
    config['shared']['addressmappings'] = {}
    config['shared']['servicemappings'] = {}
    config['shared']['services'] = {}
    config['shared']['policies'] = {}
    config['shared']['nat'] = {}
    config['shared']['config'] = {}
    # config['shared']['']={}

    config['new'] = {}
    config['new']['policies'] = OrderedDict()
    config['new']['addresses'] = OrderedDict()
    config['new']['services'] = OrderedDict()
    config['new']['addressmappings'] = {}
    config['new']['servicemappings'] = {}

    ## sanity check - print list of policy address/service objects that were not loaded via load_checkpoint
    for context in ['source', 'dest']:
        for policy in config[context]['policies']:

            for source in config[context]['policies'][policy]['policySrcNet']:

                if source not in config[context]['addresses'] and source.lower() != 'any':
                    print(source)

            for dest in config[context]['policies'][policy]['policyDstNet']:
                if dest not in config[context]['addresses'] and dest.lower() != 'any':
                    print(dest)

            for service in config[context]['policies'][policy]['policyDstSvc']:
                if service not in config[context]['services'] and service.lower() != 'any':
                    debug(service)

        ## Create svcSet property for every service group
        for service in config[context]['services']:
            if service.lower() not in ['', 'any'] and config[context]['services'][service]['svcObjType'] == '2':
                if 'svcSet' not in config[context]['services'][service]:
                    config[context]['services'][service]['svcSet'] = []
                    for member in expand_service(config[context]['services'], service,
                                                 config[context]['servicemappings']):
                        config[context]['services'][service]['svcSet'].append((config[context]['services'][member][
                                                                                   'svcObjIpType'],
                                                                               config[context]['services'][member][
                                                                                   'svcObjPort1'],
                                                                               config[context]['services'][member][
                                                                                   'svcObjPort2']))
                config[context]['services'][service]['svcSet'].sort(key=lambda tup: (tup[0], tup[1], tup[2]))
                # debug(config[context]['services'][service]['svcSet'])

    group_searched_list = []

    for policy in config['source']['policies']:
        if config['source']['policies'][policy]['policyName'] == policy_to_move:
            config['new']['policies'][policy] = copy.deepcopy(config['source']['policies'][policy])
            config['new']['policies'][policy]['policySrcNet'] = []  # Initialize new policy config to empty
            config['new']['policies'][policy]['policyDstNet'] = []
            config['new']['policies'][policy]['policyDstSvc'] = []

            for sources in config['source']['policies'][policy]['policySrcNet']:  # do everything but groups for now.
                if sources.lower() != 'any':
                    if config['source']['addresses'][sources]['addrObjType'] in ['8']:
                        # def expand_address(address_dict, address_object, address_map, inc_group=False):
                        source_list = expand_address(config['source']['addresses'], sources,
                                                     config['source']['addressmappings'], inc_group=True)
                    else:
                        source_list = [sources]
                    for source in source_list:
                        if source in config['source']['addresses'] and source.lower() != 'any' and source not in \
                                config['new']['addresses']:
                            source_match = False
                            for dest in config['dest']['addresses']:
                                if config['source']['addresses'][source]['addrObjType'] in ['1', '2', '4']:
                                    if config['source']['addresses'][source]['addrObjIp1'] == \
                                            config['dest']['addresses'][dest]['addrObjIp1'] and \
                                            config['source']['addresses'][source]['addrObjIp2'] == \
                                            config['dest']['addresses'][dest]['addrObjIp2']:
                                        source_match = config['dest']['addresses'][dest]
                                        break
                                if config['source']['addresses'][source]['addrObjType'] in ['8']:
                                    if config['dest']['addresses'][dest]['addrObjType'] == '8':
                                        if 'IPSet' not in config['source']['addresses'][
                                            source]:  # since this should be added during loading policy, this should never be false
                                            debug('IPSet not found in source')
                                        elif 'IPSet' not in config['source']['addresses'][
                                            source]:  # since this should be added during loading policy, this should never be false
                                            debug('IPSet not found in dest')
                                        elif config['source']['addresses'][source]['IPSet'] == \
                                                config['dest']['addresses'][dest]['IPSet']:
                                            source_match = config['dest']['addresses'][dest]
                                            break
                            if source_match:
                                break
                        elif sources in config['new']['addresses']:
                            source_match = config['new']['addresses'][sources]
                            ## BLOCK 1
                            ## Currently exact group matches are never found - should add group matching back into routine above
                        if not source_match:
                            config['new']['addresses'][source] = copy.deepcopy(config['source']['addresses'][source])
                            if config['new']['addresses'][source]['addrObjId'] in config['dest']['addresses']:
                                config['new']['addresses'][source]['addrObjId'] += '_NEW'
                            config['new']['addresses'][source]['addrObjIsNew'] = True
                            if config['new']['addresses'][sources]['addrObjId'] not in \
                                    config['new']['policies'][policy]['policySrcNet']:
                                config['new']['policies'][policy]['policySrcNet'].append(
                                    config['new']['addresses'][sources]['addrObjId'])
                            log('Adding new object type {:3.3s}      : {}'.format(
                                config['source']['addresses'][source]['addrObjType'],
                                config['new']['addresses'][source]['addrObjId']))
                        elif source_match != 'group':
                            log('Match found Type   : {:3.3s} Source : {:50.50s} Destination : {:50.50s}'.format(
                                config['source']['addresses'][source]['addrObjType'], source,
                                source_match['addrObjId']))
                            config['new']['addresses'][source] = copy.deepcopy(config['dest']['addresses'][dest])
                            config['new']['addresses'][source]['addrObjIsNew'] = False
                            if source in config['source']['policies'][policy][
                                'policySrcNet']:  ## not in config['new']['policies'][policy]['policySrcNet']:
                                config['new']['policies'][policy]['policySrcNet'].append(source_match['addrObjId'])
                                pass
                        elif source.lower() == 'any':
                            log('Source Any')
                            config['new']['policies'][policy]['policySrcNet'] = ['Any']
            ## do destinations
            for destinations in config['source']['policies'][policy][
                'policyDstNet']:  # do everything but groups for now.
                if destinations.lower() != 'any':
                    if config['source']['addresses'][destinations]['addrObjType'] in ['8']:
                        # def expand_address(address_dict, address_object, address_map, inc_group=False):
                        destination_list = expand_address(config['source']['addresses'], destinations,
                                                          config['source']['addressmappings'], inc_group=True)
                    else:
                        destination_list = [destinations]
                    for destination in destination_list:
                        if destination in config['source'][
                            'addresses'] and destination.lower() != 'any' and destination not in config['new'][
                            'addresses']:
                            destination_match = False
                            for dest in config['dest']['addresses']:
                                if config['source']['addresses'][destination]['addrObjType'] in ['1', '2', '4']:
                                    if config['source']['addresses'][destination]['addrObjIp1'] == \
                                            config['dest']['addresses'][dest]['addrObjIp1'] and \
                                            config['source']['addresses'][destination]['addrObjIp2'] == \
                                            config['dest']['addresses'][dest]['addrObjIp2']:
                                        destination_match = config['dest']['addresses'][dest]
                                        break
                                if config['source']['addresses'][destination]['addrObjType'] in ['8']:
                                    if config['dest']['addresses'][dest]['addrObjType'] == '8':
                                        if 'IPSet' not in config['source']['addresses'][
                                            destination]:  # since this should be added during loading policy, this should never be false
                                            debug('IPSet not found in source')
                                        elif 'IPSet' not in config['source']['addresses'][
                                            destination]:  # since this should be added during loading policy, this should never be false
                                            debug('IPSet not found in dest')
                                        elif config['source']['addresses'][destination]['IPSet'] == \
                                                config['dest']['addresses'][dest]['IPSet']:
                                            destination_match = config['dest']['addresses'][dest]
                                            break
                            if destination_match:
                                break

                            ## Currently exact group matches are never found - should add group matching back into routine above
                            if not destination_match:
                                # log('No match found for              : {}'.format(source))
                                config['new']['addresses'][destination] = copy.deepcopy(
                                    config['source']['addresses'][destination])
                                if config['new']['addresses'][destination]['addrObjId'] in config['dest']['addresses']:
                                    config['new']['addresses'][destination]['addrObjId'] += '_NEW'
                                config['new']['addresses'][destination]['addrObjIsNew'] = True
                                if config['new']['addresses'][destinations]['addrObjId'] not in \
                                        config['new']['policies'][policy]['policyDstNet']:
                                    config['new']['policies'][policy]['policyDstNet'].append(
                                        config['new']['addresses'][destination]['addrObjId'])
                                log('Adding new object type {:3.3s}      : {}'.format(
                                    config['source']['addresses'][destination]['addrObjType'],
                                    config['new']['addresses'][destination]['addrObjId']))
                            elif destination_match != 'group':
                                log('Match found Type   : {:3.3s} Source : {:50.50s} Destination : {:50.50s}'.format(
                                    config['source']['addresses'][destination]['addrObjType'], destination,
                                    destination_match['addrObjId']))
                                config['new']['addresses'][destination] = copy.deepcopy(
                                    config['dest']['addresses'][dest])
                                config['new']['addresses'][destination]['addrObjIsNew'] = False
                                if destination in config['source']['policies'][policy]['policyDstNet']:
                                    config['new']['policies'][policy]['policyDstNet'].append(
                                        destination_match['addrObjId'])
                        elif destination.lower() == 'any':
                            log('Destination Any')
                            config['new']['policies'][policy]['policyDstNet'] = ['Any']

# routines to get IPS details on sonicwall
def get_ips_from_sw():

    import pandas as pd
    from bs4 import BeautifulSoup
    import sonicwall as sw
    import re

    '''
    {'pagename': 'idpSummary.html', 'fieldname': 'isIDPEnabled' , 'datatype': 'checkbox'},
    {'pagename': 'idpSummary.html', 'fieldname': 'idpPreventHighPriority' , 'datatype': 'checkbox'},
    {'pagename': 'idpSummary.html', 'fieldname': 'idpDetectHighPriority' , 'datatype': 'checkbox'},
    {'pagename': 'idpSummary.html', 'fieldname': 'idpLRTHigh' , 'datatype': 'inputvalue'},
    {'pagename': 'idpSummary.html', 'fieldname': 'idpPreventMediumPriority' , 'datatype': 'checkbox'},
    {'pagename': 'idpSummary.html', 'fieldname': 'idpDetectMediumPriority' , 'datatype': 'checkbox'},
    {'pagename': 'idpSummary.html', 'fieldname': 'idpLRTMedium' , 'datatype': 'inputvalue'},
    {'pagename': 'idpSummary.html', 'fieldname': 'idpPreventLowPriority' , 'datatype': 'checkbox'},
    {'pagename': 'idpSummary.html', 'fieldname': 'idpDetectLowPriority' , 'datatype': 'checkbox'},
    {'pagename': 'idpSummary.html', 'fieldname': 'idpLRTLow' , 'datatype': 'inputvalue'},
    {'pagename': 'systemAdministrationView.html', 'fieldname': 'cfTablePageSize' , 'datatype': 'inputvalue'},
    '''

    commands = ({'pagename': 'idpSummary.html', 'fieldname': 'upgradeRequired', 'regexstr': 'Upgrade Required',
                 'datatype': 'regex'},

                {'pagename': 'activationView.html', 'fieldname': 'licensing', 'datatype': 'table_id',
                 'tablename': 'Sec'},
                )

    debug(set([cmd['pagename'] for cmd in commands]))
    options.grouptargets = ['10.102.227.203', '10.215.16.60', '1.1.1.1']
    # options.grouptargets= ['10.215.16.60']
    # options.grouptargets= ['1.1.1.1']
    # options.grouptargets= ['10.102.227.203']
    # fw_list= ['10.215.16.60']
    # options.password=
    if not options.web and (options.username == None or options.password == None):
        options.username, options.password = get_creds()
    results = {}
    for fw in options.grouptargets:
        results[fw] = {}
        session = requests.Session()
        session.mount('https://' + fw, sw.DESAdapter())
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
        response = sw.do_login(session, options.username, options.password, fw, False)
        if response:
            for pagename in set([cmd['pagename'] for cmd in commands]):
                try:
                    response = session.get('https://{}/{}'.format(fw, pagename), verify=False,
                                           timeout=options.timeout_sw_webui)
                    for cmd in commands:
                        if response.status_code == 200:
                            if cmd['pagename'] == pagename:
                                soup = BeautifulSoup(response.text, 'lxml')
                                tables = [[
                                    [td.get_text(strip=True) for td in tr.find_all('td')]
                                    for tr in table.find_all('tr')
                                ]
                                    for table in soup.find_all('table')]
                                if cmd['datatype'] == 'regex':
                                    if len(re.findall(cmd['regexstr'], response.text)) > 0:
                                        results[fw][cmd['fieldname']] = True
                                    else:
                                        results[fw][cmd['fieldname']] = False
                                if cmd['datatype'] == 'checkbox':
                                    results[fw][cmd['fieldname']] = soup.find('input', attrs={
                                        'name': cmd['fieldname']}).has_attr('checked')  #
                                if cmd['datatype'] == 'tablecell':
                                    results[fw][cmd['fieldname']] = tables[cmd['tablenum']][cmd['row']][cmd['col']]
                                if cmd['datatype'] == 'table':
                                    results[fw][cmd['fieldname']] = tables[cmd['tablenum']]
                                if cmd['datatype'] == 'table_id':
                                    debug('tablename:', cmd['tablename'])
                                    tabledata = [
                                        [td.get_text(strip=True) for td in tr.find_all('td')]
                                        for tr in soup.find('table', id=cmd['tablename']).find_all('tr')
                                    ]
                                    col_widths = [len(fw) + 2]
                                    for c_idx, colname in enumerate(tabledata[0]):
                                        col_widths.append(max([len(row[c_idx]) for row in tabledata if
                                                               len(row) == len(tabledata[0])]) + 2)
                                    out_str = ''
                                    for col_width in col_widths:
                                        out_str += '{:' + '{}.{}'.format(col_width, col_width) + 's} '
                                    for row in tabledata:
                                        if len(row) == len(tabledata[0]):
                                            pass
                                            # print(out_str.format(fw+',', *row))
                                        # print(col_width[index])
                                    '''for row in tabledata:
                                        for col in row:
                                            print('{:40.40s}'.format(col), end='')
                                        print('')
                                    '''

                                    '''[   [
                                                                        [td.get_text(strip=True) for td in tr.find_all('td')] 
                                                                        for tr in tabletmp.find_all('tr') ]
                                                                        for tabletmp in soup.find('table', id=cmd['tablename']) ]
                                    soup.find('table', id=cmd['tablename']).findAll('tr')
                                    '''
                                    results[fw][cmd['fieldname']] = tabledata
                                if cmd['datatype'] == 'inputvalue':
                                    results[fw][cmd['fieldname']] = \
                                    soup.find('input', attrs={'name': cmd['fieldname']})['value']
                                if cmd['datatype'] == 'listValue':
                                    data = re.sub(r'' + cmd['listname'] + '\((.*)\);', r'\1',
                                                  re.findall(r'' + cmd['listname'] + '.*', response.text)[0]).split(
                                        '\',')
                                    newlist = [re.sub('\s*\'', '', x) for x in data]
                                    # for item in data:
                                    #    print(item)
                                    results[fw][cmd['fieldname']] = newlist[cmd['valueindex']]

                        else:
                            results[fw][cmd['fieldname']] = None
                except Exception as e:
                    print(e)
                    for cmd in commands:
                        if cmd['pagename'] == pagename:
                            results[fw][cmd['fieldname']] = None
        else:
            for cmd in commands:
                results[fw][cmd['fieldname']] = None
    for fw in results:
        for fieldname in results[fw]:
            # print(type(results[fw][fieldname]))
            if type(results[fw][fieldname]) is not list:
                print(fieldname)
                print(results[fw][fieldname])
            # print(type(results[fw][result]))
            print('-' * 180)
            # print(results)