import netaddr
from urllib.parse import unquote

from logger import log_info, debug, log
from network_helper import netmask_to_cidr, expand_address

# REMOVED 9/30/2021 -- Was used in tuples, but has been replaced with get_zone
# def get_zone_old(context, ip):


def get_zone(context, ip, config):

    try:
        ip = ip.split('/')[0]
        log_info('Searching {} for address : {}'.format(context, ip))
        log_info('-' * 100)
        #        for item in config[context]:
        #            print(item)
        if 'routing' in config[context]:
            log_info('routing found in config')
            matchlen = -1

            for interface in config[context]['interfaces']:
                log_info('interface', interface)
                if config[context]['interfaces'][interface]['iface_lan_ip'] != '0.0.0.0':
                    if ip in netaddr.IPNetwork('{}/{}'.format(config[context]['interfaces'][interface]['iface_lan_ip'],
                                                              netmask_to_cidr(config[context]['interfaces'][interface][
                                                                                  'iface_lan_mask']))):
                        debug('matches lan', config[context]['interfaces'][interface]['interface_Zone'])
                        return config[context]['interfaces'][interface]['interface_Zone']
                if config[context]['interfaces'][interface]['iface_static_ip'] != '0.0.0.0':
                    # log(config[context]['interfaces'][interface]['iface_static_ip'])
                    debug(ip)
                    if ip in netaddr.IPNetwork(
                            '{}/{}'.format(config[context]['interfaces'][interface]['iface_static_ip'], netmask_to_cidr(
                                    config[context]['interfaces'][interface]['iface_static_mask']))):
                        debug('matches static', config[context]['interfaces'][interface]['interface_Zone'])
                        return config[context]['interfaces'][interface]['interface_Zone']
                if config[context]['interfaces'][interface]['iface_mgmt_ip'] != '0.0.0.0':
                    # log(config[context]['interfaces'][interface]['iface_mgmt_ip'])
                    if ip in netaddr.IPNetwork('{}/{}'.format(config[context]['interfaces'][interface]['iface_mgmt_ip'],
                                                              netmask_to_cidr(config[context]['interfaces'][interface][
                                                                                  'iface_mgmt_netmask']))):
                        debug('matches mgmt', config[context]['interfaces'][interface]['interface_Zone'])
                        return config[context]['interfaces'][interface]['interface_Zone']
            next_hop = None
            next_hop_ip = None
            # next_hop_iface = None
            next_hop_ifacenum = None
            next_hop_ifacename = None
            for route in config[context]['routing']:
                log_info('route', route)
                route_dest = config[context]['routing'][route]['pbrObjDst']
                if route_dest == '':
                    route_dest = '0.0.0.0'
                log_info('Route Destination :', route_dest)
                if config[context]['routing'][route]['pbrObjSrc'] == "":
                    if route_dest in config[context]['addresses']:
                        # print(config[context]['addresses'][route_dest])
                        # log_info(config[context]['addresses'][route_dest]['addrObjType'])
                        if config[context]['addresses'][route_dest]['addrObjType'] == '8':
                            # log_info(config[context]['addresses'][route_dest])
                            log_info('Route Destination is a group, checking each member object')
                            for route_dest_addr in expand_address(config[context]['addresses'], route_dest,
                                                                  config[context]['addressmappings']):
                                if route_dest_addr in config[context]['addresses']:
                                    log_info(route_dest_addr)
                                    # print(ip)
                                    if config[context]['addresses'][route_dest_addr]['addrObjType'] == '2':
                                        route_destination = netaddr.IPRange(
                                            config[context]['addresses'][route_dest_addr]['addrObjIp1'],
                                            config[context]['addresses'][route_dest_addr]['addrObjIp2'])
                                    else:
                                        route_destination = netaddr.IPNetwork(
                                            '{}/{}'.format(config[context]['addresses'][route_dest_addr]['addrObjIp1'],
                                                           config[context]['addresses'][route_dest_addr]['addrObjIp2']))
                                    if netaddr.IPAddress(ip) in route_destination:
                                        # if netaddr.IPAddress(ip) in netaddr.IPNetwork('{}/{}'.format(config[config[context]['addresses']['addrObjIp1'], netmask_to_cidr(config[context]['interfaces'][interface]['iface_lan_mask']))):
                                        # config[context]['addresses'][route_dest_addr]['IPSet']:
                                        debug('Matched to {}/{}'.format(
                                            config[context]['addresses'][route_dest_addr]['addrObjIp1'],
                                            config[context]['addresses'][route_dest_addr]['addrObjIp2']))
                                        if netmask_to_cidr(
                                                config[context]['addresses'][route_dest_addr]['addrObjIp2']) > matchlen:
                                            # log(config[context]['routing'][route])
                                            matchlen = netmask_to_cidr(
                                                config[context]['addresses'][route_dest_addr]['addrObjIp2'])
                                            next_hop = config[context]['routing'][route]['pbrObjGw']
                                            next_hop_ifacenum = config[context]['routing'][route]['pbrObjIface']
                                            debug('Nexthop : ', next_hop)
                                            debug(config[context]['routing'][route])
                                            if next_hop in config[context]['addresses']:
                                                debug('Next hop object found in addresses')
                                                next_hop_ip = config[context]['addresses'][next_hop]['addrObjIp1']
                                            else:
                                                next_hop_ip = next_hop
                                            if next_hop_ip == '':
                                                if config[context]['routing'][route]['pbrObjIface'] in [
                                                    config[context]['interfaces'][x]['iface_name'] for x in
                                                    config[context]['interfaces']]:
                                                    for x in config[context]['interfaces']:
                                                        if config[context]['routing'][route]['pbrObjIface'] == \
                                                                config[context]['interfaces'][x]['iface_name']:
                                                            if config[context]['interfaces'][x][
                                                                'iface_lan_ip'] != '0.0.0.0':
                                                                next_hop_ip = config[context]['interfaces'][x][
                                                                    'iface_lan_default_gw']
                                                            else:
                                                                next_hop_ip = config[context]['interfaces'][x][
                                                                    'iface_static_gateway']
                                            log_info('Searched address found in destination group: "{}" -'
                                                     ' MatchLength {} Nexthop {} {}'
                                                     .format(unquote(route_dest), matchlen, next_hop, next_hop_ip))
                                            ## THIS IS THE CORRECT GET_ZONE

                                        else:
                                            log_info('Skipping - not longest match')
                                else:
                                    log_info('Address group not found in context')
                        elif config[context]['addresses'][route_dest]['addrObjType'] == '2':
                            if netaddr.IPAddress(ip) in netaddr.IPRange(
                                    config[context]['addresses'][route_dest]['addrObjIp1'],
                                    config[context]['addresses'][route_dest]['addrObjIp2']):
                                # if ip in config[context]['addresses'][route_dest]['IPSet']:
                                log_info('Searched address found in destination range address object')
                                if netmask_to_cidr(config[context]['addresses'][route_dest]['addrObjIp2']) > matchlen:
                                    matchlen = 32
                                    next_hop = config[context]['routing'][route]['pbrObjGw']
                                    next_hop_ifacenum = config[context]['routing'][route]['pbrObjIface']
                                    if next_hop in config[context]['addresses']:
                                        next_hop_ip = config[context]['addresses'][next_hop]['addrObjIp1']
                                    else:
                                        next_hop_ip = next_hop
                                else:
                                    log_info('Skipping - not longest match')
                        else:
                            # if 'IPSet' in config[context]['addresses'][route_dest]:
                            if netaddr.IPAddress(ip) in netaddr.IPNetwork(
                                    '{}/{}'.format(config[context]['addresses'][route_dest]['addrObjIp1'],
                                                   config[context]['addresses'][route_dest]['addrObjIp2'])):
                                # if ip in config[context]['addresses'][route_dest]['IPSet']:
                                log_info('Searched address found in destination address')
                                if netmask_to_cidr(config[context]['addresses'][route_dest]['addrObjIp2']) > matchlen:
                                    matchlen = netmask_to_cidr(config[context]['addresses'][route_dest]['addrObjIp2'])
                                    next_hop = config[context]['routing'][route]['pbrObjGw']
                                    next_hop_ifacenum = config[context]['routing'][route]['pbrObjIface']
                                    if next_hop in config[context]['addresses']:
                                        next_hop_ip = config[context]['addresses'][next_hop]['addrObjIp1']
                                    else:
                                        next_hop_ip = next_hop
                                else:
                                    log_info('Skipping - not longest match')
                            # else:
                            #    log('WARNING - Route destinations with Range objects not yet supported - need to add IPSet property to Range address objects - {}-{}'.format(config[context]['addresses'][route_dest]['addrObjIp1'], config[context]['addresses'][route_dest]['addrObjIp2']))
                            # print(next_hop)
                            # print(next_hop_ip)
                    elif len(route_dest.split('/')) == 2:
                        log_info('Route destination is not in address objects')
                        try:
                            if netaddr.IPAddress(ip) in netaddr.IPNetwork(route_dest):
                                network, mask = route_dest.split('/')
                                if int(mask) >= matchlen:

                                    matchlen = int(mask)
                                    next_hop = config[context]['routing'][route]['pbrObjGw']
                                    next_hop_ifacenum = str(config[context]['routing'][route]['pbrObjIface'])
                                    if 'pbrObjIfaceName' in config[context]['routing'][route]:
                                        next_hop_ifacename = config[context]['routing'][route]['pbrObjIfaceName']
                                    else:
                                        next_hop_ifacename = ''
                                    log_info('MATCH1 "{}" "{}" "{}" "{}"'.format(network, mask,
                                                                                 config[context]['routing'][route][
                                                                                     'pbrObjGw'],
                                                                                 config[context]['routing'][route][
                                                                                     'pbrObjIface'], ))
                                if next_hop in config[context]['addresses']:
                                    next_hop_ip = config[context]['addresses'][next_hop]['addrObjIp1']
                                else:
                                    next_hop_ip = next_hop
                        except Exception as e:
                            log(e)
                            log('Route destination not in network/mask format')
                    elif route_dest == '0.0.0.0' and matchlen < 0:  # route is a default route
                        matchlen = 0
                        next_hop = config[context]['routing'][route]['pbrObjGw']
                        next_hop_ifacenum = config[context]['routing'][route]['pbrObjIface']
                        if 'pbrObjIfaceName' in config[context]['routing'][route]:
                            next_hop_ifacename = config[context]['routing'][route]['pbrObjIfaceName']
                        else:
                            next_hop_ifacename = ''
                        if next_hop in config[context]['addresses']:
                            next_hop_ip = config[context]['addresses'][next_hop]['addrObjIp1']
                        else:
                            next_hop_ip = next_hop
                        log_info('Default Route!')

                    # print(config[context]['interfaces'])
            log_info('Matchlen', matchlen)

            if next_hop_ifacenum != None:
                for interface in config[context]['interfaces']:
                    # log('"{}" "{}" "{}" "{}"'.format(config[context]['interfaces'][interface]['iface_ifnum'], next_hop_ifacenum, config[context]['interfaces'][interface]['iface_name'], next_hop_ifacename))
                    if config[context]['interfaces'][interface][
                        'iface_name'] == next_hop_ifacename:  # or config[context]['interfaces'][interface]['iface_name'] == next_hop_ifacen:
                        # log("-" *180)
                        # log('!!!!{}!!!!!!'.format(config[context]['interfaces'][interface]['iface_name']))
                        # log("-" *180)
                        # log(config[context]['interfaces'][interface]['interface_Zone'])
                        return config[context]['interfaces'][interface]['interface_Zone']

            if matchlen != -1:
                if next_hop_ip == '':
                    next_hop_ip = '0.0.0.0'
                log_info('NEXTHOP', next_hop, next_hop_ip, next_hop_ifacenum)

                for interface in config[context]['interfaces']:
                    if config[context]['interfaces'][interface]['iface_lan_ip'] != '0.0.0.0':
                        if netaddr.IPAddress(next_hop_ip) in netaddr.IPNetwork(
                                '{}/{}'.format(config[context]['interfaces'][interface]['iface_lan_ip'],
                                               netmask_to_cidr(
                                                       config[context]['interfaces'][interface]['iface_lan_mask']))):
                            # print('{} - {}/{}'.format(config[context]['interfaces'][interface]['iface_name'],config[context]['interfaces'][interface]['iface_lan_ip'],config[context]['interfaces'][interface]['iface_lan_mask']))
                            # print('ROUTE MATCH - Searched address {} is in Zone : {} Interface Name: {} Interface Address {}/{}'.format(ip, config[context]['interfaces'][interface]['interface_Zone'], config[context]['interfaces'][interface]['iface_name'], config[context]['interfaces'][interface]['iface_lan_ip'],netmask_to_cidr(config[context]['interfaces'][interface]['iface_lan_mask'])))
                            return config[context]['interfaces'][interface]['interface_Zone']
                    elif config[context]['interfaces'][interface]['iface_static_ip'] != '0.0.0.0':
                        # log(netaddr.IPAddress(next_hop_ip))
                        # log(config[context]['interfaces'][interface]['iface_static_ip'], config[context]['interfaces'][interface]['iface_static_mask'])
                        if netaddr.IPAddress(next_hop_ip) in netaddr.IPNetwork(
                                '{}/{}'.format(config[context]['interfaces'][interface]['iface_static_ip'],
                                               netmask_to_cidr(
                                                       config[context]['interfaces'][interface]['iface_static_mask']))):
                            ##print('{} - {}/{}'.format(config[context]['interfaces'][interface]['iface_name'],config[context]['interfaces'][interface]['iface_static_ip'],config[context]['interfaces'][interface]['iface_static_mask']))
                            # print('ROUTE MATCH - Searched address {} is in Zone : {} Interface Name: {} Interface Address {}/{}'.format(ip, config[context]['interfaces'][interface]['interface_Zone'], config[context]['interfaces'][interface]['iface_name'], config[context]['interfaces'][interface]['iface_static_ip'],netmask_to_cidr(config[context]['interfaces'][interface]['iface_static_mask'])))
                            return config[context]['interfaces'][interface]['interface_Zone']
                    elif config[context]['interfaces'][interface]['iface_mgmt_ip'] != '0.0.0.0':
                        if netaddr.IPAddress(next_hop_ip) in netaddr.IPNetwork(
                                '{}/{}'.format(config[context]['interfaces'][interface]['iface_mgmt_ip'],
                                               netmask_to_cidr(config[context]['interfaces'][interface][
                                                                   'iface_mgmt_netmask']))):
                            # print('{} - {}/{}'.format(config[context]['interfaces'][interface]['iface_name'],config[context]['interfaces'][interface]['iface_mgmt_ip'],config[context]['interfaces'][interface]['iface_mgmt_netmask']))
                            # print('ROUTE MATCH - Searched address {} is in Zone : {} Interface Name: {} Interface Address {}/{}'.format(ip, config[context]['interfaces'][interface]['interface_Zone'], config[context]['interfaces'][interface]['iface_name'], config[context]['interfaces'][interface]['iface_mgmt_ip'],netmask_to_cidr(config[context]['interfaces'][interface]['iface_mgmt_netmask'])))
                            return config[context]['interfaces'][interface]['interface_Zone']
                else:  # as a last resort, try getting static gateway from interface config -- these are auto added rules and not part of the pbr config
                    if next_hop_ip == '0.0.0.0':
                        return 'WAN'
                    log_info('Trying to see if ip is on same net as interface')
                    for interface in config[context]['interfaces']:
                        if config[context]['interfaces'][interface]['iface_lan_ip'] != '0.0.0.0':
                            if ip in netaddr.IPNetwork(
                                    '{}/{}'.format(config[context]['interfaces'][interface]['iface_lan_ip'],
                                                   netmask_to_cidr(config[context]['interfaces'][interface][
                                                                       'iface_lan_mask']))):
                                return config[context]['interfaces'][interface]['interface_Zone']

                    # return None

            else:  # check if ip address is on same subnet as interfaces - lan_ip should likely be done before checking pbr, static_ip should likely be done after
                # log_info('Trying to see if ip is on same net as interface')
                for interface in config[context]['interfaces']:
                    if config[context]['interfaces'][interface]['iface_lan_ip'] != '0.0.0.0':
                        if ip in netaddr.IPNetwork(
                                '{}/{}'.format(config[context]['interfaces'][interface]['iface_lan_ip'],
                                               netmask_to_cidr(
                                                       config[context]['interfaces'][interface]['iface_lan_mask']))):
                            return config[context]['interfaces'][interface]['interface_Zone']
                for interface in config[context]['interfaces']:
                    if config[context]['interfaces'][interface]['iface_static_ip'] != '0.0.0.0':
                        # if ip in netaddr.IPNetwork('{}/{}'.format(config[context]['interfaces'][interface]['iface_static_ip'],netmask_to_cidr(config[context]['interfaces'][interface]['iface_static_mask']))):
                        return config[context]['interfaces'][interface]['interface_Zone']

        else:
            log_info('Routing not in config')
    except Exception as e:
        debug(e, e.__traceback__.tb_lineno)
        return None
    return None


def get_zone2(context, ip, config):
    import netaddr
    import urllib

    try:
        ip, mask = ip.split('/')
    except:
        ip, mask = (ip, '32')
    try:
        ipNetwork = netaddr.IPNetwork('{}/{}'.format(ip, mask))

        log_info('Searching {} for address : {}'.format(context, ip))
        log_info('-' * 100)
        #        for item in config[context]:
        #            print(item)
        return_zones = []
        if 'routing' in config[context]:
            log_info('routing found in config')
            matchlen = -1

            for interface in config[context]['interfaces']:  ## this 
                log_info('interface', interface)
                if config[context]['interfaces'][interface]['iface_lan_ip'] != '0.0.0.0':
                    if ip in netaddr.IPNetwork('{}/{}'.format(config[context]['interfaces'][interface]['iface_lan_ip'],
                                                              netmask_to_cidr(config[context]['interfaces'][interface][
                                                                                  'iface_lan_mask']))) or netaddr.IPNetwork(
                            '{}/{}'.format(config[context]['interfaces'][interface]['iface_lan_ip'], netmask_to_cidr(
                                    config[context]['interfaces'][interface]['iface_lan_mask']))) in ipNetwork:
                        debug('matches lan', config[context]['interfaces'][interface]['interface_Zone'])
                        return_zones.append(config[context]['interfaces'][interface]['interface_Zone'])
                if config[context]['interfaces'][interface]['iface_static_ip'] != '0.0.0.0':
                    # log(config[context]['interfaces'][interface]['iface_static_ip'])
                    debug(ip)
                    if ip in netaddr.IPNetwork(
                            '{}/{}'.format(config[context]['interfaces'][interface]['iface_static_ip'], netmask_to_cidr(
                                    config[context]['interfaces'][interface][
                                        'iface_static_mask']))) or netaddr.IPNetwork(
                            '{}/{}'.format(config[context]['interfaces'][interface]['iface_static_ip'], netmask_to_cidr(
                                    config[context]['interfaces'][interface]['iface_static_mask']))) in ipNetwork:
                        debug('matches static', config[context]['interfaces'][interface]['interface_Zone'])
                        return_zones.append(config[context]['interfaces'][interface]['interface_Zone'])
                if config[context]['interfaces'][interface]['iface_mgmt_ip'] != '0.0.0.0':
                    # log(config[context]['interfaces'][interface]['iface_mgmt_ip'])
                    if ip in netaddr.IPNetwork('{}/{}'.format(config[context]['interfaces'][interface]['iface_mgmt_ip'],
                                                              netmask_to_cidr(config[context]['interfaces'][interface][
                                                                                  'iface_mgmt_netmask']))) or netaddr.IPNetwork(
                            '{}/{}'.format(config[context]['interfaces'][interface]['iface_mgmt_ip'], netmask_to_cidr(
                                    config[context]['interfaces'][interface]['iface_mgmt_netmask']))) in ipNetwork:
                        debug('matches mgmt', config[context]['interfaces'][interface]['interface_Zone'])
                        return_zones.append(config[context]['interfaces'][interface]['interface_Zone'])
            # log('return_zones after checking intrfaces', return_zones)
            next_hop = None
            next_hop_ip = None
            next_hop_iface = None
            next_hop_ifacenum = None

            ## this was added becasue of zone calc here and in expedition was wrong is an address object is a "supernet" -- the result is that it is likely part of multiple zones, rather than just 1
            ## its likely that this should only be performed if matchlen=0 (default route)
            '''
            for route in config[context]['routing']:  
                route_dest=config[context]['routing'][route]['pbrObjDst']
                if len(route_dest.split('/'))==2 and config[context]['routing'][route]['pbrObjDst'] not in config[context]['addresses']:
                    #log_info('Route destination is not in address objects')
                    try:
                        #log('{},{}'.format(netaddr.IPNetwork(route_dest), ipNetwork))
                        if netaddr.IPNetwork(route_dest) in ipNetwork:
                            return_zones.append(config[context]['interfaces'][config[context]['routing'][route]['pbrObjIface']]['interface_Zone'])
                    except Exception as e: 
                        log('EXCEPTION!!!! {}'.format(e))
            '''

            for route in config[context]['routing']:
                log_info('route', route)
                route_dest = config[context]['routing'][route]['pbrObjDst']
                if route_dest == '':
                    pass
                    # route_dest='0.0.0.0'
                log_info('Route Destination :', route_dest)
                if config[context]['routing'][route]['pbrObjSrc'] == "":
                    if route_dest in config[context]['addresses']:
                        # log('JEFF!!!', route_dest)
                        # print(config[context]['addresses'][route_dest])
                        # log_info(config[context]['addresses'][route_dest]['addrObjType'])
                        if config[context]['addresses'][route_dest]['addrObjType'] == '8':
                            # log_info(config[context]['addresses'][route_dest])
                            log_info('Route Destination is a group, checking each member object')
                            for route_dest_addr in expand_address(config[context]['addresses'], route_dest,
                                                                  config[context]['addressmappings']):
                                if route_dest_addr in config[context]['addresses']:
                                    log_info(route_dest_addr)
                                    # print(ip)
                                    if config[context]['addresses'][route_dest_addr]['addrObjType'] == '2':
                                        route_destination = netaddr.IPRange(
                                            config[context]['addresses'][route_dest_addr]['addrObjIp1'],
                                            config[context]['addresses'][route_dest_addr]['addrObjIp2'])
                                    else:
                                        route_destination = netaddr.IPNetwork(
                                            '{}/{}'.format(config[context]['addresses'][route_dest_addr]['addrObjIp1'],
                                                           config[context]['addresses'][route_dest_addr]['addrObjIp2']))
                                    if netaddr.IPAddress(ip) in route_destination:
                                        # if netaddr.IPAddress(ip) in netaddr.IPNetwork('{}/{}'.format(config[config[context]['addresses']['addrObjIp1'], netmask_to_cidr(config[context]['interfaces'][interface]['iface_lan_mask']))):
                                        # config[context]['addresses'][route_dest_addr]['IPSet']:
                                        debug('Matched to {}/{}'.format(
                                            config[context]['addresses'][route_dest_addr]['addrObjIp1'],
                                            config[context]['addresses'][route_dest_addr]['addrObjIp2']))
                                        if netmask_to_cidr(
                                                config[context]['addresses'][route_dest_addr]['addrObjIp2']) > matchlen:
                                            # log(config[context]['routing'][route])
                                            matchlen = netmask_to_cidr(
                                                config[context]['addresses'][route_dest_addr]['addrObjIp2'])
                                            next_hop = config[context]['routing'][route]['pbrObjGw']
                                            next_hop_ifacenum = config[context]['routing'][route]['pbrObjIface']
                                            debug('Nexthop : ', next_hop)
                                            debug(config[context]['routing'][route])
                                            if next_hop in config[context]['addresses']:
                                                debug('Next hop object found in addresses')
                                                next_hop_ip = config[context]['addresses'][next_hop]['addrObjIp1']
                                            else:
                                                next_hop_ip = next_hop
                                            if next_hop_ip == '':
                                                if config[context]['routing'][route]['pbrObjIface'] in [
                                                    config[context]['interfaces'][x]['iface_name'] for x in
                                                    config[context]['interfaces']]:
                                                    for x in config[context]['interfaces']:
                                                        if config[context]['routing'][route]['pbrObjIface'] == \
                                                                config[context]['interfaces'][x]['iface_name']:
                                                            if config[context]['interfaces'][x][
                                                                'iface_lan_ip'] != '0.0.0.0':
                                                                next_hop_ip = config[context]['interfaces'][x][
                                                                    'iface_lan_default_gw']
                                                            else:
                                                                next_hop_ip = config[context]['interfaces'][x][
                                                                    'iface_static_gateway']
                                            log_info(
                                                'Searched address found in destination group: "{}" - MatchLength {} Nexthop {} {}'.format(
                                                    urllib.parse.unquote(route_dest), matchlen, next_hop, next_hop_ip))
                                            ## THIS IS THE CORRECT GET_ZONE

                                        else:
                                            log_info('Skipping - not longest match')
                                else:
                                    log_info('Address group not found in context')
                        elif config[context]['addresses'][route_dest]['addrObjType'] == '2':
                            if netaddr.IPAddress(ip) in netaddr.IPRange(
                                    config[context]['addresses'][route_dest]['addrObjIp1'],
                                    config[context]['addresses'][route_dest]['addrObjIp2']):
                                # if ip in config[context]['addresses'][route_dest]['IPSet']:
                                log_info('Searched address found in destination range address object')
                                if netmask_to_cidr(config[context]['addresses'][route_dest]['addrObjIp2']) > matchlen:
                                    matchlen = 32
                                    next_hop = config[context]['routing'][route]['pbrObjGw']
                                    next_hop_ifacenum = config[context]['routing'][route]['pbrObjIface']
                                    if next_hop in config[context]['addresses']:
                                        next_hop_ip = config[context]['addresses'][next_hop]['addrObjIp1']
                                    else:
                                        next_hop_ip = next_hop
                                else:
                                    log_info('Skipping - not longest match')
                        else:
                            # if 'IPSet' in config[context]['addresses'][route_dest]:
                            if netaddr.IPAddress(ip) in netaddr.IPNetwork(
                                    '{}/{}'.format(config[context]['addresses'][route_dest]['addrObjIp1'],
                                                   config[context]['addresses'][route_dest]['addrObjIp2'])):
                                # if ip in config[context]['addresses'][route_dest]['IPSet']:
                                log_info('Searched address found in destination address')
                                if netmask_to_cidr(config[context]['addresses'][route_dest]['addrObjIp2']) > matchlen:
                                    matchlen = netmask_to_cidr(config[context]['addresses'][route_dest]['addrObjIp2'])
                                    next_hop = config[context]['routing'][route]['pbrObjGw']
                                    next_hop_ifacenum = config[context]['routing'][route]['pbrObjIface']
                                    if next_hop in config[context]['addresses']:
                                        next_hop_ip = config[context]['addresses'][next_hop]['addrObjIp1']
                                    else:
                                        next_hop_ip = next_hop
                                else:
                                    log_info('Skipping - not longest match')
                            # else:
                            #    log('WARNING - Route destinations with Range objects not yet supported - need to add IPSet property to Range address objects - {}-{}'.format(config[context]['addresses'][route_dest]['addrObjIp1'], config[context]['addresses'][route_dest]['addrObjIp2']))
                            # print(next_hop)
                            # print(next_hop_ip)
                    elif len(route_dest.split('/')) == 2:
                        log_info('Route destination is not in address objects')
                        try:
                            if netaddr.IPAddress(ip) in netaddr.IPNetwork(route_dest):
                                network, mask = route_dest.split('/')
                                if int(mask) >= matchlen:
                                    log_info('MATCH1', network, mask, config[context]['routing'][route]['pbrObjGw'])
                                    matchlen = int(mask)
                                    next_hop = config[context]['routing'][route]['pbrObjGw']
                                    next_hop_ifacenum = config[context]['routing'][route]['pbrObjIface']
                                if next_hop in config[context]['addresses']:
                                    next_hop_ip = config[context]['addresses'][next_hop]['addrObjIp1']
                                else:
                                    next_hop_ip = next_hop
                        except Exception as e:
                            log(e)
                            log('Route destination not in network/mask format')
                    elif route_dest == '0.0.0.0' and matchlen < 0:  # route is a default route
                        matchlen = 0
                        next_hop = config[context]['routing'][route]['pbrObjGw']
                        next_hop_ifacenum = config[context]['routing'][route]['pbrObjIface']
                        if next_hop in config[context]['addresses']:
                            next_hop_ip = config[context]['addresses'][next_hop]['addrObjIp1']
                        else:
                            next_hop_ip = next_hop
                        # log(config[context]['routing'][route])
                        log_info('Default Route! "{}" "{}"'.format(next_hop, next_hop_ifacenum))

                    # print(config[context]['interfaces'])
            log_info('Matchlen', matchlen)
            # log('return_zones before next_hop_ifacenum != 1', return_zones)
            if next_hop_ifacenum != None:
                for interface in config[context]['interfaces']:
                    if config[context]['interfaces'][interface]['iface_ifnum'] == next_hop_ifacenum or \
                            config[context]['interfaces'][interface]['iface_name'] == next_hop_ifacenum:
                        return_zones.append(config[context]['interfaces'][interface]['interface_Zone'])
            # log('return_zones before matchlength != 1', return_zones)
            if matchlen != -1:
                if next_hop_ip == '':
                    next_hop_ip = '0.0.0.0'
                log_info('NEXTHOP', next_hop, next_hop_ip, next_hop_ifacenum)

                for interface in config[context]['interfaces']:
                    if config[context]['interfaces'][interface]['iface_lan_ip'] != '0.0.0.0':
                        if netaddr.IPAddress(next_hop_ip) in netaddr.IPNetwork(
                                '{}/{}'.format(config[context]['interfaces'][interface]['iface_lan_ip'],
                                               netmask_to_cidr(
                                                       config[context]['interfaces'][interface]['iface_lan_mask']))):
                            # print('{} - {}/{}'.format(config[context]['interfaces'][interface]['iface_name'],config[context]['interfaces'][interface]['iface_lan_ip'],config[context]['interfaces'][interface]['iface_lan_mask']))
                            # print('ROUTE MATCH - Searched address {} is in Zone : {} Interface Name: {} Interface Address {}/{}'.format(ip, config[context]['interfaces'][interface]['interface_Zone'], config[context]['interfaces'][interface]['iface_name'], config[context]['interfaces'][interface]['iface_lan_ip'],netmask_to_cidr(config[context]['interfaces'][interface]['iface_lan_mask'])))
                            return_zones.append(config[context]['interfaces'][interface]['interface_Zone'])
                    elif config[context]['interfaces'][interface]['iface_static_ip'] != '0.0.0.0':
                        # log(netaddr.IPAddress(next_hop_ip))
                        # log(config[context]['interfaces'][interface]['iface_static_ip'], config[context]['interfaces'][interface]['iface_static_mask'])
                        if netaddr.IPAddress(next_hop_ip) in netaddr.IPNetwork(
                                '{}/{}'.format(config[context]['interfaces'][interface]['iface_static_ip'],
                                               netmask_to_cidr(
                                                       config[context]['interfaces'][interface]['iface_static_mask']))):
                            ##print('{} - {}/{}'.format(config[context]['interfaces'][interface]['iface_name'],config[context]['interfaces'][interface]['iface_static_ip'],config[context]['interfaces'][interface]['iface_static_mask']))
                            # print('ROUTE MATCH - Searched address {} is in Zone : {} Interface Name: {} Interface Address {}/{}'.format(ip, config[context]['interfaces'][interface]['interface_Zone'], config[context]['interfaces'][interface]['iface_name'], config[context]['interfaces'][interface]['iface_static_ip'],netmask_to_cidr(config[context]['interfaces'][interface]['iface_static_mask'])))
                            return_zones.append(config[context]['interfaces'][interface]['interface_Zone'])
                    elif config[context]['interfaces'][interface]['iface_mgmt_ip'] != '0.0.0.0':
                        if netaddr.IPAddress(next_hop_ip) in netaddr.IPNetwork(
                                '{}/{}'.format(config[context]['interfaces'][interface]['iface_mgmt_ip'],
                                               netmask_to_cidr(config[context]['interfaces'][interface][
                                                                   'iface_mgmt_netmask']))):
                            # print('{} - {}/{}'.format(config[context]['interfaces'][interface]['iface_name'],config[context]['interfaces'][interface]['iface_mgmt_ip'],config[context]['interfaces'][interface]['iface_mgmt_netmask']))
                            # print('ROUTE MATCH - Searched address {} is in Zone : {} Interface Name: {} Interface Address {}/{}'.format(ip, config[context]['interfaces'][interface]['interface_Zone'], config[context]['interfaces'][interface]['iface_name'], config[context]['interfaces'][interface]['iface_mgmt_ip'],netmask_to_cidr(config[context]['interfaces'][interface]['iface_mgmt_netmask'])))
                            return_zones.append(config[context]['interfaces'][interface]['interface_Zone'])
                else:  # as a last resort, try getting static gateway from interface config -- these are auto added rules and not part of the pbr config
                    if next_hop_ip == '0.0.0.0':
                        return_zones.append('WAN')
                    log_info('Trying to see if ip is on same net as interface')
                    for interface in config[context]['interfaces']:
                        if config[context]['interfaces'][interface]['iface_lan_ip'] != '0.0.0.0':
                            if ip in netaddr.IPNetwork(
                                    '{}/{}'.format(config[context]['interfaces'][interface]['iface_lan_ip'],
                                                   netmask_to_cidr(config[context]['interfaces'][interface][
                                                                       'iface_lan_mask']))):
                                return_zones.append(config[context]['interfaces'][interface]['interface_Zone'])

                    # return None

            else:  # check if ip address is on same subnet as interfaces - lan_ip should likely be done before checking pbr, static_ip should likely be done after
                # log_info('Trying to see if ip is on same net as interface')
                for interface in config[context]['interfaces']:
                    # log('interface', config[context]['interfaces'][interface])
                    if config[context]['interfaces'][interface]['iface_lan_ip'] != '0.0.0.0':
                        if ip in netaddr.IPNetwork(
                                '{}/{}'.format(config[context]['interfaces'][interface]['iface_lan_ip'],
                                               netmask_to_cidr(
                                                       config[context]['interfaces'][interface]['iface_lan_mask']))):
                            return_zones.append(config[context]['interfaces'][interface]['interface_Zone'])
                if return_zones == []:
                    for interface in config[context]['interfaces']:
                        if config[context]['interfaces'][interface]['iface_static_ip'] != '0.0.0.0':
                            if ip in netaddr.IPNetwork(
                                    '{}/{}'.format(config[context]['interfaces'][interface]['iface_static_ip'],
                                                   netmask_to_cidr(config[context]['interfaces'][interface][
                                                                       'iface_static_mask']))):
                                return_zones.append(config[context]['interfaces'][interface]['interface_Zone'])
                if return_zones == []:
                    return_zones.append('WAN')
                '''
                for interface in config[context]['interfaces']:
                    if config[context]['interfaces'][interface]['iface_static_ip']!='0.0.0.0' and config[context]['interfaces'][interface]['interface_Zone']=='WAN':
                        #if ip in netaddr.IPNetwork('{}/{}'.format(config[context]['interfaces'][interface]['iface_static_ip'],netmask_to_cidr(config[context]['interfaces'][interface]['iface_static_mask']))):
                        #log(config[context]['interfaces'][interface]['interface_Zone'])
                        return_zones.append(config[context]['interfaces'][interface]['interface_Zone'])
                '''

                # log('return_zones after failing matchlen check', return_zones)
            return list(set(return_zones))
        else:
            log_info('Routing not in config')
    except:
        return None
    return None
