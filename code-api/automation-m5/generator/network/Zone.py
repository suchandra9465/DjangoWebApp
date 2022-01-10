import netaddr
import urllib
import json

from ...generator import NetworkLogs

import Service as S
import CreateService as CS


class Zones:

    def _init_(self, options, config):
        self.log = NetworkLogs().log
        self.sc = NetworkLogs().sc
        self.ss = NetworkLogs().ss
        self.debug = NetworkLogs().debug
        self.config = config
        self.options = options
        self.service = S.Service(self.options)
        self.createNetworkService = CS.CreateNetworkService(self.options, self.config)

    def get_zones(self, context, address_obj, config):
        zones = []
        for address in self.createNetworkService.expand_address(config[context]['addresses'], address_obj,
                                                                config[context]['addressmappings']):
            for network in config[context]['addresses'][address]['IPv4Networks']:
                self.debug(context)
                tmp_zone = self.get_zone(context, '{}'.format(network[0]), config)
                if tmp_zone not in zones:
                    zones.append(tmp_zone)
        return zones

    def get_zones2(self, context, address_obj, tmpconfig=None):
        zones = []
        if tmpconfig:
            config = tmpconfig
        for address in self.createNetworkService.expand_address(self.config[context]['addresses'], address_obj,
                                                                self.config[context]['addressmappings']):
            for network in config[context]['addresses'][address]['IPv4Networks']:
                tmp_zones = self.get_zone2(context, '{}'.format(network), config)
                for tmp_zone in tmp_zones:
                    if tmp_zone not in zones:
                        zones.append(tmp_zone)
        return zones

    def get_zone_old(self, context, ip):
        self.debug('Searching {} for address : {}'.format(context, ip))
        self.debug('-' * 100)
        if 'routing' in self.config[context]:
            matchlen = -1
            for interface in self.config[context]['interfaces']:
                if self.config[context]['interfaces'][interface]['iface_lan_ip'] != '0.0.0.0':
                    if ip in netaddr.IPNetwork(
                            '{}/{}'.format(self.config[context]['interfaces'][interface]['iface_lan_ip'],
                                           self.service.netmask_to_cidr(self.config[context]['interfaces'][interface][
                                                                            'iface_lan_mask']))):
                        self.debug('matches lan', self.config[context]['interfaces'][interface]['interface_Zone'])
                        return self.config[context]['interfaces'][interface]['interface_Zone']
                if self.config[context]['interfaces'][interface]['iface_static_ip'] != '0.0.0.0':
                    if ip in netaddr.IPNetwork(
                            '{}/{}'.format(self.config[context]['interfaces'][interface]['iface_static_ip'],
                                           self.service.netmask_to_cidr(self.config[context]['interfaces'][interface][
                                                                            'iface_static_mask']))):
                        self.debug('matches static', self.config[context]['interfaces'][interface]['interface_Zone'])
                        return self.config[context]['interfaces'][interface]['interface_Zone']
                if self.config[context]['interfaces'][interface]['iface_mgmt_ip'] != '0.0.0.0':
                    if ip in netaddr.IPNetwork(
                            '{}/{}'.format(self.config[context]['interfaces'][interface]['iface_mgmt_ip'],
                                           self.service.netmask_to_cidr(self.config[context]['interfaces'][interface][
                                                                            'iface_mgmt_netmask']))):
                        self.debug('matches mgmt', self.config[context]['interfaces'][interface]['interface_Zone'])
                        return self.config[context]['interfaces'][interface]['interface_Zone']

            for route in self.config[context]['routing']:
                route_dest = self.config[context]['routing'][route]['pbrObjDst']
                if route_dest == '':
                    route_dest = '0.0.0.0'
                self.debug(route_dest)
                if route_dest in self.config[context]['addresses']:
                    self.debug(self.config[context]['addresses'][route_dest]['addrObjType'])
                    if self.config[context]['addresses'][route_dest]['addrObjType'] == '8':
                        self.debug(self.config[context]['addresses'][route_dest])
                        self.debug('Route Destination is a group, checking each member object')
                        for route_dest_addr in self.createNetworkService.expand_address(
                                self.config[context]['addresses'], route_dest,
                                self.config[context]['addressmappings']):
                            if route_dest_addr in self.config[context]['addresses']:
                                self.debug(route_dest_addr)
                                if netaddr.IPAddress(ip) in netaddr.IPNetwork(
                                        '{}/{}'.format(self.config[context]['addresses'][route_dest_addr]['addrObjIp1'],
                                                       self.config[context]['addresses'][route_dest_addr][
                                                           'addrObjIp2'])):
                                    self.debug('Searched address found in destination group: "{}"'.format(
                                        urllib.parse.unquote(route_dest)))
                                    if self.service.netmask_to_cidr(
                                            self.config[context]['addresses'][route_dest_addr][
                                                'addrObjIp2']) > matchlen:
                                        matchlen = self.service.netmask_to_cidr(
                                            self.config[context]['addresses'][route_dest_addr]['addrObjIp2'])
                                        next_hop = self.config[context]['routing'][route]['pbrObjGw']
                                        next_hop_int = self.config[context]['routing'][route]['pbrObjIface']
                                        if next_hop in self.config[context]['addresses']:
                                            next_hop_ip = self.config[context]['addresses'][next_hop]['addrObjIp1']
                                        else:
                                            next_hop_ip = next_hop
                                    else:
                                        self.debug('Skipping - not longest match')
                            else:
                                self.debug('Address group not found in context')
                    else:
                        if netaddr.IPAddress(ip) in netaddr.IPNetwork(
                                '{}/{}'.format(self.config[context]['addresses'][route_dest]['addrObjIp1'],
                                               self.config[context]['addresses'][route_dest]['addrObjIp2'])):
                            self.debug('Searched address found in destination address')
                            if self.service.netmask_to_cidr(
                                    self.config[context]['addresses'][route_dest]['addrObjIp2']) > matchlen:
                                matchlen = self.service.netmask_to_cidr(
                                    self.config[context]['addresses'][route_dest]['addrObjIp2'])
                                next_hop = self.config[context]['routing'][route]['pbrObjGw']
                                next_hop_int = self.config[context]['routing'][route]['pbrObjIface']
                                if next_hop in self.config[context]['addresses']:
                                    next_hop_ip = self.config[context]['addresses'][next_hop]['addrObjIp1']
                                else:
                                    next_hop_ip = next_hop
                            else:
                                self.debug('Skipping - not longest match')
                elif len(route_dest.split('/')) == 2:
                    self.debug('Route destination is not in address objects')
                    try:
                        if netaddr.IPAddress(ip) in netaddr.IPNetwork(route_dest):
                            network, mask = route_dest.split('/')
                            if int(mask) >= matchlen:
                                self.debug('MATCH1', network, mask, self.config[context]['routing'][route]['pbrObjGw'])
                                matchlen = int(mask)
                                next_hop = self.config[context]['routing'][route]['pbrObjGw']
                                next_hop_int = self.config[context]['routing'][route]['pbrObjIface']
                            if next_hop in self.config[context]['addresses']:
                                next_hop_ip = self.config[context]['addresses'][next_hop]['addrObjIp1']
                            else:
                                next_hop_ip = next_hop
                    except Exception as e:
                        self.log(e)
                        self.log('Route destination not in network/mask format')
                # route is a default route
                elif route_dest == '0.0.0.0':
                    matchlen = 0
                    next_hop = self.config[context]['routing'][route]['pbrObjGw']
                    if next_hop in self.config[context]['addresses']:
                        next_hop_ip = self.config[context]['addresses'][next_hop]['addrObjIp1']
                    else:
                        next_hop_ip = next_hop
                    self.debug('Default Route!')

            self.debug('Matchlen', matchlen)
            if matchlen != -1:
                self.debug('NEXTHOP', next_hop_ip)
                for interface in self.config[context]['interfaces']:
                    if self.config[context]['interfaces'][interface]['iface_name'] == next_hop_int and \
                            self.config[context]['interfaces'][interface]['interface_Zone'] != "":
                        return self.config[context]['interfaces'][interface]['interface_Zone']
                    if self.config[context]['interfaces'][interface]['iface_lan_ip'] != '0.0.0.0':
                        if netaddr.IPAddress(next_hop_ip) in netaddr.IPNetwork(
                                '{}/{}'.format(self.config[context]['interfaces'][interface]['iface_lan_ip'],
                                               self.service.netmask_to_cidr(
                                                   self.config[context]['interfaces'][interface]['iface_lan_mask']))):
                            # print('{} - {}/{}'.format(config[context]['interfaces'][interface]['iface_name'],config[context]['interfaces'][interface]['iface_lan_ip'],config[context]['interfaces'][interface]['iface_lan_mask']))
                            # print('ROUTE MATCH - Searched address {} is in Zone : {} Interface Name: {} Interface Address {}/{}'.format(ip, config[context]['interfaces'][interface]['interface_Zone'], config[context]['interfaces'][interface]['iface_name'], config[context]['interfaces'][interface]['iface_lan_ip'],self.service.netmask_to_cidr(config[context]['interfaces'][interface]['iface_lan_mask'])))
                            return self.config[context]['interfaces'][interface]['interface_Zone']
                    elif self.config[context]['interfaces'][interface]['iface_static_ip'] != '0.0.0.0':
                        if netaddr.IPAddress(next_hop_ip) in netaddr.IPNetwork(
                                '{}/{}'.format(self.config[context]['interfaces'][interface]['iface_static_ip'],
                                               self.service.netmask_to_cidr(
                                                   self.config[context]['interfaces'][interface][
                                                       'iface_static_mask']))):
                            ##print('{} - {}/{}'.format(config[context]['interfaces'][interface]['iface_name'],config[context]['interfaces'][interface]['iface_static_ip'],config[context]['interfaces'][interface]['iface_static_mask']))
                            # print('ROUTE MATCH - Searched address {} is in Zone : {} Interface Name: {} Interface Address {}/{}'.format(ip, config[context]['interfaces'][interface]['interface_Zone'], config[context]['interfaces'][interface]['iface_name'], config[context]['interfaces'][interface]['iface_static_ip'],self.service.netmask_to_cidr(config[context]['interfaces'][interface]['iface_static_mask'])))
                            return self.config[context]['interfaces'][interface]['interface_Zone']
                    elif self.config[context]['interfaces'][interface]['iface_mgmt_ip'] != '0.0.0.0':
                        if netaddr.IPAddress(next_hop_ip) in netaddr.IPNetwork(
                                '{}/{}'.format(self.config[context]['interfaces'][interface]['iface_mgmt_ip'],
                                               self.service.netmask_to_cidr(
                                                   self.config[context]['interfaces'][interface][
                                                       'iface_mgmt_netmask']))):
                            # print('{} - {}/{}'.format(config[context]['interfaces'][interface]['iface_name'],config[context]['interfaces'][interface]['iface_mgmt_ip'],config[context]['interfaces'][interface]['iface_mgmt_netmask']))
                            # print('ROUTE MATCH - Searched address {} is in Zone : {} Interface Name: {} Interface Address {}/{}'.format(ip, config[context]['interfaces'][interface]['interface_Zone'], config[context]['interfaces'][interface]['iface_name'], config[context]['interfaces'][interface]['iface_mgmt_ip'],self.service.netmask_to_cidr(config[context]['interfaces'][interface]['iface_mgmt_netmask'])))
                            return self.config[context]['interfaces'][interface]['interface_Zone']
                    else:  # as a last resort, try getting static gateway from interface config -- these are auto added rules and not part of the pbr config
                        self.log('Trying to see if ip is on same net as interface')
                        for interface in self.config[context]['interfaces']:
                            if self.config[context]['interfaces'][interface]['iface_lan_ip'] != '0.0.0.0':
                                if ip in netaddr.IPNetwork(
                                        '{}/{}'.format(self.config[context]['interfaces'][interface]['iface_lan_ip'],
                                                       self.service.netmask_to_cidr(
                                                           self.config[context]['interfaces'][interface][
                                                               'iface_lan_mask']))):
                                    return self.config[context]['interfaces'][interface]['interface_Zone']

                        return None
            # check if ip address is on same subnet as interfaces - lan_ip should
            # likely be done before checking pbr, static_ip should likely be done after
            else:
                # self.log('Trying to see if ip is on same net as interface')
                for interface in self.config[context]['interfaces']:
                    if self.config[context]['interfaces'][interface]['iface_lan_ip'] != '0.0.0.0':
                        if ip in netaddr.IPNetwork(
                                '{}/{}'.format(self.config[context]['interfaces'][interface]['iface_lan_ip'],
                                               self.service.netmask_to_cidr(
                                                   self.config[context]['interfaces'][interface][
                                                       'iface_lan_mask']))):
                            return self.config[context]['interfaces'][interface]['interface_Zone']
                for interface in self.config[context]['interfaces']:
                    if self.config[context]['interfaces'][interface]['iface_static_ip'] != '0.0.0.0':
                        # if ip in netaddr.IPNetwork('{}/{}'.format(config[context]['interfaces'][interface]['iface_static_ip'],self.service.netmask_to_cidr(config[context]['interfaces'][interface]['iface_static_mask']))):
                        return self.config[context]['interfaces'][interface]['interface_Zone']
        else:
            self.log('Routing not in config')
        return None

    def get_zone(self, context, ip, config):

        try:
            ip = ip.split('/')[0]
            self.log_info('Searching {} for address : {}'.format(context, ip))
            self.log_info('-' * 100)
            if 'routing' in config[context]:
                self.log_info('routing found in config')
                matchlen = -1

                for interface in config[context]['interfaces']:
                    self.log_info('interface', interface)
                    if config[context]['interfaces'][interface]['iface_lan_ip'] != '0.0.0.0':
                        if ip in netaddr.IPNetwork(
                                '{}/{}'.format(config[context]['interfaces'][interface]['iface_lan_ip'],
                                               self.service.netmask_to_cidr(config[context]['interfaces'][interface][
                                                                                'iface_lan_mask']))):
                            self.debug('matches lan', config[context]['interfaces'][interface]['interface_Zone'])
                            return config[context]['interfaces'][interface]['interface_Zone']
                    if config[context]['interfaces'][interface]['iface_static_ip'] != '0.0.0.0':
                        self.debug(ip)
                        if ip in netaddr.IPNetwork(
                                '{}/{}'.format(config[context]['interfaces'][interface]['iface_static_ip'],
                                               self.service.netmask_to_cidr(
                                                   config[context]['interfaces'][interface]['iface_static_mask']))):
                            self.debug('matches static', config[context]['interfaces'][interface]['interface_Zone'])
                            return config[context]['interfaces'][interface]['interface_Zone']
                    if config[context]['interfaces'][interface]['iface_mgmt_ip'] != '0.0.0.0':
                        if ip in netaddr.IPNetwork(
                                '{}/{}'.format(config[context]['interfaces'][interface]['iface_mgmt_ip'],
                                               self.service.netmask_to_cidr(config[context]['interfaces'][interface][
                                                                                'iface_mgmt_netmask']))):
                            self.debug('matches mgmt', config[context]['interfaces'][interface]['interface_Zone'])
                            return config[context]['interfaces'][interface]['interface_Zone']
                next_hop = None
                next_hop_ip = None
                next_hop_iface = None
                next_hop_ifacenum = None
                next_hop_ifacename = None
                for route in config[context]['routing']:
                    self.log_info('route', route)
                    route_dest = config[context]['routing'][route]['pbrObjDst']
                    if route_dest == '':
                        route_dest = '0.0.0.0'
                    self.log_info('Route Destination :', route_dest)
                    if config[context]['routing'][route]['pbrObjSrc'] == "":
                        if route_dest in config[context]['addresses']:
                            # print(config[context]['addresses'][route_dest])
                            # log_info(config[context]['addresses'][route_dest]['addrObjType'])
                            if config[context]['addresses'][route_dest]['addrObjType'] == '8':
                                # log_info(config[context]['addresses'][route_dest])
                                self.log_info('Route Destination is a group, checking each member object')
                                for route_dest_addr in self.createNetworkService.expand_address(
                                        config[context]['addresses'], route_dest,
                                        config[context]['addressmappings']):
                                    if route_dest_addr in config[context]['addresses']:
                                        self.log_info(route_dest_addr)
                                        # print(ip)
                                        if config[context]['addresses'][route_dest_addr]['addrObjType'] == '2':
                                            route_destination = netaddr.IPRange(
                                                config[context]['addresses'][route_dest_addr]['addrObjIp1'],
                                                config[context]['addresses'][route_dest_addr]['addrObjIp2'])
                                        else:
                                            route_destination = netaddr.IPNetwork(
                                                '{}/{}'.format(
                                                    config[context]['addresses'][route_dest_addr]['addrObjIp1'],
                                                    config[context]['addresses'][route_dest_addr]['addrObjIp2']))
                                        if netaddr.IPAddress(ip) in route_destination:
                                            # if netaddr.IPAddress(ip) in netaddr.IPNetwork('{}/{}'.format(config[config[context]['addresses']['addrObjIp1'], self.service.netmask_to_cidr(config[context]['interfaces'][interface]['iface_lan_mask']))):
                                            # config[context]['addresses'][route_dest_addr]['IPSet']:
                                            self.debug('Matched to {}/{}'.format(
                                                config[context]['addresses'][route_dest_addr]['addrObjIp1'],
                                                config[context]['addresses'][route_dest_addr]['addrObjIp2']))
                                            if self.service.netmask_to_cidr(
                                                    config[context]['addresses'][route_dest_addr][
                                                        'addrObjIp2']) > matchlen:
                                                # self.log(config[context]['routing'][route])
                                                matchlen = self.service.netmask_to_cidr(
                                                    config[context]['addresses'][route_dest_addr]['addrObjIp2'])
                                                next_hop = config[context]['routing'][route]['pbrObjGw']
                                                next_hop_ifacenum = config[context]['routing'][route]['pbrObjIface']
                                                self.debug('Nexthop : ', next_hop)
                                                self.debug(config[context]['routing'][route])
                                                if next_hop in config[context]['addresses']:
                                                    self.debug('Next hop object found in addresses')
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
                                                self.log_info(
                                                    'Searched address found in destination group: "{}" - MatchLength {} Nexthop {} {}'.format(
                                                        urllib.parse.unquote(route_dest), matchlen, next_hop,
                                                        next_hop_ip))
                                                # THIS IS THE CORRECT GET_ZONE
                                            else:
                                                self.log_info('Skipping - not longest match')
                                    else:
                                        self.log_info('Address group not found in context')
                            elif config[context]['addresses'][route_dest]['addrObjType'] == '2':
                                if netaddr.IPAddress(ip) in netaddr.IPRange(
                                        config[context]['addresses'][route_dest]['addrObjIp1'],
                                        config[context]['addresses'][route_dest]['addrObjIp2']):
                                    # if ip in config[context]['addresses'][route_dest]['IPSet']:
                                    self.log_info('Searched address found in destination range address object')
                                    if self.service.netmask_to_cidr(
                                            config[context]['addresses'][route_dest]['addrObjIp2']) > matchlen:
                                        matchlen = 32
                                        next_hop = config[context]['routing'][route]['pbrObjGw']
                                        next_hop_ifacenum = config[context]['routing'][route]['pbrObjIface']
                                        if next_hop in config[context]['addresses']:
                                            next_hop_ip = config[context]['addresses'][next_hop]['addrObjIp1']
                                        else:
                                            next_hop_ip = next_hop
                                    else:
                                        self.log_info('Skipping - not longest match')
                            else:
                                # if 'IPSet' in config[context]['addresses'][route_dest]:
                                if netaddr.IPAddress(ip) in netaddr.IPNetwork(
                                        '{}/{}'.format(config[context]['addresses'][route_dest]['addrObjIp1'],
                                                       config[context]['addresses'][route_dest]['addrObjIp2'])):
                                    # if ip in config[context]['addresses'][route_dest]['IPSet']:
                                    self.log_info('Searched address found in destination address')
                                    if self.service.netmask_to_cidr(
                                            config[context]['addresses'][route_dest]['addrObjIp2']) > matchlen:
                                        matchlen = self.service.netmask_to_cidr(
                                            config[context]['addresses'][route_dest]['addrObjIp2'])
                                        next_hop = config[context]['routing'][route]['pbrObjGw']
                                        next_hop_ifacenum = config[context]['routing'][route]['pbrObjIface']
                                        if next_hop in config[context]['addresses']:
                                            next_hop_ip = config[context]['addresses'][next_hop]['addrObjIp1']
                                        else:
                                            next_hop_ip = next_hop
                                    else:
                                        self.log_info('Skipping - not longest match')
                                # else:
                                #    self.log('WARNING - Route destinations with Range objects not yet supported - need to add IPSet property to Range address objects - {}-{}'.format(config[context]['addresses'][route_dest]['addrObjIp1'], config[context]['addresses'][route_dest]['addrObjIp2']))
                                # print(next_hop)
                                # print(next_hop_ip)
                        elif len(route_dest.split('/')) == 2:
                            self.log_info('Route destination is not in address objects')
                            try:
                                if netaddr.IPAddress(ip) in netaddr.IPNetwork(route_dest):
                                    network, mask = route_dest.split('/')
                                    if int(mask) >= matchlen:
                                        matchlen = int(mask)
                                        next_hop = config[context]['routing'][route]['pbrObjGw']
                                        next_hop_ifacenum = str(config[context]['routing'][route]['pbrObjIface'])
                                        next_hop_ifacename = config[context]['routing'][route]['pbrObjIfaceName']
                                        self.log_info('MATCH1 "{}" "{}" "{}" "{}"'.format(network, mask,
                                                                                          config[context]['routing'][
                                                                                              route][
                                                                                              'pbrObjGw'],
                                                                                          config[context]['routing'][
                                                                                              route][
                                                                                              'pbrObjIface'], ))
                                    if next_hop in config[context]['addresses']:
                                        next_hop_ip = config[context]['addresses'][next_hop]['addrObjIp1']
                                    else:
                                        next_hop_ip = next_hop
                            except Exception as e:
                                self.log(e)
                                self.log('Route destination not in network/mask format')
                        elif route_dest == '0.0.0.0' and matchlen < 0:  # route is a default route
                            matchlen = 0
                            next_hop = config[context]['routing'][route]['pbrObjGw']
                            next_hop_ifacenum = config[context]['routing'][route]['pbrObjIface']
                            next_hop_ifacename = config[context]['routing'][route]['pbrObjIfaceName']
                            if next_hop in config[context]['addresses']:
                                next_hop_ip = config[context]['addresses'][next_hop]['addrObjIp1']
                            else:
                                next_hop_ip = next_hop
                            self.log_info('Default Route!')

                        # print(config[context]['interfaces'])
                self.log_info('Matchlen', matchlen)

                if next_hop_ifacenum != None:
                    for interface in config[context]['interfaces']:
                        # self.log('"{}" "{}" "{}" "{}"'.format(config[context]['interfaces'][interface]['iface_ifnum'], next_hop_ifacenum, config[context]['interfaces'][interface]['iface_name'], next_hop_ifacename))
                        if config[context]['interfaces'][interface]['iface_name'] == next_hop_ifacename:
                            # or config[context]['interfaces'][interface]['iface_name'] == next_hop_ifacen:
                            # self.log("-" *180)
                            # self.log('!!!!{}!!!!!!'.format(config[context]['interfaces'][interface]['iface_name']))
                            # self.log("-" *180)
                            # self.log(config[context]['interfaces'][interface]['interface_Zone'])
                            return config[context]['interfaces'][interface]['interface_Zone']

                if matchlen != -1:
                    if next_hop_ip == '':
                        next_hop_ip = '0.0.0.0'
                    self.log_info('NEXTHOP', next_hop, next_hop_ip, next_hop_ifacenum)

                    for interface in config[context]['interfaces']:
                        if config[context]['interfaces'][interface]['iface_lan_ip'] != '0.0.0.0':
                            if netaddr.IPAddress(next_hop_ip) in netaddr.IPNetwork(
                                    '{}/{}'.format(config[context]['interfaces'][interface]['iface_lan_ip'],
                                                   self.service.netmask_to_cidr(
                                                       config[context]['interfaces'][interface]['iface_lan_mask']))):
                                # print('{} - {}/{}'.format(config[context]['interfaces'][interface]['iface_name'],config[context]['interfaces'][interface]['iface_lan_ip'],config[context]['interfaces'][interface]['iface_lan_mask']))
                                # print('ROUTE MATCH - Searched address {} is in Zone : {} Interface Name: {} Interface Address {}/{}'.format(ip, config[context]['interfaces'][interface]['interface_Zone'], config[context]['interfaces'][interface]['iface_name'], config[context]['interfaces'][interface]['iface_lan_ip'],self.service.netmask_to_cidr(config[context]['interfaces'][interface]['iface_lan_mask'])))
                                return config[context]['interfaces'][interface]['interface_Zone']
                        elif config[context]['interfaces'][interface]['iface_static_ip'] != '0.0.0.0':
                            # self.log(netaddr.IPAddress(next_hop_ip))
                            # self.log(config[context]['interfaces'][interface]['iface_static_ip'], config[context]['interfaces'][interface]['iface_static_mask'])
                            if netaddr.IPAddress(next_hop_ip) in netaddr.IPNetwork(
                                    '{}/{}'.format(config[context]['interfaces'][interface]['iface_static_ip'],
                                                   self.service.netmask_to_cidr(
                                                       config[context]['interfaces'][interface]['iface_static_mask']))):
                                # print('{} - {}/{}'.format(config[context]['interfaces'][interface]['iface_name'],config[context]['interfaces'][interface]['iface_static_ip'],config[context]['interfaces'][interface]['iface_static_mask']))
                                # print('ROUTE MATCH - Searched address {} is in Zone : {} Interface Name: {} Interface Address {}/{}'.format(ip, config[context]['interfaces'][interface]['interface_Zone'], config[context]['interfaces'][interface]['iface_name'], config[context]['interfaces'][interface]['iface_static_ip'],self.service.netmask_to_cidr(config[context]['interfaces'][interface]['iface_static_mask'])))
                                return config[context]['interfaces'][interface]['interface_Zone']
                        elif config[context]['interfaces'][interface]['iface_mgmt_ip'] != '0.0.0.0':
                            if netaddr.IPAddress(next_hop_ip) in netaddr.IPNetwork(
                                    '{}/{}'.format(config[context]['interfaces'][interface]['iface_mgmt_ip'],
                                                   self.service.netmask_to_cidr(
                                                       config[context]['interfaces'][interface][
                                                           'iface_mgmt_netmask']))):
                                # print('{} - {}/{}'.format(config[context]['interfaces'][interface]['iface_name'],config[context]['interfaces'][interface]['iface_mgmt_ip'],config[context]['interfaces'][interface]['iface_mgmt_netmask']))
                                # print('ROUTE MATCH - Searched address {} is in Zone : {} Interface Name: {} Interface Address {}/{}'.format(ip, config[context]['interfaces'][interface]['interface_Zone'], config[context]['interfaces'][interface]['iface_name'], config[context]['interfaces'][interface]['iface_mgmt_ip'],self.service.netmask_to_cidr(config[context]['interfaces'][interface]['iface_mgmt_netmask'])))
                                return config[context]['interfaces'][interface]['interface_Zone']
                    else:  # as a last resort, try getting static gateway from interface config -- these are auto added rules and not part of the pbr config
                        if next_hop_ip == '0.0.0.0':
                            return 'WAN'
                        self.log_info('Trying to see if ip is on same net as interface')
                        for interface in config[context]['interfaces']:
                            if config[context]['interfaces'][interface]['iface_lan_ip'] != '0.0.0.0':
                                if ip in netaddr.IPNetwork(
                                        '{}/{}'.format(config[context]['interfaces'][interface]['iface_lan_ip'],
                                                       self.service.netmask_to_cidr(
                                                           config[context]['interfaces'][interface][
                                                               'iface_lan_mask']))):
                                    return config[context]['interfaces'][interface]['interface_Zone']

                        # return None

                else:  # check if ip address is on same subnet as interfaces - lan_ip should likely be done before checking pbr, static_ip should likely be done after
                    # log_info('Trying to see if ip is on same net as interface')
                    for interface in config[context]['interfaces']:
                        if config[context]['interfaces'][interface]['iface_lan_ip'] != '0.0.0.0':
                            if ip in netaddr.IPNetwork(
                                    '{}/{}'.format(config[context]['interfaces'][interface]['iface_lan_ip'],
                                                   self.service.netmask_to_cidr(
                                                       config[context]['interfaces'][interface]['iface_lan_mask']))):
                                return config[context]['interfaces'][interface]['interface_Zone']
                    for interface in config[context]['interfaces']:
                        if config[context]['interfaces'][interface]['iface_static_ip'] != '0.0.0.0':
                            # if ip in netaddr.IPNetwork('{}/{}'.format(config[context]['interfaces'][interface]['iface_static_ip'],self.service.netmask_to_cidr(config[context]['interfaces'][interface]['iface_static_mask']))):
                            return config[context]['interfaces'][interface]['interface_Zone']
            else:
                self.log_info('Routing not in config')
        except Exception as e:
            self.debug(e, e.__traceback__.tb_lineno)
            return None
        return None

    def get_zone2(self, context, ip, config):

        try:
            ip, mask = ip.split('/')
        except:
            ip, mask = (ip, '32')
        try:
            ipNetwork = netaddr.IPNetwork('{}/{}'.format(ip, mask))

            self.log_info('Searching {} for address : {}'.format(context, ip))
            self.log_info('-' * 100)
            return_zones = []
            if 'routing' in config[context]:
                self.log_info('routing found in config')
                matchlen = -1

                for interface in config[context]['interfaces']:  ## this
                    self.log_info('interface', interface)
                    if config[context]['interfaces'][interface]['iface_lan_ip'] != '0.0.0.0':
                        if ip in netaddr.IPNetwork(
                                '{}/{}'.format(config[context]['interfaces'][interface]['iface_lan_ip'],
                                               self.service.netmask_to_cidr(config[context]['interfaces'][interface][
                                                                                'iface_lan_mask']))) or netaddr.IPNetwork(
                            '{}/{}'.format(config[context]['interfaces'][interface]['iface_lan_ip'],
                                           self.service.netmask_to_cidr(
                                               config[context]['interfaces'][interface][
                                                   'iface_lan_mask']))) in ipNetwork:
                            self.debug('matches lan', config[context]['interfaces'][interface]['interface_Zone'])
                            return_zones.append(config[context]['interfaces'][interface]['interface_Zone'])
                    if config[context]['interfaces'][interface]['iface_static_ip'] != '0.0.0.0':
                        self.debug(ip)
                        if ip in netaddr.IPNetwork(
                                '{}/{}'.format(config[context]['interfaces'][interface]['iface_static_ip'],
                                               self.service.netmask_to_cidr(
                                                   config[context]['interfaces'][interface][
                                                       'iface_static_mask']))) or netaddr.IPNetwork(
                            '{}/{}'.format(config[context]['interfaces'][interface]['iface_static_ip'],
                                           self.service.netmask_to_cidr(
                                               config[context]['interfaces'][interface][
                                                   'iface_static_mask']))) in ipNetwork:
                            self.debug('matches static', config[context]['interfaces'][interface]['interface_Zone'])
                            return_zones.append(config[context]['interfaces'][interface]['interface_Zone'])
                    if config[context]['interfaces'][interface]['iface_mgmt_ip'] != '0.0.0.0':
                        if ip in netaddr.IPNetwork(
                                '{}/{}'.format(config[context]['interfaces'][interface]['iface_mgmt_ip'],
                                               self.service.netmask_to_cidr(config[context]['interfaces'][interface][
                                                                                'iface_mgmt_netmask']))) or netaddr.IPNetwork(
                            '{}/{}'.format(config[context]['interfaces'][interface]['iface_mgmt_ip'],
                                           self.service.netmask_to_cidr(
                                               config[context]['interfaces'][interface][
                                                   'iface_mgmt_netmask']))) in ipNetwork:
                            self.debug('matches mgmt', config[context]['interfaces'][interface]['interface_Zone'])
                            return_zones.append(config[context]['interfaces'][interface]['interface_Zone'])
                # self.log('return_zones after checking intrfaces', return_zones)
                next_hop = None
                next_hop_ip = None
                next_hop_iface = None
                next_hop_ifacenum = None

                # this was added becasue of zone calc here and in expedition was wrong is an address object is a "supernet"
                # -- the result is that it is likely part of multiple zones, rather than just 1
                # its likely that this should only be performed if matchlen=0 (default route)

                for route in config[context]['routing']:
                    self.log_info('route', route)
                    route_dest = config[context]['routing'][route]['pbrObjDst']
                    if route_dest == '':
                        pass

                    self.log_info('Route Destination :', route_dest)
                    if config[context]['routing'][route]['pbrObjSrc'] == "":
                        if route_dest in config[context]['addresses']:
                            # self.log('JEFF!!!', route_dest)
                            # print(config[context]['addresses'][route_dest])
                            # log_info(config[context]['addresses'][route_dest]['addrObjType'])
                            if config[context]['addresses'][route_dest]['addrObjType'] == '8':
                                # log_info(config[context]['addresses'][route_dest])
                                self.log_info('Route Destination is a group, checking each member object')
                                for route_dest_addr in self.createNetworkService.expand_address(
                                        config[context]['addresses'], route_dest,
                                        config[context]['addressmappings']):
                                    if route_dest_addr in config[context]['addresses']:
                                        self.log_info(route_dest_addr)
                                        # print(ip)
                                        if config[context]['addresses'][route_dest_addr]['addrObjType'] == '2':
                                            route_destination = netaddr.IPRange(
                                                config[context]['addresses'][route_dest_addr]['addrObjIp1'],
                                                config[context]['addresses'][route_dest_addr]['addrObjIp2'])
                                        else:
                                            route_destination = netaddr.IPNetwork(
                                                '{}/{}'.format(
                                                    config[context]['addresses'][route_dest_addr]['addrObjIp1'],
                                                    config[context]['addresses'][route_dest_addr]['addrObjIp2']))
                                        if netaddr.IPAddress(ip) in route_destination:
                                            # if netaddr.IPAddress(ip) in netaddr.IPNetwork('{}/{}'.format(config[config[context]['addresses']['addrObjIp1'], self.service.netmask_to_cidr(config[context]['interfaces'][interface]['iface_lan_mask']))):
                                            # config[context]['addresses'][route_dest_addr]['IPSet']:
                                            self.debug('Matched to {}/{}'.format(
                                                config[context]['addresses'][route_dest_addr]['addrObjIp1'],
                                                config[context]['addresses'][route_dest_addr]['addrObjIp2']))
                                            if self.service.netmask_to_cidr(
                                                    config[context]['addresses'][route_dest_addr][
                                                        'addrObjIp2']) > matchlen:
                                                # self.log(config[context]['routing'][route])
                                                matchlen = self.service.netmask_to_cidr(
                                                    config[context]['addresses'][route_dest_addr]['addrObjIp2'])
                                                next_hop = config[context]['routing'][route]['pbrObjGw']
                                                next_hop_ifacenum = config[context]['routing'][route]['pbrObjIface']
                                                self.debug('Nexthop : ', next_hop)
                                                self.debug(config[context]['routing'][route])
                                                if next_hop in config[context]['addresses']:
                                                    self.debug('Next hop object found in addresses')
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
                                                self.log_info(
                                                    'Searched address found in destination group: "{}" - MatchLength {} Nexthop {} {}'.format(
                                                        urllib.parse.unquote(route_dest), matchlen, next_hop,
                                                        next_hop_ip))
                                                # THIS IS THE CORRECT GET_ZONE
                                            else:
                                                self.log_info('Skipping - not longest match')
                                    else:
                                        self.log_info('Address group not found in context')
                            elif config[context]['addresses'][route_dest]['addrObjType'] == '2':
                                if netaddr.IPAddress(ip) in netaddr.IPRange(
                                        config[context]['addresses'][route_dest]['addrObjIp1'],
                                        config[context]['addresses'][route_dest]['addrObjIp2']):
                                    # if ip in config[context]['addresses'][route_dest]['IPSet']:
                                    self.log_info('Searched address found in destination range address object')
                                    if self.service.netmask_to_cidr(
                                            config[context]['addresses'][route_dest]['addrObjIp2']) > matchlen:
                                        matchlen = 32
                                        next_hop = config[context]['routing'][route]['pbrObjGw']
                                        next_hop_ifacenum = config[context]['routing'][route]['pbrObjIface']
                                        if next_hop in config[context]['addresses']:
                                            next_hop_ip = config[context]['addresses'][next_hop]['addrObjIp1']
                                        else:
                                            next_hop_ip = next_hop
                                    else:
                                        self.log_info('Skipping - not longest match')
                            else:
                                # if 'IPSet' in config[context]['addresses'][route_dest]:
                                if netaddr.IPAddress(ip) in netaddr.IPNetwork(
                                        '{}/{}'.format(config[context]['addresses'][route_dest]['addrObjIp1'],
                                                       config[context]['addresses'][route_dest]['addrObjIp2'])):
                                    # if ip in config[context]['addresses'][route_dest]['IPSet']:
                                    self.log_info('Searched address found in destination address')
                                    if self.service.netmask_to_cidr(
                                            config[context]['addresses'][route_dest]['addrObjIp2']) > matchlen:
                                        matchlen = self.service.netmask_to_cidr(
                                            config[context]['addresses'][route_dest]['addrObjIp2'])
                                        next_hop = config[context]['routing'][route]['pbrObjGw']
                                        next_hop_ifacenum = config[context]['routing'][route]['pbrObjIface']
                                        if next_hop in config[context]['addresses']:
                                            next_hop_ip = config[context]['addresses'][next_hop]['addrObjIp1']
                                        else:
                                            next_hop_ip = next_hop
                                    else:
                                        self.log_info('Skipping - not longest match')
                                # else:
                                #    self.log('WARNING - Route destinations with Range objects not yet supported - need to add IPSet property to Range address objects - {}-{}'.format(config[context]['addresses'][route_dest]['addrObjIp1'], config[context]['addresses'][route_dest]['addrObjIp2']))
                                # print(next_hop)
                                # print(next_hop_ip)
                        elif len(route_dest.split('/')) == 2:
                            self.log_info('Route destination is not in address objects')
                            try:
                                if netaddr.IPAddress(ip) in netaddr.IPNetwork(route_dest):
                                    network, mask = route_dest.split('/')
                                    if int(mask) >= matchlen:
                                        self.log_info('MATCH1', network, mask,
                                                      config[context]['routing'][route]['pbrObjGw'])
                                        matchlen = int(mask)
                                        next_hop = config[context]['routing'][route]['pbrObjGw']
                                        next_hop_ifacenum = config[context]['routing'][route]['pbrObjIface']
                                    if next_hop in config[context]['addresses']:
                                        next_hop_ip = config[context]['addresses'][next_hop]['addrObjIp1']
                                    else:
                                        next_hop_ip = next_hop
                            except Exception as e:
                                self.log(e)
                                self.log('Route destination not in network/mask format')
                        elif route_dest == '0.0.0.0' and matchlen < 0:  # route is a default route
                            matchlen = 0
                            next_hop = config[context]['routing'][route]['pbrObjGw']
                            next_hop_ifacenum = config[context]['routing'][route]['pbrObjIface']
                            if next_hop in config[context]['addresses']:
                                next_hop_ip = config[context]['addresses'][next_hop]['addrObjIp1']
                            else:
                                next_hop_ip = next_hop
                            self.log_info('Default Route! "{}" "{}"'.format(next_hop, next_hop_ifacenum))
                self.log_info('Matchlen', matchlen)
                # self.log('return_zones before next_hop_ifacenum != 1', return_zones)
                if next_hop_ifacenum != None:
                    for interface in config[context]['interfaces']:
                        if config[context]['interfaces'][interface]['iface_ifnum'] == next_hop_ifacenum or \
                                config[context]['interfaces'][interface]['iface_name'] == next_hop_ifacenum:
                            return_zones.append(config[context]['interfaces'][interface]['interface_Zone'])
                # self.log('return_zones before matchlength != 1', return_zones)
                if matchlen != -1:
                    if next_hop_ip == '':
                        next_hop_ip = '0.0.0.0'
                    self.log_info('NEXTHOP', next_hop, next_hop_ip, next_hop_ifacenum)

                    for interface in config[context]['interfaces']:
                        if config[context]['interfaces'][interface]['iface_lan_ip'] != '0.0.0.0':
                            if netaddr.IPAddress(next_hop_ip) in netaddr.IPNetwork(
                                    '{}/{}'.format(config[context]['interfaces'][interface]['iface_lan_ip'],
                                                   self.service.netmask_to_cidr(
                                                       config[context]['interfaces'][interface]['iface_lan_mask']))):
                                # print('{} - {}/{}'.format(config[context]['interfaces'][interface]['iface_name'],config[context]['interfaces'][interface]['iface_lan_ip'],config[context]['interfaces'][interface]['iface_lan_mask']))
                                # print('ROUTE MATCH - Searched address {} is in Zone : {} Interface Name: {} Interface Address {}/{}'.format(ip, config[context]['interfaces'][interface]['interface_Zone'], config[context]['interfaces'][interface]['iface_name'], config[context]['interfaces'][interface]['iface_lan_ip'],self.service.netmask_to_cidr(config[context]['interfaces'][interface]['iface_lan_mask'])))
                                return_zones.append(config[context]['interfaces'][interface]['interface_Zone'])
                        elif config[context]['interfaces'][interface]['iface_static_ip'] != '0.0.0.0':
                            # self.log(netaddr.IPAddress(next_hop_ip))
                            # self.log(config[context]['interfaces'][interface]['iface_static_ip'], config[context]['interfaces'][interface]['iface_static_mask'])
                            if netaddr.IPAddress(next_hop_ip) in netaddr.IPNetwork(
                                    '{}/{}'.format(config[context]['interfaces'][interface]['iface_static_ip'],
                                                   self.service.netmask_to_cidr(
                                                       config[context]['interfaces'][interface]['iface_static_mask']))):
                                ##print('{} - {}/{}'.format(config[context]['interfaces'][interface]['iface_name'],config[context]['interfaces'][interface]['iface_static_ip'],config[context]['interfaces'][interface]['iface_static_mask']))
                                # print('ROUTE MATCH - Searched address {} is in Zone : {} Interface Name: {} Interface Address {}/{}'.format(ip, config[context]['interfaces'][interface]['interface_Zone'], config[context]['interfaces'][interface]['iface_name'], config[context]['interfaces'][interface]['iface_static_ip'],self.service.netmask_to_cidr(config[context]['interfaces'][interface]['iface_static_mask'])))
                                return_zones.append(config[context]['interfaces'][interface]['interface_Zone'])
                        elif config[context]['interfaces'][interface]['iface_mgmt_ip'] != '0.0.0.0':
                            if netaddr.IPAddress(next_hop_ip) in netaddr.IPNetwork(
                                    '{}/{}'.format(config[context]['interfaces'][interface]['iface_mgmt_ip'],
                                                   self.service.netmask_to_cidr(
                                                       config[context]['interfaces'][interface][
                                                           'iface_mgmt_netmask']))):
                                # print('{} - {}/{}'.format(config[context]['interfaces'][interface]['iface_name'],config[context]['interfaces'][interface]['iface_mgmt_ip'],config[context]['interfaces'][interface]['iface_mgmt_netmask']))
                                # print('ROUTE MATCH - Searched address {} is in Zone : {} Interface Name: {} Interface Address {}/{}'.format(ip, config[context]['interfaces'][interface]['interface_Zone'], config[context]['interfaces'][interface]['iface_name'], config[context]['interfaces'][interface]['iface_mgmt_ip'],self.service.netmask_to_cidr(config[context]['interfaces'][interface]['iface_mgmt_netmask'])))
                                return_zones.append(config[context]['interfaces'][interface]['interface_Zone'])
                    else:  # as a last resort, try getting static gateway from interface config -- these are auto added rules and not part of the pbr config
                        if next_hop_ip == '0.0.0.0':
                            return_zones.append('WAN')
                        self.log_info('Trying to see if ip is on same net as interface')
                        for interface in config[context]['interfaces']:
                            if config[context]['interfaces'][interface]['iface_lan_ip'] != '0.0.0.0':
                                if ip in netaddr.IPNetwork(
                                        '{}/{}'.format(config[context]['interfaces'][interface]['iface_lan_ip'],
                                                       self.service.netmask_to_cidr(
                                                           config[context]['interfaces'][interface][
                                                               'iface_lan_mask']))):
                                    return_zones.append(config[context]['interfaces'][interface]['interface_Zone'])

                        # return None

                else:  # check if ip address is on same subnet as interfaces - lan_ip should likely be done before checking pbr, static_ip should likely be done after
                    # log_info('Trying to see if ip is on same net as interface')
                    for interface in config[context]['interfaces']:
                        # self.log('interface', config[context]['interfaces'][interface])
                        if config[context]['interfaces'][interface]['iface_lan_ip'] != '0.0.0.0':
                            if ip in netaddr.IPNetwork(
                                    '{}/{}'.format(config[context]['interfaces'][interface]['iface_lan_ip'],
                                                   self.service.netmask_to_cidr(
                                                       config[context]['interfaces'][interface]['iface_lan_mask']))):
                                return_zones.append(config[context]['interfaces'][interface]['interface_Zone'])
                    if return_zones == []:
                        for interface in config[context]['interfaces']:
                            if config[context]['interfaces'][interface]['iface_static_ip'] != '0.0.0.0':
                                if ip in netaddr.IPNetwork(
                                        '{}/{}'.format(config[context]['interfaces'][interface]['iface_static_ip'],
                                                       self.service.netmask_to_cidr(
                                                           config[context]['interfaces'][interface][
                                                               'iface_static_mask']))):
                                    return_zones.append(config[context]['interfaces'][interface]['interface_Zone'])
                    if return_zones == []:
                        return_zones.append('WAN')
                    '''
                    for interface in config[context]['interfaces']:
                        if config[context]['interfaces'][interface]['iface_static_ip']!='0.0.0.0' and config[context]['interfaces'][interface]['interface_Zone']=='WAN':
                            #if ip in netaddr.IPNetwork('{}/{}'.format(config[context]['interfaces'][interface]['iface_static_ip'],self.service.netmask_to_cidr(config[context]['interfaces'][interface]['iface_static_mask']))):
                            #log(config[context]['interfaces'][interface]['interface_Zone'])
                            return_zones.append(config[context]['interfaces'][interface]['interface_Zone'])
                    '''

                    # self.log('return_zones after failing matchlen check', return_zones)
                return list(set(return_zones))
            else:
                self.log_info('Routing not in config')
        except:
            return None
        return None

    # These were improved routines that may have been unneeded because I was testing against the lab box which
    # had default route set as MGMT
    def get_zone_new(self, context, ip):

        self.debug('Searching {} for address : {}'.format(context, ip))
        self.debug('-' * 100)
        self.debug(json.dumps(self.config[context]['routing'], indent=4))
        if 'routing' in self.config[context]:
            matchlen = -1
            for interface in self.config[context]['interfaces']:
                if self.config[context]['interfaces'][interface]['iface_lan_ip'] != '0.0.0.0':
                    if ip in netaddr.IPNetwork(
                            '{}/{}'.format(self.config[context]['interfaces'][interface]['iface_lan_ip'],
                                           self.service.netmask_to_cidr(self.config[context]['interfaces'][interface][
                                                                            'iface_lan_mask']))):
                        self.debug('matches lan', self.config[context]['interfaces'][interface]['interface_Zone'])
                        return self.config[context]['interfaces'][interface]['interface_Zone']
                if self.config[context]['interfaces'][interface]['iface_static_ip'] != '0.0.0.0':
                    if ip in netaddr.IPNetwork(
                            '{}/{}'.format(self.config[context]['interfaces'][interface]['iface_static_ip'],
                                           self.service.netmask_to_cidr(self.config[context]['interfaces'][interface][
                                                                            'iface_static_mask']))):
                        self.debug('matches static', self.config[context]['interfaces'][interface]['interface_Zone'])
                        return self.config[context]['interfaces'][interface]['interface_Zone']
                if self.config[context]['interfaces'][interface]['iface_mgmt_ip'] != '0.0.0.0':
                    if ip in netaddr.IPNetwork(
                            '{}/{}'.format(self.config[context]['interfaces'][interface]['iface_mgmt_ip'],
                                           self.service.netmask_to_cidr(self.config[context]['interfaces'][interface][
                                                                            'iface_mgmt_netmask']))):
                        self.debug('matches mgmt', self.config[context]['interfaces'][interface]['interface_Zone'])
                        return self.config[context]['interfaces'][interface]['interface_Zone']
            for route in self.config[context]['routing']:
                route_dest = self.config[context]['routing'][route]['pbrObjDst']
                if route_dest == '':
                    route_dest = '0.0.0.0'
                self.debug(route_dest)
                if self.config[context]['routing'][route]['pbrObjSrc'] == "":
                    if route_dest in self.config[context]['addresses']:
                        # print(config[context]['addresses'][route_dest])
                        self.debug('route dest obj type :',
                                   self.config[context]['addresses'][route_dest]['addrObjType'])
                        if self.config[context]['addresses'][route_dest]['addrObjType'] == '8':
                            self.debug(self.config[context]['addresses'][route_dest])
                            self.debug('Route Destination is a group, checking each member object')
                            for route_dest_addr in self.createNetworkService.expand_address(
                                    self.config[context]['addresses'], route_dest,
                                    self.config[context]['addressmappings']):
                                if route_dest_addr in self.config[context]['addresses']:
                                    self.debug(route_dest_addr)
                                    # print(ip)
                                    if netaddr.IPAddress(ip) in netaddr.IPNetwork(
                                            '{}/{}'.format(
                                                self.config[context]['addresses'][route_dest_addr]['addrObjIp1'],
                                                self.config[context]['addresses'][route_dest_addr]['addrObjIp2'])):

                                        if self.service.netmask_to_cidr(
                                                self.config[context]['addresses'][route_dest_addr][
                                                    'addrObjIp2']) > matchlen:
                                            matchlen = self.service.netmask_to_cidr(
                                                self.config[context]['addresses'][route_dest_addr]['addrObjIp2'])
                                            next_hop = self.config[context]['routing'][route]['pbrObjGw']
                                            if next_hop in self.config[context]['addresses']:
                                                next_hop_ip = self.config[context]['addresses'][next_hop]['addrObjIp1']
                                            else:
                                                next_hop_ip = next_hop
                                            self.debug(
                                                'Searched address found in destination group: "{}" - MatchLength {} Nexthop {} {}'.format(
                                                    urllib.parse.unquote(route_dest), matchlen, next_hop, next_hop_ip))
                                        else:
                                            self.debug('Skipping - not longest match')

                                else:
                                    self.debug('Address group not found in context')
                        else:
                            # if 'IPSet' in config[context]['addresses'][route_dest]:
                            if netaddr.IPAddress(ip) in netaddr.IPNetwork(
                                    '{}/{}'.format(self.config[context]['addresses'][route_dest]['addrObjIp1'],
                                                   self.config[context]['addresses'][route_dest]['addrObjIp2'])):
                                # if ip in config[context]['addresses'][route_dest]['IPSet']:
                                self.debug('Searched address found in destination address')
                                if self.service.netmask_to_cidr(
                                        self.config[context]['addresses'][route_dest]['addrObjIp2']) > matchlen:
                                    matchlen = self.service.netmask_to_cidr(
                                        self.config[context]['addresses'][route_dest]['addrObjIp2'])
                                    next_hop = self.config[context]['routing'][route]['pbrObjGw']
                                    if next_hop in self.config[context]['addresses']:
                                        next_hop_ip = self.config[context]['addresses'][next_hop]['addrObjIp1']
                                    else:
                                        next_hop_ip = next_hop
                                else:
                                    self.debug('Skipping - not longest match')
                            # else:
                            #    self.log('WARNING - Route destinations with Range objects not yet supported - need to add IPSet property to Range address objects - {}-{}'.format(self.config[context]['addresses'][route_dest]['addrObjIp1'], self.config[context]['addresses'][route_dest]['addrObjIp2']))
                            # print(next_hop)
                            # print(next_hop_ip)
                    elif len(route_dest.split('/')) == 2:
                        self.debug('Route destination is not in address objects')
                        try:
                            if netaddr.IPAddress(ip) in netaddr.IPNetwork(route_dest):
                                network, mask = route_dest.split('/')
                                if int(mask) > matchlen:
                                    self.debug('MATCH1', network, mask,
                                               self.config[context]['routing'][route]['pbrObjGw'])
                                    matchlen = int(mask)
                                    next_hop = self.config[context]['routing'][route]['pbrObjGw']
                                if next_hop in self.config[context]['addresses']:
                                    next_hop_ip = self.config[context]['addresses'][next_hop]['addrObjIp1']
                                else:
                                    next_hop_ip = next_hop
                        except Exception as e:
                            self.log(e)
                            self.log('Route destination not in network/mask format')
                    elif route_dest == '0.0.0.0':  # route is a default route
                        matchlen = 0
                        next_hop = self.config[context]['routing'][route]['pbrObjGw']
                        if next_hop in self.config[context]['addresses']:
                            next_hop_ip = self.config[context]['addresses'][next_hop]['addrObjIp1']
                        else:
                            next_hop_ip = next_hop
                        self.debug('Default Route!')

                    # print(self.config[context]['interfaces'])
            self.debug('Matchlen', matchlen)
            if matchlen != -1:
                self.debug('NEXTHOP', next_hop, next_hop_ip)
                for interface in self.config[context]['interfaces']:
                    if self.config[context]['interfaces'][interface]['iface_lan_ip'] != '0.0.0.0':
                        if netaddr.IPAddress(next_hop_ip) in netaddr.IPNetwork(
                                '{}/{}'.format(self.config[context]['interfaces'][interface]['iface_lan_ip'],
                                               self.service.netmask_to_cidr(
                                                   self.config[context]['interfaces'][interface]['iface_lan_mask']))):
                            # print('{} - {}/{}'.format(self.config[context]['interfaces'][interface]['iface_name'],self.config[context]['interfaces'][interface]['iface_lan_ip'],self.config[context]['interfaces'][interface]['iface_lan_mask']))
                            # print('ROUTE MATCH - Searched address {} is in Zone : {} Interface Name: {} Interface Address {}/{}'.format(ip, self.config[context]['interfaces'][interface]['interface_Zone'], self.config[context]['interfaces'][interface]['iface_name'], self.config[context]['interfaces'][interface]['iface_lan_ip'],self.service.netmask_to_cidr(self.config[context]['interfaces'][interface]['iface_lan_mask'])))
                            return self.config[context]['interfaces'][interface]['interface_Zone']
                    elif self.config[context]['interfaces'][interface]['iface_static_ip'] != '0.0.0.0':
                        if netaddr.IPAddress(next_hop_ip) in netaddr.IPNetwork(
                                '{}/{}'.format(self.config[context]['interfaces'][interface]['iface_static_ip'],
                                               self.service.netmask_to_cidr(
                                                   self.config[context]['interfaces'][interface][
                                                       'iface_static_mask']))):
                            ##print('{} - {}/{}'.format(self.config[context]['interfaces'][interface]['iface_name'],self.config[context]['interfaces'][interface]['iface_static_ip'],self.config[context]['interfaces'][interface]['iface_static_mask']))
                            # print('ROUTE MATCH - Searched address {} is in Zone : {} Interface Name: {} Interface Address {}/{}'.format(ip, self.config[context]['interfaces'][interface]['interface_Zone'], self.config[context]['interfaces'][interface]['iface_name'], self.config[context]['interfaces'][interface]['iface_static_ip'],self.service.netmask_to_cidr(self.config[context]['interfaces'][interface]['iface_static_mask'])))
                            return self.config[context]['interfaces'][interface]['interface_Zone']
                    elif self.config[context]['interfaces'][interface]['iface_mgmt_ip'] != '0.0.0.0':
                        if netaddr.IPAddress(next_hop_ip) in netaddr.IPNetwork(
                                '{}/{}'.format(self.config[context]['interfaces'][interface]['iface_mgmt_ip'],
                                               self.service.netmask_to_cidr(
                                                   self.config[context]['interfaces'][interface][
                                                       'iface_mgmt_netmask']))):
                            # print('{} - {}/{}'.format(self.config[context]['interfaces'][interface]['iface_name'],self.config[context]['interfaces'][interface]['iface_mgmt_ip'],self.config[context]['interfaces'][interface]['iface_mgmt_netmask']))
                            # print('ROUTE MATCH - Searched address {} is in Zone : {} Interface Name: {} Interface Address {}/{}'.format(ip, self.config[context]['interfaces'][interface]['interface_Zone'], self.config[context]['interfaces'][interface]['iface_name'], self.config[context]['interfaces'][interface]['iface_mgmt_ip'],self.service.netmask_to_cidr(self.config[context]['interfaces'][interface]['iface_mgmt_netmask'])))
                            return self.config[context]['interfaces'][interface]['interface_Zone']
                else:  # as a last resort, try getting static gateway from interface self.config -- these are auto added rules and not part of the pbr self.config
                    self.log('Trying to see if ip is on same net as interface')
                    for interface in self.config[context]['interfaces']:
                        if self.config[context]['interfaces'][interface]['iface_lan_ip'] != '0.0.0.0':
                            if ip in netaddr.IPNetwork(
                                    '{}/{}'.format(self.config[context]['interfaces'][interface]['iface_lan_ip'],
                                                   self.service.netmask_to_cidr(
                                                       self.config[context]['interfaces'][interface][
                                                           'iface_lan_mask']))):
                                return self.config[context]['interfaces'][interface]['interface_Zone']

                        return None
            else:  # check if ip address is on same subnet as interfaces - lan_ip should likely be done before checking pbr, static_ip should likely be done after
                # self.log('Trying to see if ip is on same net as interface')
                for interface in self.config[context]['interfaces']:
                    if self.config[context]['interfaces'][interface]['iface_lan_ip'] != '0.0.0.0':
                        if ip in netaddr.IPNetwork(
                                '{}/{}'.format(self.config[context]['interfaces'][interface]['iface_lan_ip'],
                                               self.service.netmask_to_cidr(
                                                   self.config[context]['interfaces'][interface][
                                                       'iface_lan_mask']))):
                            self.debug('Using interface {} as next hop'.format(interface))
                            return self.config[context]['interfaces'][interface]['interface_Zone']
                for interface in self.config[context]['interfaces']:
                    if self.config[context]['interfaces'][interface]['iface_static_ip'] != '0.0.0.0':
                        if ip in netaddr.IPNetwork(
                                '{}/{}'.format(self.config[context]['interfaces'][interface]['iface_static_ip'],
                                               self.service.netmask_to_cidr(
                                                   self.config[context]['interfaces'][interface][
                                                       'iface_static_mask']))):
                            self.debug('Using interface {} as next hop'.format(interface))
                            return self.config[context]['interfaces'][interface]['interface_Zone']
                if self.config[context]['self.config']['fw_type'] in ['sw65', 'sonicwall']:
                    self.debug('Address object likely using default route on WAN'.format(interface))
                    return 'WAN'

        else:
            self.log('Routing not in config')
        return None
