import re


class GetNetworkService:


    def _init_(self, config):
        self.config = config

    # Given an address object name, it will return the IP address object of it.
    # (DONE) Should be modified to also return netmask
    def get_address_of(self, addresses, address_object):
        # this should be handled better
        if address_object not in addresses:
            addresses = self.config['shared']['addresses']
        if address_object == '0.0.0.0' or address_object == '':
            return '0.0.0.0', '0'
        elif addresses[address_object]['addrObjType'] in ['1', '99', '91']:
            return addresses[address_object]['addrObjIp1'], '32'
        # Palo FQDN object
        elif addresses[address_object]['addrObjType'] == '89':
            return addresses[address_object]['fqdn'], 'fqdn'
        elif addresses[address_object]['addrObjType'] == '2':
            return addresses[address_object]['addrObjIp1'], addresses[address_object]['addrObjIp2']
        # group with exception
        elif addresses[address_object]['addrObjType'] == '98':
            return None, None
        else:
            return addresses[address_object]['addrObjIp1'], str(
                sum([bin(int(x)).count("1") for x in addresses[address_object]['addrObjIp2'].split(".")]))
        return

    # Given a service object name, will return the IP protocol number of it.
    def get_prot_of(self, services, service_object):
        if service_object not in services:
            services = self.config['shared']['services']
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

    # Given a service object name, will return the L4 protocol number of it.
    def get_port_of(self, services, service_object):
        if service_object not in services:
            services = self.config['shared']['services']
        if service_object == '0':
            return 'any', 'any'
        else:
            return services[service_object]['svcObjPort1'], services[service_object]['svcObjPort2']
        return

    # Given a service object name, will return the L4 protocol number of it.
    def get_ports_of(self, services, service_object):
        portlist = []
        if service_object == '0':
            return ['any']  # list(range(1))
        if service_object not in services:
            services = self.config['shared']['services']
        if service_object in services:
            if services[service_object]['svcObjType'] == '1':
                if services[service_object]['svcObjPort1'] == '':
                    services[service_object]['svcObjPort1'] = '0'
                if services[service_object]['svcObjPort2'] == '':
                    services[service_object]['svcObjPort2'] = services[service_object]['svcObjPort1']
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

                # needed to fix Port2 value for icmp objects read in via sonicwall API
                if services[service_object]['svcObjPort2'] == 'echo-request':
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
                    range(int(services[service_object]['svcObjPort1']),
                          int(services[service_object]['svcObjPort2']) + 1))
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

    # Given a service object name, will return the L4 protocol number of it.
    def get_src_ports_of(self, services, service_object):
        portlist = []
        if service_object == '0':
            return ['any']  # list(range(1))
        if service_object not in services:
            services = self.config['shared']['services']
        if service_object in services:
            if services[service_object]['svcObjType'] == '1':
                if services[service_object]['svcObjPort1'] == '':
                    services[service_object]['svcObjPort1'] = '0'
                if services[service_object]['svcObjPort2'] == '':
                    services[service_object]['svcObjPort2'] = services[service_object]['svcObjPort1']
                return list(
                    range(int(services[service_object]['svcObjPort1']),
                          int(services[service_object]['svcObjPort2']) + 1))
            elif services[service_object]['svcObjType'] == '4':
                for ports in services[service_object]['svcObjPortSet']:
                    if re.findall('-', ports):
                        first, last = ports.split('-')
                        portlist.extend(list(range(int(first), int(last) + 1)))
                    else:
                        portlist.extend([int(ports)])
            # add support to get port list for service group
            elif services[service_object]['svcObjType'] == '4':
                pass
            return portlist

        return []
