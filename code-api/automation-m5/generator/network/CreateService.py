import json
import urllib

import sys

from urllib.parse import unquote, quote
from xml.sax.saxutils import escape

from ...generator import NetworkLogs
import GetService as GS
import Zone as Z
from .sonicwall import LoadService as SLS
from .paloaulto import LoadService as PLS

class CreateNetworkService:

    def _init_(self, options, config):
        self.log = NetworkLogs().log
        self.sc = NetworkLogs().sc
        self.ss = NetworkLogs().ss
        self.debug = NetworkLogs().debug
        self.options = options
        self.config = config
        self.getService = GS.GetNetworkService(self.options)
        self.getPaloService = PLS.LoadService(self.options)
        self.zone = Z.Zones
        self.sw = SLS.SonicWallService(self.options, self.config)

    # Generate address and address-group portions of Palo Alto .xml configuration
    def create_addresses(self, addresses, addressesfqdn, address_map, builtin_map):
        self.log('          <address>')
        for index in addresses:
            if addresses[index]['addrObjType'] != '8':
                if addresses[index]['addrObjProperties'] == '14':
                    tmp_addr = self.sc(addresses[index]['addrObjId'])
                else:
                    tmp_addr = "BUILTIN_" + self.sc(
                        addresses[index]['addrObjId'])  # placeholder name, eventually use the builtin map name
                self.log('            <entry name="' + tmp_addr + '">')
                if addresses[index]['addrObjType'] == '1':
                    self.log('              <ip-netmask>' + addresses[index]['addrObjIp1'] + '/32</ip-netmask>')
                elif addresses[index]['addrObjType'] == '2':
                    self.log('              <ip-range>' + addresses[index]['addrObjIp1'] + '-' + addresses[index][
                        'addrObjIp2'] + '</ip-range>')
                elif addresses[index]['addrObjType'] == '4':
                    bitmask = sum([bin(int(x)).count("1") for x in addresses[index]['addrObjIp2'].split(".")])
                    self.log('              <ip-netmask>' + addresses[index]['addrObjIp1'] + '/' + str(
                        bitmask) + '</ip-netmask>')
                self.log('              <description>' + self.ss(addresses[index]['addrObjIdDisp']) + '</description>')
                self.log('            </entry>')
                # addressfqdn_props = ['addrObjFqdnId', 'addrObjFqdnType', 'addrObjFqdnZone', 'addrObjFqdnProperties', 'addrObjFqdn']

        for index in addressesfqdn:
            self.log('            <entry name="' + self.sc(addressesfqdn[index]['addrObjFqdnId']) + '">')
            self.log('              <fqdn>{}</fqdn>'.format(addressesfqdn[index]['addrObjFqdn']))
            self.log('              <disable-override>no</disable-override>')
            self.log('              <description>{}</description>'.format(addressesfqdn[index]['addrObjFqdnId']))
            self.log('            </entry>')

        # self.log('            <entry name="' + 'Address_Object_Placeholder' + '">')
        # self.log('              <ip-netmask>' + '255.255.255.255/32</ip-netmask>')
        # self.log('            </entry>')

        self.log('          </address>')
        self.log('          <address-group>')
        for index in addresses:
            if addresses[index]['addrObjType'] == '8':
                if addresses[index]['addrObjProperties'] == '14':
                    tmp_addr = self.sc(addresses[index]['addrObjId'])
                else:
                    tmp_addr = "BUILTIN_" + self.sc(addresses[index]['addrObjId'])
                self.log('            <entry name="' + tmp_addr + '">')

                if index in address_map:
                    if len(address_map[index]) > 0:
                        self.log('              <static>')
                        for member in address_map[index]:
                            if member in addresses:
                                if addresses[member]['addrObjProperties'] != '14':  # in builtin_map:
                                    self.log('                <member>' + "BUILTIN_" + self.sc(member) + '</member>')
                                else:

                                    self.log('                <member>' + self.sc(member) + '</member>')
                            else:  # member is likely addressfqdn
                                self.log('                <member>' + self.sc(member) + '</member>')
                        self.log('              </static>')
                # else:
                #    self.log('<member>Address_Object_Placeholder</member>')

                self.log('            <description>"' + self.ss(addresses[index]['addrObjId']) + '"</description>')
                self.log('            </entry>')
        self.log('          </address-group>')
        return

    # Generate service and service-group portions of Palo Alto .xml configuration
    def create_services(self, services, service_map):
        self.log("          <service>")
        for index in services:
            if services[index]['svcObjIpType'] in ['6', '17']:
                self.log('            <entry name="' + self.sc(services[index]['svcObjId']) + '">')
                self.log('              <description>"' + self.ss(services[index]['svcObjId']) + '"</description>')
                self.log('              <protocol>')
                if services[index]['svcObjIpType'] == '6':
                    self.log('                <tcp>')
                elif services[index]['svcObjIpType'] == '17':
                    self.log('                <udp>')
                self.log('                  <port>' + services[index]['svcObjPort1'], end='')
                if services[index]['svcObjPort1'] != services[index]['svcObjPort2']:
                    self.log('-' + services[index]['svcObjPort2'], end='')
                self.log('</port>')
                if services[index]['svcObjIpType'] == '6':
                    self.log('                </tcp>')
                elif services[index]['svcObjIpType'] == '17':
                    self.log('                </udp>')
                self.log('              </protocol>')
                self.log('            </entry>')

        self.log('            <entry name="' + 'Service_Object_Placeholder' + '">')
        self.log('              <description>"' + 'Service Object Placeholder for empty groups' + '"</description>')
        self.log('              <protocol>')
        self.log('                <tcp>')
        self.log('                  <port>0</port>')
        self.log('                </tcp>')
        self.log('              </protocol>')
        self.log('            </entry>')

        self.log('          </service>')

        self.log('          <service-group>')
        for index in services:
            if services[index]['svcObjIpType'] == '0':
                self.log('            <entry name="' + self.sc(services[index]['svcObjId']) + '">')
                self.log('              <members>')
                memberfound = False
                if index in service_map:
                    if len(service_map[index]) > 0:
                        for member in service_map[index]:
                            if services[member]['svcObjIpType'] in ['6', '17', '0']:
                                self.log('                <member>' + self.sc(member) + '</member>')
                                memberfound = True
                if not memberfound:
                    self.log('<member>Service_Object_Placeholder</member>')
                self.log('              </members>')
                self.log('            </entry>')
        self.log('          </service-group>')
        return

    # Create Network, Interface and Zone portions of Palo Alto .xml configuration
    def create_network(self, interfaces, interface_map, zones, routes, context, zone_map, customops):
        self.log('      <vsys>')
        self.log('        <entry name=\'vsys1\'>')
        self.log('          <zone>')
        for zone_index in zones:
            memberfound = False
            if zones[zone_index]['zoneObjId'].lower() in zone_map:
                out_zone = zone_map[zones[zone_index]['zoneObjId'].lower()]
                # else:
                # out_zone=zones[zone_index]['zoneObjId']
                self.log('            <entry name="' + out_zone + '">')
                self.log('              <network>')
                for interface_index in interfaces:
                    if interfaces[interface_index]['interface_Zone'].lower() == zones[zone_index][
                        'zoneObjId'].lower() and \
                            zones[zone_index]['zoneObjId'] != 'MGMT' and interface_index in interface_map:
                        if memberfound == False:
                            self.log('                <layer3>')
                            memberfound = 1
                        self.log('                  <member>' + interface_map[
                            unquote(interfaces[interface_index]['iface_name'])] + '</member>')
                if memberfound == False:
                    self.log('                <layer3/>')
                else:
                    self.log('                </layer3>')
                self.log('              </network>')
                if zones[zone_index]['zoneObjId'].lower() == 'lan' and self.options.userid:
                    self.log('              <enable-user-identification>yes</enable-user-identification>')
                self.log('            </entry>')
        self.log('          </zone>')
        if self.options.userid:
            self.log('          <user-id-agent>')
            self.log('            <entry name="Admin-UserID">')
            self.log('              <host>10.58.90.53</host>')
            self.log('              <port>5007</port>')
            self.log('              <ldap-proxy>yes</ldap-proxy>')
            self.log('              <collectorname>Admin-UserID</collectorname>')
            self.log('              <secret>-AQ==bsiEbjhCKN6u/kaJRdoALKqdudY=CvD+ExaF9qHBrdQejLQD7g==</secret>')
            self.log('            </entry>')
            self.log('          </user-id-agent>')
        self.log('          <import>')
        self.log('            <network>')
        self.log('              <interface>')
        # for zone_index in zones:
        self.log(interface_map)
        self.log(interfaces)
        for interface_index in interfaces:
            # if interfaces[interface_index]['interface_Zone'].lower() in zone_map and interface_map[interfaces[interface_index]['iface_name']] != 'MGMT' and interface_index in interface_map:
            if interfaces[interface_index]['interface_Zone'].lower() in zone_map and unquote(
                    interface_index) in interface_map:
                if interface_map[unquote(interfaces[interface_index]['iface_name'])] != 'MGMT':
                    self.log('                <member>' + interface_map[
                        unquote(interfaces[interface_index]['iface_name'])] + '</member>')
        self.log('              </interface>')
        self.log('              <virtual-router>')
        self.log('                <member>' + self.options.vrouter + '</member>')
        self.log('              </virtual-router>')
        self.log('            </network>')
        self.log('          </import>')
        self.log('        </entry>')
        self.log('</vsys>')

        # Missing config elements
        self.log("      <network>")

        # create interface-management-profile
        # TODO Some of the networks below should be removed as they now belong to NTT

        self.log("        <profiles>")
        self.log("          <interface-management-profile>")
        self.log("            <entry name=\"" + customops.int_mgmt_profile + "\">")
        self.log("              <https>yes</https>")
        self.log("              <ssh>yes</ssh>")
        self.log("              <ping>yes</ping>")
        self.log("              <permitted-ip>")
        self.log("                <entry name=\"10.0.0.0/8\"/>")
        self.log("                <entry name=\"143.166.0.0/16\"/>")
        self.log("                <entry name=\"163.244.0.0/16\"/>")
        self.log("                <entry name=\"155.16.0.0/15\"/>")
        self.log("                <entry name=\"160.110.0.0/16\"/>")
        self.log("                <entry name=\"165.136.0.0/16\"/>")
        self.log("                <entry name=\"148.9.32.0/20\"/>")
        self.log("              </permitted-ip>")
        self.log("              <snmp>yes</snmp>")
        self.log("              <userid-service>yes</userid-service>")
        self.log("              <userid-syslog-listener-ssl>yes</userid-syslog-listener-ssl>")
        self.log("              <userid-syslog-listener-udp>yes</userid-syslog-listener-udp>")
        self.log("            </entry>")
        self.log("          </interface-management-profile>")
        self.log("        </profiles>")

        # create interfaces

        self.log("        <interface>")
        self.log("          <ethernet>")
        #  need to get interface mappings

        for interface_index in interfaces:
            if interfaces[interface_index]['iface_type'] in ['1', '6', '7'] and interfaces[interface_index][
                'interface_Zone'].lower() in zone_map and interface_index in interface_map:
                self.log("          <entry name=\"" + interface_map[
                    unquote(interfaces[interface_index]['iface_name'])] + "\">")
                self.log("            <layer3>")
                self.log("              <ipv6>")
                self.log("                <neighbor-discovery>")
                self.log("                  <router-advertisement>")
                self.log("                    <enable>no</enable>")
                self.log("                  </router-advertisement>")
                self.log("                </neighbor-discovery>")
                self.log("              </ipv6>")
                ### Add lines here for VLAN subinterfaces
                subint_found = False
                import re
                for sub_interface in interfaces:
                    if re.findall(interface_map[unquote(interfaces[interface_index]['iface_name'])] + "\.",
                                  interface_map[unquote(interfaces[sub_interface]['iface_name'])]) and interface_map[
                        unquote(interfaces[interface_index]['iface_name'])] != interface_map[
                        unquote(interfaces[sub_interface]['iface_name'])] and sub_interface in interface_map:
                        if not subint_found:
                            self.log("              <untagged-sub-interface>no</untagged-sub-interface>")
                            self.log("              <units>")
                            subint_found = True
                        self.log('                <entry name="' + interface_map[
                            unquote(interfaces[sub_interface]['iface_name'])] + '">')
                        self.log('                  <ipv6>')
                        self.log('                    <neighbor-discovery>')
                        self.log('                      <enable-dad>no</enable-dad>')
                        self.log('                      <dad-attempts>1</dad-attempts>')
                        self.log('                      <ns-interval>1</ns-interval>')
                        self.log('                      <reachable-time>30</reachable-time>')
                        self.log('                    </neighbor-discovery>')
                        self.log('                    <enabled>no</enabled>')
                        self.log('                    <interface-id>EUI-64</interface-id>')
                        self.log('                  </ipv6>')
                        self.log('                  <ip>')
                        ip = interfaces[sub_interface]['iface_lan_ip']
                        mask = str(
                            sum([bin(int(x)).count("1") for x in
                                 interfaces[sub_interface]['iface_lan_mask'].split(".")]))

                        self.log('                    <entry name="' + ip + '/' + mask + '"/>')
                        self.log('                  </ip>')
                        self.log('                  <adjust-tcp-mss>')
                        self.log('                    <enable>no</enable>')
                        self.log('                    <ipv4-mss-adjustment>40</ipv4-mss-adjustment>')
                        self.log('                    <ipv6-mss-adjustment>60</ipv6-mss-adjustment>')
                        self.log('                  </adjust-tcp-mss>')
                        self.log('                  <tag>' + interfaces[sub_interface]['iface_vlan_tag'] + '</tag>')
                        # CHANGEME - use customops.int_mgmt_profile if interface zone is LAN
                        if interfaces[sub_interface]['interface_Zone'] == "LAN":
                            self.log(
                                '                  <interface-management-profile>' + customops.int_mgmt_profile + '</interface-management-profile>')
                        else:
                            self.log(
                                '                  <interface-management-profile>Allow ping</interface-management-profile>')
                        self.log('                </entry>')
                if subint_found:
                    self.log("              </units>")
                self.log("              <ndp-proxy>")
                self.log("                <enabled>no</enabled>")
                self.log("              </ndp-proxy>")
                self.log("              <lldp>")
                self.log("                <enable>no</enable>")
                self.log("              </lldp>")
                self.log("              <ip>")

                if interfaces[interface_index]['iface_type'] == '1' and interfaces[interface_index][
                    'interface_Zone'].lower() in zone_map and interface_index in interface_map:
                    ip = interfaces[interface_index]['iface_static_ip']
                    mask = str(
                        sum([bin(int(x)).count("1") for x in
                             interfaces[interface_index]['iface_static_mask'].split(".")]))
                    self.log("                <entry name=\"" + ip + "/" + mask + "\"/>")
                    self.log("              </ip>")
                    if interfaces[interface_index]['interface_Zone'].lower() == "lan":
                        self.log(
                            "              <interface-management-profile>" + customops.int_mgmt_profile + "</interface-management-profile>")
                    self.log("            </layer3>")
                    self.log("          </entry>")

                if interfaces[interface_index]['iface_type'] in ['6', '7'] and interfaces[interface_index][
                    'interface_Zone'].lower() in zone_map and interface_index in interface_map:
                    ip = interfaces[interface_index]['iface_lan_ip']
                    mask = str(
                        sum([bin(int(x)).count("1") for x in interfaces[interface_index]['iface_lan_mask'].split(".")]))
                    self.log("                <entry name=\"" + ip + "/" + mask + "\"/>")
                    self.log("             </ip>")
                    if interfaces[interface_index]['interface_Zone'].lower() == "lan":
                        self.log(
                            "             <interface-management-profile>" + customops.int_mgmt_profile + "</interface-management-profile>")
                    self.log("           </layer3>")
                    self.log("          </entry>")
        self.log("          </ethernet>")
        self.log("        </interface>")

        # Add virtual router
        self.log("        <virtual-router>")
        self.log("          <entry name=\"" + self.options.vrouter + "\">")
        self.log("            <routing-table>")
        self.log("              <ip>")
        self.log("                <static-route>")
        routecounter = 1

        defroute = False

        for route_index in routes:
            if routes[route_index]['pbrObjGw'] != '':
                nexthop, mask = self.getService.get_address_of(self.config[context]['addresses'],
                                                                 routes[route_index]['pbrObjGw'])
                # CHANGEME -- Use expand_address instead of address_mappings for dest, as dest can be any address type, not just a group
                if routes[route_index]['pbrObjSrc'] == '':  ## only add routes without a source specified
                    if routes[route_index]['pbrObjSrc'] == '' and routes[route_index]['pbrObjDst'] == '' and \
                            routes[route_index]['pbrObjSvc'] == '':  # default route
                        self.log("                <entry name=\"Default Route\">")
                        self.log("                  <nexthop>")
                        self.log("                    <ip-address>" + nexthop + "</ip-address>")
                        self.log("                  </nexthop>")
                        self.log("                  <destination>0.0.0.0/0</destination>")
                        self.log("                </entry>")
                        defroute = True
                    for dest in self.getService.expand_address(self.config[context]['addresses'],
                                                                 routes[route_index]['pbrObjDst'],
                                                                 self.config[context]['addressmappings']):
                        if self.config[context]['addresses'][dest]['addrObjType'] in ['1', '4']:
                            address, mask = self.getService.get_address_of([context]['addresses'], dest)
                            self.log("                  <entry name=\"Route " + str(routecounter) + "\">")
                            self.log("                    <nexthop>")
                            self.log("                      <ip-address>" + nexthop + "</ip-address>")
                            self.log("                    </nexthop>")
                            self.log("                    <destination>" + address + "/" + mask + "</destination>")
                            self.log("                  </entry>")
                            routecounter = routecounter + 1

        # Add Default Route
        # Is this a valid assumption?? CHANGEME
        if not defroute:
            defgateway = False
            for defgateway_index in interfaces:
                if interfaces[defgateway_index]['iface_static_gateway'] != '0.0.0.0' and \
                        interfaces[defgateway_index]['iface_static_gateway'] != '0.0.0.1':
                    defgateway = interfaces[defgateway_index]['iface_static_gateway']

            if defgateway:
                self.log("                <entry name=\"Default Route\">")
                self.log("                  <nexthop>")
                self.log("                    <ip-address>" + defgateway + "</ip-address>")
                self.log("                  </nexthop>")
                self.log("                  <destination>0.0.0.0/0</destination>")
                self.log("                </entry>")

        self.log("              </static-route>")
        self.log("            </ip>")
        self.log("          </routing-table>")

        # Add Network Interfaces to VRouter
        self.log("          <interface>")
        for interface_index in interfaces:
            if interfaces[interface_index]['iface_type'] in ['1', '6', '7'] and interfaces[interface_index][
                'interface_Zone'].lower() in zone_map and interface_index in interface_map:
                self.log("            <member>" + interface_map[
                    unquote(interfaces[interface_index]['iface_name'])] + "</member>")
        self.log("            </interface>")
        self.log("          </entry>")
        self.log("        </virtual-router>")
        self.log("      </network>")

        self.log("      <deviceconfig>")
        self.log("        <system>")
        self.log(
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
                mask = sum(
                    [bin(int(x)).count("1") for x in interfaces[interface_index]['iface_mgmt_netmask'].split(".")])
                self.log("          <ip-address>" + ip + "</ip-address>")
                self.log("          <netmask>" + interfaces[interface_index]['iface_mgmt_netmask'] + "</netmask>")
                self.log("         <default-gateway>" + interfaces[interface_index][
                    'iface_mgmt_default_gw'] + "</default-gateway>")
        self.log("        </system>")
        self.log("      </deviceconfig>")
        return

    # Create Policy portion of Palo Alto .xml configuration
    def create_policies(self, policy_object, context, zone_map, customops):
        count = 1
        self.log('            <security>')
        self.log('              <rules>')

        # self.log(zone_map)
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

            if policy_object[policy_index]['policyProps'] == '0' and 'MULTICAST' not in policy_object[policy_index][
                'policySrcZone'] and 'MULTICAST' not in policy_object[policy_index]['policyDstZone']:

                # if dstzone.lower() in zone_map and srczone.lower() in zone_map:
                if (list(set([x.lower() for x in policy_object[policy_index]['policySrcZone']]) & set(
                        [y.lower() for y in zone_map])) != []) and (
                        list(set([xx.lower() for xx in policy_object[policy_index]['policyDstZone']]) & set(
                            [yy.lower() for yy in zone_map])) != []):  ##m3 line
                    # if list(set([x.lower() for x in policy_object[policy_index]['policySrcZone']]) & set([y.lower() for y in zone_map])) != [] and list(set([xx.lower() for xx in policy_object[policy_index]['policyDstZone']])  & set([yy.lower() for yy in zone_map])) != []:
                    self.log(
                        '                <entry name="' + customops.base_rule_name + '%04d' % count + '_' + self.sc(
                            tmp_dstsvc[0]) + '">')
                    self.log('                  <target>')
                    self.log('                    <negate>no</negate>')
                    self.log('                  </target>')
                    self.log('                  <to>')
                    for dstzone in policy_object[policy_index]['policyDstZone']:
                        if dstzone.lower() in zone_map:
                            out_zone = zone_map[dstzone.lower()]
                        else:
                            out_zone = dstzone

                        self.log('                    <member>' + out_zone + '</member>')
                    self.log('                  </to>')
                    self.log('                  <from>')
                    for srczone in policy_object[policy_index]['policySrcZone']:
                        if srczone.lower() in zone_map:
                            out_zone = zone_map[srczone.lower()]
                        else:
                            out_zone = srczone
                        self.log('                    <member>' + out_zone + '</member>')
                    self.log('                  </from>')
                    self.log('                  <source>')
                    for srcnet in tmp_srcnet:
                        if srcnet.lower() == 'any':
                            tmp_src = srcnet
                        elif srcnet in self.config[context]['addresses']:
                            if self.config[context]['addresses'][srcnet]['addrObjProperties'] == '14':
                                tmp_src = srcnet
                            else:
                                tmp_src = "BUILTIN_" + self.sc(srcnet)
                        elif srcnet in self.config[context]['addressesfqdn']:
                            tmp_src = srcnet
                        self.log('                    <member>' + self.sc(tmp_src) + '</member>')
                    self.log('                  </source>')
                    self.log('                  <destination>')
                    for dstnet in tmp_dstnet:
                        if dstnet.lower() == 'any':
                            tmp_dst = dstnet
                        elif dstnet in self.config[context]['addresses']:
                            if self.config[context]['addresses'][dstnet]['addrObjProperties'] == '14':
                                tmp_dst = dstnet
                            else:
                                tmp_dst = "BUILTIN_" + self.sc(dstnet)
                        elif dstnet in self.config[context]['addressesfqdn']:
                            tmp_dst = dstnet
                        self.log('                    <member>' + self.sc(tmp_dst) + '</member>')
                    self.log('                  </destination>')
                    self.log('                            <source-user>')
                    self.log('                    <member>any</member>')
                    self.log('                  </source-user>')
                    self.log('                  <category>')
                    self.log('                    <member>any</member>')
                    self.log('                  </category>')
                    self.log('                  <application>')
                    self.log('                    <member>any</member>')
                    self.log('                  </application>')
                    self.log('                 <service>')
                    for dstsvc in tmp_dstsvc:
                        self.log('                    <member>' + self.sc(dstsvc) + '</member>')
                    self.log('                  </service>')
                    self.log('                  <hip-profiles>')
                    self.log('                    <member>any</member>')
                    self.log('                  </hip-profiles>')
                    self.log('                  <description>' + self.ss(policy_object[policy_index]['policyComment']))
                    self.log('')
                    if policy_object[policy_index]['policySrcZone'][0].lower() in zone_map:
                        out_srczone = zone_map[policy_object[policy_index]['policySrcZone'][0].lower()]
                    else:
                        out_srczone = policy_object[policy_index]['policySrcZone'][0]
                    if policy_object[policy_index]['policyDstZone'][0].lower() in zone_map:
                        out_dstzone = zone_map[policy_object[policy_index]['policyDstZone'][0].lower()]
                    else:
                        out_dstzone = policy_object[policy_index]['policyDstZone'][0]
                    self.log(out_srczone + '__' + out_dstzone + '__' + self.sc(tmp_srcnet[0]) + '__' + self.sc(
                        tmp_dstnet[0]) + '__' + self.sc(
                        tmp_dstsvc[0]))
                    self.log('                  </description>')
                    if policy_object[policy_index]['policyAction'] == '0':
                        self.log('                  <action>deny</action>')
                    if policy_object[policy_index]['policyAction'] == '1':
                        self.log('                  <action>drop</action>')
                    if policy_object[policy_index]['policyAction'] == '2':
                        self.log('                  <action>allow</action>')
                    if policy_object[policy_index]['policyEnabled'] != '1':
                        self.log('<disabled>yes</disabled>')
                    self.log('                  <log-setting>' + customops.log_forward_profile_name + '</log-setting>')
                    self.log('                  <profile-setting>')
                    self.log('                    <group>')
                    self.log('                      <member>' + customops.rule_profile_setting + '</member>')
                    self.log('                    </group>')
                    self.log('                  </profile-setting>')
                    self.log('                </entry>')

            # Get a list of ICMP services used in this rule
            icmp_ports = []
            for dstsvc in tmp_dstsvc:
                for svc in self.expand_service(self.config[context]['services'], dstsvc, self.config[context]['servicemappings'],
                                          inc_group=False):
                    if str.lower(self.getService.get_prot_of(self.config[context]['services'], svc)) == 'icmp':
                        icmp_ports.append(self.getService.get_port_of(self.config[context]['services'], svc))

            # If ICMP is defined in this rule, add a new icmp rule using application
            if icmp_ports != []:
                if policy_object[policy_index]['policyProps'] == '0' and 'MULTICAST' not in policy_object[policy_index][
                    'policySrcZone'] and 'MULTICAST' not in policy_object[policy_index]['policyDstZone']:
                    if list(set([x.lower() for x in policy_object[policy_index]['policySrcZone']]) & set(
                            [y.lower() for y in zone_map])) != [] and list(
                        set([xx.lower() for xx in policy_object[policy_index]['policyDstZone']]) & set(
                            [yy.lower() for yy in zone_map])) != []:
                        self.log('                <entry name="' + customops.base_rule_name + '%04d-icmp">' % count)
                        self.log('                  <target>')
                        self.log('                    <negate>no</negate>')
                        self.log('                  </target>')
                        self.log('                  <to>')
                        for dstzone in policy_object[policy_index]['policyDstZone']:
                            if dstzone.lower() in zone_map:
                                out_zone = zone_map[dstzone.lower()]
                            else:
                                out_zone = dstzone
                            self.log('                    <member>' + out_zone + '</member>')
                        self.log('                  </to>')
                        self.log('                  <from>')
                        for srczone in policy_object[policy_index]['policySrcZone']:
                            if srczone.lower() in zone_map:
                                out_zone = zone_map[srczone.lower()]
                            else:
                                out_zone = srczone
                            self.log('                    <member>' + out_zone + '</member>')
                        self.log('                  </from>')
                        self.log('                  <source>')
                        for srcnet in tmp_srcnet:
                            self.log('                    <member>' + self.sc(srcnet) + '</member>')
                        self.log('                  </source>')
                        self.log('                  <destination>')
                        for dstnet in tmp_dstnet:
                            self.log('                    <member>' + self.sc(dstnet) + '</member>')
                        self.log('                  </destination>')
                        self.log('                            <source-user>')
                        self.log('                    <member>any</member>')
                        self.log('                  </source-user>')
                        self.log('                  <category>')
                        self.log('                    <member>any</member>')
                        self.log('                  </category>')

                        self.log('                  <application>')
                        '''if sorted(icmp_ports) == ['0','8']:
                            icmp_svc = 'ping'
                        else:
                            icmp_svc = 'icmp'
                        self.log('                    <member>' + icmp_svc + '</member>')
                        '''
                        self.log('                    <member>' + 'ping' + '</member>')
                        self.log('                    <member>' + 'icmp' + '</member>')
                        self.log('                    <member>' + 'traceroute' + '</member>')

                        self.log('                  </application>')
                        self.log('                 <service>')
                        self.log('                    <member>application-default</member>')
                        self.log('                  </service>')
                        self.log('                  <hip-profiles>')
                        self.log('                    <member>any</member>')
                        self.log('                  </hip-profiles>')
                        self.log(
                            '                  <description>' + self.ss(policy_object[policy_index]['policyComment']))
                        self.log('')
                        if policy_object[policy_index]['policySrcZone'][0].lower() in zone_map:
                            out_srczone = zone_map[policy_object[policy_index]['policySrcZone'][0].lower()]
                        else:
                            out_srczone = policy_object[policy_index]['policySrcZone'][0]
                        if policy_object[policy_index]['policyDstZone'][0].lower() in zone_map:
                            out_dstzone = zone_map[policy_object[policy_index]['policyDstZone'][0].lower()]
                        else:
                            out_dstzone = policy_object[policy_index]['policyDstZone'][0]
                        self.log(out_srczone + '__' + out_dstzone + '__' + self.sc(tmp_srcnet[0]) + '__' + self.sc(
                            tmp_dstnet[0]) + '__' + self.sc(tmp_dstsvc[0]))
                        self.log('                  </description>')
                        if policy_object[policy_index]['policyAction'] == '0':
                            self.log('                  <action>deny</action>')
                        if policy_object[policy_index]['policyAction'] == '1':
                            self.log('                  <action>drop</action>')
                        if policy_object[policy_index]['policyAction'] == '2':
                            self.log('                  <action>allow</action>')
                        if policy_object[policy_index]['policyEnabled'] != '1':
                            self.log('<disabled>yes</disabled>')
                        self.log(
                            '                  <log-setting>' + customops.log_forward_profile_name + '</log-setting>')
                        self.log('                  <profile-setting>')
                        self.log('                    <group>')
                        self.log('                      <member>' + customops.rule_profile_setting + '</member>')
                        self.log('                    </group>')
                        self.log('                  </profile-setting>')
                        self.log('                </entry>')

            if 'MULTICAST' not in policy_object[policy_index]['policySrcZone'] and 'MULTICAST' not in \
                    policy_object[policy_index]['policyDstZone']:
                count = count + 1
        self.log('              </rules>')
        self.log('            </security>')
        return

    # currently only handles source NAT (and bidirectionals)
    # Interface objects do not appear to be in the output xml file, some built in types may not be converted
    # Object names in groups not expanded as expected
    def create_nat(self, nat_policies, context, zone_map, interface_map, interfaces, builtin_map):
        # nat_props = [ 'natPolicyOrigSrc', 'natPolicyOrigDst', 'natPolicyOrigSvc', 'natPolicyTransSrc', 'natPolicyTransDst', 'natPolicyTransSvc', 'natPolicySrcIface', 'natPolicyDstIface', 'natPolicyEnabled', 'natPolicyComment', 'natPolicyProperties', 'natPolicyName' ]
        # if source if a "default"/built-in address GROUP, the code below does not handle this properly.
        # change orig/trans src/dest to lists

        policynum = 1
        intnums = {}
        added_policies = []
        for interface in interfaces:
            intnums[interfaces[interface]['iface_ifnum']] = interface
        self.log('            <nat>')
        self.log('              <rules>')

        for policy in nat_policies:
            if nat_policies[policy]['natPolicyProperties'] not in ['1023', '17407']:  # skip default NAT rules

                src_zones = ['any']
                dst_zones = ['any']
                trans_source = ''

                if nat_policies[policy]['natPolicySrcIface'] == '-1':
                    src_zones = ['any']
                    src_int = 'any'
                else:
                    if interfaces[nat_policies[policy]['natPolicySrcIface']]['interface_Zone'] in zone_map:
                        src_zones = [zone_map[interfaces[nat_policies[policy]['natPolicySrcIface']]['interface_Zone']]]
                    else:
                        src_zones = [interfaces[nat_policies[policy]['natPolicySrcIface']]['interface_Zone']]

                if nat_policies[policy]['natPolicyDstIface'] == '-1':
                    dst_zones = ['any']
                    dst_int = 'any'
                else:
                    if interfaces[nat_policies[policy]['natPolicyDstIface']]['interface_Zone'] in zone_map:
                        dst_zones = [zone_map[interfaces[nat_policies[policy]['natPolicyDstIface']]['interface_Zone']]]
                    else:
                        dst_zones = [interfaces[nat_policies[policy]['natPolicyDstIface']]['interface_Zone']]
                    if interfaces[nat_policies[policy]['natPolicyDstIface']]['iface_name'] in interface_map:
                        dst_int = interface_map[
                            unquote(interfaces[nat_policies[policy]['natPolicyDstIface']]['iface_name'])]
                    else:
                        dst_int = 'Error'
                        self.debug(nat_policies[policy]['natPolicyDstIface'])
                        self.debug(interface_map)

                if nat_policies[policy]['natPolicyOrigSrc'][0] == '':
                    orig_source = ['any']
                else:
                    if self.config[context]['addresses'][nat_policies[policy]['natPolicyOrigSrc'][0]][
                        'addrObjProperties'] != '14':
                        orig_source = [
                            "BUILTIN_" + self.sc(nat_policies[policy]['natPolicyOrigSrc'][0])]  ## placeholder
                    else:
                        orig_source = [nat_policies[policy]['natPolicyOrigSrc'][0]]

                if nat_policies[policy]['natPolicyTransSrc'][0] != '':
                    if self.config[context]['addresses'][nat_policies[policy]['natPolicyTransSrc'][0]][
                        'addrObjProperties'] != '14':
                        trans_source = "BUILTIN_" + self.sc(
                            nat_policies[policy]['natPolicyTransSrc'][0])  ## placeholder
                    else:
                        trans_source = nat_policies[policy]['natPolicyTransSrc'][0]

                if nat_policies[policy]['natPolicyOrigDst'][0] == '':
                    orig_dest = ['any']
                else:
                    if self.config[context]['addresses'][nat_policies[policy]['natPolicyOrigDst'][0]][
                        'addrObjProperties'] != '14':
                        orig_dest = ["BUILTIN_" + self.sc(nat_policies[policy]['natPolicyOrigDst'][0])]  ## placeholder
                    else:
                        orig_dest = [nat_policies[policy]['natPolicyOrigDst'][0]]

                if dst_zones == ['any']:
                    # dst_zones=zone_map[get_zones(context, str(config[context]['addresses'][orig_dest[0]]['IPSet'].iter_cidrs()[0][0])).lower()]
                    tmp_dst_zones = self.zone.get_zones(context, orig_dest[0])
                    dst_zones = []
                    for zone in tmp_dst_zones:
                        if zone in zone_map:
                            dst_zones.append(zone_map[zone])
                        else:
                            dst_zones.append(zone)

                # if src_zones==['any']:
                #    #src_zones=zone_map[get_zones(context, str(config[context]['addresses'][orig_source[0]]['IPSet'].iter_cidrs()[0][0])).lower()]
                #    src_zones=get_zones(context, orig_source[0])
                # self.log('DSTZONE: ', dst_zones)
                if nat_policies[policy]['natPolicyTransDst'][0] != '':
                    if self.config[context]['addresses'][nat_policies[policy]['natPolicyTransDst'][0]][
                        'addrObjProperties'] != '14':
                        trans_dest = "BUILTIN_" + self.sc(nat_policies[policy]['natPolicyTransDst'][0])  ## placeholder
                    else:
                        trans_dest = nat_policies[policy]['natPolicyTransDst'][0]

                # self.log('"{}" "{}" "{}"'.format('translated', nat_policies[policy]['natPolicyTransSrc'][0], trans_source))
                if nat_policies[policy]['natPolicyOrigSvc'][0] == '':
                    orig_svc = 'any'
                else:
                    orig_svc = nat_policies[policy]['natPolicyOrigSvc'][0]
                bidirectional = 'no'
                for tmp_policy in nat_policies:
                    if tmp_policy != policy:
                        if (nat_policies[policy]['natPolicyOrigSrc'], nat_policies[policy]['natPolicyTransSrc'],
                            nat_policies[policy]['natPolicyOrigDst'], nat_policies[policy]['natPolicyTransDst'],
                            nat_policies[policy]['natPolicyOrigSvc'], nat_policies[policy]['natPolicyTransSvc']) == (
                                nat_policies[tmp_policy]['natPolicyTransDst'],
                                nat_policies[tmp_policy]['natPolicyOrigDst'],
                                nat_policies[tmp_policy]['natPolicyOrigSrc'],
                                nat_policies[tmp_policy]['natPolicyTransSrc'],
                                nat_policies[tmp_policy]['natPolicyOrigSvc'],
                                nat_policies[tmp_policy]['natPolicyTransSvc']):
                            # (nat_policies[tmp_policy]['natPolicyTransDst'], nat_policies[tmp_policy]['natPolicyOrigDst'], nat_policies[tmp_policy]['natPolicyTransSrc'], nat_policies[tmp_policy]['natPolicyOrigSrc'], nat_policies[tmp_policy]['natPolicyOrigSvc'], nat_policies[tmp_policy]['natPolicyTransSvc']):
                            bidirectional = 'yes'
                        elif (nat_policies[policy]['natPolicyTransDst'], nat_policies[policy]['natPolicyOrigDst'],
                              nat_policies[policy]['natPolicyOrigSrc'], nat_policies[policy]['natPolicyTransSrc'],
                              nat_policies[policy]['natPolicyOrigSvc'],
                              nat_policies[policy]['natPolicyTransSvc']) in added_policies:
                            bidirectional = 'done'
                # debug(policynum, bidirectional)
                if bidirectional != 'done':
                    # debug('Using translated source: {}'.format(trans_source))
                    for dst_zone in dst_zones:
                        for src_zone in src_zones:
                            self.log('                  <entry name="Imported NAT Policy {}-{}">'.format(policynum,
                                                                                                         dst_zone))

                            if nat_policies[policy]['natPolicyTransSrc'][0] != '':
                                self.log('                    <source-translation>')
                                self.log('                      <static-ip>')
                                self.log('                       <translated-address>{}</translated-address>'.format(
                                    self.sc(trans_source)))
                                self.log(
                                    '                      <bi-directional>{}</bi-directional>'.format(bidirectional))
                                self.log('                     </static-ip>')
                                self.log('                   </source-translation>')
                            if nat_policies[policy]['natPolicyTransDst'][0] != '':
                                self.log('                    <destination-translation>')
                                self.log('                       <translated-address>{}</translated-address>'.format(
                                    self.sc(trans_dest)))
                                self.log('                   </destination-translation>')
                            self.log('                    <target>')
                            self.log('                      <negate>no</negate>')
                            self.log('                    </target>')
                            self.log('                    <to>')
                            self.log('                      <member>{}</member>'.format(urllib.parse.unquote(dst_zone)))
                            self.log('                    </to>')
                            self.log('                    <from>')
                            self.log('                      <member>{}</member>'.format(urllib.parse.unquote(src_zone)))
                            self.log('                    </from>')
                            self.log('                    <source>')
                            for source in orig_source:
                                self.log('                      <member>{}</member>'.format(self.sc(source)))
                            self.log('                    </source>')
                            self.log('                    <destination>')
                            for dest in orig_dest:
                                self.log('                      <member>{}</member>'.format(self.sc(dest)))
                            self.log('                    </destination>')
                            self.log('                    <service>{}</service>'.format(urllib.parse.unquote(orig_svc)))
                            self.log('                    <nat-type>ipv4</nat-type>')
                            if nat_policies[policy]['natPolicyEnabled'] == '0':
                                self.log('                    <disabled>yes</disabled>')
                            # self.log(policynum, nat_policies[policy]['natPolicyProperties'], nat_policies[policy]['natPolicyEnabled'])
                            self.log('                    <description>{}</description>'.format(
                                urllib.parse.unquote(nat_policies[policy]['natPolicyComment'])))
                            self.log('                    <to-interface>{}</to-interface>'.format(dst_int))

                            self.log('                  </entry>')
                    added_policies.append((nat_policies[policy]['natPolicyOrigSrc'],
                                           nat_policies[policy]['natPolicyTransSrc'],
                                           nat_policies[policy]['natPolicyOrigDst'],
                                           nat_policies[policy]['natPolicyTransDst'],
                                           nat_policies[policy]['natPolicyOrigSvc'],
                                           nat_policies[policy]['natPolicyTransSvc']))
            policynum += 1
            # self.log('                </entry>')
        self.log('              </rules>')
        self.log('            </nat>')

        return

    # Takes an address group object (by name) and expands it into a list of all of its individual address objects
    def expand_address(self, address_dict, address_object, address_map, inc_group=False):
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
                            for group_member in self.expand_address(address_dict, group_members, address_map, inc_group):
                                expanded_addresses.append(group_member)
        elif 'addresses' in self.config['shared']:
            if address_object in self.config['shared']['addresses']:
                if 'addrObjType' in self.config['shared']['addresses'][address_object]:
                    if self.config['shared']['addresses'][address_object]['addrObjType'] != '8':
                        expanded_addresses.append(address_object)
                    else:
                        if inc_group:
                            expanded_addresses.append(address_object)
                        if address_object in address_map:
                            for group_members in self.config['shared']['addressesmappings'][
                                self.config['shared']['addresses'][address_object]['addrObjId']]:
                                for group_member in self.expand_address(self.config['shared']['addresses'], group_members,
                                                                   self.config['shared']['addressesmappings'], inc_group):
                                    expanded_addresses.append(group_member)

        return expanded_addresses

    # Takes a service group object (by name) and expands it into a list of all of its individual service objects
    def expand_service(self, service_dict, service_object, service_map, inc_group=False):
        expanded_services = []
        if service_object.lower() in [name.lower() for name in service_dict]:  # do case insensitive match
            if service_object in service_dict:
                if service_dict[service_object]['svcObjIpType'] != '0':
                    expanded_services.append(service_object)
                else:
                    if inc_group:
                        expanded_services.append(service_object)
                    if service_object in service_map:
                        for member in service_map[service_dict[service_object]['svcObjId']]:
                            for members in self.expand_service(service_dict, member, service_map, inc_group):
                                expanded_services.append(members)
            elif service_object in self.config['shared']['services']:
                if self.config['shared']['services'][service_object]['svcObjIpType'] != '0':
                    expanded_services.append(service_object)
                else:
                    if inc_group:
                        expanded_services.append(service_object)
                    if service_object in self.config['shared']['servicemappings']:
                        for member in self.config['shared']['servicemappings'][
                            self.config['shared']['services'][service_object]['svcObjId']]:
                            for members in self.expand_service(self.config['shared']['services'], member,
                                                          self.config['shared']['servicemappings'], inc_group):
                                expanded_services.append(members)
        return expanded_services

    # Create a Palo Alto configuration file.  Intended to be used with a Sonicwall source input file.
    # Not intended to be used for Palo Alto to Palo Alto use.
    def create_config(self, config, interface_map, outfile, context, customops):
        if self.options.zonemaps:
            zone_map = {}
            for zonemap in self.options.zonemaps:
                old_zone, new_zone = zonemap.split(',')
                zone_map[old_zone.lower()] = new_zone

        out = open(outfile, 'w')
        stdout = sys.stdout
        sys.stdout = out

        # build list of built-in objects that are in use by nat policies
        builtin_map = {}
        builtin_index = 0
        for policy in config['nat']:
            if config['nat'][policy]['natPolicyProperties'] not in ['1023', '17407']:
                for obj_type in ['natPolicyOrigSrc', 'natPolicyOrigDst', 'natPolicyTransSrc', 'natPolicyTransDst']:
                    if config['nat'][policy][obj_type][0] != '':
                        if config['addresses'][config['nat'][policy][obj_type][0]]['addrObjProperties'] != '14':
                            if config['nat'][policy][obj_type][0] not in builtin_map:
                                builtin_map[config['nat'][policy][obj_type][0]] = 'BUILTIN_' + self.sc(
                                    config['nat'][policy][obj_type][0])
                                # debug('built-in object {}'.format(config['nat'][policy][obj_type][0]))
                                # debug('built-in object {}'.format(sc(config['nat'][policy][obj_type][0])))
                            if config['addresses'][config['nat'][policy][obj_type][0]]['addrObjType'] == '8':
                                for addr in self.expand_address(config['addresses'],
                                                           config['addresses'][config['nat'][policy][obj_type][0]][
                                                               'addrObjId'], config['addressmappings']):
                                    if config['addresses'][addr]['addrObjProperties'] != '14':
                                        if addr not in builtin_map:
                                            # debug('built-in group member {}'.format(ss(addr)))
                                            builtin_map[addr] = 'BUILTIN_' + self.sc(addr)

        self.log('<config version=\"7.1.0\" urldb=\"paloaltonetworks\">')
        self.create_logging()
        self.log('  <devices>')
        self.log('    <entry name=\"localhost.localdomain\">')

        self.create_network(config['interfaces'], interface_map, config['zones'], config['routing'], context, zone_map)

        self.log('      <device-group>')
        self.log('        <entry name="' + customops.devicegroup_name + '">')

        self.create_addresses(config['addresses'], config['addressesfqdn'], config['addressmappings'], builtin_map)
        self.create_services(config['services'], config['servicemappings'])

        self.log('          <pre-rulebase>')

        self.create_policies(config['policies'], context, zone_map)
        self.create_nat(config['nat'], context, zone_map, interface_map, config['interfaces'], builtin_map)

        self.log('          </pre-rulebase>')
        self.log('          <profile-group>')
        self.log('            <entry name="' + customops.rule_profile_setting + '"/>')
        self.log('          </profile-group>')
        self.log('        <devices/>')
        self.log('        </entry>')
        self.log('      </device-group>')
        self.log('    </entry>')
        self.log('  </devices>')
        self.log('</config>')
        sys.stdout = stdout
        out.close
        return

    def create_address_obj(self, target, session, apikey, fw_type, syntax, params, sw_objects=None):
        if 'members' not in params:
            params['members'] = []

        result = False
        if 'comment' in params and fw_type.lower() in ['palo', 'pano', 'paloalto'] and syntax.lower() in ['webui',
                                                                                                          'api']:
            params['comment'] = escape(params['comment'])

        if syntax == 'cli':
            result = True
            if 'prefix' in params:
                prefix = params['prefix']
            else:
                prefix = '{}CLI:'.format(fw_type.upper())
        self.debug(fw_type)
        if fw_type == 'sonicwall':
            if syntax.lower() == 'cli':
                if params['addresstype'].lower() in ['1', 'host']:
                    self.log('{}address-object ipv4 "{}" host {} zone {}'.format(prefix, params['addressname'],
                                                                                 params['ip1'],
                                                                                 params['zone']))
                elif params['addresstype'].lower() in ['2', 'range']:
                    self.log('{}address-object ipv4 "{}" range {} {} zone {}'.format(prefix, params['addressname'],
                                                                                     params['ip1'], params['ip2'],
                                                                                     params['zone']))
                elif params['addresstype'].lower() in ['4', 'network']:
                    self.log('{}address-object ipv4 "{}" network {} {} zone {}'.format(prefix, params['addressname'],
                                                                                       params['ip1'], params['ip2'],
                                                                                       params['zone']))
                elif params['addresstype'].lower() in ['8', 'group']:
                    self.log('{}address-group ipv4 "{}"'.format(prefix, params['addressname']))
                    for member in params['members']:
                        self.log('{}address-object ipv4 "{}"'.format(prefix, member))
                    self.log('{}exit'.format(prefix))
            elif syntax.lower() in ['webui', 'api']:
                if params['addresstype'].lower() in ['8', 'group']:
                    params['zone'] = ''
                    params['ip1'] = '0.0.0.0'
                    params['ip2'] = '0.0.0.0'
                    params['addresstype'] = '8'
                if params['addresstype'].lower() == 'host':
                    params['addresstype'] = '1'
                elif params['addresstype'].lower() == 'range':
                    params['addresstype'] = '2'
                elif params['addresstype'].lower() == 'network':
                    params['addresstype'] = '4'
                postdata = {'addrObjId_-1': params['addressname'],
                            'addrObjType_-1': params['addresstype'],
                            'addrObjZone_-1': params['zone'],
                            'addrObjProperties_-1': '14',
                            'addrObjIp1_-1': params['ip1'],
                            'addrObjIp2_-1': params['ip2']
                            }
                self.debug(postdata)
                url = 'https://' + target + '/main.cgi'
                result = self.sw.send_sw_webcmd(session, url, postdata)
                if params['addresstype'].lower() in ['8', 'group']:
                    for member in params['members']:
                        if result:
                            postdata = {'addro_atomToGrp_0': member,
                                        'addro_grpToGrp_0': params['addressname']
                                        }
                            result = self.sw.send_sw_webcmd(session, url, postdata)
            else:
                return 'Unknown syntax "{}" specified for Sonicwall'.format(syntax)
        elif fw_type.lower() in ['sw65']:
            if syntax.lower() in ['api']:
                # CHANGE_ME - to add a group, it must have members, and member object type
                # (address_group/address_object/fqdn/mac) needs to be known
                if params['addresstype'].lower() in ['8', 'group']:
                    if 'members' not in params:
                        params['members'] == []

                    url = 'https://{}/api/sonicos/address-groups/ipv4'.format(target)
                    members = []
                    post_data = {'address_group': {
                        'ipv4': {
                            'name': params['addressname']
                        }
                    }
                    }

                    members_added = False
                    for address_object in params['members']:
                        members_added = True
                        if address_object in sw_objects['address_objects']['ipv4']:
                            if 'address_object' in post_data['address_group']['ipv4']:
                                post_data['address_group']['ipv4']['address_object']['ipv4'].append(
                                    {'name': address_object})
                            else:
                                post_data['address_group']['ipv4']['address_object'] = {
                                    'ipv4': [{'name': address_object}]}

                    for address_object in params['members']:
                        members_added = True
                        if address_object in sw_objects['address_objects']['fqdn']:
                            pass
                            if 'address_object' in post_data['address_group']['ipv4']:
                                post_data['address_group']['ipv4']['address_object']['fqdn'].append(
                                    {'name': address_object})
                            else:
                                post_data['address_group']['ipv4']['address_object'] = {
                                    'fqdn': [{'name': address_object}]}

                    for address_object in params['members']:
                        members_added = True
                        if address_object in sw_objects['address_groups']['ipv4']:
                            if 'address_group' in post_data['address_group']['ipv4']:
                                post_data['address_group']['ipv4']['address_group']['ipv4'].append(
                                    {'name': address_object})
                            else:
                                post_data['address_group']['ipv4']['address_group'] = {
                                    'ipv4': [{'name': address_object}]}

                    # post_data['address_group']['ipv4']['address_object']['ipv4']  != []: # members!=[]:
                    if members_added:
                        self.debug(post_data)
                        result = session.post(url=url, json=post_data, verify=False,
                                              timeout=self.options.timeout_sw_webui_post)
                        if not json.loads(result.text)['status']['success']:
                            result = False, json.loads(result.text)['status']['info'][0]['message']
                        else:
                            result = True

                    else:
                        result = False, 'no valid member objects'

                elif params['addresstype'].lower() in ['host', '1']:
                    url = 'https://{}/api/sonicos/address-objects/ipv4'.format(target)
                    post_data = {'address_object': {
                        'ipv4': {
                            'name': params['addressname'],
                            'zone': params['zone'],
                            'host': {'ip': params['ip1']}}}}
                    result = session.post(url=url, json=post_data, verify=False,
                                          timeout=self.options.timeout_sw_webui_post)
                    if not json.loads(result.text)['status']['success']:
                        result = False, json.loads(result.text)['status']['info'][0]['message']
                    else:
                        result = True
                elif params['addresstype'].lower() in ['range', '2']:
                    url = 'https://{}/api/sonicos/address-objects/ipv4'.format(target)
                    post_data = {'address_object': {
                        'ipv4': {
                            'name': params['addressname'],
                            'zone': params['zone'],
                            'range': {'begin': params['ip1'], 'end': params['ip2']}}}}
                    result = session.post(url=url, json=post_data, verify=False,
                                          timeout=self.options.timeout_sw_webui_post)
                    if not json.loads(result.text)['status']['success']:
                        result = False, json.loads(result.text)['status']['info'][0]['message']
                    else:
                        result = True
                elif params['addresstype'].lower() in ['network', '4']:
                    url = 'https://{}/api/sonicos/address-objects/ipv4'.format(target)
                    post_data = {'address_object': {
                        'ipv4': {
                            'name': params['addressname'],
                            'zone': params['zone'],
                            'network': {'subnet': params['ip1'], 'mask': params['ip2']}}}}

                    result = session.post(url=url, json=post_data, verify=False,
                                          timeout=self.options.timeout_sw_webui_post)
                    if not json.loads(result.text)['status']['success']:
                        result = False, json.loads(result.text)['status']['info'][0]['message']
                    else:
                        result = True
                elif params['addresstype'].lower() in ['fqdn']:
                    url = 'https://{}/api/sonicos/address-objects/fqdn'.format(target)
                    post_data = {'address_object': {
                        'fqdn': {
                            'name': params['addressname'],
                            'zone': params['zone'],
                            'domain': params['domain']}}}
                    if 'ttl' in params:
                        post_data['address_object']['fqdn']['dns_ttl'] = int(params['ttl'])

                    result = session.post(url=url, json=post_data, verify=False,
                                          timeout=self.options.timeout_sw_webui_post)
                    if not json.loads(result.text)['status']['success']:
                        result = False, json.loads(result.text)['status']['info'][0]['message']
                    else:
                        result = True
                # result=send_palo_apicmd(session, target, url, apikey)

        elif fw_type == 'checkpoint':
            if syntax.lower() == 'cli':
                if params['addresstype'].lower() in ['1', 'host']:
                    self.log('{}create host_plain {}'.format(prefix, params['addressname']))
                    self.log('{}update_all'.format(prefix))
                    self.log(
                        '{}modify network_objects {} ipaddr {}'.format(prefix, params['addressname'], params['ip1']))
                if params['addresstype'].lower() in ['2', 'range']:
                    self.log('{}create address_range {}'.format(prefix, params['addressname']))
                    self.log('{}update_all'.format(prefix))
                    self.log('{}modify network_objects {} ipaddr_first {}'.format(prefix, params['addressname'],
                                                                                  params['ip1']))
                    self.log('{}modify network_objects {} ipaddr_last {}'.format(prefix, params['addressname'],
                                                                                 params['ip2']))
                if params['addresstype'].lower() in ['4', 'network']:
                    self.log('{}create network {}'.format(prefix, params['addressname']))
                    self.log('{}update_all'.format(prefix))
                    self.log(
                        '{}modify network_objects {} ipaddr {}'.format(prefix, params['addressname'], params['ip1']))
                    self.log(
                        '{}modify network_objects {} netmask {}'.format(prefix, params['addressname'], params['ip2']))
                # self.log('{}:modify network_objects'.format(addressname))
                if params['addresstype'].lower() in ['8', 'group']:
                    self.log('{}create network_object_group {}'.format(prefix, params['addressname']))
                    self.log('{}update_all'.format(prefix))
                self.log('{}modify network_objects {} comments "{}"'.format(prefix, params['addressname'],
                                                                            params['comment']))
                self.log('{}modify network_objects {} color {}'.format(prefix, params['addressname'], params['color']))
                for member in params['members']:
                    self.log(
                        '{}addelement network_objects {} \'\' network_objects:{}'.format(prefix, params['addressname'],
                                                                                         member))
            elif syntax.lower() == 'api':
                post_data = None
                if params['addresstype'].lower() in ['1', 'host']:
                    post_command = 'add-host'
                    post_data = {"name": params['addressname'], "ip-address": params['ip1'], "ignore-warnings": True}
                    self.debug('RESULT', result)
                if params['addresstype'].lower() in ['2', 'range']:
                    post_command = 'add-address-range'
                    post_data = {"name": params['addressname'], "ip-address-first": params['ip1'],
                                 "ip-address-last": params['ip2'], "ignore-warnings": True}

                if params['addresstype'].lower() in ['4', 'network']:
                    post_command = 'add-network'
                    post_data = {"name": params['addressname'], "subnet": params['ip1'], "subnet-mask": params['ip2'],
                                 "ignore-warnings": True}

                if params['addresstype'].lower() in ['8', 'group']:
                    post_command = 'add-group'
                    post_data = {"name": params['addressname'], "ignore-warnings": True}
                    if 'members' in params:
                        post_data['members'] = params['members']

                if post_data != None:
                    if 'tags' in params:
                        post_data['tags'] = params['tags']
                    if 'comments' in params:
                        post_data['comments'] = params['comments']
                    if 'color' in params:
                        post_data['color'] = params['color']

                    result = self.service.ckpt_api_call(target, 443, post_command, post_data, apikey)
                    self.debug('create addr', result)
                    if result.status_code != 200:
                        self.debug(result.text)
                        result = False, json.loads(result.text)['message']
                    else:
                        result = True
            else:
                result = False

        elif fw_type in ['palo', 'paloalto', 'pano']:
            if syntax.lower() in ['webui', 'api']:
                if fw_type in ['palo', 'paloalto']:
                    object_base = "/config/devices/entry[@name='localhost.localdomain']/vsys/entry[@name='vsys1']"

                elif fw_type == 'pano':
                    if params['context'] == 'shared':
                        object_base = "/config/shared"
                    else:
                        object_base = "/config/devices/entry[@name='localhost.localdomain']/device-group/entry[@name='{}']".format(
                            params['context'])
                if 'comment' not in params:
                    params['comment'] = ''
                if params['addresstype'].lower() in ['1', 'host']:
                    url = '/api/?type=config&action=set&xpath={}/address/entry[@name=\'{}\']&element=<ip-netmask>{}/{}</ip-netmask><description>{}</description>'.format(
                        object_base, params['addressname'], params['ip1'], '32', quote(params['comment'], safe=''))
                if params['addresstype'].lower() in ['2', 'range']:
                    url = '/api/?type=config&action=set&xpath={}/address/entry[@name=\'{}\']&element=<ip-range>{}-{}</ip-range><description>{}</description>'.format(
                        object_base, params['addressname'], params['ip1'], params['ip2'],
                        quote(params['comment'], safe=''))
                if params['addresstype'].lower() in ['4', 'network']:
                    url = '/api/?type=config&action=set&xpath={}/address/entry[@name=\'{}\']&element=<ip-netmask>{}/{}</ip-netmask><description>{}</description>'.format(
                        object_base, params['addressname'], params['ip1'], self.service.netmask_to_cidr(params['ip2']),
                        quote(params['comment'], safe=''))
                if params['addresstype'].lower() in ['8', 'group']:
                    url = '/api/?type=config&action=set&xpath={}/address-group/entry[@name=\'{}\']&element=<static></static><description>{}</description>'.format(
                        object_base, params['addressname'], quote(params['comment']))
                result = self.getPaloService.send_palo_apicmd(session, target, url, apikey)
                self.debug(target, result)
                if params['addresstype'].lower() in ['8', 'group']:
                    memberlist = ''
                    for member in params['members']:
                        memberlist = memberlist + '<member>{}</member>'.format(member)
                    if memberlist != '':
                        url = '/api/?type=config&action=set&xpath={}/address-group/entry[@name=\'{}\']/static&element={}'.format(
                            object_base, params['addressname'], memberlist)
                        result = self.getPaloService.send_palo_apicmd(session, target, url, apikey)
                        # print(result)
            elif syntax.lower() == 'cli':
                cmds = []
                if fw_type.lower() in ['palo', 'paloalto']:
                    cmd_base = ''
                elif fw_type.lower() == 'pano':
                    if params['context'] == 'shared':
                        cmd_base = 'shared '
                    else:
                        cmd_base = 'device-group "{}" '.format(params['context'])
                if 'prefix' in params:
                    prefix = params['prefix']
                else:
                    prefix = '{}CLI:'.format(fw_type.upper())
                if params['addresstype'].lower() in ['1', 'host']:
                    cmds.append(
                        '{}set {}address {} description "{}" ip-netmask {}'.format(prefix, cmd_base,
                                                                                   params['addressname'],
                                                                                   params['comment'], params['ip1']))
                if params['addresstype'].lower() in ['2', 'range']:
                    cmds.append(
                        '{}set {}address {} description "{}" ip-range {}-{}'.format(prefix, cmd_base,
                                                                                    params['addressname'],
                                                                                    params['comment'], params['ip1'],
                                                                                    params['ip2']))
                if params['addresstype'].lower() in ['4', 'network']:
                    cmds.append('{}set {}address {} description "{}" ip-netmask {}/{}'.format(prefix, cmd_base,
                                                                                              params['addressname'],
                                                                                              params['comment'],
                                                                                              params['ip1'],
                                                                                              self.service.netmask_to_cidr(
                                                                                                  params['ip2'])))
                if params['addresstype'].lower() in ['8', 'group']:
                    cmds.append(
                        '{}set {}address-group {} description "{}"'.format(prefix, cmd_base, params['addressname'],
                                                                           params['comment']))
                    for member in params[
                        'members']:  ## one member is added at a time intentionally -- unsure what would happen if all were to be added at once and one address was bad
                        cmds.append(
                            '{}set {}address-group {} static "{}"'.format(prefix, cmd_base, params['addressname'],
                                                                          member))
                for cmd in cmds:
                    self.log(cmd)

                return True
            else:
                return 'Unsupported syntax type: {} specified for Palo/Pano config'.format(syntax)
        return result

    def create_service_obj(self, target, session, apikey, fw_type, syntax, params, sw_objects=None):

        if 'members' not in params:
            params['members'] = []

        result = False
        if 'comment' in params and fw_type.lower() in ['palo', 'pano', 'paloalto'] and syntax.lower() in ['webui',
                                                                                                          'api']:
            params['comment'] = escape(params['comment'])

        if syntax.lower() == 'cli':
            result = True
            if 'prefix' in params:
                prefix = params['prefix']
            else:
                prefix = '{}CLI:'.format(fw_type.upper())

        if fw_type == 'sonicwall':
            if syntax.lower() == 'cli':
                if params['servicetype'].lower() in ['1', 'service']:
                    if params['protocol'].lower() in ['tcp', '6']:
                        if 'port2' in params:
                            self.log(
                                '{}service-object "{}" tcp {} {}'.format(prefix, params['servicename'], params['port1'],
                                                                         params['port2']))
                        else:
                            self.log(
                                '{}service-object "{}" tcp {} {}'.format(prefix, params['servicename'], params['port1'],
                                                                         params['port1']))
                    elif params['protocol'].lower() in ['udp', '17']:
                        if 'port2' in params:
                            self.log(
                                '{}service-object "{}" udp {} {}'.format(prefix, params['servicename'], params['port1'],
                                                                         params['port2']))
                        else:
                            self.log(
                                '{}service-object "{}" udp {} {}'.format(prefix, params['servicename'], params['port1'],
                                                                         params['port1']))
                elif params['servicetype'].lower() in ['2', 'service-group', 'servicegroup', 'group']:
                    self.log('{}service-group "{}"'.format(prefix, params['servicename']))
                    for member in params['members']:
                        self.log('{}service-object "{}"'.format(prefix, member))
                    self.log('{}exit'.format(prefix))
            elif syntax.lower() in ['webui', 'api']:
                postdata = {'svcObjId_-1': params['servicename'],
                            'svcObjType_-1': params['servicetype'],
                            'svcObjProperties_-1': '14',
                            }
                if params['servicetype'].lower() in ['1', 'service']:
                    postdata.update({'svcObjPort1_-1': params['port1'],
                                     'svcObjManagement_-1': '0',
                                     'svcObjHigherPrecedence_-1': '0'})
                    if 'port2' in params:
                        postdata.update({'svcObjPort2_-1': params['port2']})
                    else:
                        postdata.update({'svcObjPort2_-1': params['port1']})
                    if params['servicetype'].lower() == 'tcp':
                        postdata.update({'svcObjIpType_-1': '6'})
                    elif params['servicetype'].lower() == 'udp':
                        postdata.update({'svcObjIpType_-1': '17'})

                url = 'https://' + target + '/main.cgi'
                result = self.sw.send_sw_webcmd(session, url, postdata)
                if params['servicetype'].lower() in ['2', 'service-group', 'servicegroup', 'group']:
                    for member in params['members']:
                        if result:
                            postdata = {'so_atomToGrp_0': member,
                                        'so_grpToGrp_0': params['servicename']
                                        }
                            result = self.sw.send_sw_webcmd(session, url, postdata)
            else:
                return 'Unknown syntax "{}" specified for Sonicwall'.format(syntax)
        elif fw_type.lower() in ['sw65']:
            if syntax.lower() in ['api']:
                if params['servicetype'].lower() in ['1', 'service']:
                    if params['protocol'].lower() in ['tcp', '6']:
                        if 'port2' in params:
                            post_data = {'service_object': {'name': params['servicename'],
                                                            'tcp': {'begin': int(params['port1']),
                                                                    'end': int(params['port2'])}}}
                        else:
                            post_data = {'service_object': {'name': params['servicename'],
                                                            'tcp': {'begin': int(params['port1']),
                                                                    'end': int(params['port1'])}}}
                    elif params['protocol'].lower() in ['udp', '17']:
                        if 'port2' in params:
                            post_data = {'service_object': {'name': params['servicename'],
                                                            'udp': {'begin': int(params['port1']),
                                                                    'end': int(params['port2'])}}}
                        else:
                            post_data = {'service_object': {'name': params['servicename'],
                                                            'udp': {'begin': int(params['port1']),
                                                                    'end': int(params['port1'])}}}
                    url = 'https://{}/api/sonicos/service-objects'.format(target)
                    result = session.post(url=url, json=post_data)
                    if not json.loads(result.text)['status']['success']:
                        result = False, json.loads(result.text)['status']['info'][0]['message']
                    else:
                        result = True

                elif params['servicetype'].lower() in ['2', 'service-group', 'servicegroup', 'group']:
                    service_objects = []
                    service_groups = []
                    members = []
                    for service_object in params['members']:
                        if service_object in sw_objects['service_objects']:
                            members.append({'name': service_object})
                    for service_object in params['members']:
                        if service_object in sw_objects['service_groups']:
                            members.append({'group': service_object})
                    if members != []:
                        post_data = {'service_group': {'name': params['servicename'], 'service_object': members}}
                        url = 'https://{}/api/sonicos/service-groups'.format(target)
                        result = session.post(url=url, json=post_data)
                        if not json.loads(result.text)['status']['success']:
                            result = False, json.loads(result.text)['status']['info'][0]['message']
                        else:
                            result = True

                    else:
                        result = False, 'no valid member objects'

        elif fw_type == 'checkpoint':
            if syntax.lower() == 'cli':
                if params['servicetype'].lower() in ['1', 'service']:
                    if params['protocol'].lower() in ['tcp', '6']:
                        self.log('{}create tcp_service {}'.format(prefix, params['servicename']))
                    elif params['protocol'].lower() in ['udp', '17']:
                        self.log('{}create udp_service {}'.format(prefix, params['servicename']))
                    self.log('{}update_all'.format(prefix))
                    self.log('{}modify services {} port {}'.format(prefix, params['servicename'], params['port1']))
                    self.log('{}modify services {} color {}'.format(prefix, params['servicename'], params['color']))
                if params['servicetype'].lower() in ['2', 'service-group', 'servicegroup', 'group']:
                    self.log('{}create service_group {}'.format(prefix, params['servicename']))
                    self.log('{}update_all'.format(prefix))
                self.log('{}modify services {} comments "{}"'.format(prefix, params['servicename'], params['comment']))
                self.log('{}modify services {} color {}'.format(prefix, params['servicename'], params['color']))
                for member in params['members']:
                    self.log('{}addelement services {} \'\' services:{}'.format(prefix, params['servicename'], member))
            elif syntax.lower() == 'api':
                post_data = None
                if params['servicetype'].lower() in ['1', 'service']:
                    post_data = {"name": params['servicename'], "ignore-warnings": True}
                    if params['protocol'].lower() in ['tcp', '6']:
                        post_command = 'add-service-tcp'
                        if 'port2' in params:
                            post_data['port'] = '{}-{}'.format(params['port1'], params['port2'])
                        else:
                            post_data['port'] = params['port1']
                    elif params['protocol'].lower() in ['udp', '17']:
                        post_command = 'add-service-udp'
                        if 'port2' in params:
                            post_data['port'] = '{}-{}'.format(params['port1'], params['port2'])
                        else:
                            post_data['port'] = params['port1']
                    elif params['protocol'].lower() in ['icmp', '1']:
                        post_command = 'add-service-icmp'
                        post_data['icmp-type'] = params['port1']
                        if 'port2' in params:
                            post_data['icmp-code'] = params['port2']
                    elif params['protocol'].lower() in ['icmp6', 'icmpv6', '58']:
                        post_command = 'add-service-icmp6'
                        post_data['icmp-type'] = params['port1']
                        if 'port2' in params:
                            post_data['icmp-code'] = params['port2']
                    elif params['protocol'].lower() in ['sctp', '132']:
                        post_command = 'add-service-sctp'
                        if 'port2' in params:
                            post_data['port'] = '{}-{}'.format(params['port1'], params['port2'])
                        else:
                            post_data['port'] = params['port1']
                    elif params['protocol'].lower() in ['other', '255']:
                        post_command = 'add-service-other'
                        post_data['ip-protocol'] = params['port1']
                    elif params['protocol'].lower() in ['dce-rpc']:
                        post_command = 'add-service-dce-rpc'
                    elif params['protocol'].lower() in ['rpc']:
                        post_command = 'add-service-rpc'
                        post_data['program-number'] = params['port1']
                    elif params['protocol'].lower() in ['gtp']:
                        post_command = 'add-service-gtp'

                    elif params['protocol'].lower() in ['citrix-tcp']:
                        post_command = 'add-service-citrix-tcp'
                    elif params['protocol'].lower() in ['compound-tcp']:
                        post_command = 'add-service-compound-tcp'

                    # post_data={"name": params['servicename'], "ip-address": params['ip1'], "ignore-warnings": True}
                    self.debug('RESULT', result)

                elif params['servicetype'].lower() in ['2', 'group']:
                    post_command = 'add-service-group'
                    post_data = {"name": params['servicename'], "ignore-warnings": True}
                    if 'members' in params:
                        post_data['members'] = params['members']

                if post_data != None:
                    if 'tags' in params:
                        post_data['tags'] = params['tags']
                    if 'comments' in params:
                        post_data['comments'] = params['comments']
                    if 'color' in params:
                        post_data['color'] = params['color']

                    result = self.getService.ckpt_api_call(target, 443, post_command, post_data, apikey)
                    self.debug('create svc', result)
                    if result.status_code != 200:
                        self.debug(result.text)
                        result = False, json.loads(result.text)['message']
                    else:
                        result = True


        elif fw_type in ['palo', 'paloalto', 'pano']:

            if syntax.lower() in ['webui', 'api']:
                if fw_type in ['palo', 'paloalto']:
                    object_base = "/config/devices/entry[@name='localhost.localdomain']/vsys/entry[@name='vsys1']"

                elif fw_type == 'pano':
                    if params['context'] == 'shared':
                        object_base = "/config/shared"
                    else:
                        object_base = "/config/devices/entry[@name='localhost.localdomain']/device-group/entry[@name='{}']".format(
                            params['context'])
                if params['servicetype'].lower() in ['1', 'service']:
                    if params['protocol'].lower() in ['tcp', '6']:
                        tmp_protocol = 'tcp'
                    elif params['protocol'].lower() in ['udp', '17']:
                        tmp_protocol = 'udp'
                    else:
                        tmp_protocol = params['protocol']
                    if 'port2' in params:
                        if params['port2'] != '' and params['port1'] != params['port2']:
                            url = '/api/?type=config&action=set&xpath={}/service/entry[@name=\'{}\']&element=<protocol><{}><port>{}-{}</port></{}></protocol><description>{}</description>'.format(
                                object_base, params['servicename'], tmp_protocol, params['port1'], params['port2'],
                                params['protocol'], quote(params['comment'], safe=''))
                        else:
                            url = '/api/?type=config&action=set&xpath={}/service/entry[@name=\'{}\']&element=<protocol><{}><port>{}</port></{}></protocol><description>{}</description>'.format(
                                object_base, params['servicename'], tmp_protocol, params['port1'], params['protocol'],
                                quote(params['comment'], safe=''))
                    else:
                        url = '/api/?type=config&action=set&xpath={}/service/entry[@name=\'{}\']&element=<protocol><{}><port>{}</port></{}></protocol><description>{}</description>'.format(
                            object_base, params['servicename'], tmp_protocol, params['port1'], params['protocol'],
                            quote(params['comment'], safe=''))
                if params['servicetype'].lower() in ['2', 'service-group', 'servicegroup', 'group']:
                    url = '/api/?type=config&action=set&xpath={}/service-group/entry[@name=\'{}\']&element=<members></members>'.format(
                        object_base, params['servicename'])
                result = self.getPaloService.send_palo_apicmd(session, target, url, apikey)
                if params['servicetype'].lower() in ['2', 'service-group', 'servicegroup', 'group']:
                    memberlist = ''
                    for member in params['members']:
                        memberlist = memberlist + '<member>{}</member>'.format(member)
                    if memberlist != '':
                        url = '/api/?type=config&action=set&xpath={}/service-group/entry[@name=\'{}\']/members&element={}'.format(
                            object_base, params['servicename'], memberlist)
                        result = self.getPaloService.send_palo_apicmd(session, target, url, apikey)
                        # print(result)
            elif syntax.lower() == 'cli':
                cmds = []
                if fw_type.lower() in ['palo', 'paloalto']:
                    cmd_base = ''
                elif fw_type.lower() == 'pano':
                    if params['context'] == 'shared':
                        cmd_base = 'shared '
                    else:
                        cmd_base = 'device-group "{}" '.format(params['context'])
                if 'prefix' in params:
                    prefix = params['prefix']
                else:
                    prefix = '{}CLI:'.format(fw_type.upper())
                if params['servicetype'].lower() in ['1', 'service']:
                    if params['protocol'].lower() in ['tcp', '6']:
                        tmp_protocol = 'tcp'
                    elif params['protocol'].lower() in ['udp', '17']:
                        tmp_protocol = 'udp'
                    else:
                        tmp_protocol = params['protocol']
                    if 'port2' in params:
                        cmds.append(
                            '{}set {}service {} description "{}" protocol {} port {}-{}'.format(prefix, cmd_base,
                                                                                                params[
                                                                                                    'servicename'],
                                                                                                params['comment'],
                                                                                                tmp_protocol,
                                                                                                params['port1'],
                                                                                                params['port2']))
                    else:
                        cmds.append('{}set {}service {} description "{}" protocol {} port {}'.format(prefix, cmd_base,
                                                                                                     params[
                                                                                                         'servicename'],
                                                                                                     params['comment'],
                                                                                                     tmp_protocol,
                                                                                                     params['port1']))
                if params['servicetype'].lower() in ['2', 'service-group', 'servicegroup', 'group']:
                    cmds.append(
                        '{}set {}service-group {}'.format(prefix, cmd_base, params['servicename'], params['comment']))
                    for member in params[
                        'members']:  ## one member is added at a time intentionally -- unsure what would happen if all were to be added at once and one address was bad
                        cmds.append(
                            '{}set {}service-group {} members "{}"'.format(prefix, cmd_base, params['servicename'],
                                                                           member))
                for cmd in cmds:
                    self.log(cmd)

                return True
            else:
                return 'Unsupported syntax type: {} specified for Palo/Pano config'.format(syntax)
        return result

    def create_rule_obj(self, target, session, apikey, fw_type, syntax, params, sw_objects=None):
        result = False
        if 'comment' in params and fw_type.lower() in ['palo', 'pano', 'paloalto'] and syntax.lower() in ['webui',
                                                                                                          'api']:
            params['comment'] = escape(params['comment'])

        if syntax.lower() == 'cli':
            result = True
            if 'prefix' in params:
                prefix = params['prefix']
            else:
                prefix = '{}CLI:'.format(fw_type.upper())
        if fw_type == 'sonicwall':
            if syntax.lower() == 'cli':
                if params['polaction'] in ['1', 'drop', 'discard']:
                    action = 'discard'
                elif params['polaction'] in ['2', 'allow', 'pass', 'accept']:
                    action = 'allow'
                elif params['polaction'] in ['0', 'deny']:
                    action = 'deny'
                self.log(
                    '{}access-rule from "{srczone}" to "{dstzone}" action "{action}" source address name {source} service {service} destination address name {destination}'.format(
                        prefix, srczone=params['srczones'][0], dstzone=params['dstzones'][0], action=action,
                        source=params['sources'][0], destination=params['dests'][0], service=params['services'][0]))
            elif syntax.lower() in ['webui', 'api']:
                if params['services'][0].lower() == 'any':
                    service = ''
                else:
                    service = params['services'][0]
                if params['srczones'][0].lower() == 'any':
                    srczone = ''
                else:
                    srczone = params['srczones'][0]
                if params['dstzones'][0].lower() == 'any':
                    dstzone = ''
                else:
                    dstzone = params['dstzones'][0]
                if params['sources'][0].lower() == 'any':
                    source = ''
                else:
                    source = params['sources'][0]
                if params['dests'][0].lower() == 'any':
                    dest = ''
                else:
                    dest = params['dests'][0]

                postdata = {'policyAction_-1': params['polaction'],
                            'policyEnabled_-1': '1',
                            'policySrcIf_-1': '4294967295',
                            'policyDstIf_-1': '4294967295',
                            'policySrcSvc_-1': '',
                            'policyDstSvc_-1': service,
                            'policySrcZone_-1': srczone,
                            'policyDstZone_-1': dstzone,
                            'policySrcNet_-1': source,
                            'policyDstNet_-1': dest,
                            'policyTime_-1': '',
                            'policyConnPercent_-1': '100',
                            'policyConnLmtSrcEnb_-1': '0',
                            'policyConnLmtDstEnb_-1': '0',
                            'policyConnLmtSrcThrhld_-1': '128',
                            'policyConnLmtDstThrhld_-1': '128',
                            'policyQosDscpAction_-1': '0',
                            'policyQosDscpTagValue_-1': '0',
                            'policyQosDscp8021pOverride_-1': '0',
                            'policyQos8021pAction_-1': '0',
                            'policyQos8021pTagValue_-1': '0',
                            'policyDefaultRule_-1': '1',
                            'policyInactivity_-1': '15',
                            'policyInactivityUdp_-1': '30',
                            'policyFrag_-1': '1',
                            'policyNetflow_-1': '0',
                            'policyGeoIpBlock_-1': '0',
                            'policyBotnetBlock_-1': '0',
                            'policyPktCap_-1': '0',
                            'policyNoSSO_-1': '0',
                            'policyNoSSOTrafficBlk_-1': '0',
                            'policyWhom_-1': '0',
                            'policyWhomExcl_-1': '0',
                            'policyComment_-1': params['comment'],
                            'policyLog_-1': '1',
                            'policyPriType_-1': '0',
                            'policyProps_-1': '0',
                            'policyManagement_-1': '0',
                            'policyBypassDpi_-1': '0',
                            'policyBwEnabled_-1': '0',
                            'policyBwPri_-1': '0',
                            'policyIbwEnabled_-1': '0',
                            'policyIbwPri_-1': '0',
                            'policyBwmDirectStyle_-1': '0',
                            'policyBwmEgrsEnable_-1': '0',
                            'policyBwmEgrsObj_-1': '',
                            'policyBwmIgrsEnable_-1': '0',
                            'policyBwmIgrsObj_-1': '',
                            'policyBwmTrackBw_-1': '0'
                            }
                url = 'https://' + target + '/main.cgi'
                result = self.sw.send_sw_webcmd(session, url, postdata)
            else:
                return 'Unknown syntax "{}" specified for Sonicwall'.format(syntax)

        elif fw_type == 'sw65':
            if syntax.lower() == 'api':
                post_data = {'access_rule': {'ipv4': {
                    # 'comment': '',
                    # 'connection_limit': {'source': {}, 'destination': {}},
                    # 'users': {'included': {'all': True}, 'excluded': {'none': True}},
                    # 'logging': True,
                    # 'botnet_filter': False,
                    # 'udp': {'timeout': 30},
                    'to': 'LAN',
                    # 'h323': False,
                    'destination': {},
                    # 'uuid': 'b768308a-ff0f-9898-0700-c0eae4904a98',
                    # 'priority': {'manual': 1},
                    # 'sip': False,
                    # 'tcp': {'urgent': False, 'timeout': 15},
                    # 'geo_ip_filter': False,
                    # 'schedule': {'always_on': True},
                    # 'max_connections': 100,
                    'action': 'drop',
                    # 'dpi': True,
                    # 'packet_monitoring': False,
                    # 'management': True,
                    # 'flow_reporting': False,
                    'name': '',
                    # 'quality_of_service': {'dscp': {'preserve': True}, 'class_of_service': {}},
                    # 'fragments': True,
                    'from': 'LAN',
                    'enable': False,
                    'source': {},
                    # 'port': {'any': True}},
                    # 'service': {'any': True},
                    # 'dpi_ssl': {'server': True, 'client': True}
                }}}
                post_data['access_rule']['ipv4']['name'] = params['rulename']

                if params['polaction'].lower() in ['1', 'drop', 'discard']:
                    post_data['access_rule']['ipv4']['action'] = 'discard'
                elif params['polaction'].lower() in ['2', 'allow', 'pass', 'accept']:
                    post_data['access_rule']['ipv4']['action'] = 'allow'
                elif params['polaction'].lower() in ['0', 'deny']:
                    post_data['access_rule']['ipv4']['action'] = 'deny'

                if params['enabled'].lower() in ['1', 'enable', 'enabled', True]:
                    post_data['access_rule']['ipv4']['enable'] = True

                # log (params['services'])

                if params['services'][0].lower() in ['any', ['any']]:
                    post_data['access_rule']['ipv4']['service'] = {'any': True}
                elif params['services'][0] in sw_objects['service_objects']:
                    post_data['access_rule']['ipv4']['service'] = {'name': params['services'][0]}
                elif params['services'][0] in sw_objects['service_groups']:
                    post_data['access_rule']['ipv4']['service'] = {'group': params['services'][0]}

                else:
                    return (False, 'Bad Service specified')

                # self.log(post_data['access_rule']['ipv4']['service'])

                if params['srczones'][0].lower() in ['any', ['any']]:
                    post_data['access_rule']['ipv4']['from'] = 'any'  # {'any': True}
                else:
                    post_data['access_rule']['ipv4']['from'] = params['srczones'][0]

                if params['dstzones'][0].lower() in ['any', ['any']]:
                    post_data['access_rule']['ipv4']['to'] = 'any'  # {'any': True}
                else:
                    post_data['access_rule']['ipv4']['to'] = params['dstzones'][0]

                if params['sources'][0].lower() in ['any', ['any']]:
                    post_data['access_rule']['ipv4']['source'] = {'address': {'any': True}}
                elif params['sources'][0] in sw_objects['address_objects']['ipv4']:
                    post_data['access_rule']['ipv4']['source']['address'] = {'name': params['sources'][0]}
                elif params['sources'][0] in sw_objects['address_objects']['fqdn']:
                    post_data['access_rule']['ipv4']['source']['address'] = {'fqdn': params['sources'][0]}
                elif params['sources'][0] in sw_objects['address_groups']['ipv4']:
                    post_data['access_rule']['ipv4']['source']['address'] = {'group': params['sources'][0]}

                else:
                    return (False, 'Bad Source(s) specified : {}'.format(params['sources'][0]))

                # 'destination': {'address': {'group': 'All Interface IPv6 Addresses'}}
                # 'destination': {'group': 'test_group'}
                if params['dests'][0].lower() in ['any', ['any']]:
                    post_data['access_rule']['ipv4']['destination'] = {'address': {'any': True}}
                elif params['dests'][0] in sw_objects['address_objects']['ipv4']:
                    post_data['access_rule']['ipv4']['destination']['address'] = {'name': params['dests'][0]}
                elif params['dests'][0] in sw_objects['address_objects']['fqdn']:
                    post_data['access_rule']['ipv4']['destination']['address'] = {'fqdn': params['dests'][0]}
                elif params['dests'][0] in sw_objects['address_groups']['ipv4']:
                    post_data['access_rule']['ipv4']['destination']['address'] = {'group': params['dests'][0]}
                elif params['dests'][0] in sw_objects['address_groups']['ipv6']:
                    post_data['access_rule']['ipv4']['destination']['address'] = {'group': params['dests'][0]}
                else:
                    self.log(sw_objects['address_objects']['fqdn'])
                    return (False, 'Bad Destination(s) specified')

                if 'comment' in params:
                    post_data['access_rule']['ipv4']['comment'] = params['comment']
                url = 'https://{}/api/sonicos/access-rules/ipv4'.format(target)
                self.debug(post_data)
                result = session.post(url=url, json=post_data)
                self.debug(result.text)
                if not json.loads(result.text)['status']['success']:
                    result = False, json.loads(result.text)['status']['info'][0]['message']
                else:
                    result = True

        elif fw_type == 'checkpoint':

            import copy

            if syntax.lower() == 'cli':
                lastindex = None
                for context in self.contexts:
                    if self.config[context]['config']['fw_type'] == 'checkpoint':
                        if params['policyname'] in self.config[context]['config']['policylen']:
                            lastindex = copy.deepcopy(self.config[context]['config']['policylen'][params['policyname']])
                            self.config[context]['config']['policylen'][params['policyname']] = \
                                self.config[context]['config']['policylen'][params['policyname']] + 1
                            self.debug('lastindex', lastindex)
                            break
                        else:
                            self.debug('Policy not found')
                            return False
                if lastindex:
                    self.log('{}addelement fw_policies {} rule security_rule'.format(prefix, params['policyname']))
                    if 'comment' not in params: params['comment'] = ''
                    self.log(
                        '{}modify fw_policies {} rule:{}:comments "{}"'.format(prefix, params['policyname'], lastindex,
                                                                               params['comment']))
                    if 'disabled' in params:
                        disabled = 'true'
                    else:
                        disabled = 'false'
                    self.log(
                        '{}modify fw_policies {} rule:{}:disabled {}'.format(prefix, params['policyname'], lastindex,
                                                                             disabled))
                    if params['polaction'].lower() in ['allow', 'pass', 'accept', '2']:
                        polaction = 'accept_action:accept'
                    elif params['polaction'].lower() in ['deny', '0']:
                        polaction = 'drop_action:deny'
                    elif params['polaction'].lower() in ['drop', 'discard', '1']:
                        polaction = 'drop_action:drop'
                    self.log(
                        '{}addelement fw_policies {} rule:{}:action {}'.format(prefix, params['policyname'], lastindex,
                                                                               polaction))
                    for member in params['sources']:
                        if member.lower() == 'any':
                            table = 'globals'
                            member = 'Any'
                        else:
                            table = 'network_objects'
                        self.log("{}addelement fw_policies {} rule:{}:src:'' {}:{}".format(prefix, params['policyname'],
                                                                                           lastindex, table, member))
                    for member in params['dests']:
                        if member.lower() == 'any':
                            table = 'globals'
                            member = 'Any'
                        else:
                            table = 'network_objects'
                        self.log("{}addelement fw_policies {} rule:{}:dst:'' {}:{}".format(prefix, params['policyname'],
                                                                                           lastindex, table, member))
                    for member in params['services']:
                        if member.lower() == 'any':
                            table = 'globals'
                            member = 'Any'
                        else:
                            table = 'services'
                        self.log(
                            "{}addelement fw_policies {} rule:{}:services:'' {}:{}".format(prefix, params['policyname'],
                                                                                           lastindex, table, member))
                else:
                    self.debug('No checkpoint configuration found')
                    return False
        elif fw_type in ['palo', 'pano', 'paloalto']:
            if syntax.lower() in ['webui', 'api']:
                if fw_type in ['palo', 'paloalto']:
                    object_base = "/config/devices/entry[@name='localhost.localdomain']/vsys/entry[@name='vsys1']/rulebase/security/rules"
                elif fw_type == 'pano':
                    if params['context'] == 'shared':
                        object_base = "/config/shared/pre-rulebase/security/rules"
                    else:
                        object_base = "/config/devices/entry[@name='localhost.localdomain']/device-group/entry[@name='{}']/pre-rulebase/security/rules".format(
                            params['context'])
                srczones = ''
                dstzones = ''
                srcaddr = ''
                dstaddr = ''
                services = ''
                tags = ''
                disabled = 'no'
                description = ''
                action = 'drop'
                applications = ''
                negate_source = 'no'
                negate_destination = 'no'
                profile_setting = ''  ## this has to be set with keyword included
                log_setting = ''  ## this has to be set with keyword included
                log_start = 'no'
                log_end = 'yes'
                if 'srczones' in params:
                    for member in params['srczones']:
                        if member.lower() == 'any':
                            srczones += '<member>any</member>'
                            break
                        else:
                            srczones += '<member>{}</member>'.format(member)
                if 'dstzones' in params:
                    for member in params['dstzones']:
                        if member.lower() == 'any':
                            dstzones += '<member>any</member>'
                            break
                        else:
                            dstzones += '<member>{}</member>'.format(member)
                if 'sources' in params:
                    for member in params['sources']:
                        if member.lower() == 'any':
                            srcaddr += '<member>any</member>'
                            break
                        else:
                            srcaddr += '<member>{}</member>'.format(member)
                if 'dests' in params:
                    for member in params['dests']:
                        if member.lower() == 'any':
                            dstaddr += '<member>any</member>'
                            break
                        else:
                            dstaddr += '<member>{}</member>'.format(member)
                if 'services' in params:
                    for member in params['services']:
                        if member.lower() == 'any':
                            services += '<member>any</member>'
                            break
                        else:
                            services += '<member>{}</member>'.format(member)
                if 'tags' in params:
                    for member in params['tags']:
                        tags += '<member>{}</member>'.format(member)
                if 'applications' in params:
                    for member in params['applications']:
                        if member.lower() == 'any':
                            applications += '<member>any</member>'
                            break
                        else:
                            applications += '<member>{}</member>'.format(member)
                if 'comment' in params:
                    description = params['comment']
                elif 'description' in params:
                    description = params['description']

                if 'polaction' in params:
                    if params['polaction'].lower() in ['allow', 'deny', 'drop', 'reset-both', 'reset-client',
                                                       'reset-server']:
                        action = params['polaction'].lower()
                    elif params['polaction'].lower() in ['deny', '0']:
                        action = 'deny'
                    elif params['polaction'].lower() in ['drop', 'discard', '1']:
                        action = 'drop'
                    elif params['polaction'].lower() in ['allow', 'pass', 'accept', '2']:
                        action = 'allow'

                if 'log_end' in params:
                    if str(params['log_end']).lower() in ['', 'true', 'yes', 'on', 'enabled', 'enable']:
                        log_end = 'yes'
                    else:
                        log_end = 'no'
                if 'log_start' in params:
                    if str(params['log_start']).lower() in ['', 'true', 'yes', 'on', 'enabled', 'enable']:
                        log_start = 'yes'
                    else:
                        log_start = 'no'
                if 'negate_source' in params:
                    if str(params['negate_source']).lower() in ['', 'true', 'yes', 'on', 'enabled', 'enable']:
                        negate_source = 'yes'
                    else:
                        negate_source = 'no'
                if 'negate_destination' in params:
                    if str(params['negate_destination']).lower() in ['', 'true', 'yes', 'on', 'enabled', 'enable']:
                        negate_destination = 'yes'
                    else:
                        negate_destination = 'no'

                if 'disabled' in params:
                    if str(params['disabled']).lower() in ['', 'true', 'yes', 'on', 'enabled', 'enable']:
                        disabled = 'yes'
                    else:
                        disabled = 'no'
                if 'enabled' in params:
                    if str(params['enabled']).lower() in ['', 'true', 'yes', 'on', 'enabled', 'enable']:
                        disabled = 'no'
                    else:
                        disabled = 'yes'
                if 'profile_setting' in params:
                    profile_setting = ' profile-setting {}'.format(params['profile-setting'])
                if 'log_setting' in params:
                    profile_setting = ' log-setting {}'.format(params['log-setting'])

                url = '/api/?type=config&action=set&xpath={}&element=<entry name=\'{}\'><source>{}</source><destination>{}</destination><service>{}</service><application>{}</application><action>{}</action><log-end>{}</log-end><log-start>{}</log-start><from>{}</from><to>{}</to><disabled>{}</disabled><description>{}</description></entry>'.format(
                    object_base, params['rulename'], srcaddr, dstaddr, services, applications, action, log_end,
                    log_start,
                    srczones, dstzones, disabled, description)
                # url='/api/?type=config&action=set&xpath={}&element=<entry name=\'{}\'><source>{}</source><destination>{}</destination><service>{}</service><application>{}</application><action>{}</action><log-end>{}</log-end><log-start>{}</log-start><from>{}</from><to>{}</to></entry>'.format(object_base, params['rulename'], srcaddr, dstaddr, services, applications, action, log_end, log_start, srczones, dstzones)
                result = self.getPaloService.send_palo_apicmd(session, target, url, apikey)

            elif syntax.lower() == 'cli':
                if fw_type.lower() in ['palo', 'paloalto']:
                    cmd_base = 'rulebase'
                elif fw_type.lower() == 'pano':
                    if params['context'] == 'shared':
                        cmd_base = 'shared pre-rulebase'
                    else:
                        cmd_base = 'device-group "{}" pre-rulebase'.format(params['context'])
                ## set default values
                srczones = '['
                dstzones = '['
                srcaddr = '['
                dstaddr = '['
                services = '['
                tags = '['
                disabled = 'no'
                description = ''
                action = 'drop'
                applications = '[ any'
                negate_source = 'no'
                negate_destination = 'no'
                profile_setting = ''  ## this has to be set with keyword included
                log_setting = ''  ## this has to be set with keyword included
                log_start = 'no'
                log_end = 'yes'

                if 'srczones' in params:
                    for member in params['srczones']:
                        if member.lower() == 'any':
                            srczones += ' any'
                            break
                        else:
                            srczones += ' {}'.format(member)
                srczones += ' ]'
                if 'dstzones' in params:
                    for member in params['dstzones']:
                        if member.lower() == 'any':
                            dstzones += ' any'
                            break
                        else:
                            dstzones += ' {}'.format(member)
                dstzones += ' ]'

                if 'sources' in params:
                    for member in params['sources']:
                        if member.lower() == 'any':
                            srcaddr += ' any'
                            break
                        else:
                            srcaddr += ' {}'.format(member)
                srcaddr += ' ]'
                if 'dests' in params:
                    for member in params['dests']:
                        if member.lower() == 'any':
                            dstaddr += ' any'
                            break
                        else:
                            dstaddr += ' {}'.format(member)
                dstaddr += ' ]'
                if 'services' in params:
                    for member in params['services']:
                        if member.lower() == 'any':
                            services += ' any'
                            break
                        else:
                            services += ' {}'.format(member)
                services += ' ]'
                if 'tags' in params:
                    for member in params['tags']:
                        if member.lower() == 'any':
                            tags += ' any'
                            break
                        else:
                            tags += ' {}'.format(member)
                tags += ' ]'
                if 'applications' in params:
                    applications = '['
                    for member in params['applications']:
                        if member.lower() == 'any':
                            applications += ' any'
                            break
                        else:
                            applications += ' {}'.format(member)
                applications += ' ]'
                if 'polaction' in params:
                    if params['polaction'].lower() in ['allow', 'deny', 'drop', 'reset-both', 'reset-client',
                                                       'reset-server']:
                        action = params['polaction'].lower()
                    elif params['polaction'].lower() in ['deny', '0']:
                        action = 'deny'
                    elif params['polaction'].lower() in ['drop', 'discard', '1']:
                        action = 'drop'
                    elif params['polaction'].lower() in ['allow', 'pass', 'accept', '2']:
                        action = 'allow'

                if 'log_end' in params:
                    if str(params['log_end']).lower() in ['', 'true', 'yes', 'on', 'enabled', 'enable']:
                        log_end = 'yes'
                    else:
                        log_end = 'no'
                if 'log_start' in params:
                    if str(params['log_start']).lower() in ['', 'true', 'yes', 'on', 'enabled', 'enable']:
                        log_start = 'yes'
                    else:
                        log_start = 'no'
                if 'negate_source' in params:
                    if str(params['negate_source']).lower() in ['', 'true', 'yes', 'on', 'enabled', 'enable']:
                        negate_source = 'yes'
                    else:
                        negate_source = 'no'
                if 'negate_destination' in params:
                    if str(params['negate_destination']).lower() in ['', 'true', 'yes', 'on', 'enabled', 'enable']:
                        negate_destination = 'yes'
                    else:
                        negate_destination = 'no'

                if 'disabled' in params:
                    if str(params['disabled']).lower() in ['', 'true', 'yes', 'on', 'enabled', 'enable']:
                        disabled = 'yes'
                    else:
                        disabled = 'no'
                if 'enabled' in params:
                    if str(params['enabled']).lower() in ['', 'true', 'yes', 'on', 'enabled', 'enable']:
                        disabled = 'no'
                    else:
                        disabled = 'yes'
                if 'profile_setting' in params:
                    profile_setting = ' profile-setting {}'.format(params['profile-setting'])
                if 'log_setting' in params:
                    profile_setting = ' log-setting {}'.format(params['log-setting'])

                cmd = '{}set {} security rules "{}" from {} to {} action {} source {} destination {} log-end {} log-start {} service {} application {} tag {} description "{}" disabled {} negate-source {} negate-destination {} {} {}'.format(
                    prefix, cmd_base, params['rulename'], srczones, dstzones, action, srcaddr, dstaddr, log_end,
                    log_start,
                    services, applications, tags, description, disabled, negate_source, negate_destination, log_setting,
                    profile_setting)
                self.log(cmd)
        return result
