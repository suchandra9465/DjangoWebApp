import ipaddress
import ipaddress
import xml.etree.ElementTree as et
from collections import OrderedDict

import urllib3
import xmltodict
from netaddr import IPSet

from ... import NetworkLogs


class LoadService:

    def _init_(self, options):
        self.log = NetworkLogs().log
        self.sc = NetworkLogs().sc
        self.ss = NetworkLogs().ss
        self.debug = NetworkLogs().debug
        self.options = options

    def load_checkpoint_api(self, mgmt_ip, context, username, password):

        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

        def get_all_objects(ip_addr, sid, item, obj_property='objects', params=None):

            limit = 30
            start_offset = 0
            all_items = []
            num_returned = -1
            while num_returned != 0:
                if item == 'show-access-rulebase':
                    get_items_result = self.service.ckpt_api_call(ip_addr, 443, item,
                                                                  {"limit": limit, "offset": start_offset,
                                                                   "details-level": "full",
                                                                   "name": params, "use-object-dictionary": False}, sid)
                if item == 'show-nat-rulebase':
                    get_items_result = self.service.ckpt_api_call(ip_addr, 443, item,
                                                                  {"limit": limit, "offset": start_offset,
                                                                   "details-level": "full",
                                                                   "package": params, "use-object-dictionary": False},
                                                                  sid)
                elif item == 'show-groups':
                    get_items_result = self.service.ckpt_api_call(ip_addr, 443, item,
                                                                  {"limit": limit, "offset": start_offset,
                                                                   "details-level": "full",
                                                                   'dereference-group-members': False,
                                                                   "show-membership": False},
                                                                  sid)
                elif item == 'show-object':
                    get_items_result = self.service.ckpt_api_call(ip_addr, 443, item,
                                                                  {"uid": params, "details-level": "full"}, sid)
                else:
                    get_items_result = self.service.ckpt_api_call(ip_addr, 443, item,
                                                                  {"limit": limit, "offset": start_offset,
                                                                   "details-level": "full"},
                                                                  sid)
                if obj_property in get_items_result:
                    if item == 'show-object':
                        all_items = get_items_result[obj_property]
                        num_returned = 0
                    else:
                        all_items.extend(get_items_result[obj_property])
                        num_returned = len(get_items_result[obj_property])
                else:
                    num_returned = 0
                start_offset += limit
            return all_items

        sid, uid, message = self.service.ckpt_login(mgmt_ip, context, username, password)

        if sid:
            self.debug("session id: " + sid)

            return_config = OrderedDict()
            return_config['config'] = OrderedDict()
            return_config['config']['policylen'] = {}

            return_addresses = OrderedDict()
            return_services = OrderedDict()
            return_service = OrderedDict()
            return_policy = OrderedDict()
            return_nat = OrderedDict()
            return_address = OrderedDict()
            addr_mappings = OrderedDict()
            svc_mappings = OrderedDict()
            uid_mappings = OrderedDict()

            self.log('!-- Retreiving Checkpoint Config via API')
            objects = get_all_objects(mgmt_ip, sid, 'show-gateways-and-servers')
            self.log('!-- Retreived Gateways and Servers objects : ', len(objects))
            for address in objects:
                return_address = OrderedDict()
                return_address['addrObjId'] = address['name']
                return_address['addrObjDisp'] = address['name']
                return_address['addrObjType'] = '1'
                return_address['addrObjZone'] = ''
                return_address['addrObjProperties'] = ''
                return_address['addrObjIp1'] = address['ipv4-address']
                return_address['addrObjIp2'] = '255.255.255.255'
                return_address['addrObjComment'] = address['comments']
                return_address['addrObjColor'] = address['color']
                return_address['addrObjUid'] = address['uid']
                return_address['IPv4Networks'] = [ipaddress.IPv4Network(address['ipv4-address'] + '/32', strict=False)]
                return_addresses[return_address['addrObjId']] = return_address
                uid_mappings[address['uid']] = address['name']

            objects = get_all_objects(mgmt_ip, sid, 'show-simple-gateways')
            self.log('!-- Retreived Simple Gateways objects : ', len(objects))
            for address in objects:
                return_address = OrderedDict()
                return_address['addrObjId'] = address['name']
                return_address['addrObjDisp'] = address['name']
                return_address['addrObjType'] = '1'
                return_address['addrObjZone'] = ''
                return_address['addrObjProperties'] = ''
                return_address['addrObjIp1'] = address['ipv4-address']
                return_address['addrObjIp2'] = '255.255.255.255'
                return_address['addrObjComment'] = address['comments']
                return_address['addrObjColor'] = address['color']
                return_address['addrObjUid'] = address['uid']
                return_address['IPv4Networks'] = [ipaddress.IPv4Network(address['ipv4-address'] + '/32', strict=False)]
                return_addresses[return_address['addrObjId']] = return_address
                uid_mappings[address['uid']] = address['name']

            objects = get_all_objects(mgmt_ip, sid, 'show-hosts')
            self.log('!-- Retreived Hosts objects : ', len(objects))
            for address in objects:
                return_address = OrderedDict()
                return_address['addrObjId'] = address['name']
                return_address['addrObjDisp'] = address['name']
                if 'ipv4-address' in address:
                    return_address['addrObjType'] = '1'
                    return_address['addrObjIp1'] = address['ipv4-address']
                    return_address['IPv4Networks'] = [
                        ipaddress.IPv4Network(address['ipv4-address'] + '/32', strict=False)]
                    return_address['addrObjIp2'] = '255.255.255.255'
                elif 'ipv6-address' in address:
                    return_address['addrObjType'] = '6'
                    return_address['addrObjIp1'] = address['ipv6-address']

                return_address['addrObjZone'] = ''
                return_address['addrObjProperties'] = ''
                return_address['addrObjComment'] = address['comments']
                return_address['addrObjColor'] = address['color']
                return_address['addrObjUid'] = address['uid']
                return_addresses[return_address['addrObjId']] = return_address
                uid_mappings[address['uid']] = address['name']

            objects = get_all_objects(mgmt_ip, sid, 'show-networks')
            self.log('!-- Retreived Networks objects : ', len(objects))
            for address in objects:
                if 'subnet4' in address or 'subnet6' in address:
                    return_address = OrderedDict()
                    return_address['addrObjId'] = address['name']
                    return_address['addrObjDisp'] = address['name']
                    if 'subnet4' in address:
                        return_address['addrObjType'] = '4'
                        return_address['addrObjIp1'] = address['subnet4']
                        return_address['addrObjIp2'] = address['subnet-mask']
                        return_address['IPv4Networks'] = [ipaddress.IPv4Network(
                            return_address['addrObjIp1'] + '/' + str(
                                self.service.netmask_to_cidr(return_address['addrObjIp2'])),
                            strict=False)]
                    elif 'subnet6' in address:
                        return_address['addrObjType'] = '7'
                        return_address['addrObjIp1'] = address['subnet6']
                        return_address['addrObjIp2'] = address['mask-length6']
                    return_address['addrObjZone'] = ''
                    return_address['addrObjProperties'] = ''
                    return_address['addrObjComment'] = address['comments']
                    return_address['addrObjColor'] = address['color']
                    return_address['addrObjUid'] = address['uid']
                    return_addresses[return_address['addrObjId']] = return_address
                    uid_mappings[address['uid']] = address['name']

            objects = get_all_objects(mgmt_ip, sid, 'show-address-ranges')
            self.log('!-- Retreived Address Ranges objects : ', len(objects))
            for address in objects:
                if 'ipv4-address-first' in address:
                    return_address = OrderedDict()
                    return_address['addrObjId'] = address['name']
                    return_address['addrObjDisp'] = address['name']
                    return_address['addrObjType'] = '2'
                    return_address['addrObjZone'] = ''
                    return_address['addrObjProperties'] = ''
                    return_address['addrObjIp1'] = address['ipv4-address-first']
                    return_address['addrObjIp2'] = address['ipv4-address-last']
                    return_address['addrObjComment'] = address['comments']
                    return_address['addrObjColor'] = address['color']
                    return_address['addrObjUid'] = address['uid']
                    return_address['IPv4Networks'] = [ipaddr for ipaddr in ipaddress.summarize_address_range(
                        ipaddress.IPv4Address(return_address['addrObjIp1']),
                        ipaddress.IPv4Address(return_address['addrObjIp2']))]
                    return_addresses[return_address['addrObjId']] = return_address
                    uid_mappings[address['uid']] = address['name']

            objects = get_all_objects(mgmt_ip, sid, 'show-groups')
            self.log('!-- Retreived Address Groups objects : ', len(objects))
            for address in objects:
                return_address = OrderedDict()
                return_address['addrObjId'] = address['name']
                return_address['addrObjDisp'] = address['name']
                return_address['addrObjType'] = '8'
                return_address['addrObjZone'] = ''
                return_address['addrObjProperties'] = ''
                return_address['addrObjIp1'] = ''
                return_address['addrObjIp2'] = ''
                return_address['addrObjComment'] = address['comments']
                return_address['addrObjColor'] = address['color']
                return_address['addrObjUid'] = address['uid']
                return_address['addrObjMembers'] = address['members']
                return_addresses[return_address['addrObjId']] = return_address
                uid_mappings[address['uid']] = address['name']

            objects = get_all_objects(mgmt_ip, sid, 'show-groups-with-exclusion')
            self.log('!-- Retreived Groups with exclusions objects : ', len(objects))
            for address in objects:
                return_address = OrderedDict()
                return_address['addrObjId'] = address['name']
                return_address['addrObjDisp'] = address['name']
                return_address['addrObjType'] = '8'
                return_address['addrObjZone'] = ''
                return_address['addrObjProperties'] = ''
                return_address['addrObjIp1'] = ''
                return_address['addrObjIp2'] = ''
                return_address['addrObjComment'] = address['comments']
                return_address['addrObjColor'] = address['color']
                return_address['addrObjUid'] = address['uid']
                return_address['addrObjMembers'] = address['include']
                return_address['addrObjMembers'] = []
                return_address['addrObjExclude'] = address['except']
                return_addresses[return_address['addrObjId']] = return_address
                uid_mappings[address['uid']] = address['name']

            tmp_addresses = OrderedDict()
            for address in return_addresses:
                if return_addresses[address]['addrObjType'] == '8':
                    for member in return_addresses[address]['addrObjMembers']:
                        if member in uid_mappings:
                            if return_addresses[address]['addrObjId'] not in addr_mappings:
                                addr_mappings[return_addresses[address]['addrObjId']] = []
                            addr_mappings[return_addresses[address]['addrObjId']].append(uid_mappings[member])
                        else:  # look up mappings for unknown objects

                            tmp_object = get_all_objects(mgmt_ip, sid, 'show-object', 'object', member)
                            uid_mappings[member] = tmp_object['name']
                            self.debug('uid', member)
                            self.debug('address', address)
                            self.debug('addr_mapping', return_addresses[address]['addrObjId'])
                            self.debug('-' * 180)
                            if return_addresses[address]['addrObjId'] not in addr_mappings:
                                addr_mappings[return_addresses[address]['addrObjId']] = []
                            addr_mappings[return_addresses[address]['addrObjId']].append(uid_mappings[member])
                            if tmp_object['type'] == 'CpmiGatewayPlain':
                                return_address = OrderedDict()
                                return_address['addrObjId'] = tmp_object['name']
                                return_address['addrObjDisp'] = tmp_object['name']
                                return_address['addrObjType'] = '1'
                                return_address['addrObjZone'] = ''
                                return_address['addrObjProperties'] = ''
                                return_address['addrObjIp1'] = tmp_object['ipv4-address']
                                return_address['addrObjIp2'] = ''
                                return_address['addrObjComment'] = tmp_object['comments']
                                return_address['addrObjColor'] = tmp_object['color']
                                return_address['addrObjUid'] = tmp_object['uid']
                                # return_address['addrObjMembers']=tmp_object['include']
                                # eturn_address['addrObjMembers']=[]
                                # return_address['addrObjExclude']=address['except']
                                tmp_addresses[return_address['addrObjId']] = return_address
                            else:
                                self.debug(
                                    '{} not in address dictionary - type : {} '.format(member, tmp_object['type']))
            return_addresses.update(tmp_addresses)

            objects = get_all_objects(mgmt_ip, sid, 'show-services-tcp')
            self.log('!-- Retreived TCP Services objects : ', len(objects))
            for service in objects:
                return_service = OrderedDict()
                return_service['svcObjId'] = service['name']
                return_service['svcObjType'] = '1'
                return_service['svcObjProperties'] = ''
                return_service['svcObjIpType'] = '6'
                return_service['svcObjPort1'] = service['port']
                return_service['svcObjPort2'] = service['port']
                return_service['svcObjManagement'] = ''
                return_service['svcObjHigherPrecedence'] = ''
                return_service['svcObjComment'] = service['comments']
                return_service['svcObjSrcPort'] = '0'
                if 'color' in service:
                    return_service['svcObjColor'] = service['color']
                else:
                    return_service['svcObjColor'] = 'black'  # set default color to black if none is set
                return_address['svcObjUid'] = service['uid']
                return_services[return_service['svcObjId']] = return_service
                uid_mappings[service['uid']] = service['name']

            objects = get_all_objects(mgmt_ip, sid, 'show-services-udp')
            self.log('!-- Retreived UDP Services objects : ', len(objects))
            for service in objects:
                try:
                    return_service = OrderedDict()
                    return_service['svcObjId'] = service['name']
                    return_service['svcObjType'] = '1'
                    return_service['svcObjProperties'] = ''
                    return_service['svcObjIpType'] = '17'
                    return_service['svcObjPort1'] = service['port']
                    return_service['svcObjPort2'] = service['port']
                    return_service['svcObjManagement'] = ''
                    return_service['svcObjHigherPrecedence'] = ''
                    return_service['svcObjComment'] = service['comments']
                    if 'color' in service:
                        return_service['svcObjColor'] = service['color']
                    else:
                        return_service['svcObjColor'] = 'black'  # set default color to black if none is set
                    return_address['svcObjUid'] = service['uid']
                    return_services[return_service['svcObjId']] = return_service
                    uid_mappings[service['uid']] = service['name']
                except:
                    self.debug(service)
                    exit(1)

            objects = get_all_objects(mgmt_ip, sid, 'show-services-icmp')
            self.log('!-- Retreived ICMP Services objects : ', len(objects))
            for service in objects:
                try:
                    return_service = OrderedDict()
                    return_service['svcObjId'] = service['name']
                    return_service['svcObjType'] = '1'
                    return_service['svcObjProperties'] = ''
                    return_service['svcObjIpType'] = '1'
                    return_service['svcObjPort1'] = service['icmp-type']
                    return_service['svcObjPort2'] = ''
                    return_service['svcObjManagement'] = ''
                    return_service['svcObjHigherPrecedence'] = ''
                    return_service['svcObjComment'] = service['comments']
                    if 'color' in service:
                        return_service['svcObjColor'] = service['color']
                    else:
                        return_service['svcObjColor'] = 'black'  # set default color to black if none is set
                    return_address['svcObjUid'] = service['uid']
                    return_services[return_service['svcObjId']] = return_service
                    uid_mappings[service['uid']] = service['name']
                except:
                    self.debug(service)
                    exit(1)

            objects = get_all_objects(mgmt_ip, sid, 'show-services-dce-rpc')
            self.log('!-- Retreived DCE-RPC Services objects : ', len(objects))
            for service in objects:
                try:
                    return_service = OrderedDict()
                    return_service['svcObjId'] = service['name']
                    return_service['svcObjType'] = '1'
                    return_service['svcObjProperties'] = ''
                    return_service['svcObjIpType'] = '80'
                    return_service['svcObjPort1'] = '0'
                    return_service['svcObjPort2'] = ''
                    return_service['svcObjManagement'] = ''
                    return_service['svcObjHigherPrecedence'] = ''
                    return_service['svcObjComment'] = service['comments']
                    if 'color' in service:
                        return_service['svcObjColor'] = service['color']
                    else:
                        return_service['svcObjColor'] = 'black'  # set default color to black if none is set
                    return_address['svcObjUid'] = service['uid']
                    return_services[return_service['svcObjId']] = return_service
                    uid_mappings[service['uid']] = service['name']
                except:
                    self.debug(service)
                    exit(1)

            objects = get_all_objects(mgmt_ip, sid, 'show-services-rpc')
            self.log('!-- Retreived RPC Services objects : ', len(objects))
            for service in objects:
                try:
                    return_service = OrderedDict()
                    return_service['svcObjId'] = service['name']
                    return_service['svcObjType'] = '1'
                    return_service['svcObjProperties'] = ''
                    return_service['svcObjIpType'] = '81'
                    return_service['svcObjPort1'] = '0'
                    return_service['svcObjPort2'] = ''
                    return_service['svcObjManagement'] = ''
                    return_service['svcObjHigherPrecedence'] = ''
                    return_service['svcObjComment'] = service['comments']
                    if 'color' in service:
                        return_service['svcObjColor'] = service['color']
                    else:
                        return_service['svcObjColor'] = 'black'  # set default color to black if none is set
                    return_address['svcObjUid'] = service['uid']
                    return_services[return_service['svcObjId']] = return_service
                    uid_mappings[service['uid']] = service['name']
                except:
                    self.debug(service)
                    exit(1)

            objects = get_all_objects(mgmt_ip, sid, 'show-services-icmp6')
            self.log('!-- Retreived ICMPv6 Services objects : ', len(objects))
            for service in objects:
                try:
                    return_service = OrderedDict()
                    return_service['svcObjId'] = service['name']
                    return_service['svcObjType'] = '1'
                    return_service['svcObjProperties'] = ''
                    return_service['svcObjIpType'] = '58'
                    return_service['svcObjPort1'] = service['icmp-type']
                    return_service['svcObjPort2'] = ''
                    return_service['svcObjManagement'] = ''
                    return_service['svcObjHigherPrecedence'] = ''
                    return_service['svcObjComment'] = service['comments']
                    if 'color' in service:
                        return_service['svcObjColor'] = service['color']
                    else:
                        return_service['svcObjColor'] = 'black'  # set default color to black if none is set
                    return_address['svcObjUid'] = service['uid']
                    return_services[return_service['svcObjId']] = return_service
                    uid_mappings[service['uid']] = service['name']
                except:
                    self.debug(service)
                    exit(1)

            objects = get_all_objects(mgmt_ip, sid, 'show-services-other')
            self.log('!-- Retreived other Services objects : ', len(objects))
            for service in objects:
                try:
                    return_service = OrderedDict()
                    return_service['svcObjId'] = service['name']
                    return_service['svcObjType'] = '1'
                    return_service['svcObjProperties'] = ''
                    return_service['svcObjIpType'] = '82'
                    return_service['svcObjPort1'] = ''
                    return_service['svcObjPort2'] = ''
                    return_service['svcObjManagement'] = ''
                    return_service['svcObjHigherPrecedence'] = ''
                    return_service['svcObjComment'] = service['comments']
                    if 'color' in service:
                        return_service['svcObjColor'] = service['color']
                    else:
                        return_service['svcObjColor'] = 'black'  # set default color to black if none is set
                    return_address['svcObjUid'] = service['uid']
                    return_services[return_service['svcObjId']] = return_service
                    uid_mappings[service['uid']] = service['name']
                except:
                    self.debug(service)
                    exit(1)

            objects = get_all_objects(mgmt_ip, sid, 'show-service-groups')
            self.log('!-- Retreived Service Groups objects : ', len(objects))
            for service in objects:
                return_service = OrderedDict()
                return_service['svcObjId'] = service['name']
                return_service['svcObjType'] = '2'
                return_service['svcObjProperties'] = ''
                return_service['svcObjIpType'] = ''
                return_service['svcObjPort1'] = ''
                return_service['svcObjPort2'] = ''
                return_service['svcObjManagement'] = ''
                return_service['svcObjHigherPrecedence'] = ''
                return_service['svcObjComment'] = service['comments']
                return_service['svcObjColor'] = service['color']
                return_address['svcObjUid'] = service['uid']
                return_service['svcObjMembers'] = service['members']
                return_services[return_service['svcObjId']] = return_service
                uid_mappings[service['uid']] = service['name']

            for service in return_services:
                if return_services[service]['svcObjType'] == '2':
                    svc_mappings[return_services[service]['svcObjId']] = []
                    for member in return_services[service]['svcObjMembers']:
                        if member in uid_mappings:
                            svc_mappings[return_services[service]['svcObjId']].append(uid_mappings[member])
                        else:  # look up mappings for unknown objects
                            tmp_object = get_all_objects(mgmt_ip, sid, 'show-object', 'object', member)
                            uid_mappings[member] = tmp_object['name']
                            svc_mappings[return_services[service]['svcObjId']].append(uid_mappings[member])
                            self.debug('{} not in service dictionary - type : {}'.format(member, tmp_object['type']))

            policies = get_all_objects(mgmt_ip, sid, 'show-packages', 'packages')
            self.log('!-- Retreived Policy Names objects : ', len(policies))

            layers = get_all_objects(mgmt_ip, sid, 'show-access-layers', 'access-layers')
            self.log('!-- Retreived Layers objects : ', len(objects))

            policy_index = 0
            self.log('!-- Retreiving Security Rules')
            for policy in policies:
                self.log('!-- Retrieving Security Policy {}'.format(policy['name']))
                rulesets = get_all_objects(mgmt_ip, sid, 'show-access-rulebase', 'rulebase',
                                           policy['name'] + ' Security')
                for ruleitem in rulesets:
                    if 'rulebase' in ruleitem:
                        for rule in ruleset['rulebase']:
                            return_policy[policy_index] = OrderedDict()
                            return_policy[policy_index]['policySrcNegate'] = False
                            return_policy[policy_index]['policyDstNegate'] = False
                            return_policy[policy_index]['policySvcNegate'] = False
                            if rule['action']['name'].lower() == 'deny':
                                return_policy[policy_index]['policyAction'] = '0'
                            elif rule['action']['name'].lower() == 'drop':
                                return_policy[policy_index]['policyAction'] = '1'
                            elif rule['action']['name'].lower() == 'accept':
                                return_policy[policy_index]['policyAction'] = '2'
                            elif rule['action']['name'].lower() == 'client auth':
                                return_policy[policy_index]['policyAction'] = '3'
                            return_policy[policy_index]['policySrcZone'] = ''
                            return_policy[policy_index]['policyDstZone'] = ''
                            return_policy[policy_index]['policySrcNegate'] = False
                            return_policy[policy_index]['policyDstNegate'] = False
                            return_policy[policy_index]['policySvcNegate'] = False
                            return_policy[policy_index]['policySrcNet'] = [x['name'] for x in rule['source']]
                            for obj in return_policy[policy_index]['policySrcNet']:
                                if obj not in return_addresses and obj.lower() != 'any':
                                    self.debug('{} not in address dictionary'.format(obj))
                                    try:
                                        userobj, addrobj = obj.split('@')
                                        self.debug('Using Address object {} instead'.format(addrobj))
                                    except:
                                        pass
                            return_policy[policy_index]['policyDstNet'] = [x['name'] for x in rule['destination']]
                            for obj in return_policy[policy_index]['policyDstNet']:
                                if obj not in return_addresses and obj.lower() != 'any':
                                    self.debug('{} not in address dictionary'.format(obj))
                                    try:
                                        userobj, addrobj = obj.split('@')
                                        self.debug('Using Address object {} instead'.format(addrobj))
                                    except:
                                        pass

                            return_policy[policy_index]['policyDstSvc'] = [x['name'] for x in rule['service']]
                            for obj in return_policy[policy_index]['policyDstSvc']:
                                if obj not in return_services and obj.lower() != 'any':
                                    self.debug('{} not in service dictionary'.format(obj))
                                    try:
                                        userobj, svcobj = obj.split('@')
                                        self.debug('Using Service object {} instead'.format(svcobj))
                                    except:
                                        pass

                            return_policy[policy_index]['policyDstApps'] = ''
                            return_policy[policy_index]['policyComment'] = rule['comments']
                            return_policy[policy_index]['policyLog'] = ''
                            if rule['enabled']:
                                return_policy[policy_index]['policyEnabled'] = '1'
                            else:
                                return_policy[policy_index]['policyEnabled'] = '0'
                            return_policy[policy_index]['policyProps'] = ''
                            return_policy[policy_index]['policyNum'] = rule['rule-number']
                            return_policy[policy_index]['policyUiNum'] = rule['rule-number']
                            return_policy[policy_index]['policyName'] = policy['name']
                            return_policy[policy_index]['policyUid'] = policy['uid']
                            policy_index += 1
                    else:
                        return_policy[policy_index] = OrderedDict()
                        if ruleitem['action']['name'].lower() == 'deny':
                            return_policy[policy_index]['policyAction'] = '0'
                        elif ruleitem['action']['name'].lower() == 'drop':
                            return_policy[policy_index]['policyAction'] = '1'
                        elif ruleitem['action']['name'].lower() == 'accept':
                            return_policy[policy_index]['policyAction'] = '2'
                        elif ruleitem['action']['name'].lower() == 'client auth':
                            return_policy[policy_index]['policyAction'] = '3'
                        return_policy[policy_index]['policySrcZone'] = ''
                        return_policy[policy_index]['policyDstZone'] = ''
                        return_policy[policy_index]['policySrcNet'] = [x['name'] for x in ruleitem['source']]
                        for obj in return_policy[policy_index]['policySrcNet']:
                            if obj not in return_addresses and obj.lower() != 'any':
                                self.debug('{} not in address dictionary'.format(obj))
                                try:
                                    userobj, addrobj = obj.split('@')
                                    self.debug('Using Address object {} instead'.format(addrobj))
                                except:
                                    pass
                        return_policy[policy_index]['policyDstNet'] = [x['name'] for x in ruleitem['destination']]
                        for obj in return_policy[policy_index]['policyDstNet']:
                            if obj not in return_addresses and obj.lower() != 'any':
                                self.debug('{} not in address dictionary'.format(obj))
                                try:
                                    userobj, addrobj = obj.split('@')
                                    self.debug('Using Address object {} instead'.format(addrobj))
                                except:
                                    pass

                        return_policy[policy_index]['policyDstSvc'] = [x['name'] for x in ruleitem['service']]
                        for obj in return_policy[policy_index]['policyDstSvc']:
                            if obj not in return_services and obj.lower() != 'any':
                                self.debug('{} not in service dictionary'.format(obj))
                                try:
                                    userobj, svcobj = obj.split('@')
                                    self.debug('Using Service object {} instead'.format(svcobj))
                                except:
                                    pass

                        return_policy[policy_index]['policyDstApps'] = ''
                        return_policy[policy_index]['policyComment'] = ruleitem['comments']
                        return_policy[policy_index]['policyLog'] = ''
                        if ruleitem['enabled']:
                            return_policy[policy_index]['policyEnabled'] = '1'
                        else:
                            return_policy[policy_index]['policyEnabled'] = '0'
                        return_policy[policy_index]['policyProps'] = ''
                        return_policy[policy_index]['policyNum'] = ruleitem['rule-number']
                        return_policy[policy_index]['policyUiNum'] = ruleitem['rule-number']
                        return_policy[policy_index]['policyName'] = policy['name']
                        return_policy[policy_index]['policyUid'] = policy['uid']
                        policy_index += 1
            policy_index = 0
            self.log('!-- Retreiving NAT Rules')
            for policy in policies:
                policy_index = 0
                self.log('!-- Retrieving NAT Policy {}'.format(policy['name']))
                rulesets = get_all_objects(mgmt_ip, sid, 'show-nat-rulebase', 'rulebase', policy['name'])
                for ruleitem in rulesets:
                    if 'rulebase' in ruleitem:
                        for rule in ruleitem['rulebase']:
                            return_nat[policy_index] = OrderedDict()
                            # print(json.dumps(rule, indent=4))
                            return_nat[policy_index]['policyOrigSrc'] = rule['original-source']['name']
                            return_nat[policy_index]['policyTransSrc'] = rule['translated-source']['name']
                            return_nat[policy_index]['policyOrigDst'] = rule['original-destination']['name']
                            return_nat[policy_index]['policyTransDst'] = rule['translated-destination']['name']
                            return_nat[policy_index]['policyOrigSvc'] = rule['original-service']['name']
                            return_nat[policy_index]['policyTransSvc'] = rule['translated-service']['name']
                            return_nat[policy_index]['policyDstApps'] = ''
                            return_nat[policy_index]['policyComment'] = rule['comments']
                            return_nat[policy_index]['policyLog'] = ''
                            if rule['enabled']:
                                return_nat[policy_index]['policyEnabled'] = '1'
                            else:
                                return_nat[policy_index]['policyEnabled'] = '0'
                            return_nat[policy_index]['policyProps'] = ''
                            return_nat[policy_index]['policyNum'] = rule['rule-number']
                            return_nat[policy_index]['policyUiNum'] = rule['rule-number']
                            return_nat[policy_index]['policyName'] = policy['name']
                            return_nat[policy_index]['policyUid'] = policy['uid']
                            policy_index += 1
                    else:
                        return_nat[policy_index] = OrderedDict()
                        return_nat[policy_index]['policyOrigSrc'] = ruleitem['original-source']['name']
                        return_nat[policy_index]['policyTransSrc'] = ruleitem['translated-source']['name']
                        return_nat[policy_index]['policyOrigDst'] = ruleitem['original-destination']['name']
                        return_nat[policy_index]['policyTransDst'] = ruleitem['translated-destination']['name']
                        return_nat[policy_index]['policyOrigSvc'] = ruleitem['original-service']['name']
                        return_nat[policy_index]['policyTransSvc'] = ruleitem['translated-service']['name']
                        return_nat[policy_index]['policyDstApps'] = ''
                        return_nat[policy_index]['policyComment'] = ruleitem['comments']
                        return_nat[policy_index]['policyLog'] = ''
                        if ruleitem['enabled']:
                            return_nat[policy_index]['policyEnabled'] = '1'
                        else:
                            return_nat[policy_index]['policyEnabled'] = '0'
                        return_nat[policy_index]['policyProps'] = ''
                        return_nat[policy_index]['policyNum'] = ruleitem['rule-number']
                        return_nat[policy_index]['policyUiNum'] = ruleitem['rule-number']
                        return_nat[policy_index]['policyName'] = policy['name']
                        return_nat[policy_index]['policyUid'] = policy['uid']
                        policy_index += 1

        else:
            self.log(message)
        # temp_config=None
        # print ('policy len', len(return_policy))
        # print(json.dumps(return_nat, indent=4))
        return_config['addresses'] = return_addresses
        return_config['services'] = return_services
        return_config['policies'] = return_policy  # return_policy
        return_config['nat'] = return_nat
        return_config['zones'] = {}
        return_config['interfaces'] = {}
        return_config['apps'] = {}
        return_config['routing'] = OrderedDict()
        return_config['addressmappings'] = addr_mappings
        return_config['servicemappings'] = svc_mappings
        return_config['logprofiles'] = ''
        return_config['config']['name'] = context  ## CHANGEME (how do I get firewall name)
        return_config['config']['version'] = ''
        return_config['config']['fw_type'] = 'R80'
        return_config['config']['mgmtip'] = None
        return_config['usedzones'] = []

        return return_config

    def load_checkpoint_routing(self, routeobj):

        return_routing = OrderedDict()
        return_interface = OrderedDict()
        return_zone = OrderedDict()

        with open(routeobj, 'r') as infile:
            content = infile.read()
            infile.close()
            route_index = 0
            if_index = 1
            # self.log(content.split('\n'))
            try:
                for line in content.split('\n'):
                    if len(line.split(',')) == 8:
                        return_routing[route_index] = {}
                        dest, gateway, destmask, flags, mss, window, irtt, interface = list(line.split(','))
                        return_routing[route_index]['pbrObjDst'] = '{}/{}'.format(dest, self.service.netmask_to_cidr(
                            destmask))
                        if gateway != '0.0.0.0':
                            return_routing[route_index]['pbrObjGw'] = gateway
                        else:
                            return_routing[route_index]['pbrObjGw'] = dest
                        return_routing[route_index]['pbrObjIface'] = interface
                        return_routing[route_index]['pbrObjMetric'] = '0'
                        return_routing[route_index]['pbrObjSrc'] = ''

                        if interface not in return_interface:
                            zone_name = 'Zone{}'.format(str(if_index))
                            self.debug('INTERFACE: {} Zone: {} '.format(interface, zone_name))
                            return_interface[interface] = {}
                            return_interface[interface]['iface_ifnum'] = str(if_index)
                            return_interface[interface]['iface_name'] = interface
                            return_interface[interface]['interface_Zone'] = zone_name
                            if gateway != '0.0.0.0':
                                return_interface[interface]['iface_static_ip'] = gateway
                            else:
                                return_interface[interface]['iface_static_ip'] = dest
                            return_interface[interface]['iface_lan_ip'] = '0.0.0.0'
                            return_interface[interface]['iface_mgmt_ip'] = '0.0.0.0'
                            return_interface[interface]['iface_static_mask'] = destmask
                            return_interface[interface]['iface_lan_mask'] = '0.0.0.0'
                            return_interface[interface]['iface_mgmt_netmask'] = '0.0.0.0'
                            return_interface[interface]['iface_static_gateway'] = gateway
                            return_interface[interface]['iface_lan_default_gw'] = '0.0.0.0'
                            return_interface[interface]['iface_mgmt_default_gw'] = '0.0.0.0'
                            return_zone[zone_name] = {}
                            return_zone[zone_name]['zoneObjId'] = zone_name
                            return_zone[zone_name]['zoneObjComment'] = ''
                            if_index += 1
                        if dest == '0.0.0.0':
                            return_zone['default'] = return_interface[interface]['interface_Zone']

                        route_index += 1
            except Exception as e:
                self.debug('!-- Reading Route file failed')
                self.debug(e)
                self.debug(e)
                self.debug(e)

        return return_routing, return_interface, return_zone

    def load_checkpoint(self, path='', netobj='network_objects.xml', secobj='Security_Policy.xml',
                        svcobj='services.xml',
                        natobj='NAT_Policy.xml', routeobj=None):

        return_config = OrderedDict()
        return_config['config'] = OrderedDict()
        return_config['config']['policylen'] = {}

        return_addresses = OrderedDict()
        return_service = OrderedDict()
        return_policy = OrderedDict()
        return_nat = OrderedDict()
        return_address = OrderedDict()
        return_routing = OrderedDict()
        return_interface = OrderedDict()
        return_zone = OrderedDict()
        addr_mappings = OrderedDict()
        svc_mappings = OrderedDict()

        self.log('  |-- Routing Policy  \r', end=' ')
        ## ['pbrObjId', 'pbrObjProperties', 'pbrObjSrc', 'pbrObjDst', 'pbrObjSvc', 'pbrObjGw', 'pbrObjIface', 'pbrObjIfaceName', 'pbrObjMetric', 'pbrObjPriority', 'pbrObjProbe', 'pbrObjComment']
        ## interface_props = ['iface_ifnum', 'iface_type', 'iface_name', 'interface_Zone', 'iface_comment', 'iface_static_ip', 'iface_static_mask', 'iface_static_gateway', 'iface_lan_ip', 'iface_lan_mask', 'iface_lan_default_gw', 'iface_mgmt_ip', 'iface_mgmt_netmask', 'iface_mgmt_default_gw', 'iface_static_gateway', 'iface_vlan_tag', 'iface_comment', 'iface_http_mgmt', 'iface_https_mgmt', 'iface_ssh_mgmt', 'iface_ping_mgmt', 'iface_snmp_mgmt', 'portShutdown']
        ## zone_props = ['zoneObjId', 'zoneObjComment']

        if routeobj:
            return_routing, return_interface, return_zone = self.load_checkpoint_routing(routeobj)

        else:
            return_routing = OrderedDict()

        for index in return_routing:
            self.debug(return_routing[index])
        for index in return_interface:
            self.debug(return_interface[index])

        self.log('  |-- Address Objects  \r', end=' ')

        with open(netobj, 'r') as infile:
            content = infile.read()
        infile.close()
        networkdict = xmltodict.parse(content)
        classes = []

        ## load address objects

        for z in networkdict['network_objects']['network_object']:
            return_address = OrderedDict()
            current_address = z['Name']
            if z['Class_Name'].lower() == 'security_zone':
                return_address['addrObjType'] = '97'  # placeholder
            elif z['Class_Name'].lower() in ['network_object_group', 'group_with_exception', 'host_plain',
                                             'address_range', 'network', 'gateway_plain', 'cluster_member',
                                             'dynamic_object', 'gateway_cluster', 'host_ckp', 'ep_hostname',
                                             'gateway_ckp', 'vs_cluster_member', 'vs_cluster_netobj']:
                return_address['addrObjId'] = current_address
                return_address['addrObjIdDisp'] = ''
                return_address['addrObjType'] = ''
                return_address['addrObjZone'] = ''
                return_address['addrObjProperties'] = '14'
                return_address['addrObjIp1'] = ''
                return_address['addrObjIp2'] = ''
                return_address['addrObjComment'] = ''
                return_address['addrObjColor'] = ''
                return_address['IPv4Networks'] = [ipaddress.IPv4Network(u'255.255.255.255/32')]

                if z['Class_Name'].lower() == 'network_object_group':
                    addr_mappings[current_address] = []
                    return_address['addrObjType'] = '8'
                    return_address['addrObjIdDisp'] = z['comments']
                    if z['comments'] != None:
                        return_address['addrObjComment'] = z['comments']
                    else:
                        return_address['addrObjComment'] = ''
                    if z['members'] != None:
                        if 'Name' in z['members']['reference']:
                            addr_mappings[current_address] = [z['members']['reference']['Name']]
                        else:
                            for mem in z['members']['reference']:
                                addr_mappings[current_address].append(mem['Name'])
                    if 'color' in z:
                        return_address['addrObjColor'] = z['color']


                elif z['Class_Name'].lower() in ['cluster_member', 'gateway_ckp', 'vs_cluster_member',
                                                 'vs_cluster_netobj']:
                    return_address['addrObjType'] = '91'  ## Unsupported Checkpoint Type
                    if z['interfaces'] != None:
                        if len(z['interfaces']['interfaces']) >= 1:
                            return_address['IPv4Networks'] == []
                            return_address['addrObjList'] = []
                    elif 'ipaddr' in z:
                        return_address['IPv4Networks'] == []
                        return_address['addrObjList'] = []
                        return_address['addrObjIp1'] = z['ipaddr']
                        return_address['addrObjIp2'] = '255.255.255.255'
                        return_address['addrObjList'].append((z['ipaddr'], '255.255.255.255'))
                        return_address['IPv4Networks'].append(ipaddress.IPv4Network(z['ipaddr'] + '/32', strict=False))
                    if z['comments'] != None:
                        return_address['addrObjComment'] = z['comments']
                        return_address['addrObjIdDisp'] = z['comments']
                    else:
                        return_address['addrObjComment'] = ''
                        return_address['addrObjIdDisp'] = ''
                    if 'color' in z: return_address['addrObjColor'] = z['color']

                elif z['Class_Name'].lower() == 'group_with_exception':
                    ## A group with exceptions is simply a single group of included addresses with a single group of excluded addresses
                    ## handle this as a group type, parameters are GroupName, ExcludedGroup -
                    return_address['addrObjType'] = '98'
                    addr_mappings[current_address] = []
                    # return_address['addrObjType'] = '8'
                    return_address['addrObjIdDisp'] = z['comments']
                    if z['comments'] != None: return_address['addrObjComment'] = z['comments']
                    if 'color' in z: return_address['addrObjColor'] = z['color']
                    return_address['include'] = z['base']['Name']
                    return_address['exclude'] = z['exception']['Name']
                elif z['Class_Name'].lower() == 'host_plain' and z['ipaddr'] != None:  # ipv4 support only
                    return_address['addrObjType'] = '1'
                    return_address['addrObjIp1'] = z['ipaddr']
                    return_address['addrObjIp2'] = '255.255.255.255'
                    return_address['addrObjIdDisp'] = z['comments']
                    if z['comments'] != None: return_address['addrObjComment'] = z['comments']
                    if 'color' in z: return_address['addrObjColor'] = z['color']
                    return_address['IPv4Networks'] = [ipaddress.IPv4Network(return_address['addrObjIp1'] + '/32')]
                elif z['Class_Name'].lower() == 'address_range' and z['ipaddr_first'] != None:
                    return_address['addrObjType'] = '2'
                    return_address['addrObjIp1'] = z['ipaddr_first']
                    return_address['addrObjIp2'] = z['ipaddr_last']
                    return_address['IPv4Networks'] = [ipaddr for ipaddr in ipaddress.summarize_address_range(
                        ipaddress.IPv4Address(return_address['addrObjIp1']),
                        ipaddress.IPv4Address(return_address['addrObjIp2']))]
                    return_address['addrObjIdDisp'] = z['comments']
                    if z['comments'] != None: return_address['addrObjComment'] = z['comments']
                    if 'color' in z: return_address['addrObjColor'] = z['color']
                elif z['Class_Name'].lower() == 'network' and z['ipaddr'] != None:
                    return_address['addrObjType'] = '4'
                    return_address['addrObjIdDisp'] = z['comments']
                    if z['comments'] != None: return_address['addrObjComment'] = z['comments']
                    return_address['addrObjIp1'] = z['ipaddr']
                    return_address['addrObjIp2'] = z['netmask']
                    return_address['IPv4Networks'] = [
                        ipaddress.IPv4Network(return_address['addrObjIp1'] + '/' + return_address['addrObjIp2'],
                                              strict=False)]
                    if 'color' in z: return_address['addrObjColor'] = z['color']
                elif z['Class_Name'].lower() in ['gateway_plain', 'cluster_member', 'dynamic_object', 'gateway_cluster',
                                                 'host_ckp', 'ep_hostname']:
                    return_address['addrObjType'] = '99'  ## Unhandled address types are set to 99
                    return_address['addrObjIdDisp'] = z['comments']
                    if z['comments'] != None: return_address['addrObjComment'] = z['comments']
                    if 'ipaddr' in z: return_address['addrObjIp1'] = z['ipaddr']
                    return_address['addrObjIp2'] = '255.255.255.255'
                    if 'ipaddr' in z: return_address['IPv4Networks'] = [
                        ipaddress.IPv4Network(return_address['addrObjIp1'] + '/' + return_address['addrObjIp2'],
                                              strict=False)]  #
                    if 'color' in z: return_address['addrObjColor'] = z['color']
                else:
                    self.log(z['Class_Name'].lower() + ' skipped - Unknown Address Type', level=self.logging.INFO)
                try:
                    return_address['connection_limit'] = z['firewall_setting']['connections_limit']
                    return_address['auto_calc_conns'] = z['firewall_setting']['auto_calc_concurrent_conns']
                except:
                    pass

                ## The assignment below should only be done if one of the supported address types were found

                return_addresses[current_address] = OrderedDict()
                return_addresses[current_address] = return_address

        ## Add IPSet property to address groups
        for addr in return_addresses:
            if return_addresses[addr]['addrObjType'] == '8':
                return_addresses[addr]['IPSet'] = IPSet([])
                for groupmember in self.createNetworkService.expand_address(return_addresses, addr, addr_mappings):
                    for network in return_addresses[groupmember]['IPv4Networks']:
                        return_addresses[addr]['IPSet'].add(str(network))
        for addr in return_addresses:
            if return_addresses[addr]['addrObjType'] == '98':
                self.debug('address', addr)
                if return_addresses[addr]['include'].lower() in ['any', 'all']:
                    included = IPSet(['0.0.0.0/0'])
                else:
                    included = return_addresses[return_addresses[addr]['include']]['IPSet']
                if return_addresses[addr]['exclude'] in ['any', 'all']:
                    included = IPSet(['0.0.0.0/0'])
                else:
                    excluded = return_addresses[return_addresses[addr]['exclude']]['IPSet']
                self.debug('included', included)
                self.debug('excluded', excluded)
                self.debug('result set', included ^ excluded)
                return_addresses[addr]['IPSet'] = included ^ excluded

        ## load policies

        ## 11/26/18 - Policies need to be loaded differently.. Previously the entire XML was simply converted to an OrderedDict() via xmltodict.  This is insufficient
        ## as there may be multiple elements at the same level with the same tag (Ie: <Name> for the policy name)
        ## The new method will iterate through each element within ./fw_policies/fw_policie, change the current policy name as it encounters it, and use that for the subsequent
        ## <rule> section, which can be converted to OderedDict to keep the same routines previously used for processing rules.

        ## 12/10/18 -- new method for reading in merged policies made.  first, the policies should be combined using xmlstarlet to format the xml, and all but the first "<?xml>" line stripped.
        ## In addition all of the top level policies "<fw_policies>" must be wrapped in a new root tag.  I am using "<multi>" to do this.  This means to support a single policy, I had to
        ## artifically place a "<multi>" tag in the XML so that the structure is the same.

        self.log('  |-- Policy Objects         \r', end='')

        tree = et.parse(path + secobj)
        root = tree.getroot()
        if root.tag.lower() != 'multi':  # this is an individual policy package XML file, so we need to wrap the XML in a <multi> tag
            oldroot = root
            root = et.Element('multi')
            root.append(oldroot)

        classes = []
        rule_index = 0
        ui_index = 1
        policy_index = 0
        policyname = '##Standard'  # set default policy name, just in case
        skippedpolicies = []

        for multi in root:
            for policy in multi:
                for child in policy:
                    if child.tag.lower() == 'name':
                        ## following two lines are to print the last rule for each policy for secureid validation
                        # print(policyname)
                        # if policy_index-1 in return_policy:
                        #    print(return_policy[policy_index-1])

                        policyname = child.text
                        section_name = ''
                        self.log("  |-- " + policyname)  # , level=logging.INFO)
                        rule_index = 0  # rule index is reset for each policy name, as each policy name is a seperate policy package, and therefore a seperate database table
                        ui_index = 1
                    # self.debug(options.includepolicies)
                    if policyname[2:] in self.options.includepolicies or self.options.includepolicies == ['all']:

                        if child.tag.lower() == 'rule':
                            # print('"'+ policyname + '"', rule_index)

                            ## process rules
                            policydict = xmltodict.parse(et.tostring(child))
                            # if policyname == '##Isilon-Tokyo-Lab-PreMPLS':
                            # print(policyname, end=' ')
                            # print(len(policydict['rule']['rule']))
                            if policydict['rule'] != None:
                                # print(policyname, end=' ')
                                # print(type(policydict['rule']['rule']))
                                if type(policydict['rule']['rule']) != list:
                                    # print(policyname)
                                    tempx = policydict  # ['rule']
                                else:
                                    tempx = policydict['rule']['rule']
                            # print('-' * 180)
                            if policydict['rule'] != None:
                                # print(len(policydict['rule'['rule']]))
                                return_config['config']['policylen'][policyname] = len(tempx)
                                for x in tempx:
                                    # if policyname=='##Isilon-Tokyo-Lab-PreMPLS':
                                    # print(x)
                                    if 'header_text' not in x:
                                        return_policy[policy_index] = OrderedDict()
                                        return_policy[policy_index]['policyName'] = policyname
                                        return_policy[policy_index]['policyProps'] = '0'
                                        return_policy[policy_index]['policyAction'] = ''
                                        return_policy[policy_index]['policySrcZone'] = []
                                        return_policy[policy_index]['policyDstZone'] = []
                                        return_policy[policy_index]['policySrcNet'] = []
                                        return_policy[policy_index]['policyDstNet'] = []
                                        return_policy[policy_index]['policySrcNegate'] = False
                                        return_policy[policy_index]['policyDstNegate'] = False
                                        return_policy[policy_index]['policySvcNegate'] = False
                                        return_policy[policy_index]['policyDstSvc'] = []
                                        return_policy[policy_index]['policyDstApps'] = []
                                        return_policy[policy_index]['policyUid'] = ''
                                        return_policy[policy_index]['policyNum'] = rule_index
                                        return_policy[policy_index]['policyUiNum'] = ui_index
                                        return_policy[policy_index]['policySection'] = section_name

                                        ui_index += 1  ## verify this is the right place to increase UI Index, and it doesnt belong in the if statement below

                                        if type(x) != str:
                                            if 'comments' in x:
                                                if x['comments'] == None:
                                                    return_policy[policy_index]['policyComment'] = ''
                                                else:
                                                    return_policy[policy_index]['policyComment'] = x['comments']
                                            else:
                                                return_policy[policy_index]['policyComment'] = ''
                                            return_policy[policy_index]['policyLog'] = ''
                                            return_policy[policy_index]['policyProps'] = '0'
                                            return_policy[policy_index]['policyUid'] = x['Rule_UUID']
                                            try:
                                                if x['action']['action']['Name'].lower() == 'accept':
                                                    pass
                                            except:
                                                self.log(json.dumps(x, indent=4))
                                            if x['action']['action']['Name'].lower() == 'accept':
                                                return_policy[policy_index]['policyAction'] = '2'
                                            elif x['action']['action']['Name'].lower() == 'client auth':
                                                return_policy[policy_index]['policyAction'] = '3'
                                            else:
                                                return_policy[policy_index]['policyAction'] = '1'

                                            if x['disabled'].lower() == 'false':  # default to policy disabled
                                                return_policy[policy_index]['policyEnabled'] = '1'
                                            else:
                                                return_policy[policy_index]['policyEnabled'] = '0'
                                            if x['src']['members'] != None:
                                                if 'Name' in x['src']['members']['reference']:
                                                    return_policy[policy_index]['policySrcNet'] = [
                                                        x['src']['members']['reference']['Name']]
                                                else:
                                                    for mem in x['src']['members']['reference']:
                                                        return_policy[policy_index]['policySrcNet'].append(mem['Name'])
                                            else:
                                                return_policy[policy_index]['policySrcNet'] = ['any']
                                            if 'op' in x['src']:
                                                if x['src']['op'] == 'not in':
                                                    return_policy[policy_index]['policySrcNegate'] = True
                                                    self.debug('Source Objects are negated in this rule')
                                            if x['dst']['members'] != None:
                                                if 'Name' in x['dst']['members']['reference']:
                                                    return_policy[policy_index]['policyDstNet'] = [
                                                        x['dst']['members']['reference']['Name']]
                                                else:
                                                    for mem in x['dst']['members']['reference']:
                                                        return_policy[policy_index]['policyDstNet'].append(mem['Name'])
                                            else:
                                                return_policy[policy_index]['policyDstNet'] = ['any']
                                            if 'op' in x['dst']:
                                                if x['dst']['op'] == 'not in':
                                                    return_policy[policy_index]['policyDstNegate'] = True
                                                    self.debug('Destination Objects are negated in this rule')

                                            if x['services']['members'] != None:
                                                if 'Name' in x['services']['members']['reference']:
                                                    return_policy[policy_index]['policyDstSvc'] = [
                                                        x['services']['members']['reference']['Name']]
                                                else:
                                                    for mem in x['services']['members']['reference']:
                                                        return_policy[policy_index]['policyDstSvc'].append(mem['Name'])
                                            else:
                                                return_policy[policy_index]['policyDstSvc'] = ['any']
                                            if 'op' in x['services']:
                                                if x['services']['op'] == 'not in':
                                                    return_policy[policy_index]['policySvcNegate'] = True
                                                    self.debug('Service Objects are negated in this rule')
                                    else:
                                        section_header = x['header_text']
                                        self.log('   Policy Section :', section_header)
                                    policy_index += 1
                                    rule_index += 1
                                '''if policydict['rule']!=None:
                                    if policydict['rule']['rule']!=None:
                                        if len(return_config['config']['policylen'][policyname])!= rule_index:
                                            print(policyname, end=' ')
                            '''
                    else:
                        if policyname not in skippedpolicies:
                            self.log('Skipping policy : ' + policyname[2:], level=self.logging.INFO)
                            skippedpolicies.append(policyname)
        ## load NAT policies
        self.log('  |-- NAT Objects             \r', end='')

        tree = et.parse(path + natobj)
        root = tree.getroot()
        if root.tag.lower() != 'multi':  # this is an individual policy package XML file, so we need to wrap the XML in a <multi> tag
            oldroot = root
            root = et.Element('multi')
            root.append(oldroot)

        import re

        classes = []
        rule_index = 0
        policy_index = 0
        ui_index = 1
        policyname = '##Standard'  # set default policy name, just in case
        for multi in root:
            for policy in multi:
                for child in policy:
                    if child.tag.lower() == 'name':
                        policyname = child.text
                        self.log("  |-- " + policyname, level=self.logging.INFO)
                        rule_index = 0  # rule index is reset for each policy name, as each policy name is a seperate policy package, and therefore a seperate database table
                        ui_index = 1
                    if policyname[2:] in self.options.includepolicies or self.options.includepolicies == ['all']:
                        if child.tag.lower() == 'rule_adtr':
                            ## process rules
                            policydict = xmltodict.parse(et.tostring(child))
                            if policydict['rule_adtr'] != None:
                                for x in policydict['rule_adtr']['rule_adtr']:
                                    if 'Class_Name' in x and type(x) != str:
                                        if x['Class_Name'] == 'address_translation_rule':
                                            return_nat[policy_index] = OrderedDict()
                                            return_nat[policy_index]['natPolicyName'] = policyname
                                            return_nat[policy_index]['natPolicyNum'] = rule_index
                                            return_nat[policy_index]['natPolicyUiNum'] = ui_index
                                            return_nat[policy_index]['natPolicyOrigSrc'] = []
                                            return_nat[policy_index]['natPolicyOrigDst'] = []
                                            return_nat[policy_index]['natPolicyOrigSvc'] = []
                                            return_nat[policy_index]['natPolicyTransSrc'] = []
                                            return_nat[policy_index]['natPolicyTransDst'] = []
                                            return_nat[policy_index]['natPolicyTransSvc'] = []
                                            return_nat[policy_index]['natPolicySrcIface'] = []
                                            return_nat[policy_index]['natPolicyDstIface'] = []
                                            return_nat[policy_index]['natPolicyEnabled'] = ''
                                            return_nat[policy_index]['natPolicyComment'] = ''
                                            return_nat[policy_index]['natpolicyUid'] = ''
                                            return_nat[policy_index]['natPolicyProperties'] = '0'
                                            ui_index += 1
                                            if 'comments' in x:
                                                if x['comments'] != None:
                                                    return_nat[policy_index]['policyComment'] = x['comments']
                                                else:
                                                    return_nat[policy_index]['policyComment'] = ''
                                            else:
                                                return_nat[policy_index]['policyComment'] = ''

                                            if x['disabled'].lower() == 'false':  # default to policy disabled
                                                return_nat[policy_index]['natPolicyEnabled'] = '1'
                                            else:
                                                return_nat[policy_index]['natPolicyEnabled'] = '0'

                                            if 'src_adtr' in x:
                                                if x['src_adtr'] != None:
                                                    if 'Name' in x['src_adtr']['src_adtr']:
                                                        return_nat[policy_index]['natPolicyOrigSrc'] = [
                                                            x['src_adtr']['src_adtr']['Name']]
                                                    else:
                                                        return_nat[policy_index]['natPolicyOrigSrc'] = 'Any'
                                            else:
                                                return_nat[policy_index]['natPolicyOrigSrc'] = 'Any'

                                            if 'dst_adtr' in x:
                                                if x['dst_adtr'] != None:
                                                    if 'Name' in x['dst_adtr']['dst_adtr']:
                                                        return_nat[policy_index]['natPolicyOrigDst'] = [
                                                            x['dst_adtr']['dst_adtr']['Name']]
                                                    else:
                                                        return_nat[policy_index]['natPolicyOrigDst'] = 'Any'
                                            else:
                                                return_nat[policy_index]['natPolicyOrigDst'] = 'Any'

                                            if 'services_adtr' in x:
                                                if x['services_adtr'] != None:
                                                    if 'Name' in x['services_adtr']['services_adtr']:
                                                        return_nat[policy_index]['natPolicyOrigSvc'] = [
                                                            x['services_adtr']['services_adtr']['Name']]
                                                    else:
                                                        return_nat[policy_index]['natPolicyOrigSvc'] = 'Any'
                                            else:
                                                return_nat[policy_index]['natPolicyOrigSvc'] = 'Any'

                                            if x['src_adtr_translated'] != None:
                                                if 'Name' in x['src_adtr_translated']['reference']:
                                                    return_nat[policy_index]['natPolicyTransSrc'] = [
                                                        x['src_adtr_translated']['reference']['Name']]
                                                    if len(re.findall('method_hide',
                                                                      x['src_adtr_translated']['adtr_method'])) > 0:
                                                        return_nat[policy_index][
                                                            'natPolicyTransSrcMethod'] = 'translate_hide'
                                                    else:
                                                        return_nat[policy_index][
                                                            'natPolicyTransSrcMethod'] = 'translate_static'
                                            else:
                                                return_nat[policy_index]['natPolicyTransSrc'] = 'Any'

                                            if x['dst_adtr_translated'] != None:
                                                if 'Name' in x['dst_adtr_translated']['reference']:
                                                    return_nat[policy_index]['natPolicyTransDst'] = [
                                                        x['dst_adtr_translated']['reference']['Name']]
                                                    if len(re.findall('method_hide',
                                                                      x['dst_adtr_translated']['adtr_method'])) > 0:
                                                        return_nat[policy_index][
                                                            'natPolicyTransDstMethod'] = 'translate_hide'
                                                    else:
                                                        return_nat[policy_index][
                                                            'natPolicyTransDstMethod'] = 'translate_static'
                                            else:
                                                return_nat[policy_index]['natPolicyTransDst'] = 'Any'

                                            if x['services_adtr_translated'] != None:
                                                if 'Name' in x['services_adtr_translated']['reference']:
                                                    return_nat[policy_index]['natPolicyTransSvc'] = [
                                                        x['services_adtr_translated']['reference']['Name']]
                                                    return_nat[policy_index][
                                                        'natPolicyTransSvcMethod'] = 'service_translate'
                                            else:
                                                return_nat[policy_index]['natPolicyTransSvc'] = 'Any'
                                        policy_index += 1
                                        rule_index += 1

        ## load services

        if svcobj != '':
            self.log('  |-- Service Objects         \r', end='')
            with open(path + svcobj, 'r') as infile:
                content = infile.read()
            infile.close()
            servicedict = xmltodict.parse(content)
            classes = []

            ## need to handle 'other_service', rpc_service'

            for x in servicedict['services']['service']:
                if x['Class_Name'].lower() in ['tcp_service', 'udp_service', 'service_group', 'other_service',
                                               'rpc_service', 'icmp_service']:
                    current_service = x['Name']
                    return_service[current_service] = OrderedDict()
                    return_service[current_service]['svcObjId'] = current_service
                    return_service[current_service]['svcObjType'] = '1'
                    return_service[current_service]['svcObjProperties'] = '14'
                    return_service[current_service]['svcObjIpType'] = '0'
                    return_service[current_service]['svcObjPort1'] = ''
                    return_service[current_service]['svcObjPort2'] = ''
                    return_service[current_service]['svcObjSrcPort'] = '0'
                    return_service[current_service]['svcObjManagement'] = ''
                    return_service[current_service]['svcObjHigherPrecedence'] = ''
                    return_service[current_service]['svcObjComment'] = ''
                    return_service[current_service]['svcObjColor'] = ''

                    if x['comments'] != None:
                        return_service[current_service]['svcObjComment'] = x['comments']
                    if x['color'] != None:
                        return_service[current_service]['svcObjColor'] = x['color']

                    if x['Class_Name'] not in classes:
                        classes.append(x['Class_Name'])
                    if x['Class_Name'].lower() == 'tcp_service':
                        return_service[current_service]['svcObjIpType'] = '6'
                    if x['Class_Name'].lower() == 'udp_service':
                        return_service[current_service]['svcObjIpType'] = '17'
                    if x['Class_Name'].lower() in ['tcp_service', 'udp_service']:
                        # return_service[current_service]['svcObjComment'] = x['comments']
                        if x['port'][0] == '>':  ## greater than port modifier
                            return_service[current_service]['svcObjPort1'] = str(int(x['port'][1:]) + 1)
                            return_service[current_service]['svcObjPort2'] = '65535'
                        elif x['port'][0] == '<':  ## greater than port modifier
                            return_service[current_service]['svcObjPort1'] = '1'
                            return_service[current_service]['svcObjPort2'] = str(int(x['port'][1:]) - 1)
                        else:
                            ports = x['port'].split('-')
                            if len(ports) == 2:
                                return_service[current_service]['svcObjPort1'], return_service[current_service][
                                    'svcObjPort2'] = x['port'].split('-')
                            else:
                                return_service[current_service]['svcObjPort1'] = x['port']
                                return_service[current_service]['svcObjPort2'] = x['port']
                    if x['Class_Name'].lower() == 'icmp_service':
                        return_service[current_service]['svcObjIpType'] = '1'
                        return_service[current_service]['svcObjPort1'] = x[
                            'icmp_type']  ## putting the ICMP type into the port1 field
                        # return_service[current_service]['svcObjComment'] = x['comments']
                    if x['Class_Name'].lower() == 'other_service':  # placeholder for other_service type
                        return_service[current_service][
                            'svcObjType'] = '99'  # placeholder for other_type which likely uses an expression
                        # return_service[current_service]['svcObjIpType'] = x['protocol'] ## this was commented out as it was allowing get_prot_of and get_port_of to function, but returning bad results.
                        # return_service[current_service]['svcObjComment'] = x['comments']
                    if x['Class_Name'].lower() == 'rpc_service':  # placeholder for rpc_service type
                        return_service[current_service]['svcObjIpType'] = '97'  ## placeholder for RPC service type
                        return_service[current_service]['svcObjPort1'] = x[
                            'port']  ## putting the RPC port into the port1 field
                        # return_service[current_service]['svcObjComment'] = x['comments']

                    if x['Class_Name'].lower() == 'service_group':
                        svc_mappings[current_service] = []
                        return_service[current_service]['svcObjType'] = '2'
                        # return_service[current_service]['svcObjComment'] = x['comments']
                        if x['members'] != None:
                            if 'Name' in x['members']['reference']:
                                svc_mappings[current_service] = [x['members']['reference']['Name']]
                            else:
                                for mem in x['members']['reference']:
                                    svc_mappings[current_service].append(mem['Name'])
                else:
                    pass
                    self.debug('unknown service type ' + x['Class_Name'].lower() + ' for ' + x['Name'])

        ## This loop checks that each service specified in each policy is loaded as a configuration object

        for pol in return_policy:
            for svc in return_policy[pol]['policyDstSvc']:
                if svc not in return_service and svc.lower() != 'any':
                    self.log(svc + ' not found', level=self.logging.INFO)

        for pol in return_policy:
            for addr in return_policy[pol]['policySrcNet']:
                if addr not in return_addresses and addr.lower() != 'any':
                    self.log(addr + ' not found', level=self.logging.INFO)
            for addr in return_policy[pol]['policyDstNet']:
                if addr not in return_addresses and addr.lower() != 'any':
                    self.log(addr + ' not found', level=self.logging.INFO)

        return_config['addresses'] = return_addresses
        return_config['services'] = return_service
        return_config['policies'] = return_policy  # return_policy
        return_config['nat'] = return_nat
        return_config['zones'] = return_zone
        return_config['interfaces'] = return_interface
        return_config['apps'] = {}
        return_config['routing'] = return_routing
        return_config['addressmappings'] = addr_mappings
        return_config['servicemappings'] = svc_mappings
        return_config['logprofiles'] = ''
        return_config['config']['name'] = self.options.checkpointcontext  ## CHANGEME (how do I get firewall name)
        return_config['config']['version'] = ''
        return_config['config']['fw_type'] = 'checkpoint'
        return_config['config']['mgmtip'] = None
        return_config['config']['usedzones'] = []

        return return_config
