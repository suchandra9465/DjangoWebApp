import base64
import json
import re
import time
from collections import OrderedDict
from collections import defaultdict
from urllib.parse import unquote as url_unquote

import requests
import urllib3
from bs4 import BeautifulSoup
from netaddr import IPSet

import sonicwall as sw
from .. import CreateService as CS
from .. import Service as S
from .. import Zone as Z
from ... import NetworkLogs


# !Addresses
# !Services
# Security Rules - need to load source/dest
# NAT Rules
# !Routes
# !Zones
# !Interfaces
# !Address and service mappings details - should be easy from group items?
# Perform a diff in json.dumps of config read from each method

class SonicWallService:

    def _init_(self, options, config, contexts):
        self.log = NetworkLogs().log
        self.sc = NetworkLogs().sc
        self.ss = NetworkLogs().ss
        self.debug = NetworkLogs().debug
        self.options = options
        self.config = config
        self.contexts = contexts

        self.service = S.Service(self.options)
        self.createNetworkService = CS.CreateNetworkService(self.options, self.config)

        self.zone = Z.Zones

    def load_sonicwall_api(self, ip, username, password, skipdisabled=False, memoryconfig=None, retries=1, retry_delay=1,
                           enable_api=False, revert_api=False):
        self.log('!-- Loading Sonicwall configuration via API requested')
        # Use API to send CLI command for groups
        orig_api_enabled = self.sw_get_api_status(ip, username, password)
        # orig_api_enabled=True
        # self.log(orig_api_enabled)
        api_enabled = False

        # Add command to force API enablement, if needed
        if enable_api and not orig_api_enabled:
            self.log('!-- Sonicwall API not enabled - enablement requested')
            self.sw_enable_api(ip, username, password)
            api_enabled = self.sw_get_api_status(ip, username, password)
            if api_enabled:
                self.log('!-- Sonicwall API enablement successful')
            else:
                self.log('!-- Sonicwall API enablement failed')

        sonicwall_config = defaultdict(dict)

        if api_enabled or orig_api_enabled:

            sonicwall_config['addresses'] = OrderedDict()
            sonicwall_config['config'] = OrderedDict()
            sonicwall_config['policies'] = OrderedDict()
            sonicwall_config['services'] = OrderedDict()
            sonicwall_config['routing'] = OrderedDict()
            sonicwall_config['nat'] = OrderedDict()
            sonicwall_config['interfaces'] = OrderedDict()
            sonicwall_config['zones'] = OrderedDict()
            sonicwall_config['apps'] = OrderedDict()
            sonicwall_config['policiesV6'] = OrderedDict()
            sonicwall_config['addressesV6'] = OrderedDict()
            sonicwall_config['addressesfqdn'] = OrderedDict()
            sonicwall_config['addressmappings'] = OrderedDict()
            sonicwall_config['servicemappings'] = OrderedDict()

            # get routing table via WebUI which is complete
            # routing_props = ['pbrObjId', 'pbrObjProperties', 'pbrObjSrc', 'pbrObjDst', 'pbrObjSvc', 'pbrObjGw',
            # 'pbrObjIface', 'pbrObjIfaceName', 'pbrObjMetric', 'pbrObjPriority', 'pbrObjProbe', 'pbrObjComment']

            session = requests.Session()
            session.mount('https://' + ip, sw.DESAdapter())
            urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

            session = requests.Session()
            session.mount('https://' + ip, sw.DESAdapter())
            loginResult = sw.do_login(session, self.options.username, self.options.password, ip, preempt=True)
            pbrResult = None
            if loginResult:
                pbrResult = sw.get_url(session, 'https://' + ip + '/getRouteList.json')
            sw.do_logout(session, ip)

            url = 'https://{}/api/sonicos/auth'.format(ip)
            session.headers = OrderedDict(
                [('User-Agent', 'python-requests/2.18.4'), ('Accept', '*/*'), ('Accept-Encoding', 'gzip, deflate'),
                 ('Connection', 'keep-alive')])
            post_data = None
            # auth = requests.auth.HTTPBasicAuth(username, password)
            response_code = None
            login_tries = 0
            while response_code != 200 and login_tries < retries:
                try:
                    login_tries += 1
                    response = session.post(url=url, headers={
                        'authorization': "Basic " + base64.b64encode(
                            '{}:{}'.format(username, password).encode()).decode()},
                                            verify=False, timeout=self.options.timeout_sw_webui_login)
                    response_code = response.status_code
                    if response_code != 200:
                        self.debug('Login failed, retrying in 10 seconds')
                        time.sleep(retry_delay)
                except:
                    response_code = None
            # /api/sonicos/access-rules/ipv4

            sonicwall_config['config']['fw_type'] = 'sonicwall'

            if response_code == 200:

                session.headers.update({'content-type': 'text/plain'})
                session.headers.update({'Accept': 'application/json'})

                self.log('!-- Reading Security Policy Objects')
                url = 'https://{}/api/sonicos/access-rules/ipv4'.format(ip)
                result = session.get(url=url, data=post_data, verify=False, timeout=self.options.timeout_sw_api)
                self.debug(result.text)
                security_ipv4 = json.loads(result.text)
                self.debug('{:20.20} {:20.20} {}'.format('Length', ' Security Policies', len(security_ipv4['access_rules'])))
                # self.debug(security_ipv4['access_rules'][0])

                rule_num_int = 0
                for access_rule in security_ipv4['access_rules']:
                    # {'ipv4': {'schedule': {'always_on': True}, 'geo_ip_filter': False, 'comment': 'Auto-added management rule', 'name': '',
                    # 'source': {'port': {'any': True}, 'address': {'any': True}}, 'sip': False, 'udp': {'timeout': 30}, 'h323': False, 'packet_monitoring': False, 'from': 'LAN', 'quality_of_service': {'class_of_service': {}, 'dscp': {'preserve': True}},
                    # 'service': {'group': 'Ping'}, 'fragments': True, 'max_connections': 100, 'flow_reporting': False, 'tcp': {'timeout': 15, 'urgent': True}, 'logging': True, 'botnet_filter': False, 'enable': True, 'priority': {'manual': 1}, 'connection_limit': {'source': {}, 'destination': {}}, 'dpi': True, 'action': 'allow', 'uuid': '00b7ea07-d3f5-1e66-0700-c0eae46b8088', 'to': 'LAN',
                    # 'users': {'excluded': {'none': True}, 'included': {'all': True}}, 'dpi_ssl': {'server': True, 'client': True}, 'management': True, 'destination': {'address': {'group': 'All X0 Management IP'}}}}
                    # policy_props = ['policyAction', 'policySrcZone', 'policyDstZone', 'policySrcNet', 'policyDstNet', 'policyDstSvc', 'policyDstApps', 'policyComment', 'policyLog', 'policyEnabled', 'policyProps' ]
                    rule_num = str(rule_num_int)
                    self.debug(access_rule)
                    # rule_num=str(access_rule['ipv4']['priority']['manual'])
                    sonicwall_config['policies'][rule_num] = OrderedDict()

                    sonicwall_config['policies'][rule_num]['policyAction'] = ''
                    sonicwall_config['policies'][rule_num]['policySrcZone'] = ''
                    sonicwall_config['policies'][rule_num]['policyDstZone'] = ''
                    sonicwall_config['policies'][rule_num]['policySrcNet'] = ''
                    sonicwall_config['policies'][rule_num]['policyDstNet'] = ''
                    sonicwall_config['policies'][rule_num]['policyDstSvc'] = ''
                    sonicwall_config['policies'][rule_num]['policySrcNegate'] = False
                    sonicwall_config['policies'][rule_num]['policyDstNegate'] = False
                    sonicwall_config['policies'][rule_num]['policySvcNegate'] = False
                    sonicwall_config['policies'][rule_num]['policyDstApps'] = ''
                    sonicwall_config['policies'][rule_num]['policyComment'] = ''
                    sonicwall_config['policies'][rule_num]['policyLog'] = ''
                    sonicwall_config['policies'][rule_num]['policyEnabled'] = ''
                    sonicwall_config['policies'][rule_num]['policyProps'] = ''
                    sonicwall_config['policies'][rule_num]['policyUUID'] = ''
                    sonicwall_config['policies'][rule_num]['policyName'] = "Empty"
                    sonicwall_config['policies'][rule_num]['policyNum'] = ''
                    sonicwall_config['policies'][rule_num]['policyUiNum'] = ''
                    sonicwall_config['policies'][rule_num]['policyDstApps'] = ['']
                    if access_rule['ipv4']['action'].lower() == 'deny':
                        sonicwall_config['policies'][rule_num]['policyAction'] = '0'
                    elif access_rule['ipv4']['action'].lower() in ['drop', 'discard']:
                        sonicwall_config['policies'][rule_num]['policyAction'] = '1'
                    elif access_rule['ipv4']['action'].lower() == 'allow':
                        sonicwall_config['policies'][rule_num]['policyAction'] = '2'
                    else:
                        self.log(access_rule)
                    sonicwall_config['policies'][rule_num]['policySrcZone'] = [access_rule['ipv4']['from']]
                    sonicwall_config['policies'][rule_num]['policyDstZone'] = [access_rule['ipv4']['to']]
                    sonicwall_config['policies'][rule_num]['policyName'] = access_rule['ipv4']['name']
                    if 'any' in access_rule['ipv4']['source']['address']:
                        sonicwall_config['policies'][rule_num]['policySrcNet'] = ['']
                    elif 'name' in access_rule['ipv4']['source']['address']:
                        sonicwall_config['policies'][rule_num]['policySrcNet'] = [
                            access_rule['ipv4']['source']['address']['name']]
                    elif 'group' in access_rule['ipv4']['source']['address']:
                        sonicwall_config['policies'][rule_num]['policySrcNet'] = [
                            access_rule['ipv4']['source']['address']['group']]
                    else:
                        sonicwall_config['policies'][rule_num]['policySrcNet'] = ['']
                        self.log('!-- Warning Unknown Policy policySrcNet')

                    if 'any' in access_rule['ipv4']['destination']['address']:
                        sonicwall_config['policies'][rule_num]['policyDstNet'] = ['']
                    elif 'name' in access_rule['ipv4']['destination']['address']:
                        sonicwall_config['policies'][rule_num]['policyDstNet'] = [
                            access_rule['ipv4']['destination']['address']['name']]
                    elif 'group' in access_rule['ipv4']['destination']['address']:
                        sonicwall_config['policies'][rule_num]['policyDstNet'] = [
                            access_rule['ipv4']['destination']['address']['group']]
                    else:
                        sonicwall_config['policies'][rule_num]['policyDstNet'] = ['']
                        self.log('!-- Warning Unknown Policy policyDstNet')

                    if 'any' in access_rule['ipv4']['service']:
                        sonicwall_config['policies'][rule_num]['policyDstSvc'] = ['']
                    elif 'group' in access_rule['ipv4']['service']:
                        sonicwall_config['policies'][rule_num]['policyDstSvc'] = [
                            access_rule['ipv4']['service']['group']]
                    elif 'name' in access_rule['ipv4']['service']:
                        sonicwall_config['policies'][rule_num]['policyDstSvc'] = [
                            access_rule['ipv4']['service']['name']]
                    else:
                        sonicwall_config['policies'][rule_num]['policyDstSvc'] = ['']
                        self.log('!-- Warning Unknown Policy policyDstSvc')

                    sonicwall_config['policies'][rule_num]['policyComment'] = access_rule['ipv4']['comment']
                    if access_rule['ipv4']['logging']:
                        sonicwall_config['policies'][rule_num]['policyLog'] = '1'
                    else:
                        sonicwall_config['policies'][rule_num]['policyLog'] = '0'
                    if access_rule['ipv4']['enable']:
                        sonicwall_config['policies'][rule_num]['policyEnabled'] = '1'
                    else:
                        sonicwall_config['policies'][rule_num]['policyEnabled'] = '0'
                    sonicwall_config['policies'][rule_num]['policyProps'] = ''  ## unknown for sonicwall6.5 policies
                    sonicwall_config['policies'][rule_num]['policyUUID'] = access_rule['ipv4']['uuid']
                    # self.log(json.dumps(access_rule, indent=3))
                    # self.log(json.dumps(sonicwall_config['policies'][rule_num], indent=3))
                    # self.log('-' *100)
                    rule_num_int += 1

                # policyV6_props = ['policyActionV6', 'policySrcZoneV6', 'policyDstZoneV6', 'policySrcNetV6', 'policyDstNetV6', 'policyDstSvcV6', 'policyCommentV6', 'policyLogV6', 'policyEnabledV6', 'policyPropsV6' ]

                self.log('!-- Reading IPv6 Security Policy Objects')
                url = 'https://{}/api/sonicos/access-rules/ipv6'.format(ip)
                result = session.get(url=url, data=post_data, verify=False, timeout=self.options.timeout_sw_api)
                self.debug(result.text)
                security_ipv6 = json.loads(result.text)
                if 'access_rules' in security_ipv6:
                    self.debug(security_ipv6)
                    self.debug('{:20.20} {:20.20} {}'.format('Length', ' Security Policies',
                                                        len(security_ipv6['access_rules'])))
                    rule_num_int = 0
                    for access_rule in security_ipv6['access_rules']:
                        # {'ipv4': {'schedule': {'always_on': True}, 'geo_ip_filter': False, 'comment': 'Auto-added management rule', 'name': '',
                        # 'source': {'port': {'any': True}, 'address': {'any': True}}, 'sip': False, 'udp': {'timeout': 30}, 'h323': False, 'packet_monitoring': False, 'from': 'LAN', 'quality_of_service': {'class_of_service': {}, 'dscp': {'preserve': True}},
                        # 'service': {'group': 'Ping'}, 'fragments': True, 'max_connections': 100, 'flow_reporting': False, 'tcp': {'timeout': 15, 'urgent': True}, 'logging': True, 'botnet_filter': False, 'enable': True, 'priority': {'manual': 1}, 'connection_limit': {'source': {}, 'destination': {}}, 'dpi': True, 'action': 'allow', 'uuid': '00b7ea07-d3f5-1e66-0700-c0eae46b8088', 'to': 'LAN',
                        # 'users': {'excluded': {'none': True}, 'included': {'all': True}}, 'dpi_ssl': {'server': True, 'client': True}, 'management': True, 'destination': {'address': {'group': 'All X0 Management IP'}}}}
                        # policy_props = ['policyAction', 'policySrcZone', 'policyDstZone', 'policySrcNet', 'policyDstNet', 'policyDstSvc', 'policyDstApps', 'policyComment', 'policyLog', 'policyEnabled', 'policyProps' ]
                        # policyV6_props = ['policyActionV6', 'policySrcZoneV6', 'policyDstZoneV6', 'policySrcNetV6', 'policyDstNetV6', 'policyDstSvcV6', 'policyCommentV6', 'policyLogV6', 'policyEnabledV6', 'policyPropsV6' ]

                        rule_num = str(rule_num_int)
                        self.debug(access_rule)
                        # rule_num=str(access_rule['ipv6']['priority']['manual'])
                        sonicwall_config['policiesV6'][rule_num] = OrderedDict()

                        sonicwall_config['policiesV6'][rule_num]['policyAction'] = ''
                        sonicwall_config['policiesV6'][rule_num]['policySrcZone'] = ''
                        sonicwall_config['policiesV6'][rule_num]['policyDstZone'] = ''
                        sonicwall_config['policiesV6'][rule_num]['policySrcNet'] = ''
                        sonicwall_config['policiesV6'][rule_num]['policyDstNet'] = ''
                        sonicwall_config['policiesV6'][rule_num]['policyDstSvc'] = ''
                        sonicwall_config['policiesV6'][rule_num]['policyDstApps'] = ''
                        sonicwall_config['policiesV6'][rule_num]['policyComment'] = ''
                        sonicwall_config['policiesV6'][rule_num]['policyLog'] = ''
                        sonicwall_config['policiesV6'][rule_num]['policyEnabled'] = ''
                        sonicwall_config['policiesV6'][rule_num]['policyProps'] = ''
                        sonicwall_config['policiesV6'][rule_num]['policyUUID'] = ''
                        sonicwall_config['policiesV6'][rule_num]['policyName'] = "Empty"
                        sonicwall_config['policiesV6'][rule_num]['policyNum'] = ''
                        sonicwall_config['policiesV6'][rule_num]['policyUiNum'] = ''
                        sonicwall_config['policiesV6'][rule_num]['policyDstApps'] = ['']
                        if access_rule['ipv6']['action'].lower() == 'deny':
                            sonicwall_config['policiesV6'][rule_num]['policyAction'] = '0'
                        elif access_rule['ipv6']['action'].lower() in ['drop', 'discard']:
                            sonicwall_config['policiesV6'][rule_num]['policyAction'] = '1'
                        elif access_rule['ipv6']['action'].lower() == 'allow':
                            sonicwall_config['policiesV6'][rule_num]['policyAction'] = '2'
                        else:
                            self.log(access_rule)
                        sonicwall_config['policiesV6'][rule_num]['policySrcZone'] = [access_rule['ipv6']['from']]
                        sonicwall_config['policiesV6'][rule_num]['policyDstZone'] = [access_rule['ipv6']['to']]

                        if 'any' in access_rule['ipv6']['source']['address']:
                            sonicwall_config['policiesV6'][rule_num]['policySrcNet'] = ['']
                        elif 'name' in access_rule['ipv6']['source']['address']:
                            sonicwall_config['policiesV6'][rule_num]['policySrcNet'] = [
                                access_rule['ipv6']['source']['address']['name']]
                        elif 'group' in access_rule['ipv6']['source']['address']:
                            sonicwall_config['policiesV6'][rule_num]['policySrcNet'] = [
                                access_rule['ipv6']['source']['address']['group']]
                        else:
                            sonicwall_config['policiesV6'][rule_num]['policySrcNet'] = ['']
                            self.log('!-- Warning Unknown Policy policySrcNet')

                        if 'any' in access_rule['ipv6']['destination']['address']:
                            sonicwall_config['policiesV6'][rule_num]['policyDstNet'] = ['']
                        elif 'name' in access_rule['ipv6']['destination']['address']:
                            sonicwall_config['policiesV6'][rule_num]['policyDstNet'] = [
                                access_rule['ipv6']['destination']['address']['name']]
                        elif 'group' in access_rule['ipv6']['destination']['address']:
                            sonicwall_config['policiesV6'][rule_num]['policyDstNet'] = [
                                access_rule['ipv6']['destination']['address']['group']]
                        else:
                            sonicwall_config['policiesV6'][rule_num]['policyDstNet'] = ['']
                            self.log('!-- Warning Unknown Policy policyDstNet')

                        if 'any' in access_rule['ipv6']['service']:
                            sonicwall_config['policiesV6'][rule_num]['policyDstSvc'] = ['']
                        elif 'group' in access_rule['ipv6']['service']:
                            sonicwall_config['policiesV6'][rule_num]['policyDstSvc'] = [
                                access_rule['ipv6']['service']['group']]
                        elif 'name' in access_rule['ipv6']['service']:
                            sonicwall_config['policiesV6'][rule_num]['policyDstSvc'] = [
                                access_rule['ipv6']['service']['name']]
                        else:
                            sonicwall_config['policiesV6'][rule_num]['policyDstSvc'] = ['']
                            self.log('!-- Warning Unknown Policy policyDstSvc')

                        sonicwall_config['policiesV6'][rule_num]['policyComment'] = access_rule['ipv6']['comment']

                        if access_rule['ipv6']['logging']:
                            sonicwall_config['policiesV6'][rule_num]['policyLog'] = '1'
                        else:
                            sonicwall_config['policiesV6'][rule_num]['policyLog'] = '0'
                        if access_rule['ipv6']['enable']:
                            sonicwall_config['policiesV6'][rule_num]['policyEnabled'] = '1'
                        else:
                            sonicwall_config['policies'][rule_num]['policyEnabled'] = '0'
                        sonicwall_config['policiesV6'][rule_num][
                            'policyProps'] = ''  ## unknown for sonicwall6.5 policies
                        sonicwall_config['policiesV6'][rule_num]['policyUUID'] = access_rule['ipv6']['uuid']
                        # self.log(json.dumps(access_rule, indent=3))
                        # self.log(json.dumps(sonicwall_config['policies'][rule_num], indent=3))
                        # self.log('-' *100)
                        rule_num_int += 1

                self.log('!-- Reading NAT Policy Objects')
                url = 'https://{}/api/sonicos/nat-policies/ipv4'.format(ip)
                result = session.get(url=url, data=post_data, verify=False, timeout=self.options.timeout_sw_api)
                nat_ipv4 = json.loads(result.text)
                # self.log('NATPOL: ', json.dumps(nat_ipv4['nat_policies'][28], indent=2))
                # {'ipv4': {'translated_service': {'original': True}, 'comment': 'Management NAT Policy', 'outbound': 'MGMT', 'source': {'any': True}, 'service': {'name': 'SNMP'}, 'enable': True, 'uuid': 'ed660693-3b9a-77f1-0800-c0eae46b8088', 'inbound': 'MGMT', 'name': '', 'translated_source': {'original': True}, 'translated_destination': {'original': True}, 'destination': {'name': 'MGMT IP'}}}
                # nat_props = [ 'natPolicyOrigSrc', 'natPolicyOrigDst', 'natPolicyOrigSvc', 'natPolicyTransSrc', 'natPolicyTransDst', 'natPolicyTransSvc', 'natPolicySrcIface', 'natPolicyDstIface', 'natPolicyEnabled', 'natPolicyComment', 'natPolicyProperties', 'natPolicyName' ]

                rule_num_int = 0
                for nat_rule in nat_ipv4['nat_policies']:
                    rule_num = str(rule_num_int)
                    # self.log('NAT: ', json.dumps(nat_rule, indent=4))
                    sonicwall_config['nat'][rule_num] = OrderedDict()
                    sonicwall_config['nat'][rule_num]['natPolicyName'] = nat_rule['ipv4']['name']
                    sonicwall_config['nat'][rule_num]['natPolicyNum'] = ''
                    sonicwall_config['nat'][rule_num]['natPolicyUiNum'] = ''
                    if nat_rule['ipv4']['enable']:
                        sonicwall_config['nat'][rule_num]['natPolicyEnabled'] = '1'
                    else:
                        sonicwall_config['nat'][rule_num]['natPolicyEnabled'] = '0'
                    sonicwall_config['nat'][rule_num]['natPolicySrcIface'] = nat_rule['ipv4']['inbound']
                    sonicwall_config['nat'][rule_num]['natPolicyDstIface'] = nat_rule['ipv4']['outbound']
                    if 'any' in nat_rule['ipv4']['source']:
                        sonicwall_config['nat'][rule_num]['natPolicyOrigSrc'] = ['']
                    elif 'name' in nat_rule['ipv4']['source']:
                        sonicwall_config['nat'][rule_num]['natPolicyOrigSrc'] = [nat_rule['ipv4']['source']['name']]
                    elif 'group' in nat_rule['ipv4']['source']:
                        sonicwall_config['nat'][rule_num]['natPolicyOrigSrc'] = [nat_rule['ipv4']['source']['group']]
                    else:
                        sonicwall_config['nat'][rule_num]['natPolicyOrigSrc'] = ['']
                        self.log('!-- Warning reading NAT OrigSrc')

                    if 'any' in nat_rule['ipv4']['destination']:
                        sonicwall_config['nat'][rule_num]['natPolicyOrigDst'] = ['']
                    elif 'name' in nat_rule['ipv4']['destination']:
                        sonicwall_config['nat'][rule_num]['natPolicyOrigDst'] = [
                            nat_rule['ipv4']['destination']['name']]
                    elif 'group' in nat_rule['ipv4']['destination']:
                        sonicwall_config['nat'][rule_num]['natPolicyOrigDst'] = [
                            nat_rule['ipv4']['destination']['group']]
                    else:
                        sonicwall_config['nat'][rule_num]['natPolicyOrigDst'] = ['']
                        self.log('!-- Warning reading NAT OrigDst')

                    if 'any' in nat_rule['ipv4']['service']:
                        sonicwall_config['nat'][rule_num]['natPolicyOrigSvc'] = ['']
                    elif 'name' in nat_rule['ipv4']['service']:
                        sonicwall_config['nat'][rule_num]['natPolicyOrigSvc'] = [nat_rule['ipv4']['service']['name']]
                    elif 'group' in nat_rule['ipv4']['service']:
                        sonicwall_config['nat'][rule_num]['natPolicyOrigSvc'] = [nat_rule['ipv4']['service']['group']]
                    else:
                        sonicwall_config['nat'][rule_num]['natPolicyOrigSvc'] = ['']
                        self.log('!-- Warning reading NAT TransOrigSvc')

                    if 'original' in nat_rule['ipv4']['translated_source']:
                        sonicwall_config['nat'][rule_num]['natPolicyTransSrc'] = ['']
                    elif 'name' in nat_rule['ipv4']['translated_source']:
                        sonicwall_config['nat'][rule_num]['natPolicyTransSrc'] = [
                            nat_rule['ipv4']['translated_source']['name']]
                    elif 'group' in nat_rule['ipv4']['translated_source']:
                        sonicwall_config['nat'][rule_num]['natPolicyTransSrc'] = [
                            nat_rule['ipv4']['translated_source']['group']]
                    else:
                        sonicwall_config['nat'][rule_num]['natPolicyTransSrc'] = ['']
                        self.log('!-- Warning reading NAT TransSrc')

                    if 'original' in nat_rule['ipv4']['translated_destination']:
                        sonicwall_config['nat'][rule_num]['natPolicyTransDst'] = ['']
                    elif 'name' in nat_rule['ipv4']['translated_destination']:
                        sonicwall_config['nat'][rule_num]['natPolicyTransDst'] = [
                            nat_rule['ipv4']['translated_destination']['name']]
                    elif 'group' in nat_rule['ipv4']['translated_destination']:
                        sonicwall_config['nat'][rule_num]['natPolicyTransDst'] = [
                            nat_rule['ipv4']['translated_destination']['group']]
                    else:
                        sonicwall_config['nat'][rule_num]['natPolicyTransDst'] = ['']
                        self.log('!-- Warning reading NAT TransDst')

                    if 'original' in nat_rule['ipv4']['translated_service']:
                        sonicwall_config['nat'][rule_num]['natPolicyTransSvc'] = ['']
                    elif 'name' in nat_rule['ipv4']['translated_service']:
                        sonicwall_config['nat'][rule_num]['natPolicyTransSvc'] = [
                            nat_rule['ipv4']['translated_service']['name']]
                    elif 'group' in nat_rule['ipv4']['translated_service']:
                        sonicwall_config['nat'][rule_num]['natPolicyTransSvc'] = [
                            nat_rule['ipv4']['translated_service']['group']]
                    else:
                        sonicwall_config['nat'][rule_num]['natPolicyTransSvc'] = ['']
                        self.log('!-- Warning reading NAT TransSvc')

                    sonicwall_config['nat'][rule_num]['natPolicyProperties'] = ''
                    sonicwall_config['nat'][rule_num]['natPolicyUUID'] = nat_rule['ipv4']['uuid']
                    sonicwall_config['nat'][rule_num]['natPolicyComment'] = nat_rule['ipv4']['comment']

                    rule_num_int += 1

                self.log('!-- Reading Address Objects')
                url = 'https://{}/api/sonicos/address-objects/ipv4'.format(ip)
                result = session.get(url=url, data=post_data, verify=False, timeout=self.options.timeout_sw_api)
                addresses_ipv4 = json.loads(result.text)
                self.debug('{:20.20} {:20.20} {}'.format('Length', ' Addresses', len(addresses_ipv4['address_objects'])))
                # self.log(addresses_ipv4['address_objects'][0])
                # {'address_objects': [{'ipv4': {'host': {'ip': '10.211.129.170'}, 'name': 'X0 IP', 'zone': 'LAN', 'uuid': 'cfeeb502-52cf-c94a-0100-c0eae46b8088'}}, {'ipv4': {'name': 'X0 Subnet', 'zone': 'LAN', 'uuid': '8d747ea4-5021-c0a5-0100-c0eae46b8088', 'network': {'mask': '255.255.255.0', 'subnet': '10.211.129.0'}}}, {'ipv4': {'host': {'ip': '97.79.140.147'}, 'name': 'X1 IP', 'zone': 'WAN', 'uuid': 'be2eb811-cb10-b105-0100-c0eae46b8088'}},
                # address_props = ['addrObjId', 'addrObjIdDisp', 'addrObjType', 'addrObjZone', 'addrObjProperties', 'addrObjIp1', 'addrObjIp2', 'addrObjComment']
                for address in addresses_ipv4['address_objects']:
                    self.debug(address)
                    address_name = address['ipv4']['name']
                    sonicwall_config['addresses'][address_name] = OrderedDict()
                    sonicwall_config['addresses'][address_name]['addrObjId'] = address_name
                    sonicwall_config['addresses'][address_name]['addrObjIdDisp'] = address_name
                    sonicwall_config['addresses'][address_name]['addrObjIp1'] = '2.2.2.2'
                    sonicwall_config['addresses'][address_name]['addrObjIp2'] = '3.3.3.3'
                    if 'host' in address['ipv4']:
                        if 'ip' in address['ipv4']['host']:
                            sonicwall_config['addresses'][address_name]['addrObjType'] = '1'
                            sonicwall_config['addresses'][address_name]['addrObjIp1'] = address['ipv4']['host']['ip']
                            sonicwall_config['addresses'][address_name]['addrObjIp2'] = '255.255.255.255'
                        else:
                            sonicwall_config['addresses'][address_name]['addrObjType'] = '1'  # 512
                            sonicwall_config['addresses'][address_name][
                                'addrObjIp1'] = '0.0.0.0'  # placeholder for undefined built in objects
                            sonicwall_config['addresses'][address_name][
                                'addrObjIp2'] = '255.255.255.255'  # placeholder for undefined built in objects
                    if 'range' in address['ipv4']:
                        sonicwall_config['addresses'][address_name]['addrObjType'] = '2'
                        sonicwall_config['addresses'][address_name]['addrObjIp1'] = address['ipv4']['range']['begin']
                        sonicwall_config['addresses'][address_name]['addrObjIp2'] = address['ipv4']['range']['end']
                    if 'network' in address['ipv4']:
                        if 'subnet' in address['ipv4']['network']:
                            sonicwall_config['addresses'][address_name]['addrObjType'] = '4'
                            sonicwall_config['addresses'][address_name]['addrObjIp1'] = address['ipv4']['network'][
                                'subnet']
                            sonicwall_config['addresses'][address_name]['addrObjIp2'] = address['ipv4']['network'][
                                'mask']
                        else:
                            sonicwall_config['addresses'][address_name]['addrObjType'] = '4'  # 2048
                            sonicwall_config['addresses'][address_name][
                                'addrObjIp1'] = '0.0.0.0'  # placeholder for undefined built in objects
                            sonicwall_config['addresses'][address_name][
                                'addrObjIp2'] = '255.255.255.255'  # placeholder for undefined built in objects
                    self.debug(sonicwall_config['addresses'][address_name])

                    if 'zone' in address['ipv4']:
                        sonicwall_config['addresses'][address_name]['addrObjZone'] = address['ipv4']['zone']
                    else:
                        sonicwall_config['addresses'][address_name][
                            'addrObjZone'] = ''  # placeholder for undefined built in objects

                    sonicwall_config['addresses'][address_name]['addrObjProperties'] = ''
                    sonicwall_config['addresses'][address_name]['addrObjComment'] = ''
                    sonicwall_config['addresses'][address_name]['addrObjColor'] = ''
                    sonicwall_config['addresses'][address_name]['addrObjUUID'] = address['ipv4']['uuid']

                self.log('!-- Reading IPv6 Address Objects')
                url = 'https://{}/api/sonicos/address-objects/ipv6'.format(ip)
                result = session.get(url=url, data=post_data, verify=False, timeout=self.options.timeout_sw_api)
                addresses_ipv6 = json.loads(result.text)
                self.debug('{:20.20} {:20.20} {}'.format('Length', ' AddressesV6', len(addresses_ipv6['address_objects'])))
                # self.log(addresses_ipv4['address_objects'][0])
                # addressV6_props = ['addrObjV6Id', 'addrObjV6IdDisp', 'addrObjV6Type', 'addrObjV6Zone', 'addrObjV6Properties', 'addrObjV6Ip1', 'addrObjV6Ip2', 'addrObjV6PrefixLen']

                # {'address_objects': [{'ipv4': {'host': {'ip': '10.211.129.170'}, 'name': 'X0 IP', 'zone': 'LAN', 'uuid': 'cfeeb502-52cf-c94a-0100-c0eae46b8088'}}, {'ipv4': {'name': 'X0 Subnet', 'zone': 'LAN', 'uuid': '8d747ea4-5021-c0a5-0100-c0eae46b8088', 'network': {'mask': '255.255.255.0', 'subnet': '10.211.129.0'}}}, {'ipv4': {'host': {'ip': '97.79.140.147'}, 'name': 'X1 IP', 'zone': 'WAN', 'uuid': 'be2eb811-cb10-b105-0100-c0eae46b8088'}},
                # address_props = ['addrObjId', 'addrObjIdDisp', 'addrObjType', 'addrObjZone', 'addrObjProperties', 'addrObjIp1', 'addrObjIp2', 'addrObjComment']
                for address in addresses_ipv6['address_objects']:
                    # self.debug('IPv6:',address)
                    address_name = address['ipv6']['name']
                    sonicwall_config['addressesV6'][address_name] = OrderedDict()
                    sonicwall_config['addressesV6'][address_name]['addrObjId'] = address_name
                    sonicwall_config['addressesV6'][address_name]['addrObjIdDisp'] = address_name
                    if 'host' in address['ipv6']:
                        sonicwall_config['addressesV6'][address_name]['addrObjType'] = '1'
                        if 'ip' in address['ipv6']['host']:
                            sonicwall_config['addressesV6'][address_name]['addrObjIp1'] = address['ipv6']['host']['ip']
                            sonicwall_config['addressesV6'][address_name]['addrObjIp2'] = '/128'
                            sonicwall_config['addressesV6'][address_name]['addrObjV6PrefixLen'] = '/128'
                        else:
                            sonicwall_config['addressesV6'][address_name][
                                'addrObjIp1'] = '::'  # placeholder for undefined built in objects
                            sonicwall_config['addressesV6'][address_name][
                                'addrObjIp2'] = '::'  # placeholder for undefined built in objects
                            sonicwall_config['addressesV6'][address_name]['addrObjV6PrefixLen'] = '/128'
                    if 'range' in address['ipv6']:
                        sonicwall_config['addressesV6'][address_name]['addrObjType'] = '2'
                        sonicwall_config['addressesV6'][address_name]['addrObjIp1'] = address['ipv6']['host']['ip']
                        sonicwall_config['addressesV6'][address_name]['addrObjIp2'] = address['ipv6']['host']['ip']
                        sonicwall_config['addressesV6'][address_name]['addrObjV6PrefixLen'] = ''
                    if 'network' in address['ipv6']:
                        sonicwall_config['addressesV6'][address_name]['addrObjType'] = '4'
                        if 'subnet' in address['ipv6']['network']:
                            sonicwall_config['addressesV6'][address_name]['addrObjIp1'] = address['ipv6']['network'][
                                'subnet']
                            sonicwall_config['addressesV6'][address_name]['addrObjIp2'] = address['ipv6']['network'][
                                'mask']
                            sonicwall_config['addressesV6'][address_name]['addrObjV6PrefixLen'] = \
                                address['ipv6']['network']['mask']
                        else:
                            sonicwall_config['addressesV6'][address_name][
                                'addrObjIp1'] = '::'  # placeholder for undefined built in objects
                            sonicwall_config['addressesV6'][address_name][
                                'addrObjIp2'] = '::'  # placeholder for undefined built in objects
                            sonicwall_config['addressesV6'][address_name]['addrObjV6PrefixLen'] = '/64'
                    self.debug(sonicwall_config['addressesV6'][address_name])

                    if 'zone' in address['ipv6']:
                        sonicwall_config['addressesV6'][address_name]['addrObjZone'] = address['ipv6']['zone']
                    else:
                        sonicwall_config['addressesV6'][address_name][
                            'addrObjZone'] = ''  # placeholder for undefined built in objects

                    sonicwall_config['addressesV6'][address_name]['addrObjProperties'] = ''
                    sonicwall_config['addressesV6'][address_name]['addrObjComment'] = ''
                    sonicwall_config['addressesV6'][address_name]['addrObjColor'] = ''
                    sonicwall_config['addressesV6'][address_name]['addrObjUUID'] = address['ipv6']['uuid']

                self.log('!-- Reading Address Group Objects')
                url = 'https://{}/api/sonicos/address-groups/ipv4'.format(ip)
                result = session.get(url=url, data=post_data, verify=False, timeout=self.options.timeout_sw_api)
                addresses_groups_ipv4 = json.loads(result.text)
                self.debug('{:20.20} {:20.20} {}'.format('Length', ' Address Groups',
                                                    len(addresses_groups_ipv4['address_groups'])))
                for address_group in addresses_groups_ipv4['address_groups']:
                    address_name = address_group['ipv4']['name']
                    sonicwall_config['addresses'][address_name] = OrderedDict()
                    sonicwall_config['addresses'][address_name]['addrObjId'] = address_name
                    sonicwall_config['addresses'][address_name]['addrObjIdDisp'] = address_name
                    sonicwall_config['addresses'][address_name]['addrObjUUID'] = address_group['ipv4']['uuid']
                    sonicwall_config['addresses'][address_name]['addrObjType'] = '8'
                    sonicwall_config['addresses'][address_name]['addrObjZone'] = ''
                    sonicwall_config['addresses'][address_name]['addrObjProperties'] = ''
                    sonicwall_config['addresses'][address_name]['addrObjIp1'] = '0.0.0.0'
                    sonicwall_config['addresses'][address_name]['addrObjIp2'] = '0.0.0.0'
                    sonicwall_config['addresses'][address_name]['addrObjComment'] = ''
                    sonicwall_config['addresses'][address_name]['addrObjColor'] = ''

                    sonicwall_config['addressmappings'][address_name] = []
                    self.debug(address_group)
                    try:
                        if 'address_object' in address_group['ipv4']:
                            for address_object in address_group['ipv4']['address_object']['ipv4']:
                                sonicwall_config['addressmappings'][address_name].append(address_object['name'])
                    except:
                        pass
                    try:
                        if 'address_group' in address_group['ipv4']:
                            for address_object in address_group['ipv4']['address_group']['ipv4']:
                                sonicwall_config['addressmappings'][address_name].append(address_object['name'])
                    except:
                        pass
                    try:
                        if 'fqdn' in address_group['ipv4']['address_object']:
                            for address_object in address_group['ipv4']['address_object']['fqdn']:
                                sonicwall_config['addressmappings'][address_name].append(address_object['name'])
                    except:
                        pass

                    # self.log(x)
                    # self.log(addresses_groups_ipv4['address_groups'][0])
                # {'ipv4': {'address_object': {'ipv4': [{'name': 'X0 Subnet'}]}, 'uuid': '9b9b3c30-59f7-f1d4-0200-c0eae46b8088', 'name': 'LAN Subnets'}}

                sonicwall_config['addresses'] = self.service.add_IPv4Network(sonicwall_config['addresses'])

                self.log('!-- Reading IPv6 Address Group Objects')
                url = 'https://{}/api/sonicos/address-groups/ipv6'.format(ip)
                result = session.get(url=url, data=post_data, verify=False, timeout=self.options.timeout_sw_api)
                addresses_groups_ipv6 = json.loads(result.text)
                self.debug('{:20.20} {:20.20} {}'.format('Length', ' Address GroupsV6',
                                                    len(addresses_groups_ipv4['address_groups'])))
                for address_group in addresses_groups_ipv6['address_groups']:
                    self.debug('IPv6:', address_group)
                    address_name = address_group['ipv6']['name']
                    sonicwall_config['addressesV6'][address_name] = OrderedDict()
                    sonicwall_config['addressesV6'][address_name]['addrObjId'] = address_name
                    sonicwall_config['addressesV6'][address_name]['addrObjIdDisp'] = address_name
                    sonicwall_config['addressesV6'][address_name]['addrObjUUID'] = address_group['ipv6']['uuid']
                    sonicwall_config['addressesV6'][address_name]['addrObjType'] = '8'
                    sonicwall_config['addressesV6'][address_name]['addrObjZone'] = ''
                    sonicwall_config['addressesV6'][address_name]['addrObjProperties'] = ''
                    sonicwall_config['addressesV6'][address_name]['addrObjIp1'] = '::'
                    sonicwall_config['addressesV6'][address_name]['addrObjIp2'] = '::'
                    sonicwall_config['addressesV6'][address_name]['addrObjComment'] = ''
                    sonicwall_config['addressesV6'][address_name]['addrObjColor'] = ''

                    sonicwall_config['addressmappings'][address_name] = []
                    try:
                        if 'address_object' in address_group['ipv6']:
                            for address_object in address_group['ipv6']['address_object']['ipv6']:
                                sonicwall_config['addressmappings'][address_name].append(address_object['name'])
                        # for address_object in address_group['ipv4']['address_object']['ipv6']:
                    except:
                        pass
                    try:
                        if 'address_group' in address_group['ipv6']:
                            for address_object in address_group['ipv6']['address_group']['ipv6']:
                                # self.debug(address_object)
                                sonicwall_config['addressmappings'][address_name].append(address_object['name'])
                    except:
                        pass
                    try:
                        if 'fqdn' in address_group['ipv6']['address_object']:
                            for address_object in address_group['ipv6']['address_object']['fqdn']:
                                sonicwall_config['addressmappings'][address_name].append(address_object['name'])
                    except:
                        pass

                self.log('!-- Reading Address FQDN Objects')
                url = 'https://{}/api/sonicos/address-objects/fqdn'.format(ip)
                result = session.get(url=url, data=post_data, verify=False, timeout=self.options.timeout_sw_api)
                # self.log(result.text)
                addresses_fqdn = json.loads(result.text)
                # self.log(addresses_fqdn['address_objects'][0])
                # {'fqdn': {'name': 'Syslog Server(0): austlrr2csdep01.us.dell.com',
                # 'uuid': '9902ae74-9724-c051-0100-c0eae46b8088', 'domain': 'austlrr2csdep01.us.dell.com', 'dns_ttl': 0}}
                # addressfqdn_props = ['addrObjFqdnId', 'addrObjFqdnType', 'addrObjFqdnZone', 'addrObjFqdnProperties', 'addrObjFqdn']
                # self.log(addresses_fqdn)
                if 'address_objects' in addresses_fqdn:
                    for address_fqdn in addresses_fqdn['address_objects']:
                        try:
                            address_name = address_fqdn['fqdn']['name']
                            sonicwall_config['addressesfqdn'][address_name] = OrderedDict()
                            sonicwall_config['addressesfqdn'][address_name]['addrObjFqdnId'] = address_fqdn['fqdn'][
                                'name']
                            sonicwall_config['addressesfqdn'][address_name][
                                'addrObjFqdnType'] = ''  # address_fqdn['fqdn']
                            sonicwall_config['addressesfqdn'][address_name]['addrObjFqdnTTL'] = address_fqdn['fqdn'][
                                'dns_ttl']
                            sonicwall_config['addressesfqdn'][address_name]['addrObjFqdn'] = address_fqdn['fqdn'][
                                'domain']
                            sonicwall_config['addressesfqdn'][address_name]['addrObjFqdnUUID'] = address_fqdn['fqdn'][
                                'uuid']
                            if 'zone' in address_fqdn['fqdn']:
                                sonicwall_config['addressesfqdn'][address_name]['addrObjFqdnZone'] = \
                                    address_fqdn['fqdn'][
                                        'zone']
                            else:
                                sonicwall_config['addressesfqdn'][address_name]['addrObjFqdnZone'] = ''
                            # self.log('-'*180)
                            # self.log(sonicwall_config['addressesfqdn'][address_name])
                        except Exception as e:
                            self.log(e)

                self.log('!-- Reading Service Objects')
                url = 'https://{}/api/sonicos/service-objects'.format(ip)
                result = session.get(url=url, data=post_data, verify=False, timeout=self.options.timeout_sw_api)
                services = json.loads(result.text)
                self.debug('{:20.20} {:20.20} {}'.format('Length', ' Services', len(services['service_objects'])))
                # {'name': 'HTTP', 'uuid': 'f40b27d6-b8b9-a4fc-0300-c0eae46b8088', 'tcp': {'end': 80, 'begin': 80}}
                #   service_props = ['svcObjId', 'svcObjType', 'svcObjProperties', 'svcObjIpType', 'svcObjPort1', 'svcObjPort2', 'svcObjManagement', 'svcObjHigherPrecedence', 'svcObjComment']
                icmp_types = {'redirect': '5',
                              'echo-reply': '0',
                              'echo-request': '8',
                              'timestamp': '13',
                              'timestamp-reply': '14',
                              'alternative-host': '6'

                              }
                for service in services['service_objects']:
                    self.debug(service)
                    service_name = service['name']
                    sonicwall_config['services'][service_name] = OrderedDict()
                    sonicwall_config['services'][service_name]['svcObjId'] = service_name
                    sonicwall_config['services'][service_name]['svcObjComment'] = ''
                    sonicwall_config['services'][service_name]['svcObjHigherPrecedence'] = 'off'
                    sonicwall_config['services'][service_name]['svcObjManagement'] = '0'
                    sonicwall_config['services'][service_name]['svcObjProperties'] = '0'
                    sonicwall_config['services'][service_name]['svcObjSrcPort'] = '0'

                    if 'tcp' in service:
                        sonicwall_config['services'][service_name]['svcObjType'] = '6'
                        sonicwall_config['services'][service_name]['svcObjIpType'] = '6'
                        sonicwall_config['services'][service_name]['svcObjPort1'] = str(service['tcp']['begin'])
                        sonicwall_config['services'][service_name]['svcObjPort2'] = str(service['tcp']['end'])
                        sonicwall_config['services'][service_name]['svcObjUUID'] = service['uuid']
                    elif 'udp' in service:
                        sonicwall_config['services'][service_name]['svcObjType'] = '17'
                        sonicwall_config['services'][service_name]['svcObjIpType'] = '17'
                        sonicwall_config['services'][service_name]['svcObjPort1'] = str(service['udp']['begin'])
                        sonicwall_config['services'][service_name]['svcObjPort2'] = str(service['udp']['end'])
                        sonicwall_config['services'][service_name]['svcObjUUID'] = service['uuid']
                    elif 'icmp' in service:
                        sonicwall_config['services'][service_name]['svcObjType'] = '1'
                        sonicwall_config['services'][service_name]['svcObjIpType'] = '1'
                        sonicwall_config['services'][service_name]['svcObjPort1'] = service['icmp']
                        sonicwall_config['services'][service_name]['svcObjPort2'] = service['icmp']
                        sonicwall_config['services'][service_name]['svcObjUUID'] = service['uuid']
                    elif 'icmpv6' in service:
                        sonicwall_config['services'][service_name]['svcObjType'] = '99'
                        sonicwall_config['services'][service_name]['svcObjIpType'] = '99'
                        sonicwall_config['services'][service_name]['svcObjPort1'] = service['icmpv6']
                        sonicwall_config['services'][service_name]['svcObjPort2'] = ''
                        sonicwall_config['services'][service_name]['svcObjUUID'] = service['uuid']
                    elif 'igmp' in service:
                        sonicwall_config['services'][service_name]['svcObjType'] = '99'
                        sonicwall_config['services'][service_name]['svcObjIpType'] = '99'
                        sonicwall_config['services'][service_name]['svcObjPort1'] = service['igmp']
                        sonicwall_config['services'][service_name]['svcObjPort2'] = ''
                        sonicwall_config['services'][service_name]['svcObjUUID'] = service['uuid']
                    elif 'esp' in service:
                        sonicwall_config['services'][service_name]['svcObjType'] = '99'
                        sonicwall_config['services'][service_name]['svcObjIpType'] = '99'
                        sonicwall_config['services'][service_name]['svcObjPort1'] = service['esp']
                        sonicwall_config['services'][service_name]['svcObjPort2'] = ''
                        sonicwall_config['services'][service_name]['svcObjUUID'] = service['uuid']
                    elif 'gre' in service:
                        sonicwall_config['services'][service_name]['svcObjType'] = '47'
                        sonicwall_config['services'][service_name]['svcObjIpType'] = '47'
                        sonicwall_config['services'][service_name]['svcObjPort1'] = '1'  # service['gre']
                        sonicwall_config['services'][service_name]['svcObjPort2'] = '65535'
                        sonicwall_config['services'][service_name]['svcObjUUID'] = service['uuid']
                    elif '6over4' in service:
                        sonicwall_config['services'][service_name]['svcObjType'] = '41'
                        sonicwall_config['services'][service_name]['svcObjIpType'] = '41'
                        sonicwall_config['services'][service_name]['svcObjPort1'] = '1'  # service['6over4']
                        sonicwall_config['services'][service_name]['svcObjPort2'] = '1'
                        sonicwall_config['services'][service_name]['svcObjUUID'] = service['uuid']
                    elif 'ipcomp' in service:
                        sonicwall_config['services'][service_name]['svcObjType'] = '108'
                        sonicwall_config['services'][service_name]['svcObjIpType'] = '108'
                        sonicwall_config['services'][service_name]['svcObjPort1'] = '1'  # service['ipcomp']
                        sonicwall_config['services'][service_name]['svcObjPort2'] = '1'
                        sonicwall_config['services'][service_name]['svcObjUUID'] = service['uuid']
                    else:
                        sonicwall_config['services'][service_name]['svcObjType'] = '99'
                        sonicwall_config['services'][service_name]['svcObjIpType'] = '99'
                        sonicwall_config['services'][service_name]['svcObjPort1'] = '99'
                        sonicwall_config['services'][service_name]['svcObjPort2'] = ''
                        sonicwall_config['services'][service_name]['svcObjUUID'] = service['uuid']
                        self.debug(service)
                        # if sonicwall_config['services'][service_name]['svcObjPort1'] == sonicwall_config['services'][service_name]['svcObjPort2']:  ## if service object type a single port or range
                    sonicwall_config['services'][service_name]['svcObjType'] = '1'
                    # else:
                    #    sonicwall_config['services'][service_name]['svcObjType']='2'

                self.log('!-- Reading Service Group Objects')
                url = 'https://{}/api/sonicos/service-groups'.format(ip)
                result = session.get(url=url, data=post_data, verify=False, timeout=self.options.timeout_sw_api)
                service_groups = json.loads(result.text)
                # self.log(json.dumps(service_groups['service_groups'], indent=3))
                # {'name': 'HTTP', 'uuid': 'f40b27d6-b8b9-a4fc-0300-c0eae46b8088', 'tcp': {'end': 80, 'begin': 80}}
                #   service_props = ['svcObjId', 'svcObjType', 'svcObjProperties', 'svcObjIpType', 'svcObjPort1', 'svcObjPort2', 'svcObjManagement', 'svcObjHigherPrecedence', 'svcObjComment']
                self.debug('{:20.20} {:20.20} {}'.format('Length', ' Service Groups', len(service_groups['service_groups'])))
                self.debug(service_groups)
                for service in service_groups['service_groups']:
                    # self.log(service)
                    service_name = service['name']
                    sonicwall_config['services'][service_name] = OrderedDict()
                    sonicwall_config['services'][service_name]['svcObjId'] = service_name
                    sonicwall_config['services'][service_name]['svcObjType'] = '2'
                    sonicwall_config['services'][service_name]['svcObjIpType'] = '0'

                    sonicwall_config['servicemappings'][service_name] = []
                    if 'service_object' in service:
                        for service_object in service['service_object']:
                            sonicwall_config['servicemappings'][service_name].append(service_object['name'])
                            # self.log(service_object['name'])
                    if 'service_group' in service:
                        for service_group in service['service_group']:
                            # self.log(service_group['name'])
                            sonicwall_config['servicemappings'][service_name].append(service_group['name'])

                self.log('!-- Reading Interface Objects')
                url = 'https://{}/api/sonicos/interfaces/ipv4'.format(ip)
                result = session.get(url=url, data=post_data, verify=False, timeout=self.options.timeout_sw_api)
                interfaces_ipv4 = json.loads(result.text)
                # self.log(interfaces_ipv4['interfaces'][0])
                # {'ipv4': {'routed_mode': {}, 'auto_discovery': False, 'flow_reporting': True, 'comment': 'Default LAN', 'name': 'X0', 'port': {'redundancy_aggregation': False}, 'user_login': {'https': False}, 'https_redirect': True, 'cos_8021p': False, 'ip_assignment': {'zone': 'LAN', 'mode': {'static': {'netmask': '255.255.255.0', 'ip': '10.211.129.170', 'gateway': '10.211.129.1'}}}, 'management': {'snmp': False, 'https': True, 'ping': True, 'ssh': True}, 'mtu': 1500, 'multicast': False, 'asymmetric_route': False, 'link_speed': {'auto_negotiate': True}, 'exclude_route': False, 'shutdown_port': False, 'mac': {'default': True}}}
                # interface_props = ['iface_ifnum', 'iface_type', 'iface_name', 'interface_Zone', 'iface_comment', 'iface_static_ip', 'iface_static_mask', 'iface_static_gateway', 'iface_lan_ip', 'iface_lan_mask', 'iface_lan_default_gw', 'iface_mgmt_ip', 'iface_mgmt_netmask', 'iface_mgmt_default_gw', 'iface_static_gateway', 'iface_vlan_tag', 'iface_comment', 'iface_http_mgmt',
                # 'iface_https_mgmt', 'iface_ssh_mgmt', 'iface_ping_mgmt', 'iface_snmp_mgmt', 'portShutdown']
                interface_num_int = 0
                for interface in interfaces_ipv4['interfaces']:
                    interface_num = str(interface_num_int)
                    self.debug(interface)
                    sonicwall_config['interfaces'][interface_num] = OrderedDict()
                    sonicwall_config['interfaces'][interface_num]['iface_name'] = interface['ipv4']['name']
                    sonicwall_config['interfaces'][interface_num]['iface_ifnum'] = str(interface_num)
                    sonicwall_config['interfaces'][interface_num]['portShutdown'] = '0'
                    sonicwall_config['interfaces'][interface_num]['interface_Zone'] = ''
                    sonicwall_config['interfaces'][interface_num]['iface_vlan_tag'] = ''
                    sonicwall_config['interfaces'][interface_num]['iface_static_ip'] = '0.0.0.0'
                    sonicwall_config['interfaces'][interface_num]['iface_static_mask'] = '255.255.255.0'
                    sonicwall_config['interfaces'][interface_num]['iface_static_gateway'] = '255.255.255.0'
                    sonicwall_config['interfaces'][interface_num]['iface_lan_ip'] = '0.0.0.0'
                    sonicwall_config['interfaces'][interface_num]['iface_lan_mask'] = '255.255.255.0'
                    sonicwall_config['interfaces'][interface_num]['iface_lan_default_gw'] = '255.255.255.0'
                    sonicwall_config['interfaces'][interface_num]['iface_mgmt_ip'] = '0.0.0.0'
                    sonicwall_config['interfaces'][interface_num]['iface_mgmt_netmask'] = '255.255.255.0'
                    sonicwall_config['interfaces'][interface_num]['iface_mgmt_default_gw'] = '255.255.255.0'
                    sonicwall_config['interfaces'][interface_num]['iface_static_gateway'] = ''
                    sonicwall_config['interfaces'][interface_num]['iface_http_mgmt'] = '0'
                    sonicwall_config['interfaces'][interface_num]['iface_https_mgmt'] = '0'
                    sonicwall_config['interfaces'][interface_num]['iface_ssh_mgmt'] = '0'
                    sonicwall_config['interfaces'][interface_num]['iface_ping_mgmt'] = '0'
                    sonicwall_config['interfaces'][interface_num]['iface_snmp_mgmt'] = '0'

                    # sonicwall_config['interfaces'][interface_num][''iface_vlan_tag'']=interface['ipv4']['']

                    if 'vlan' in interface:
                        sonicwall_config['interfaces'][interface_num]['iface_vlan_tag'] = interface['vlan']
                    if 'mode' in interface['ipv4']['ip_assignment']:
                        sonicwall_config['interfaces'][interface_num]['interface_Zone'] = \
                            interface['ipv4']['ip_assignment']['zone']
                        if 'static' in interface['ipv4']['ip_assignment']['mode']:
                            self.debug('STATIC!!!')
                            sonicwall_config['interfaces'][interface_num]['iface_static_ip'] = \
                                interface['ipv4']['ip_assignment']['mode']['static']['ip']
                            sonicwall_config['interfaces'][interface_num]['iface_static_mask'] = \
                                interface['ipv4']['ip_assignment']['mode']['static']['netmask']
                            sonicwall_config['interfaces'][interface_num]['iface_static_gateway'] = \
                                interface['ipv4']['ip_assignment']['mode']['static']['gateway']

                    # sonicwall_config['interfaces'][interface_num]['iface_type']=interface['ipv4']['']
                    # sonicwall_config['interfaces'][interface_num]['interface_Zone']=interface['ipv4']['']

                    if 'comment' in interface['ipv4']:
                        sonicwall_config['interfaces'][interface_num]['iface_comment'] = interface['ipv4']['comment']
                    else:
                        sonicwall_config['interfaces'][interface_num]['iface_comment'] = ''

                    if 'management' in interface['ipv4']:
                        if 'http' in interface['ipv4']['management']:
                            if interface['ipv4']['management']['http']:
                                sonicwall_config['interfaces'][interface_num]['iface_http_mgmt'] = '1'
                        if interface['ipv4']['management']['https']:
                            sonicwall_config['interfaces'][interface_num]['iface_https_mgmt'] = '1'
                        if interface['ipv4']['management']['ssh']:
                            sonicwall_config['interfaces'][interface_num]['iface_ssh_mgmt'] = '1'
                        if interface['ipv4']['management']['ping']:
                            sonicwall_config['interfaces'][interface_num]['iface_ping_mgmt'] = '1'
                        if interface['ipv4']['management']['snmp']:
                            sonicwall_config['interfaces'][interface_num]['iface_snmp_mgmt'] = '1'

                    if 'shutdown_port' in interface['ipv4']:
                        if interface['ipv4']['shutdown_port']:
                            sonicwall_config['interfaces'][interface_num]['portShutdown'] = '1'
                    else:
                        sonicwall_config['interfaces'][interface_num]['portShutdown'] = '0'

                    # sonicwall_config['interfaces'][interface_num]['uuid']=interface['ipv4']['uuid']  ## no uuid for interfaces

                    interface_num_int += 1

                if pbrResult:
                    if pbrResult.status_code == 200:
                        self.log('!-- Reading Routing Objects via WebUI table')
                        # routing_props = ['pbrObjId', 'pbrObjProperties', 'pbrObjSrc', 'pbrObjDst', 'pbrObjSvc', 'pbrObjGw', 'pbrObjIface', 'pbrObjIfaceName', 'pbrObjMetric', 'pbrObjPriority', 'pbrObjProbe', 'pbrObjComment']
                        pbrindex = 0
                        for index, entry in enumerate(json.loads(pbrResult.text)['pbrPolicies'].split('|')[1:]):
                            # self.log(index, entry)
                            name, properties, metric, distance, distanceAuto, priority, source, destination, service, applicationID, application, tos, tosMask, nexthopNum, \
                            gateway, gatewayVer, iface, ifName, ifaceStatus, gateway2, gatewayVer2, iface2, ifName2, ifaceStatus2, gateway3, gatewayVer3, iface3, ifName3, ifaceStatus3, \
                            gateway4, gatewayVer4, iface4, ifName4, ifaceStatus4, comment, probe, ipver, wxaGroup, uuid, rtype, psp, sdwanGroup, entryIndex = entry.split(
                                ',')
                            if ipver == '0':  ## 0 is IPv4 - do not read IPv6 routes at this time
                                # self.log([x for x in sonicwall_config['addresses']])
                                destination = destination.strip('"')
                                source = source.strip('"')
                                service = service.strip('"')
                                gateway = gateway.strip('"')
                                ifName = ifName.strip('"')
                                if destination == '':  destination = '0.0.0.0/0'
                                # self.log('"{}"'.format(destination))
                                if source in sonicwall_config['addresses']:
                                    source = '{}/{}'.format(sonicwall_config['addresses'][source]['addrObjIp1'],
                                                            self.service.netmask_to_cidr(
                                                                sonicwall_config['addresses'][source]['addrObjIp2']))
                                if gateway in sonicwall_config['addresses']:
                                    gateway = '{}'.format(sonicwall_config['addresses'][gateway]['addrObjIp1'])
                                if destination in sonicwall_config['addresses']:
                                    # self.log('Destination in Address objects - expand it!')
                                    # self.log(expand_address(sonicwall_config['addresses'], destination, sonicwall_config['addressmappings'], inc_group=False))
                                    for each_dest in self.createNetworkService.expand_address(sonicwall_config['addresses'], destination,
                                                                    sonicwall_config['addressmappings'],
                                                                    inc_group=False):
                                        # self.log(each_dest, pbrindex)
                                        sonicwall_config['routing'][pbrindex] = OrderedDict()
                                        sonicwall_config['routing'][pbrindex]['pbrObjId'] = name
                                        sonicwall_config['routing'][pbrindex]['pbrObjProperties'] = properties
                                        sonicwall_config['routing'][pbrindex]['pbrObjSrc'] = source
                                        sonicwall_config['routing'][pbrindex]['pbrObjDst'] = '{}/{}'.format(
                                            sonicwall_config['addresses'][each_dest]['addrObjIp1'],
                                            self.service.netmask_to_cidr(sonicwall_config['addresses'][each_dest]['addrObjIp2']))
                                        sonicwall_config['routing'][pbrindex]['pbrObjSvc'] = service
                                        sonicwall_config['routing'][pbrindex]['pbrObjGw'] = gateway
                                        sonicwall_config['routing'][pbrindex]['pbrObjIface'] = iface
                                        sonicwall_config['routing'][pbrindex]['pbrObjIfaceName'] = ifName
                                        sonicwall_config['routing'][pbrindex]['pbrObjMetric'] = metric
                                        sonicwall_config['routing'][pbrindex]['pbrObjPriority'] = priority
                                        sonicwall_config['routing'][pbrindex]['pbrObjProbe'] = probe
                                        sonicwall_config['routing'][pbrindex]['pbrObjComment'] = comment
                                        sonicwall_config['routing'][pbrindex]['pbrObjUUID'] = uuid
                                        # self.log(sonicwall_config['routing'][index]['pbrObjDst'], ipver)
                                        pbrindex += 1

                                else:
                                    # self.log('Destination not in Address objects - use as is!')
                                    # self.log(destination, pbrindex)
                                    sonicwall_config['routing'][pbrindex] = OrderedDict()
                                    sonicwall_config['routing'][pbrindex]['pbrObjId'] = name
                                    sonicwall_config['routing'][pbrindex]['pbrObjProperties'] = properties
                                    sonicwall_config['routing'][pbrindex]['pbrObjSrc'] = source
                                    sonicwall_config['routing'][pbrindex]['pbrObjDst'] = destination
                                    sonicwall_config['routing'][pbrindex]['pbrObjSvc'] = service
                                    sonicwall_config['routing'][pbrindex]['pbrObjGw'] = gateway
                                    sonicwall_config['routing'][pbrindex]['pbrObjIface'] = iface
                                    sonicwall_config['routing'][pbrindex]['pbrObjIfaceName'] = ifName
                                    sonicwall_config['routing'][pbrindex]['pbrObjMetric'] = metric
                                    sonicwall_config['routing'][pbrindex]['pbrObjPriority'] = priority
                                    sonicwall_config['routing'][pbrindex]['pbrObjProbe'] = probe
                                    sonicwall_config['routing'][pbrindex]['pbrObjComment'] = comment
                                    sonicwall_config['routing'][pbrindex]['pbrObjUUID'] = uuid
                                    pbrindex += 1
                                # self.log(config['sonicwall'])
                                # self.log(sonicwall_config['routing'][index]['pbrObjDst'], ipver)
                    else:
                        pbrResult = None

                if pbrResult == None:

                    ## only read using API is using WebUI failed
                    self.log('!-- Reading Routing Objects via API')
                    url = 'https://{}/api/sonicos/route-policies/ipv4'.format(ip)
                    result = session.get(url=url, data=post_data, verify=False, timeout=self.options.timeout_sw_api)
                    routing_ipv4 = json.loads(result.text)
                    # self.log(routing_ipv4['route_policies'][0])
                    # {'ipv4': {'source': {'any': True}, 'comment': '', 'interface': 'MGMT', 'name': 'ldap', 'vpn_precedence': False, 'service': {'any': True}, 'uuid': '00000000-0000-0001-0900-c0eae46b8088', 'metric': 1, 'gateway': {'name': 'MGMT Default Gateway'}, 'disable_on_interface_down': True, 'probe': '', 'destination': {'any': True}, 'wxa_group': ''}}
                    # routing_props = ['pbrObjId', 'pbrObjProperties', 'pbrObjSrc', 'pbrObjDst', 'pbrObjSvc', 'pbrObjGw', 'pbrObjIface', 'pbrObjIfaceName', 'pbrObjMetric', 'pbrObjPriority', 'pbrObjProbe', 'pbrObjComment']
                    ## need more details to read pbrObjSvc value

                    route_num_int = 0
                    for route in routing_ipv4['route_policies']:
                        route_num = str(route_num_int)
                        # self.debug("ROUTE", route['ipv4']['gateway'])

                        sonicwall_config['routing'][route_num] = OrderedDict()
                        sonicwall_config['routing'][route_num]['pbrObjId'] = route['ipv4']['name']
                        sonicwall_config['routing'][route_num]['pbrObjProperties'] = ''

                        if 'name' in route['ipv4']['source']:
                            sonicwall_config['routing'][route_num]['pbrObjSrc'] = route['ipv4']['source']['name']
                        else:
                            sonicwall_config['routing'][route_num]['pbrObjSrc'] = ''

                        if 'name' in route['ipv4']['destination']:
                            sonicwall_config['routing'][route_num]['pbrObjDst'] = route['ipv4']['destination']['name']
                        elif 'group' in route['ipv4']['destination']:
                            sonicwall_config['routing'][route_num]['pbrObjDst'] = route['ipv4']['destination']['group']
                        else:
                            sonicwall_config['routing'][route_num]['pbrObjDst'] = ''
                        try:
                            if 'name' in route['ipv4']['gateway']:
                                sonicwall_config['routing'][route_num]['pbrObjGw'] = route['ipv4']['gateway']['name']
                                # self.debug("ROUTE2", route['ipv4']['gateway'])
                            else:
                                sonicwall_config['routing'][route_num]['pbrObjGw'] = ''
                        except:
                            sonicwall_config['routing'][route_num]['pbrObjGw'] = '0.0.0.0'
                            # self.log(route['ipv4'])

                        sonicwall_config['routing'][route_num]['pbrObjIface'] = route['ipv4']['interface']
                        sonicwall_config['routing'][route_num]['pbrObjIfaceName'] = route['ipv4']['interface']
                        sonicwall_config['routing'][route_num]['pbrObjMetric'] = str(route['ipv4']['metric'])
                        sonicwall_config['routing'][route_num]['pbrObjPriority'] = ''
                        sonicwall_config['routing'][route_num]['pbrObjProbe'] = route['ipv4']['probe']
                        sonicwall_config['routing'][route_num]['pbrObjComment'] = route['ipv4']['comment']
                        sonicwall_config['routing'][route_num]['pbrObjUUID'] = route['ipv4']['uuid']
                        sonicwall_config['routing'][route_num]['pbrObjSvc'] = ''
                        route_num_int += 1

                    # Set default route to WAN/X1 interface
                    for interface_index in sonicwall_config['interfaces']:
                        # self.log(interface_index, sonicwall_config['interfaces'][interface_index]['iface_name'], sonicwall_config['interfaces'][interface_index]['portShutdown'])
                        if sonicwall_config['interfaces'][interface_index]['iface_name'] == 'X1' and \
                                sonicwall_config['interfaces'][interface_index]['portShutdown'] == '0':
                            sonicwall_config['routing'][route_num] = OrderedDict()
                            sonicwall_config['routing'][route_num]['pbrObjId'] = 'Default Route'
                            sonicwall_config['routing'][route_num]['pbrObjProperties'] = ''
                            sonicwall_config['routing'][route_num]['pbrObjSrc'] = ''
                            sonicwall_config['routing'][route_num]['pbrObjDst'] = '0.0.0.0'
                            sonicwall_config['routing'][route_num]['pbrObjGw'] = \
                                sonicwall_config['interfaces'][interface_index]['iface_static_gateway']
                            sonicwall_config['routing'][route_num]['pbrObjIface'] = 'X1'
                            sonicwall_config['routing'][route_num]['pbrObjIfaceName'] = 'X1'
                            sonicwall_config['routing'][route_num]['pbrObjMetric'] = '10'
                            sonicwall_config['routing'][route_num]['pbrObjPriority'] = ''
                            sonicwall_config['routing'][route_num]['pbrObjProbe'] = ''
                            sonicwall_config['routing'][route_num]['pbrObjComment'] = 'Auto-Added Default Route'
                            sonicwall_config['routing'][route_num]['pbrObjUUID'] = ''
                            sonicwall_config['routing'][route_num]['pbrObjSvc'] = ''
                            # self.log(sonicwall_config['routing'][route_num])
                            break
                    # self.log(json.dumps(sonicwall_config['routing'], indent=4))

                self.log('!-- Reading Zone Objects')
                url = 'https://{}/api/sonicos/zones'.format(ip)
                result = session.get(url=url, data=post_data, verify=False, timeout=self.options.timeout_sw_api)
                zones = json.loads(result.text)
                # self.log(zones['zones'][0])
                # {'create_group_vpn': False, 'intrusion_prevention': True, 'name': 'LAN', 'client': {'anti_virus': False, 'content_filtering': False}, 'auto_generate_access_rules': {'allow_from_to_equal': True, 'allow_to_lower': True, 'allow_from_higher': True, 'deny_from_lower': True}, 'dpi_ssl_client': True, 'sslvpn_access': False, 'guest_services': {}, 'interface_trust': True, 'uuid': '2ecd17a0-73de-dc8b-0a00-c0eae46b8088', 'ssl_control': False, 'gateway_anti_virus': True, 'security_type': 'trusted', 'app_control': True, 'anti_spyware': True, 'dpi_ssl_server': False}
                # zone_props = ['zoneObjId', 'zoneObjComment']
                for zone in zones['zones']:
                    zone_name = zone['name']
                    sonicwall_config['zones'][zone_name] = OrderedDict()
                    sonicwall_config['zones'][zone_name]['zoneObjId'] = zone_name
                    sonicwall_config['zones'][zone_name]['zoneObjComment'] = ''
                    sonicwall_config['zones'][zone_name]['zoneObjUUID'] = zone['uuid']

                sonicwall_config['usedzones'] = []
                for interface in sonicwall_config['interfaces']:
                    if sonicwall_config['interfaces'][interface]['interface_Zone'] != '':
                        sonicwall_config['usedzones'].append(
                            sonicwall_config['interfaces'][interface]['interface_Zone'])
            else:
                self.log('Unable to retrieve configuration via API')
            # Add IPset property to groups
            for addr in sonicwall_config['addresses']:
                if sonicwall_config['addresses'][addr]['addrObjType'] == '8':
                    sonicwall_config['addresses'][addr]['IPSet'] = IPSet([])
                    for groupmember in self.createNetworkService.expand_address(sonicwall_config['addresses'], addr,
                                                      sonicwall_config['addressmappings']):
                        self.debug(groupmember)
                        self.debug(sonicwall_config['addresses'][groupmember])
                        for network in sonicwall_config['addresses'][groupmember]['IPv4Networks']:
                            sonicwall_config['addresses'][addr]['IPSet'].add(str(network))
        else:
            self.log('!-- API not enabled for target device {} Configuration not loaded.'.format(ip))

        sonicwall_config['config']['name'] = ''  # context  ## CHANGEME (how do I get firewall name)
        sonicwall_config['config']['version'] = ''
        sonicwall_config['config']['fw_type'] = 'sw65'
        sonicwall_config['config']['mgmtip'] = ip

        if api_enabled and revert_api:
            self.sw_disable_api(ip, username, password)
            api_status = self.sw_get_api_status(ip, username, password)
            if api_status:
                self.log('!-- Sonicwall API disablement failed')
            else:
                self.log('!-- Sonicwall API disablement successful')

        try:
            url = 'https://{}/api/sonicos/auth'.format(ip)
            session.delete(url=url, verify=False, timeout=self.options.timeout_sw_webui)
        except:
            pass

        return sonicwall_config

    def load_sonicwall(self, infile, skipdisabled, memoryconfig=None):
        configfilename = "config_python.txt"
        address_props = ['addrObjId', 'addrObjIdDisp', 'addrObjType', 'addrObjZone', 'addrObjProperties', 'addrObjIp1',
                         'addrObjIp2', 'addrObjComment']
        addressfqdn_props = ['addrObjFqdnId', 'addrObjFqdnType', 'addrObjFqdnZone', 'addrObjFqdnProperties',
                             'addrObjFqdn']
        service_props = ['svcObjId', 'svcObjType', 'svcObjProperties', 'svcObjIpType', 'svcObjPort1', 'svcObjPort2',
                         'svcObjManagement', 'svcObjHigherPrecedence', 'svcObjComment']
        zone_props = ['zoneObjId', 'zoneObjComment']
        policy_props = ['policyAction', 'policySrcZone', 'policyDstZone', 'policySrcNet', 'policyDstNet',
                        'policyDstSvc',
                        'policyDstApps', 'policyComment', 'policyLog', 'policyEnabled', 'policyProps']
        interface_props = ['iface_ifnum', 'iface_type', 'iface_name', 'interface_Zone', 'iface_comment',
                           'iface_static_ip',
                           'iface_static_mask', 'iface_static_gateway', 'iface_lan_ip', 'iface_lan_mask',
                           'iface_lan_default_gw', 'iface_mgmt_ip', 'iface_mgmt_netmask', 'iface_mgmt_default_gw',
                           'iface_static_gateway', 'iface_vlan_tag', 'iface_comment', 'iface_http_mgmt',
                           'iface_https_mgmt',
                           'iface_ssh_mgmt', 'iface_ping_mgmt', 'iface_snmp_mgmt', 'portShutdown']
        routing_props = ['pbrObjId', 'pbrObjProperties', 'pbrObjSrc', 'pbrObjDst', 'pbrObjSvc', 'pbrObjGw',
                         'pbrObjIface',
                         'pbrObjIfaceName', 'pbrObjMetric', 'pbrObjPriority', 'pbrObjProbe', 'pbrObjComment']
        nat_props = ['natPolicyOrigSrc', 'natPolicyOrigDst', 'natPolicyOrigSvc', 'natPolicyTransSrc',
                     'natPolicyTransDst',
                     'natPolicyTransSvc', 'natPolicySrcIface', 'natPolicyDstIface', 'natPolicyEnabled',
                     'natPolicyComment',
                     'natPolicyProperties', 'natPolicyName']
        addressV6_props = ['addrObjV6Id', 'addrObjV6IdDisp', 'addrObjV6Type', 'addrObjV6Zone', 'addrObjV6Properties',
                           'addrObjV6Ip1', 'addrObjV6Ip2', 'addrObjV6PrefixLen']
        policyV6_props = ['policyActionV6', 'policySrcZoneV6', 'policyDstZoneV6', 'policySrcNetV6', 'policyDstNetV6',
                          'policyDstSvcV6', 'policyCommentV6', 'policyLogV6', 'policyEnabledV6', 'policyPropsV6']

        # - future use for palo alto configurations
        app_props = []
        sonicwall_config = defaultdict(dict)

        self.log('!-- Converting SonicWall configuration file')
        if not memoryconfig:
            if not self.service.convert_exp_file(infile, configfilename, memoryconfig):
                self.log('Conversion Failed')
                return False

        if memoryconfig == None:
            with open(configfilename) as working_file:
                config = working_file.read()
        else:
            config = memoryconfig

        sonicwall_config['config']['name'] = re.findall('firewallName=.*', config)[0].split('=')[1]
        sonicwall_config['config']['version'] = re.findall('buildNum=.*', config)[0].split('=')[1].split('-')[0]
        sonicwall_config['config']['fw_model'] = url_unquote(
            re.findall('shortProdName=.*', config)[0].split('=')[1].split('-')[0])
        # self.log('!-- Sonicwall version found : ' + sonicwall_config['config']['version'], level=logging.INFO)
        sonicwall_config['config']['fw_type'] = 'sonicwall'
        if self.options.sonicwallip:
            sonicwall_config['config']['mgmtip'] = self.options.sonicwallip
        else:
            sonicwall_config['config']['mgmtip'] = None
        # working_file.close()

        self.log('!-- Reading Group Mappings')
        # MAY NEED TO DECLARE THESE FIRST?
        sonicwall_config['addressmappings'] = self.service.generate_group_mappings(config, 'addro')
        sonicwall_config['servicemappings'] = self.service.generate_group_mappings(config, 'so')
        self.log('!-- Reading Address Objects')
        sonicwall_config['addresses'] = self.service.migrate('addrObj', config, address_props)
        sonicwall_config['addresses'] = self.service.add_IPv4Network(sonicwall_config['addresses'])
        # Add empty comment for all sonicwall address objects
        for address in sonicwall_config['addresses']:
            sonicwall_config['addresses'][address]['addrObjComment'] = ''
            sonicwall_config['addresses'][address]['addrObjColor'] = ''
            # Force netmask for host objects to /32, as some built in types have this set to 0.0.0.0
            if sonicwall_config['addresses'][address]['addrObjType'] == '1':
                sonicwall_config['addresses'][address]['addrObjIp2'] = '255.255.255.255'

        sonicwall_config['addressesfqdn'] = self.service.migrate('addrObjFqdn', config, addressfqdn_props)
        sonicwall_config['addressesV6'] = self.service.migrate('addrObjV6', config, addressV6_props)

        # Rename IPv6 keys to match IPv4 objects
        for address in sonicwall_config['addressesV6']:
            sonicwall_config['addressesV6'][address]['addrObjId'] = sonicwall_config['addressesV6'][address].pop(
                'addrObjV6Id')
            sonicwall_config['addressesV6'][address]['addrObjIdDisp'] = sonicwall_config['addressesV6'][address].pop(
                'addrObjV6IdDisp')
            sonicwall_config['addressesV6'][address]['addrObjType'] = sonicwall_config['addressesV6'][address].pop(
                'addrObjV6Type')
            sonicwall_config['addressesV6'][address]['addrObjZone'] = sonicwall_config['addressesV6'][address].pop(
                'addrObjV6Zone')
            sonicwall_config['addressesV6'][address]['addrObjProperties'] = sonicwall_config['addressesV6'][
                address].pop(
                'addrObjV6Properties')
            sonicwall_config['addressesV6'][address]['addrObjIp1'] = sonicwall_config['addressesV6'][address].pop(
                'addrObjV6Ip1')
            sonicwall_config['addressesV6'][address]['addrObjIp2'] = sonicwall_config['addressesV6'][address].pop(
                'addrObjV6Ip2')
            sonicwall_config['addressesV6'][address]['addrObjPrefixLen'] = sonicwall_config['addressesV6'][address].pop(
                'addrObjV6PrefixLen')

        # Add IPset property to groups
        for addr in sonicwall_config['addresses']:
            if sonicwall_config['addresses'][addr]['addrObjType'] == '8':
                sonicwall_config['addresses'][addr]['IPSet'] = IPSet([])
                for groupmember in self.createNetworkService.expand_address(sonicwall_config['addresses'], addr,
                                                  sonicwall_config['addressmappings']):
                    for network in sonicwall_config['addresses'][groupmember]['IPv4Networks']:
                        sonicwall_config['addresses'][addr]['IPSet'].add(str(network))

        self.log('!-- Reading Service Objects')
        sonicwall_config['services'] = self.service.migrate('svcObj', config, service_props)
        for service_name in sonicwall_config['services']:  ## add svcSrcPort property to all objects
            sonicwall_config['services'][service_name]['svcObjSrcPort'] = '0'

        self.log('!-- Reading Policy Objects')

        # Need to used old numerically index migrate routing for policies (WHY?)
        sonicwall_config['policies'] = self.service.migrate_orig('policy', config, policy_props, skipdisabled=False)
        sonicwall_config['policies'] = self.service.policy_objects_to_list(sonicwall_config['policies'],
                                                              ['policySrcZone', 'policyDstZone', 'policySrcNet',
                                                               'policyDstNet', 'policyDstSvc'])

        self.log('!-- Generating IPv6 Policy Objects')
        sonicwall_config['policiesV6'] = self.service.migrate_orig('policy', config, policyV6_props, skipdisabled=skipdisabled)

        # Rename IPv6 keys to match IPv4 objects
        for policy in sonicwall_config['policiesV6']:
            sonicwall_config['policiesV6'][policy]['policyAction'] = sonicwall_config['policiesV6'][policy].pop(
                'policyActionV6')
            sonicwall_config['policiesV6'][policy]['policySrcZone'] = sonicwall_config['policiesV6'][policy].pop(
                'policySrcZoneV6')
            sonicwall_config['policiesV6'][policy]['policyDstZone'] = sonicwall_config['policiesV6'][policy].pop(
                'policyDstZoneV6')
            sonicwall_config['policiesV6'][policy]['policySrcNet'] = sonicwall_config['policiesV6'][policy].pop(
                'policySrcNetV6')
            sonicwall_config['policiesV6'][policy]['policyDstNet'] = sonicwall_config['policiesV6'][policy].pop(
                'policyDstNetV6')
            sonicwall_config['policiesV6'][policy]['policyComment'] = sonicwall_config['policiesV6'][policy].pop(
                'policyCommentV6')
            sonicwall_config['policiesV6'][policy]['policyLog'] = sonicwall_config['policiesV6'][policy].pop(
                'policyLogV6')
            sonicwall_config['policiesV6'][policy]['policyEnabled'] = sonicwall_config['policiesV6'][policy].pop(
                'policyEnabledV6')
            sonicwall_config['policiesV6'][policy]['policyProps'] = sonicwall_config['policiesV6'][policy].pop(
                'policyPropsV6')
            sonicwall_config['policiesV6'][policy]['policyDstSvc'] = sonicwall_config['policiesV6'][policy].pop(
                'policyDstSvcV6')

        # change this to an argparse option
        if self.options.expandcheckpoint:
            for policy in sonicwall_config['policies']:
                if sonicwall_config['policies'][policy]['policySrcNet'][0][0:11].lower() == 'importchkpt':
                    sonicwall_config['policies'][policy]['policySrcNet'] = sonicwall_config['addressmappings'][
                        sonicwall_config['policies'][policy]['policySrcNet'][0]]
                if sonicwall_config['policies'][policy]['policyDstNet'][0][0:11].lower() == 'importchkpt':
                    sonicwall_config['policies'][policy]['policyDstNet'] = sonicwall_config['addressmappings'][
                        sonicwall_config['policies'][policy]['policyDstNet'][0]]
                if sonicwall_config['policies'][policy]['policyDstSvc'][0][0:11].lower() == 'importchkpt':
                    sonicwall_config['policies'][policy]['policyDstSvc'] = sonicwall_config['servicemappings'][
                        sonicwall_config['policies'][policy]['policyDstSvc'][0]]

        # Sonicwall does not have a "Name" for policies, but need to add it as a placeholder for PA compatibility
        for policy in sonicwall_config['policies']:
            sonicwall_config['policies'][policy]['policyName'] = "Empty"
            sonicwall_config['policies'][policy]['policyNum'] = ''
            sonicwall_config['policies'][policy]['policyUiNum'] = ''

        self.log('!-- Reading NAT Policy Objects')
        sonicwall_config['nat'] = self.service.migrate_orig('natPolicy', config, nat_props)
        sonicwall_config['nat'] = self.service.policy_objects_to_list(sonicwall_config['nat'],
                                                         ['natPolicyOrigSrc', 'natPolicyOrigDst', 'natPolicyOrigSvc',
                                                          'natPolicyTransSrc', 'natPolicyTransDst',
                                                          'natPolicyTransSvc'])
        for policy in sonicwall_config['nat']:
            sonicwall_config['nat'][policy]['natPolicyName'] = "Empty"
            sonicwall_config['nat'][policy]['natPolicyNum'] = ''
            sonicwall_config['nat'][policy]['natPolicyUiNum'] = ''

        self.log('!-- Reading Zone Objects')
        sonicwall_config['zones'] = self.service.migrate('zoneObj', config, zone_props)

        self.log('!-- Reading Interface Objects')
        sonicwall_config['interfaces'] = self.service.migrate('iface', config, interface_props)

        self.log('!-- Reading Routing Objects')
        sonicwall_config['routing'] = self.service.migrate('pbrObj', config, routing_props)

        sonicwall_config['usedzones'] = []
        for interface in sonicwall_config['interfaces']:
            if sonicwall_config['interfaces'][interface]['interface_Zone'] != '':
                sonicwall_config['usedzones'].append(sonicwall_config['interfaces'][interface]['interface_Zone'])

        all_zones = []
        for zone in sonicwall_config['zones']:
            all_zones.append(sonicwall_config['zones'][zone]['zoneObjId'])

        # empty dictionary as sonicwall does not use applications in rules
        sonicwall_config['apps'] = {}

        return sonicwall_config

    def get_sonicwall_exp(self, target):
        exp_config = self.get_sw_config_https(target, None, self.options.username, self.options.password)
        tmpconfig = None
        if exp_config:
            memory_config = self.service.convert_exp_file('', None, exp_config.encode())
            # free up memory
            exp_config = None
            if memory_config:
                if self.options.logging == self.logging.DEBUG:
                    with open('config_python_{}.txt'.format(target), 'w') as outfile:
                        outfile.write(memory_config)
                tmpconfig = self.load_sonicwall('', True, memory_config)
                # free up memory
                memory_config = None
        config = {}
        if tmpconfig:
            if self.options.context != '':
                tmpcontext = self.options.context[0]
            else:
                tmpcontext = tmpconfig['config']['name']
            config[tmpcontext] = tmpconfig
            if not self.options.context:
                self.options.context = [tmpcontext]
            for context in self.options.context:
                self.contexts.append(context)
            tmpconfig = None  # free up memory

        return config

    def get_sw_config_https(self, host, outfile, username='admin', password='admin'):

        self.log("!-- Retrieving SonicWall configuration file from host : " + host)
        try:
            sw_config = sw.get_config(host, username, password)
            # self.log('\n',sw_config,'\n')
            if outfile:
                if sw_config:
                    if outfile:
                        outfile = open(outfile, 'w')
                        # outfile.write(sw_config.text)
                        outfile.close()
            if not sw_config:
                self.log("!-- Error retrieving configuration file")
                return False
        except:
            return False
        return sw_config.text

    def send_sw_webcmd(self, session, url, data, timeout=20):
        self.debug(data)
        response = session.post(url, verify=False, data=data, stream=True, timeout=timeout)
        status = re.findall(r'<span class="message.*', response.text)
        self.debug(response.text)
        if len(status) == 1:
            statusmsg = re.sub(r'.*nowrap>(.*?)&nbsp.*', r'\1', status[0])
            if 'has been updated' in statusmsg:
                # self.log('!-- Address object created : {}'.format(addressname))
                return True
            else:
                # self.log('!-- Address object creation failed : {} - {}'.format(addressname, statusmsg))
                self.debug(statusmsg)
                return False
        return status

    def send_sw_apicmd(self, session, url, method, jsondata, timeout=60):
        status = True
        # self.log('Adata:', data)
        self.debug(data)
        if method.lower() == 'post':
            response = session.post(url, verify=False, data=jsondata, timeout=timeout)
        if method.lower() == 'put':
            response = session.put(url, verify=False, data=jsondata, timeout=timeout)
        if method.lower() == 'get':
            response = session.get(url, verify=False, data=jsondata, timeout=timeout)
        # status=re.findall(r'<span class="message.*', response.text)
        json_response = json.loads(response.text)
        if 'status' in json_response:
            status = json_response['status']
        self.debug(response.text)

        return status

    def sw_get_api_status(self, target, username, password):
        session = requests.Session()
        session.mount('https://' + target, sw.DESAdapter())
        sw.do_login(session, username, password, target, preempt=True)
        response = sw.get_url(session, 'https://' + target + '/systemAdministrationView.html')
        try:
            soup = BeautifulSoup(response.text, 'lxml')
        except:
            return None
        try:
            api_enabled = soup.find('input', attrs={'name': 'sonicOsApi_enable'}).has_attr('checked')
        except:
            api_enabled = False
        return api_enabled

    def sw_enable_api(self, target, username, password):
        session = requests.Session()
        session.mount('https://' + target, sw.DESAdapter())
        sw.do_login(session, username, password, target, preempt=True)
        response = sw.get_url(session, 'https://' + target + '/systemAdministrationView.html')
        try:
            csrf = re.findall(r'csrfToken.*"', response.text)[0].split('value=')[1].split('"')[1]
            postdata = {'csrfToken': csrf,
                        'cgiaction': "none",
                        'sonicOsApi_enable': "on",
                        'sonicOsApi_basicAuth': "on",
                        'cbox_sonicOsApi_enable': "",
                        'cbox_sonicOsApi_basicAuth': ""}
            url = 'https://' + target + '/main.cgi'
            api_result = self.send_sw_webcmd(session, url, postdata)
            sw.do_logout(session, target)
            return api_result
        except:
            return False

    def sw_set_webtimeout(self, target, username, password, timeout):
        session = requests.Session()
        session.mount('https://' + target, sw.DESAdapter())
        sw.do_login(session, username, password, target, preempt=True)
        response = sw.get_url(session, 'https://' + target + '/systemAdministrationView.html')
        try:
            csrf = re.findall(r'csrfToken.*"', response.text)[0].split('value=')[1].split('"')[1]
            postdata = {'csrfToken': csrf,
                        'cgiaction': "none",
                        'adminLoginTimeout': "{}".format(timeout),
                        # 'cli_idleTimeout': '99',
                        }
            url = 'https://' + target + '/main.cgi'
            api_result = self.send_sw_webcmd(session, url, postdata)
            sw.do_logout(session, target)
            return api_result
        except:
            return False

    def sw_disable_api(self, target, username, password):

        session = requests.Session()
        session.mount('https://' + target, sw.DESAdapter())
        sw.do_login(session, username, password, target, preempt=True)
        response = sw.get_url(session, 'https://' + target + '/systemAdministrationView.html')
        try:
            csrf = re.findall(r'csrfToken.*"', response.text)[0].split('value=')[1].split('"')[1]
            postdata = {'csrfToken': csrf,
                        'cgiaction': "none",
                        'sonicOsApi_enable': "off",
                        'sonicOsApi_basicAuth': "on",
                        'cbox_sonicOsApi_enable': "",
                        'cbox_sonicOsApi_basicAuth': ""}
            url = 'https://' + target + '/main.cgi'
            api_result = self.send_sw_webcmd(session, url, postdata)
            sw.do_logout(session, target)
            return api_result
        except:
            return False

    def bulk_get_sw_config(self, params, method='webui'):
        import pickle

        try:
            target, nodename = params.split(',')
            original_logging = self.options.logging
            if method.lower() == 'api':
                self.log('Retrieving configuration via API for Node {} IP {}'.format(nodename, target))
                # self.options.logging=logging.NONE
                self.config['sonicwall'] = self.load_sonicwall_api(target, self.options.username, self.options.password)
            else:
                self.log('Retrieving configuration via WebUI for Node {} IP {}'.format(nodename, target))
                config = self.get_sonicwall_exp(target)  # load_sonicwall(target, self.options.skip_disabled)

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
            # self.log("!-- Saving config")

            outfile = open('{}.config'.format(nodename), 'wb')
            tmp = OrderedDict()
            tmp['config'] = config
            tmp['custom'] = customops
            result = pickle.dump(tmp, outfile)
            outfile.close()
        except Exception as e:
            self.options.logging = original_logging
            return target, False, (e, e.__traceback__.tb_lineno)
        self.options.logging = original_logging
        return target, True, 'Config saved'

    def get_sw_objects(self, target, username, password, fw_type, session=None):

        sw_objects = {'address_objects': {'ipv4': [], 'ipv6': [], 'fqdn': []},
                      'address_groups': {'ipv4': [], 'ipv6': [], 'fqdn': []}, 'service_objects': [],
                      'service_groups': []}
        if session == None:
            session = requests.Session()
            session.mount('https://' + target, sw.DESAdapter())
            urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
            if not self.options.web and (self.options.username == None or self.options.password == None):
                self.options.username, self.options.password = self.service.get_creds()
            if fw_type.lower() == 'sonicwall':
                response = sw.do_login(session, self.options.username, self.options.password, target, True)
                apikey = None
            elif fw_type.lower() in ['sw65']:
                url = 'https://{}/api/sonicos/auth'.format(target)
                session.headers = OrderedDict(
                    [('User-Agent', 'python-requests/2.18.4'), ('Accept', '*/*'), ('Accept-Encoding', 'gzip, deflate'),
                     ('Connection', 'keep-alive')])
                post_data = None
                # auth = requests.auth.HTTPBasicAuth(options.username, options.password) -- replaced with manually setting headers myself since python requests basic auth was not handling special characters correctly
                response_code = None
                login_tries = 0
                while response_code != 200 and login_tries < 1:
                    try:
                        login_tries += 1
                        response = session.post(url=url, headers={'authorization': "Basic " + base64.b64encode(
                            '{}:{}'.format(self.options.username, self.options.password).encode()).decode()}, verify=False,
                                                timeout=self.options.timeout_sw_webui_login)
                        response_code = response.status_code
                        # self.debug('LOGIN RESULT', response.text)
                    except:
                        pass
                apikey = None

                if response_code != 200:
                    session = None
                    apikey = None
                    self.log('!-- Login failed')

        elif session != None:
            # self.log(session)
            self.debug('!-- Checking if in configuration mode')
            url = 'https://{}/api/sonicos/address-objects/ipv4'.format(target)
            # post_data={}
            post_data = {'address_object': {
                'ipv4': {
                    'name': 'api_test_object',
                    'zone': 'LAN',
                    'host': {'ip': '192.168.255.254'}}}}
            result = session.post(url=url, json=post_data, verify=False, timeout=self.options.timeout_sw_webui_post)
            # self.log(result)
            # self.log(json.loads(result.text))
            if not json.loads(result.text)['status']['success']:
                if not json.loads(result.text)['status']['cli']['configuring']:
                    # self.log('result',result.text)
                    return False, 'Not in config mode'

            url = 'https://{}/api/sonicos/address-objects/ipv4'.format(target)
            result = session.get(url=url, data=post_data, verify=False, timeout=self.options.timeout_sw_api)
            # self.log(result)
            addresses_ipv4 = json.loads(result.text)
            for address_object in [address['ipv4']['name'] for address in addresses_ipv4['address_objects']]:
                sw_objects['address_objects']['ipv4'].append(address_object)

            url = 'https://{}/api/sonicos/address-objects/fqdn'.format(target)
            result = session.get(url=url, data=post_data, verify=False, timeout=self.options.timeout_sw_api)
            addresses_fqdn = json.loads(result.text)
            if 'address_objects' in addresses_fqdn:
                for address_object in [address['fqdn']['name'] for address in addresses_fqdn['address_objects']]:
                    sw_objects['address_objects']['fqdn'].append(address_object)

            url = 'https://{}/api/sonicos/address-groups/ipv4'.format(target)
            result = session.get(url=url, data=post_data, verify=False, timeout=self.options.timeout_sw_api)
            addresses_ipv4 = json.loads(result.text)
            for address_object in [address['ipv4']['name'] for address in addresses_ipv4['address_groups']]:
                sw_objects['address_groups']['ipv4'].append(address_object)

            url = 'https://{}/api/sonicos/address-groups/ipv6'.format(target)
            result = session.get(url=url, data=post_data, verify=False, timeout=self.options.timeout_sw_api)
            addresses_ipv6 = json.loads(result.text)
            for address_object in [address['ipv6']['name'] for address in addresses_ipv6['address_groups']]:
                sw_objects['address_groups']['ipv6'].append(address_object)

            url = 'https://{}/api/sonicos/service-objects'.format(target)
            result = session.get(url=url, data=post_data, verify=False, timeout=self.options.timeout_sw_api)
            services = json.loads(result.text)
            for service_object in [service['name'] for service in services['service_objects']]:
                sw_objects['service_objects'].append(service_object)

            url = 'https://{}/api/sonicos/service-groups'.format(target)
            result = session.get(url=url, data=post_data, verify=False, timeout=self.options.timeout_sw_api)
            services = json.loads(result.text)
            for service_object in [service['name'] for service in services['service_groups']]:
                sw_objects['service_groups'].append(service_object)

            # url='https://{}/api/sonicos/auth'.format(target)
            # session.delete(url=url, verify=False)

        return sw_objects

    def sw_firmware(self, target):
        fw_info = {'name': 'unknown',
                   'ip': 'unknown',
                   'model': 'unknown',
                   'firmware': 'unknown',
                   'rom': 'unknown',
                   'connections': 'unknown',
                   'rulecount': 'unknown',
                   'message': 'unknown'
                   }

        config = self.get_sonicwall_exp(target)

        fw_info['ip'] = target

        target_version = "6.5.4.7"
        # target_version = "6.1.1"
        target_rom_vers = ('5.4.1.0', '5.4.1.2', '5.4.0.13')
        firmware_set = (  # use this if upgrading from 6.1.1.9
            ('9600', '/opt/scripts/sw_supermassive-9600_eng_6.2.5.4_6.2.5_1n_1201575.sig'),
            ('9400', '/opt/scripts/sw_supermassive-9400_eng_6.2.5.4_6.2.5_1n_1201575.sig'),
            # ('9400', '../sw_supermassive-9400_eng_6.5.4.4_6.5.4_44n_1201471.sig'),
            ('5600', '/opt/scripts/sw_nsa-5600_eng_6.2.5.4_6.2.5_1n_1201575.sig')
        )

        firmware_set = (  # use this if upgrading from 6.2.5.x
            ('9600', '../sw_supermassive-9600__eng_6.5.4.7-83n.sig'),
            ('9400', '../sw_supermassive-9400__eng_6.5.4.7-83n.sig'),
            # ('9400', '../sw_supermassive-9400_eng_6.5.4.4_6.5.4_44n_1201471.sig'),
            ('5600', '../sw_nsa-5600__eng_6.5.4.7-83n.sig')
        )

        firmware_set = (  # use this if upgrading from 6.5.4.x
            ('9600', '../../sw_supermassive-9600__eng_6.5.4.8-89n.sig'),
            ('9400', '../../sw_supermassive-9400__eng_6.5.4.8-89n.sig'),
            # ('9400', '../sw_supermassive-9400_eng_6.5.4.4_6.5.4_44n_1201471.sig'),
            ('5600', '../../sw_nsa-5600__eng_6.5.4.8-89n.sig')
        )

        import re

        if not self.options.web and (self.options.username == None or self.options.password == None):
            self.options.username, self.options.password = self.service.get_creds()

        sonicwallfound = False
        firmware_file = False
        for context in config:
            if config[context]['config']['fw_type'] == 'sonicwall':
                sonicwallfound = True
                if sonicwallfound:
                    session = requests.Session()
                    session.mount('https://' + target, sw.DESAdapter())

                    response = sw.do_login(session, self.options.username, self.options.password, target,
                                           True)  ## need to be in config mode to request reboot
                    response = sw.get_url(session, 'https://' + target + '/systemStatusView.html',
                                          timeout=self.options.timeout_sw_webui)
                    systemStatusObjects = re.sub(r', ', ',', re.sub(r'\'', '',
                                                                    re.sub(r'.*systemStatusObject\((.*?)\);.*', r'\1',
                                                                           response.text, flags=re.DOTALL))).split(',')
                    self.debug(systemStatusObjects)
                    fw_info['rom'] = systemStatusObjects[7]
                    if fw_info['rom'] in target_rom_vers:
                        fw_info['firmware'] = config[context]['config']['version']
                        self.log('!-- Appliance on approved ROM version : ', fw_info['rom'])
                        if re.findall(target_version, fw_info['firmware']):
                            self.log('!-- Firmware contains string ' + target_version)

                            if self.options.sw_backup:
                                self.log("!-- Creating backup : " + target)
                                sw_backup = sw.backup(target, self.options.username, self.options.password)
                                if sw_backup:
                                    if sw_backup == 'not_active':
                                        fw_info['message'] = '!-- Backup skipped - not active appliance : ' + target
                                        self.log(fw_info['message'])
                                    else:
                                        fw_info['message'] = '!-- Backup creation successful : ' + target
                                        self.log(fw_info['message'])
                                else:
                                    fw_info['message'] = '!-- Backup creation failed  : ' + target
                                    self.log(fw_info['message'])
                                    # exit(2)
                            else:
                                pass
                                # if sw_backup=='bypass':
                                # self.log('!-- Backup skipped - doing firmware upload only : ' + target)
                            if self.options.sw_upload_fw:
                                for model, filename in firmware_set:
                                    fw_info['model'] = config[context]['config']['fw_model']
                                    if re.findall(r'' + model, fw_info['model']):
                                        firmware_file = filename
                                        fw_info[
                                            'message'] = '!-- Model matching RegEx ' + model + ' -- using firmware file : ' + filename
                                        self.log(fw_info['message'])
                                        break
                                if firmware_file:
                                    fw_info['message'] = '!-- Uploading SonicWall firmware to device : ' + target
                                    self.log(fw_info['message'])
                                    sw_firmware = sw.upload_firmware(target, self.options.username, self.options.password,
                                                                     firmware_file)
                                    if sw_firmware:
                                        if sw_firmware == True:
                                            fw_info['message'] = '!-- Firmware upload successful : ' + target
                                            self.log(fw_info['message'])
                                        elif sw_firmware == 'not_active':
                                            fw_info[
                                                'message'] = '!-- Firmware skipped - not active appliance : ' + target
                                            self.log(fw_info['message'])
                                    else:
                                        fw_info['message'] = '!-- Firmware upload failed : ' + target
                                        self.log(fw_info['message'])
                                        exit(1)
                                else:
                                    fw_info['message'] = '!-- No firmware match for model : ' + fw_info[
                                        'model'] + ' : ' + target
                                    self.log(fw_info['message'])
                                    # fw_info['message']='!-- Firmware uploadeskipped  (no firmware file) : ' + target
                                    # self.debug(fw_info['message'])
                        else:
                            fw_info['message'] = '!-- Skipping, current firmware is ' + fw_info[
                                'firmware'] + ' : ' + target
                            self.log(fw_info['message'])
                    else:
                        fw_info['message'] = '!-- Skipping appliance on ROM version : ', fw_info['rom']
                        self.log(fw_info['message'])


                else:
                    fw_info[
                        'message'] = '!-- ERROR!  No sonicwall configuration loaded - Password/Connectivity/Conversion issue : ' + target
                    exit(3)
                break
        # else:
        #    self.log('ERROR: To use the --sw_upload_fw or -sw_backup self.options, you must specify the target ip using the -p option')

    def sw_audit(self, target):

        try:
            sw_version = 'Skipped'
            sw_context = 'Skipped'
            # if sw_context:
            # print(target, end=',')
            # print(sw_version, end=',')
            session = requests.Session()
            session.mount('https://' + target, sw.DESAdapter())
            response = sw.do_login(session, self.options.username, self.options.password, target, False,
                                   timeout=self.options.timeout_sw_webui_login)
            # self.log('RESPONSE', response)
            if response:
                response = sw.get_url(session, 'https://' + target + '/systemSettingsView.html',
                                      timeout=self.options.timeout_sw_webui)
                if len(re.findall(r'Backup Settings were.*', response.text)) > 0:
                    last_backup = re.sub(r'.*Backup Settings were created (.*?) (.*?) (.*?) (.*?) ([0-9]*).*',
                                         r'\1 \2 \3 \4 \5', response.text, flags=re.DOTALL)
                    nobackup = False
                else:
                    last_backup = 'No Backup'
                    nobackup = True
                if len(re.findall(r'>Uploaded Firmware<.*', response.text)) > 0:
                    uploaded_firmware = \
                        re.findall(r'SonicOS.*?<', re.findall(r'>Uploaded Firmware<.*', response.text)[0])[
                            0][:-1]
                    noimage = False
                elif len(re.findall(r'>Uploaded Firmware - <b>New!<.*', response.text)) > 0:
                    uploaded_firmware = \
                        re.findall(r'SonicOS.*?<', re.findall(r'>Uploaded Firmware - <b>New!<.*', response.text)[0])[0][
                        :-1]
                    noimage = False
                else:
                    uploaded_firmware = 'No Uploaded Image'
                    noimage = True
                response = sw.get_url(session, 'https://' + target + '/systemStatusView.html',
                                      timeout=self.options.timeout_sw_webui)
                systemStatusObjects = re.sub(r', ', ',', re.sub(r'\'', '',
                                                                re.sub(r'.*systemStatusObject\((.*?)\);.*', r'\1',
                                                                       response.text, flags=re.DOTALL))).split(',')
                # self.log(response.text)
                # self.log(systemStatusObjects)
                model = systemStatusObjects[0]
                serial = systemStatusObjects[2]
                firmwareversion = systemStatusObjects[5]
                sonicrom = systemStatusObjects[7]
                safemode = systemStatusObjects[8]
                systemtime = systemStatusObjects[13]
                uptime = systemStatusObjects[14]
                lastmodified = systemStatusObjects[19]

                # if len(systemStatusObjects) <35:
                #    print(sonicrom, end=',')
                #    print(safemode, end=',')
                print('{},{},{},{},{},{},OK'.format(target, firmwareversion, last_backup, uploaded_firmware, sonicrom,
                                                    safemode))
                sw.do_logout(session, target)
                # print('OK', end='')
            # else:
            #    print(target,',Unknown,Unknown,Unknown,Unknown,Login Failed', end='')
            else:
                print('{},Unknown,Unknown,Unknown,Unknown,Unknown,Login Failed'.format(target))
            # print('')
            return
        except:
            print('{},Unknown,Unknown,Unknown,Unknown,Unknown,Exception - Login Failed'.format(target))
