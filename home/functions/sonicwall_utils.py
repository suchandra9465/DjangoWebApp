import json
import base64
import urllib
import requests
import re
import time
import json
import base64
import urllib3
import os
import ipaddress
#to:do check for bs4 import 
# from bs4 import BeautifulSoup
from collections import defaultdict, OrderedDict
from requests.packages.urllib3.util.ssl_ import create_urllib3_context
from requests.adapters import HTTPAdapter
from urllib.parse import quote
from collections import OrderedDict
from netaddr import IPSet
from . import sonicwall as sw

def add_IPv4Network(addresses):

    ## This adds a IPv4Network dictionary entry for Sonicwall configurations after the configuration is read

    
    for address in addresses:
        debug(addresses[address])
        addresses[address]['IPSet']=IPSet([])
        try:
            if addresses[address]['addrObjType'] == '1':  ## host
                addresses[address]['IPv4Networks'] = [ipaddress.IPv4Network(addresses[address]['addrObjIp1']+'/32')]  
            if addresses[address]['addrObjType'] == '2':  ## range
                addresses[address]['IPv4Networks'] = [ipaddr for ipaddr in ipaddress.summarize_address_range(ipaddress.IPv4Address(addresses[address]['addrObjIp1']), ipaddress.IPv4Address(addresses[address]['addrObjIp2']))]
            if addresses[address]['addrObjType'] == '4': 
                bitmask = sum([bin(int(x)).count("1") for x in addresses[address]['addrObjIp2'].split(".")])
                addresses[address]['IPv4Networks'] = [ipaddress.IPv4Network(addresses[address]['addrObjIp1']+'/'+str(bitmask))]
            if addresses[address]['addrObjType'] == '8':
                addresses[address]['IPv4Networks']=[]
                pass
                # cant do anything with the group at this point
        except:
            pass
        for network in addresses[address]['IPv4Networks']:
            addresses[address]['IPSet'].add('{}'.format(network))
            pass
    return addresses;


def send_sw_webcmd(session, url, data, timeout=20):
    
    import re

    #log('Adata:', data)
    debug(data)
    response = session.post(url, verify=False, data = data, stream=True, timeout=timeout)
    status=re.findall(r'<span class="message.*', response.text)
    debug(response.text)
    if len(status)==1:
        statusmsg=re.sub(r'.*nowrap>(.*?)&nbsp.*', r'\1', status[0])
        if 'has been updated' in statusmsg:
            #log('!-- Address object created : {}'.format(addressname))
            return True
        else:
            #log('!-- Address object creation failed : {} - {}'.format(addressname, statusmsg))
            debug(statusmsg)
            return False
    return status

def sw_enable_api(target, username, password):
    
    import sonicwall as sw
    import re

    session = requests.Session()
    session.mount('https://' + target, sw.DESAdapter())
    sw.do_login(session, username, password, target, preempt=True)
    response=sw.get_url(session, 'https://' + target + '/systemAdministrationView.html')
    try:
        csrf=re.findall(r'csrfToken.*"',response.text)[0].split('value=')[1].split('"')[1]
        postdata={  'csrfToken': csrf,
                    'cgiaction':	"none",
                    'sonicOsApi_enable':	"on",
                    'sonicOsApi_basicAuth': "on",
                    'cbox_sonicOsApi_enable':	"",
                    'cbox_sonicOsApi_basicAuth': "" }
        url='https://' + target + '/main.cgi'
        api_result=send_sw_webcmd(session, url, postdata)
        sw.do_logout(session, target)
        return api_result
    except:
        return False


def convert_exp_file(infile, outfile, encoded=None):

    ## This converts a sonicwall .exp file to a plain textfile

    if os.path.isfile(infile) or encoded:
        if not encoded:
            encoded_file = open(infile, 'rb')
            encoded = encoded_file.read()
        decoded = base64.decodestring(encoded)
        decoded_with_newline = re.sub(r'&','\n',decoded.decode('utf-8', errors='ignore'))
        decoded_space_removed = re.sub(r'%20$','',decoded_with_newline)
        if outfile:
            decoded_file = open(outfile, 'wb')
            for line in decoded_space_removed.splitlines():
                decoded_space_removed = re.sub(r'%20$','',line)
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
    #with open (configfilename) as working_file:  
    #        config = working_file.read()
    return re.sub(r'&','\n',decoded.decode('utf-8', errors='ignore'))

def cidr_to_netmask(prefix):

    ## Convert CIDR notation to netmask /## --> ###.###.###.###
    return '.'.join([str((0xffffffff << (32 - int(prefix)) >> i) & 0xff) for i in [24, 16, 8, 0]])


def get_sw_config_https(host, outfile, username='admin', password='admin'):

    print("!-- Retrieving SonicWall configuration file from host : " + host)
    try:
        sw_config = sw.get_config(host, username, password)
        #log('\n',sw_config,'\n')
        if outfile:
            if sw_config:
                if outfile:
                    outfile=open(outfile,'w')
                    #outfile.write(sw_config.text)
                    outfile.close()
        if not sw_config:
            print("!-- Error retrieving configuration file")
            return False
    except:
        return False
    return sw_config.text

def get_sonicwall_exp(target,options):
        
    # change options to params
    exp_config=get_sw_config_https(target, None, options.username, options.password)
    tmpconfig=None
    if exp_config: 
        if options.logging==logging.DEBUG:
            with open('config_python_{}.exp'.format(target), 'w') as outfile:
                outfile.write(exp_config)
        
        memory_config=convert_exp_file('', None, exp_config.encode())
        exp_config=None # free up memory 
        if memory_config:
            if options.logging==logging.DEBUG:
                with open('config_python_{}.txt'.format(target), 'w') as outfile:
                    outfile.write(memory_config)
            tmpconfig=load_sonicwall('', True, memory_config)
            memory_config=None  # free up memory
    config={}
    if tmpconfig:
        if options.context !='':
            tmpcontext=options.context[0]
        else:
            tmpcontext=tmpconfig['config']['name']
        config[tmpcontext] = tmpconfig
        if not options.context:
            options.context = [tmpcontext]
        for context in options.context:
            contexts.append(context)
        tmpconfig=None  # free up memory

    return config
      
def get_palo_config_https(host, outfile, username='admin', password='password'):
    

    class DESAdapter(HTTPAdapter):

        """
        A TransportAdapter that re-enables 3DES support in Requests.
        """
        def init_poolmanager(self, *args, **kwargs):
            #context = create_urllib3_context(ciphers=CIPHERS)
            context = create_urllib3_context()
            kwargs['ssl_context'] = context
            return super(DESAdapter, self).init_poolmanager(*args, **kwargs)

        def proxy_manager_for(self, *args, **kwargs):
            context = create_urllib3_context()

            kwargs['ssl_context'] = context
            return super(DESAdapter, self).proxy_manager_for(*args, **kwargs)
  
    print("!-- Retrieving Palo Alto/Panorama configuration file from host : " + host)
    session = requests.Session()
    session.mount(host, DESAdapter())
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    #key=session.get('https://' + host + '/api/?type=keygen&user=' + username + '&password=' + quote(password), verify=False, stream=True, timeout=options.timeout_palo_api)
    #key=session.get('https://' + host + '/api/?type=keygen&user=' + username + '&password=' + quote(password), verify=False, stream=True, timeout=options.timeout_palo_api)
    #key = re.sub(r'.*<key>(.*)</key>.*',r'\1',key.text)
    #config=session.get('https://' + host + '/api/?type=export&category=configuration&key=' + key, verify=False, stream=True, timeout=options.timeout_palo_api)
    #debug(username, password)
    
    #config=session.get('https://' + host + '/api/?type=op&cmd=<show><config><merged></merged></config></show>&key=' + key, verify=False, stream=True, timeout=options.timeout_palo_api)
    
    #config=session.get('https://' + host + '/api/?type=export&category=configuration', auth=(username, quote(password)), verify=False, stream=True, timeout=options.timeout_palo_api)
    config=session.get('https://' + host + '/api/?type=export&category=configuration', headers={'authorization': "Basic " + base64.b64encode('{}:{}'.format(username,password).encode()).decode()}, verify=False, stream=True, timeout=options.timeout_palo_api)
    #outfile=open(outfile,'w', encoding='utf-8')
    #outfile.write(config.text)
    #outfile.close()
    if config.status_code!=200:
        print ('!-- Retrieval of configuration failed')
        debug(config.text)
        return False
    return config.text

def sw_get_api_status(target, username, password):

    session = requests.Session()
    session.mount('https://' + target, sw.DESAdapter())
    sw.do_login(session, username, password, target, preempt=True)
    response=sw.get_url(session, 'https://' + target + '/systemAdministrationView.html')
    #log(response.text)
    try:
        soup = BeautifulSoup(response.text, 'lxml')
    except:
        return None
    try:
        api_enabled=soup.find('input',attrs={'name': 'sonicOsApi_enable'}).has_attr('checked')
    except:
        api_enabled=False
    return api_enabled

def load_sonicwall_api(ip, username, password, skipdisabled=False, memoryconfig=None, retries=1, retry_delay=1, enable_api=False, revert_api=False):

    # !Addresses 
    # !Services
    # Security Rules - need to load source/dest
    # NAT Rules
    # !Routes
    # !Zones
    # !Interfaces
    # !Address and service mappings details - should be easy from group items?
    # Perform a diff in json.dumps of config read from each method
    # 

    print('!-- Loading Sonicwall configuration via API requested')
    ## Use API to send CLI command for groups
    orig_api_enabled=sw_get_api_status(ip, username, password)
    #orig_api_enabled=True
    
    #log(orig_api_enabled)
    api_enabled=False

    if enable_api and not orig_api_enabled:  ## Add command to force API enablement, if needed
        print('!-- Sonicwall API not enabled - enablement requested')
        sw_enable_api(ip, username, password)
        api_enabled=sw_get_api_status(ip, username, password)
        #log(api_enabled)
        if api_enabled:
            print('!-- Sonicwall API enablement successful')
        else:
            print('!-- Sonicwall API enablement failed')

    sonicwall_config = defaultdict(dict)
    
    if api_enabled or orig_api_enabled:

        sonicwall_config['addresses']=OrderedDict()
        sonicwall_config['config']=OrderedDict()
        sonicwall_config['policies']=OrderedDict()
        sonicwall_config['services']=OrderedDict()
        sonicwall_config['routing']=OrderedDict()
        sonicwall_config['nat']=OrderedDict()
        sonicwall_config['interfaces']=OrderedDict()
        sonicwall_config['zones']=OrderedDict()
        sonicwall_config['apps']=OrderedDict()
        sonicwall_config['policiesV6']=OrderedDict()
        sonicwall_config['addressesV6']=OrderedDict()
        sonicwall_config['addressesfqdn']=OrderedDict()
        sonicwall_config['addressmappings']=OrderedDict()
        sonicwall_config['servicemappings']=OrderedDict()
        
        ## get routing table via WebUI which is complete
        ## # routing_props = ['pbrObjId', 'pbrObjProperties', 'pbrObjSrc', 'pbrObjDst', 'pbrObjSvc', 'pbrObjGw', 'pbrObjIface', 'pbrObjIfaceName', 'pbrObjMetric', 'pbrObjPriority', 'pbrObjProbe', 'pbrObjComment']

        session = requests.Session()
        session.mount('https://' + ip, sw.DESAdapter())
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
        

        
        session = requests.Session()
        session.mount('https://' + ip, sw.DESAdapter())
        loginResult=sw.do_login(session, options.username, options.password, ip, preempt=True)
        pbrResult=None
        if loginResult:
            pbrResult=sw.get_url(session, 'https://' + ip + '/getRouteList.json')
        sw.do_logout(session, ip)
        
        
        url='https://{}/api/sonicos/auth'.format(ip)
        session.headers=OrderedDict([('User-Agent', 'python-requests/2.18.4'), ('Accept', '*/*'), ('Accept-Encoding', 'gzip, deflate'), ('Connection', 'keep-alive')])
        post_data=None
        #auth = requests.auth.HTTPBasicAuth(username, password)
        response_code=None
        login_tries=0
        while response_code != 200 and login_tries < retries:
            try:
                login_tries+=1
                response=session.post(url=url, headers={'authorization': "Basic " + base64.b64encode('{}:{}'.format(username, password).encode()).decode()}, verify=False, timeout=options.timeout_sw_webui_login)
                response_code=response.status_code
                if response_code != 200:
                    debug('Login failed, retrying in 10 seconds')
                    time.sleep(retry_delay)
            except:
                response_code=None
        # /api/sonicos/access-rules/ipv4
        
        sonicwall_config['config']['fw_type']='sonicwall'
        
        if response_code == 200:


            session.headers.update({'content-type': 'text/plain'})
            session.headers.update({'Accept': 'application/json'})


            print('!-- Reading Security Policy Objects')
            url='https://{}/api/sonicos/access-rules/ipv4'.format(ip)
            result=session.get(url=url, data=post_data, verify=False, timeout=options.timeout_sw_api)
            debug(result.text)
            security_ipv4=json.loads(result.text)
            debug('{:20.20} {:20.20} {}'.format('Length',' Security Policies', len(security_ipv4['access_rules'])))
            #debug(security_ipv4['access_rules'][0])

            rule_num_int=0
            for access_rule in security_ipv4['access_rules']:
                # {'ipv4': {'schedule': {'always_on': True}, 'geo_ip_filter': False, 'comment': 'Auto-added management rule', 'name': '', 
                # 'source': {'port': {'any': True}, 'address': {'any': True}}, 'sip': False, 'udp': {'timeout': 30}, 'h323': False, 'packet_monitoring': False, 'from': 'LAN', 'quality_of_service': {'class_of_service': {}, 'dscp': {'preserve': True}}, 
                # 'service': {'group': 'Ping'}, 'fragments': True, 'max_connections': 100, 'flow_reporting': False, 'tcp': {'timeout': 15, 'urgent': True}, 'logging': True, 'botnet_filter': False, 'enable': True, 'priority': {'manual': 1}, 'connection_limit': {'source': {}, 'destination': {}}, 'dpi': True, 'action': 'allow', 'uuid': '00b7ea07-d3f5-1e66-0700-c0eae46b8088', 'to': 'LAN', 
                # 'users': {'excluded': {'none': True}, 'included': {'all': True}}, 'dpi_ssl': {'server': True, 'client': True}, 'management': True, 'destination': {'address': {'group': 'All X0 Management IP'}}}}
                # policy_props = ['policyAction', 'policySrcZone', 'policyDstZone', 'policySrcNet', 'policyDstNet', 'policyDstSvc', 'policyDstApps', 'policyComment', 'policyLog', 'policyEnabled', 'policyProps' ]
                rule_num=str(rule_num_int)
                debug(access_rule)
                #rule_num=str(access_rule['ipv4']['priority']['manual'])
                sonicwall_config['policies'][rule_num]=OrderedDict()
                    
                sonicwall_config['policies'][rule_num]['policyAction']=''
                sonicwall_config['policies'][rule_num]['policySrcZone']=''
                sonicwall_config['policies'][rule_num]['policyDstZone']=''
                sonicwall_config['policies'][rule_num]['policySrcNet']=''
                sonicwall_config['policies'][rule_num]['policyDstNet']=''
                sonicwall_config['policies'][rule_num]['policyDstSvc']=''
                sonicwall_config['policies'][rule_num]['policySrcNegate'] = False
                sonicwall_config['policies'][rule_num]['policyDstNegate'] = False
                sonicwall_config['policies'][rule_num]['policySvcNegate'] = False
                sonicwall_config['policies'][rule_num]['policyDstApps']=''
                sonicwall_config['policies'][rule_num]['policyComment']=''
                sonicwall_config['policies'][rule_num]['policyLog']=''
                sonicwall_config['policies'][rule_num]['policyEnabled']=''
                sonicwall_config['policies'][rule_num]['policyProps']=''
                sonicwall_config['policies'][rule_num]['policyUUID']=''
                sonicwall_config['policies'][rule_num]['policyName']="Empty"
                sonicwall_config['policies'][rule_num]['policyNum']=''
                sonicwall_config['policies'][rule_num]['policyUiNum']=''
                sonicwall_config['policies'][rule_num]['policyDstApps']=['']
                if access_rule['ipv4']['action'].lower() == 'deny':
                    sonicwall_config['policies'][rule_num]['policyAction']='0'
                elif access_rule['ipv4']['action'].lower() in ['drop', 'discard']:
                    sonicwall_config['policies'][rule_num]['policyAction']='1'
                elif access_rule['ipv4']['action'].lower() == 'allow':
                    sonicwall_config['policies'][rule_num]['policyAction']='2'                
                else:
                    print(access_rule)
                sonicwall_config['policies'][rule_num]['policySrcZone']=[access_rule['ipv4']['from']]
                sonicwall_config['policies'][rule_num]['policyDstZone']=[access_rule['ipv4']['to']]
                sonicwall_config['policies'][rule_num]['policyName']=access_rule['ipv4']['name']
                if 'any' in access_rule['ipv4']['source']['address']:
                    sonicwall_config['policies'][rule_num]['policySrcNet']=['']
                elif 'name' in access_rule['ipv4']['source']['address']:
                    sonicwall_config['policies'][rule_num]['policySrcNet']=[access_rule['ipv4']['source']['address']['name']]
                elif 'group' in access_rule['ipv4']['source']['address']:
                    sonicwall_config['policies'][rule_num]['policySrcNet']=[access_rule['ipv4']['source']['address']['group']]
                else:
                    sonicwall_config['policies'][rule_num]['policySrcNet']=['']
                    print('!-- Warning Unknown Policy policySrcNet')

                if 'any' in access_rule['ipv4']['destination']['address']:
                    sonicwall_config['policies'][rule_num]['policyDstNet']=['']
                elif 'name' in access_rule['ipv4']['destination']['address']:
                    sonicwall_config['policies'][rule_num]['policyDstNet']=[access_rule['ipv4']['destination']['address']['name']]
                elif 'group' in access_rule['ipv4']['destination']['address']:
                    sonicwall_config['policies'][rule_num]['policyDstNet']=[access_rule['ipv4']['destination']['address']['group']]
                else:
                    sonicwall_config['policies'][rule_num]['policyDstNet']=['']
                    print('!-- Warning Unknown Policy policyDstNet')

                if 'any' in access_rule['ipv4']['service']:
                    sonicwall_config['policies'][rule_num]['policyDstSvc']=['']
                elif 'group' in access_rule['ipv4']['service']:
                    sonicwall_config['policies'][rule_num]['policyDstSvc']=[access_rule['ipv4']['service']['group']]
                elif 'name' in access_rule['ipv4']['service']:
                    sonicwall_config['policies'][rule_num]['policyDstSvc']=[access_rule['ipv4']['service']['name']]
                else:
                    sonicwall_config['policies'][rule_num]['policyDstSvc']=['']
                    print('!-- Warning Unknown Policy policyDstSvc')

                sonicwall_config['policies'][rule_num]['policyComment']=access_rule['ipv4']['comment']
                if access_rule['ipv4']['logging']:
                    sonicwall_config['policies'][rule_num]['policyLog']='1'
                else:
                    sonicwall_config['policies'][rule_num]['policyLog']='0'
                if access_rule['ipv4']['enable']:
                    sonicwall_config['policies'][rule_num]['policyEnabled']='1'
                else:
                    sonicwall_config['policies'][rule_num]['policyEnabled']='0'
                sonicwall_config['policies'][rule_num]['policyProps']='' ## unknown for sonicwall6.5 policies
                sonicwall_config['policies'][rule_num]['policyUUID']=access_rule['ipv4']['uuid']
                #log(json.dumps(access_rule, indent=3))
                #log(json.dumps(sonicwall_config['policies'][rule_num], indent=3))
                #log('-' *100)
                rule_num_int += 1
            
            #policyV6_props = ['policyActionV6', 'policySrcZoneV6', 'policyDstZoneV6', 'policySrcNetV6', 'policyDstNetV6', 'policyDstSvcV6', 'policyCommentV6', 'policyLogV6', 'policyEnabledV6', 'policyPropsV6' ]

            print('!-- Reading IPv6 Security Policy Objects')
            url='https://{}/api/sonicos/access-rules/ipv6'.format(ip)
            result=session.get(url=url, data=post_data, verify=False, timeout=options.timeout_sw_api)
            debug(result.text)
            security_ipv6=json.loads(result.text)
            if 'access_rules' in security_ipv6:
                debug(security_ipv6)
                debug('{:20.20} {:20.20} {}'.format('Length',' Security Policies', len(security_ipv6['access_rules'])))
                rule_num_int=0
                for access_rule in security_ipv6['access_rules']:
                    # {'ipv4': {'schedule': {'always_on': True}, 'geo_ip_filter': False, 'comment': 'Auto-added management rule', 'name': '', 
                    # 'source': {'port': {'any': True}, 'address': {'any': True}}, 'sip': False, 'udp': {'timeout': 30}, 'h323': False, 'packet_monitoring': False, 'from': 'LAN', 'quality_of_service': {'class_of_service': {}, 'dscp': {'preserve': True}}, 
                    # 'service': {'group': 'Ping'}, 'fragments': True, 'max_connections': 100, 'flow_reporting': False, 'tcp': {'timeout': 15, 'urgent': True}, 'logging': True, 'botnet_filter': False, 'enable': True, 'priority': {'manual': 1}, 'connection_limit': {'source': {}, 'destination': {}}, 'dpi': True, 'action': 'allow', 'uuid': '00b7ea07-d3f5-1e66-0700-c0eae46b8088', 'to': 'LAN', 
                    # 'users': {'excluded': {'none': True}, 'included': {'all': True}}, 'dpi_ssl': {'server': True, 'client': True}, 'management': True, 'destination': {'address': {'group': 'All X0 Management IP'}}}}
                    # policy_props = ['policyAction', 'policySrcZone', 'policyDstZone', 'policySrcNet', 'policyDstNet', 'policyDstSvc', 'policyDstApps', 'policyComment', 'policyLog', 'policyEnabled', 'policyProps' ]
                    #policyV6_props = ['policyActionV6', 'policySrcZoneV6', 'policyDstZoneV6', 'policySrcNetV6', 'policyDstNetV6', 'policyDstSvcV6', 'policyCommentV6', 'policyLogV6', 'policyEnabledV6', 'policyPropsV6' ]

                    rule_num=str(rule_num_int)
                    debug(access_rule)
                    #rule_num=str(access_rule['ipv6']['priority']['manual'])
                    sonicwall_config['policiesV6'][rule_num]=OrderedDict()
                        
                    sonicwall_config['policiesV6'][rule_num]['policyAction']=''
                    sonicwall_config['policiesV6'][rule_num]['policySrcZone']=''
                    sonicwall_config['policiesV6'][rule_num]['policyDstZone']=''
                    sonicwall_config['policiesV6'][rule_num]['policySrcNet']=''
                    sonicwall_config['policiesV6'][rule_num]['policyDstNet']=''
                    sonicwall_config['policiesV6'][rule_num]['policyDstSvc']=''
                    sonicwall_config['policiesV6'][rule_num]['policyDstApps']=''
                    sonicwall_config['policiesV6'][rule_num]['policyComment']=''
                    sonicwall_config['policiesV6'][rule_num]['policyLog']=''
                    sonicwall_config['policiesV6'][rule_num]['policyEnabled']=''
                    sonicwall_config['policiesV6'][rule_num]['policyProps']=''
                    sonicwall_config['policiesV6'][rule_num]['policyUUID']=''
                    sonicwall_config['policiesV6'][rule_num]['policyName']="Empty"
                    sonicwall_config['policiesV6'][rule_num]['policyNum']=''
                    sonicwall_config['policiesV6'][rule_num]['policyUiNum']=''
                    sonicwall_config['policiesV6'][rule_num]['policyDstApps']=['']
                    if access_rule['ipv6']['action'].lower() == 'deny':
                        sonicwall_config['policiesV6'][rule_num]['policyAction']='0'
                    elif access_rule['ipv6']['action'].lower() in ['drop', 'discard']:
                        sonicwall_config['policiesV6'][rule_num]['policyAction']='1'
                    elif access_rule['ipv6']['action'].lower() == 'allow':
                        sonicwall_config['policiesV6'][rule_num]['policyAction']='2'                
                    else:
                        print(access_rule)
                    sonicwall_config['policiesV6'][rule_num]['policySrcZone']=[access_rule['ipv6']['from']]
                    sonicwall_config['policiesV6'][rule_num]['policyDstZone']=[access_rule['ipv6']['to']]
                    
                    if 'any' in access_rule['ipv6']['source']['address']:
                        sonicwall_config['policiesV6'][rule_num]['policySrcNet']=['']
                    elif 'name' in access_rule['ipv6']['source']['address']:
                        sonicwall_config['policiesV6'][rule_num]['policySrcNet']=[access_rule['ipv6']['source']['address']['name']]
                    elif 'group' in access_rule['ipv6']['source']['address']:
                        sonicwall_config['policiesV6'][rule_num]['policySrcNet']=[access_rule['ipv6']['source']['address']['group']]
                    else:
                        sonicwall_config['policiesV6'][rule_num]['policySrcNet']=['']
                        print('!-- Warning Unknown Policy policySrcNet')
                    
                    if 'any' in access_rule['ipv6']['destination']['address']:
                        sonicwall_config['policiesV6'][rule_num]['policyDstNet']=['']
                    elif 'name' in access_rule['ipv6']['destination']['address']:
                        sonicwall_config['policiesV6'][rule_num]['policyDstNet']=[access_rule['ipv6']['destination']['address']['name']]
                    elif 'group' in access_rule['ipv6']['destination']['address']:
                        sonicwall_config['policiesV6'][rule_num]['policyDstNet']=[access_rule['ipv6']['destination']['address']['group']]
                    else:
                        sonicwall_config['policiesV6'][rule_num]['policyDstNet']=['']
                        print('!-- Warning Unknown Policy policyDstNet')
                    
                    if 'any' in access_rule['ipv6']['service']:
                        sonicwall_config['policiesV6'][rule_num]['policyDstSvc']=['']
                    elif 'group' in access_rule['ipv6']['service']:
                        sonicwall_config['policiesV6'][rule_num]['policyDstSvc']=[access_rule['ipv6']['service']['group']]
                    elif 'name' in access_rule['ipv6']['service']:
                        sonicwall_config['policiesV6'][rule_num]['policyDstSvc']=[access_rule['ipv6']['service']['name']]
                    else:
                        sonicwall_config['policiesV6'][rule_num]['policyDstSvc']=['']
                        print('!-- Warning Unknown Policy policyDstSvc')

                    sonicwall_config['policiesV6'][rule_num]['policyComment']=access_rule['ipv6']['comment']
                    
                    if access_rule['ipv6']['logging']:
                        sonicwall_config['policiesV6'][rule_num]['policyLog']='1'
                    else:
                        sonicwall_config['policiesV6'][rule_num]['policyLog']='0'
                    if access_rule['ipv6']['enable']:
                        sonicwall_config['policiesV6'][rule_num]['policyEnabled']='1'
                    else:
                        sonicwall_config['policies'][rule_num]['policyEnabled']='0'
                    sonicwall_config['policiesV6'][rule_num]['policyProps']='' ## unknown for sonicwall6.5 policies
                    sonicwall_config['policiesV6'][rule_num]['policyUUID']=access_rule['ipv6']['uuid']  
                    #log(json.dumps(access_rule, indent=3))
                    #log(json.dumps(sonicwall_config['policies'][rule_num], indent=3))
                    #log('-' *100)
                    rule_num_int += 1

            print('!-- Reading NAT Policy Objects')
            url='https://{}/api/sonicos/nat-policies/ipv4'.format(ip)
            result=session.get(url=url, data=post_data, verify=False, timeout=options.timeout_sw_api)
            nat_ipv4=json.loads(result.text)
            #log('NATPOL: ', json.dumps(nat_ipv4['nat_policies'][28], indent=2))
            # {'ipv4': {'translated_service': {'original': True}, 'comment': 'Management NAT Policy', 'outbound': 'MGMT', 'source': {'any': True}, 'service': {'name': 'SNMP'}, 'enable': True, 'uuid': 'ed660693-3b9a-77f1-0800-c0eae46b8088', 'inbound': 'MGMT', 'name': '', 'translated_source': {'original': True}, 'translated_destination': {'original': True}, 'destination': {'name': 'MGMT IP'}}}
            #nat_props = [ 'natPolicyOrigSrc', 'natPolicyOrigDst', 'natPolicyOrigSvc', 'natPolicyTransSrc', 'natPolicyTransDst', 'natPolicyTransSvc', 'natPolicySrcIface', 'natPolicyDstIface', 'natPolicyEnabled', 'natPolicyComment', 'natPolicyProperties', 'natPolicyName' ]

            rule_num_int=0
            for nat_rule in nat_ipv4['nat_policies']:
                rule_num=str(rule_num_int)
                #log('NAT: ', json.dumps(nat_rule, indent=4))
                sonicwall_config['nat'][rule_num]=OrderedDict()
                sonicwall_config['nat'][rule_num]['natPolicyName']=nat_rule['ipv4']['name']
                sonicwall_config['nat'][rule_num]['natPolicyNum']=''
                sonicwall_config['nat'][rule_num]['natPolicyUiNum']=''
                if nat_rule['ipv4']['enable']:
                    sonicwall_config['nat'][rule_num]['natPolicyEnabled']='1'
                else:
                    sonicwall_config['nat'][rule_num]['natPolicyEnabled']='0'
                sonicwall_config['nat'][rule_num]['natPolicySrcIface']=nat_rule['ipv4']['inbound']
                sonicwall_config['nat'][rule_num]['natPolicyDstIface']=nat_rule['ipv4']['outbound']
                if 'any' in nat_rule['ipv4']['source']:
                    sonicwall_config['nat'][rule_num]['natPolicyOrigSrc']=['']
                elif 'name' in nat_rule['ipv4']['source']:
                    sonicwall_config['nat'][rule_num]['natPolicyOrigSrc']=[nat_rule['ipv4']['source']['name']]
                elif 'group' in nat_rule['ipv4']['source']:
                    sonicwall_config['nat'][rule_num]['natPolicyOrigSrc']=[nat_rule['ipv4']['source']['group']]
                else:
                    sonicwall_config['nat'][rule_num]['natPolicyOrigSrc']=['']
                    print('!-- Warning reading NAT OrigSrc')
                
                if 'any' in nat_rule['ipv4']['destination']:
                    sonicwall_config['nat'][rule_num]['natPolicyOrigDst']=['']
                elif 'name' in nat_rule['ipv4']['destination']:
                    sonicwall_config['nat'][rule_num]['natPolicyOrigDst']=[nat_rule['ipv4']['destination']['name']]
                elif 'group' in nat_rule['ipv4']['destination']:
                    sonicwall_config['nat'][rule_num]['natPolicyOrigDst']=[nat_rule['ipv4']['destination']['group']]
                else:
                    sonicwall_config['nat'][rule_num]['natPolicyOrigDst']=['']
                    print('!-- Warning reading NAT OrigDst')
                
                if 'any' in nat_rule['ipv4']['service']:
                    sonicwall_config['nat'][rule_num]['natPolicyOrigSvc']=['']
                elif 'name' in nat_rule['ipv4']['service']:
                    sonicwall_config['nat'][rule_num]['natPolicyOrigSvc']=[nat_rule['ipv4']['service']['name']]
                elif 'group' in nat_rule['ipv4']['service']:
                    sonicwall_config['nat'][rule_num]['natPolicyOrigSvc']=[nat_rule['ipv4']['service']['group']]
                else:
                    sonicwall_config['nat'][rule_num]['natPolicyOrigSvc']=['']
                    print('!-- Warning reading NAT TransOrigSvc')

                if 'original' in nat_rule['ipv4']['translated_source']:
                    sonicwall_config['nat'][rule_num]['natPolicyTransSrc']=['']
                elif 'name' in nat_rule['ipv4']['translated_source']:
                    sonicwall_config['nat'][rule_num]['natPolicyTransSrc']=[nat_rule['ipv4']['translated_source']['name']]
                elif 'group' in nat_rule['ipv4']['translated_source']:
                    sonicwall_config['nat'][rule_num]['natPolicyTransSrc']=[nat_rule['ipv4']['translated_source']['group']]
                else:
                    sonicwall_config['nat'][rule_num]['natPolicyTransSrc']=['']
                    print('!-- Warning reading NAT TransSrc')

                if 'original' in nat_rule['ipv4']['translated_destination']:
                    sonicwall_config['nat'][rule_num]['natPolicyTransDst']=['']
                elif 'name' in nat_rule['ipv4']['translated_destination']:
                    sonicwall_config['nat'][rule_num]['natPolicyTransDst']=[nat_rule['ipv4']['translated_destination']['name']]
                elif 'group' in nat_rule['ipv4']['translated_destination']:
                    sonicwall_config['nat'][rule_num]['natPolicyTransDst']=[nat_rule['ipv4']['translated_destination']['group']]
                else:
                    sonicwall_config['nat'][rule_num]['natPolicyTransDst']=['']
                    print('!-- Warning reading NAT TransDst')

                if 'original' in nat_rule['ipv4']['translated_service']:
                    sonicwall_config['nat'][rule_num]['natPolicyTransSvc']=['']
                elif 'name' in nat_rule['ipv4']['translated_service']:
                    sonicwall_config['nat'][rule_num]['natPolicyTransSvc']=[nat_rule['ipv4']['translated_service']['name']]
                elif 'group' in nat_rule['ipv4']['translated_service']:
                    sonicwall_config['nat'][rule_num]['natPolicyTransSvc']=[nat_rule['ipv4']['translated_service']['group']]
                else:
                    sonicwall_config['nat'][rule_num]['natPolicyTransSvc']=['']
                    print('!-- Warning reading NAT TransSvc')

                sonicwall_config['nat'][rule_num]['natPolicyProperties']=''
                sonicwall_config['nat'][rule_num]['natPolicyUUID']=nat_rule['ipv4']['uuid']
                sonicwall_config['nat'][rule_num]['natPolicyComment']=nat_rule['ipv4']['comment']

                rule_num_int += 1

            print('!-- Reading Address Objects')
            url='https://{}/api/sonicos/address-objects/ipv4'.format(ip)
            result=session.get(url=url, data=post_data, verify=False, timeout=options.timeout_sw_api)
            addresses_ipv4=json.loads(result.text)
            debug('{:20.20} {:20.20} {}'.format('Length',' Addresses', len(addresses_ipv4['address_objects'])))
            #log(addresses_ipv4['address_objects'][0])
            #{'address_objects': [{'ipv4': {'host': {'ip': '10.211.129.170'}, 'name': 'X0 IP', 'zone': 'LAN', 'uuid': 'cfeeb502-52cf-c94a-0100-c0eae46b8088'}}, {'ipv4': {'name': 'X0 Subnet', 'zone': 'LAN', 'uuid': '8d747ea4-5021-c0a5-0100-c0eae46b8088', 'network': {'mask': '255.255.255.0', 'subnet': '10.211.129.0'}}}, {'ipv4': {'host': {'ip': '97.79.140.147'}, 'name': 'X1 IP', 'zone': 'WAN', 'uuid': 'be2eb811-cb10-b105-0100-c0eae46b8088'}}, 
            # address_props = ['addrObjId', 'addrObjIdDisp', 'addrObjType', 'addrObjZone', 'addrObjProperties', 'addrObjIp1', 'addrObjIp2', 'addrObjComment']
            for address in addresses_ipv4['address_objects']:
                debug(address)
                address_name=address['ipv4']['name']
                sonicwall_config['addresses'][address_name]=OrderedDict()
                sonicwall_config['addresses'][address_name]['addrObjId']=address_name
                sonicwall_config['addresses'][address_name]['addrObjIdDisp']=address_name
                sonicwall_config['addresses'][address_name]['addrObjIp1']='2.2.2.2'
                sonicwall_config['addresses'][address_name]['addrObjIp2']='3.3.3.3'
                if 'host' in address['ipv4']:
                    if 'ip' in address['ipv4']['host']:
                        sonicwall_config['addresses'][address_name]['addrObjType']='1'
                        sonicwall_config['addresses'][address_name]['addrObjIp1']=address['ipv4']['host']['ip']
                        sonicwall_config['addresses'][address_name]['addrObjIp2']='255.255.255.255'
                    else:
                        sonicwall_config['addresses'][address_name]['addrObjType']='1' #512
                        sonicwall_config['addresses'][address_name]['addrObjIp1']='0.0.0.0' # placeholder for undefined built in objects
                        sonicwall_config['addresses'][address_name]['addrObjIp2']='255.255.255.255' # placeholder for undefined built in objects
                if 'range' in address['ipv4']:
                    sonicwall_config['addresses'][address_name]['addrObjType']='2'
                    sonicwall_config['addresses'][address_name]['addrObjIp1']=address['ipv4']['range']['begin']
                    sonicwall_config['addresses'][address_name]['addrObjIp2']=address['ipv4']['range']['end']
                if 'network' in address['ipv4']:
                    if 'subnet' in address['ipv4']['network']:
                        sonicwall_config['addresses'][address_name]['addrObjType']='4'
                        sonicwall_config['addresses'][address_name]['addrObjIp1']=address['ipv4']['network']['subnet']
                        sonicwall_config['addresses'][address_name]['addrObjIp2']=address['ipv4']['network']['mask']
                    else:
                        sonicwall_config['addresses'][address_name]['addrObjType']='4' #2048
                        sonicwall_config['addresses'][address_name]['addrObjIp1']='0.0.0.0' # placeholder for undefined built in objects
                        sonicwall_config['addresses'][address_name]['addrObjIp2']='255.255.255.255' # placeholder for undefined built in objects
                debug(sonicwall_config['addresses'][address_name])

                if 'zone' in address['ipv4']:
                    sonicwall_config['addresses'][address_name]['addrObjZone']=address['ipv4']['zone']
                else:
                    sonicwall_config['addresses'][address_name]['addrObjZone']='' # placeholder for undefined built in objects

                sonicwall_config['addresses'][address_name]['addrObjProperties']=''
                sonicwall_config['addresses'][address_name]['addrObjComment']=''
                sonicwall_config['addresses'][address_name]['addrObjColor']=''
                sonicwall_config['addresses'][address_name]['addrObjUUID']=address['ipv4']['uuid']

            print('!-- Reading IPv6 Address Objects')
            url='https://{}/api/sonicos/address-objects/ipv6'.format(ip)
            result=session.get(url=url, data=post_data, verify=False, timeout=options.timeout_sw_api)
            addresses_ipv6=json.loads(result.text)
            debug('{:20.20} {:20.20} {}'.format('Length',' AddressesV6', len(addresses_ipv6['address_objects'])))
            #log(addresses_ipv4['address_objects'][0])
            #addressV6_props = ['addrObjV6Id', 'addrObjV6IdDisp', 'addrObjV6Type', 'addrObjV6Zone', 'addrObjV6Properties', 'addrObjV6Ip1', 'addrObjV6Ip2', 'addrObjV6PrefixLen']
            
            #{'address_objects': [{'ipv4': {'host': {'ip': '10.211.129.170'}, 'name': 'X0 IP', 'zone': 'LAN', 'uuid': 'cfeeb502-52cf-c94a-0100-c0eae46b8088'}}, {'ipv4': {'name': 'X0 Subnet', 'zone': 'LAN', 'uuid': '8d747ea4-5021-c0a5-0100-c0eae46b8088', 'network': {'mask': '255.255.255.0', 'subnet': '10.211.129.0'}}}, {'ipv4': {'host': {'ip': '97.79.140.147'}, 'name': 'X1 IP', 'zone': 'WAN', 'uuid': 'be2eb811-cb10-b105-0100-c0eae46b8088'}}, 
            # address_props = ['addrObjId', 'addrObjIdDisp', 'addrObjType', 'addrObjZone', 'addrObjProperties', 'addrObjIp1', 'addrObjIp2', 'addrObjComment']
            for address in addresses_ipv6['address_objects']:
                #debug('IPv6:',address)
                address_name=address['ipv6']['name']
                sonicwall_config['addressesV6'][address_name]=OrderedDict()
                sonicwall_config['addressesV6'][address_name]['addrObjId']=address_name
                sonicwall_config['addressesV6'][address_name]['addrObjIdDisp']=address_name
                if 'host' in address['ipv6']:
                    sonicwall_config['addressesV6'][address_name]['addrObjType']='1'
                    if 'ip' in address['ipv6']['host']:
                        sonicwall_config['addressesV6'][address_name]['addrObjIp1']=address['ipv6']['host']['ip']
                        sonicwall_config['addressesV6'][address_name]['addrObjIp2']='/128'
                        sonicwall_config['addressesV6'][address_name]['addrObjV6PrefixLen']='/128'
                    else:
                        sonicwall_config['addressesV6'][address_name]['addrObjIp1']='::' # placeholder for undefined built in objects
                        sonicwall_config['addressesV6'][address_name]['addrObjIp2']='::' # placeholder for undefined built in objects
                        sonicwall_config['addressesV6'][address_name]['addrObjV6PrefixLen']='/128'
                if 'range' in address['ipv6']:
                    sonicwall_config['addressesV6'][address_name]['addrObjType']='2'
                    sonicwall_config['addressesV6'][address_name]['addrObjIp1']=address['ipv6']['host']['ip']
                    sonicwall_config['addressesV6'][address_name]['addrObjIp2']=address['ipv6']['host']['ip']
                    sonicwall_config['addressesV6'][address_name]['addrObjV6PrefixLen']=''
                if 'network' in address['ipv6']:
                    sonicwall_config['addressesV6'][address_name]['addrObjType']='4'
                    if 'subnet' in address['ipv6']['network']:
                        sonicwall_config['addressesV6'][address_name]['addrObjIp1']=address['ipv6']['network']['subnet']
                        sonicwall_config['addressesV6'][address_name]['addrObjIp2']=address['ipv6']['network']['mask']
                        sonicwall_config['addressesV6'][address_name]['addrObjV6PrefixLen']=address['ipv6']['network']['mask']
                    else:
                        sonicwall_config['addressesV6'][address_name]['addrObjIp1']='::' # placeholder for undefined built in objects
                        sonicwall_config['addressesV6'][address_name]['addrObjIp2']='::' # placeholder for undefined built in objects
                        sonicwall_config['addressesV6'][address_name]['addrObjV6PrefixLen']='/64'
                debug(sonicwall_config['addressesV6'][address_name])

                if 'zone' in address['ipv6']:
                    sonicwall_config['addressesV6'][address_name]['addrObjZone']=address['ipv6']['zone']
                else:
                    sonicwall_config['addressesV6'][address_name]['addrObjZone']='' # placeholder for undefined built in objects

                sonicwall_config['addressesV6'][address_name]['addrObjProperties']=''
                sonicwall_config['addressesV6'][address_name]['addrObjComment']=''
                sonicwall_config['addressesV6'][address_name]['addrObjColor']=''
                sonicwall_config['addressesV6'][address_name]['addrObjUUID']=address['ipv6']['uuid']

            

            print('!-- Reading Address Group Objects')
            url='https://{}/api/sonicos/address-groups/ipv4'.format(ip)
            result=session.get(url=url, data=post_data, verify=False, timeout=options.timeout_sw_api)
            addresses_groups_ipv4=json.loads(result.text)
            debug('{:20.20} {:20.20} {}'.format('Length',' Address Groups', len(addresses_groups_ipv4['address_groups'])))
            for address_group in addresses_groups_ipv4['address_groups']:
                address_name=address_group['ipv4']['name']
                sonicwall_config['addresses'][address_name]=OrderedDict()
                sonicwall_config['addresses'][address_name]['addrObjId']=address_name
                sonicwall_config['addresses'][address_name]['addrObjIdDisp']=address_name
                sonicwall_config['addresses'][address_name]['addrObjUUID']=address_group['ipv4']['uuid']
                sonicwall_config['addresses'][address_name]['addrObjType']='8'
                sonicwall_config['addresses'][address_name]['addrObjZone']=''
                sonicwall_config['addresses'][address_name]['addrObjProperties']=''
                sonicwall_config['addresses'][address_name]['addrObjIp1']='0.0.0.0'
                sonicwall_config['addresses'][address_name]['addrObjIp2']='0.0.0.0'
                sonicwall_config['addresses'][address_name]['addrObjComment']=''
                sonicwall_config['addresses'][address_name]['addrObjColor']=''

                sonicwall_config['addressmappings'][address_name]=[]
                debug(address_group)
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

                #log(x)
                #log(addresses_groups_ipv4['address_groups'][0])
            # {'ipv4': {'address_object': {'ipv4': [{'name': 'X0 Subnet'}]}, 'uuid': '9b9b3c30-59f7-f1d4-0200-c0eae46b8088', 'name': 'LAN Subnets'}}

            sonicwall_config['addresses'] = add_IPv4Network(sonicwall_config['addresses'])

            log('!-- Reading IPv6 Address Group Objects')
            url='https://{}/api/sonicos/address-groups/ipv6'.format(ip)
            result=session.get(url=url, data=post_data, verify=False, timeout=options.timeout_sw_api)
            addresses_groups_ipv6=json.loads(result.text)
            debug('{:20.20} {:20.20} {}'.format('Length',' Address GroupsV6', len(addresses_groups_ipv4['address_groups'])))
            for address_group in addresses_groups_ipv6['address_groups']:
                debug('IPv6:',address_group)
                address_name=address_group['ipv6']['name']
                sonicwall_config['addressesV6'][address_name]=OrderedDict()
                sonicwall_config['addressesV6'][address_name]['addrObjId']=address_name
                sonicwall_config['addressesV6'][address_name]['addrObjIdDisp']=address_name
                sonicwall_config['addressesV6'][address_name]['addrObjUUID']=address_group['ipv6']['uuid']
                sonicwall_config['addressesV6'][address_name]['addrObjType']='8'
                sonicwall_config['addressesV6'][address_name]['addrObjZone']=''
                sonicwall_config['addressesV6'][address_name]['addrObjProperties']=''
                sonicwall_config['addressesV6'][address_name]['addrObjIp1']='::'
                sonicwall_config['addressesV6'][address_name]['addrObjIp2']='::'
                sonicwall_config['addressesV6'][address_name]['addrObjComment']=''
                sonicwall_config['addressesV6'][address_name]['addrObjColor']=''

                sonicwall_config['addressmappings'][address_name]=[]
                try:
                    if 'address_object' in address_group['ipv6']:
                        for address_object in address_group['ipv6']['address_object']['ipv6']:
                            sonicwall_config['addressmappings'][address_name].append(address_object['name'])
                    #for address_object in address_group['ipv4']['address_object']['ipv6']:
                except:
                    pass
                try:
                    if 'address_group' in address_group['ipv6']:
                        for address_object in address_group['ipv6']['address_group']['ipv6']:
                            #debug(address_object)
                            sonicwall_config['addressmappings'][address_name].append(address_object['name'])
                except:
                    pass
                try:
                    if 'fqdn' in address_group['ipv6']['address_object']:
                        for address_object in address_group['ipv6']['address_object']['fqdn']:
                            sonicwall_config['addressmappings'][address_name].append(address_object['name'])
                except:
                    pass

                '''
                if 'address_object' in address_group['ipv6']:
                    for address_object in address_group['ipv6']['address_object']['ipv6']:
                        #debug(address_object)
                        sonicwall_config['addressmappings'][address_name].append(address_object['name'])
                if 'address_group' in address_group['ipv6']:
                    for address_object in address_group['ipv6']['address_group']['ipv6']:
                        #debug(address_object)
                        sonicwall_config['addressmappings'][address_name].append(address_object['name'])
                '''

            log('!-- Reading Address FQDN Objects')
            url='https://{}/api/sonicos/address-objects/fqdn'.format(ip)
            result=session.get(url=url, data=post_data, verify=False, timeout=options.timeout_sw_api)
            #log(result.text)
            addresses_fqdn=json.loads(result.text)
            #log(addresses_fqdn['address_objects'][0])
            # {'fqdn': {'name': 'Syslog Server(0): austlrr2csdep01.us.dell.com', 'uuid': '9902ae74-9724-c051-0100-c0eae46b8088', 'domain': 'austlrr2csdep01.us.dell.com', 'dns_ttl': 0}}
            # addressfqdn_props = ['addrObjFqdnId', 'addrObjFqdnType', 'addrObjFqdnZone', 'addrObjFqdnProperties', 'addrObjFqdn']
            #log(addresses_fqdn)
            if 'address_objects' in addresses_fqdn:
                for address_fqdn in addresses_fqdn['address_objects']:
                    #log(address_fqdn)
                    try:
                        #log(address_fqdn)
                        address_name=address_fqdn['fqdn']['name']
                        sonicwall_config['addressesfqdn'][address_name]=OrderedDict()
                        sonicwall_config['addressesfqdn'][address_name]['addrObjFqdnId']=address_fqdn['fqdn']['name']
                        sonicwall_config['addressesfqdn'][address_name]['addrObjFqdnType']=''#address_fqdn['fqdn']
                        sonicwall_config['addressesfqdn'][address_name]['addrObjFqdnTTL']=address_fqdn['fqdn']['dns_ttl']
                        sonicwall_config['addressesfqdn'][address_name]['addrObjFqdn']=address_fqdn['fqdn']['domain']
                        sonicwall_config['addressesfqdn'][address_name]['addrObjFqdnUUID']=address_fqdn['fqdn']['uuid']
                        if 'zone' in address_fqdn['fqdn']:
                            sonicwall_config['addressesfqdn'][address_name]['addrObjFqdnZone']=address_fqdn['fqdn']['zone']
                        else:
                            sonicwall_config['addressesfqdn'][address_name]['addrObjFqdnZone']=''
                        #log('-'*180)
                        #log(sonicwall_config['addressesfqdn'][address_name])
                    except Exception as e: 
                        log(e)

            log('!-- Reading Service Objects')
            url='https://{}/api/sonicos/service-objects'.format(ip)
            result=session.get(url=url, data=post_data, verify=False, timeout=options.timeout_sw_api)
            services=json.loads(result.text)
            debug('{:20.20} {:20.20} {}'.format('Length',' Services', len(services['service_objects'])))
            # {'name': 'HTTP', 'uuid': 'f40b27d6-b8b9-a4fc-0300-c0eae46b8088', 'tcp': {'end': 80, 'begin': 80}}
            #   service_props = ['svcObjId', 'svcObjType', 'svcObjProperties', 'svcObjIpType', 'svcObjPort1', 'svcObjPort2', 'svcObjManagement', 'svcObjHigherPrecedence', 'svcObjComment']
            icmp_types={ 'redirect': '5',
                        'echo-reply': '0',
                        'echo-request': '8',
                        'timestamp': '13',
                        'timestamp-reply': '14',
                        'alternative-host': '6'
            
            }
            for service in services['service_objects']:
                debug(service)
                service_name=service['name']
                sonicwall_config['services'][service_name]=OrderedDict()
                sonicwall_config['services'][service_name]['svcObjId']=service_name
                sonicwall_config['services'][service_name]['svcObjComment']=''
                sonicwall_config['services'][service_name]['svcObjHigherPrecedence']='off'
                sonicwall_config['services'][service_name]['svcObjManagement']='0'
                sonicwall_config['services'][service_name]['svcObjProperties']='0'
                sonicwall_config['services'][service_name]['svcObjSrcPort']='0'

                if 'tcp' in service:
                    sonicwall_config['services'][service_name]['svcObjType']='6'
                    sonicwall_config['services'][service_name]['svcObjIpType']='6'
                    sonicwall_config['services'][service_name]['svcObjPort1']=str(service['tcp']['begin'])
                    sonicwall_config['services'][service_name]['svcObjPort2']=str(service['tcp']['end'])
                    sonicwall_config['services'][service_name]['svcObjUUID']=service['uuid']
                elif 'udp' in service:
                    sonicwall_config['services'][service_name]['svcObjType']='17'
                    sonicwall_config['services'][service_name]['svcObjIpType']='17'
                    sonicwall_config['services'][service_name]['svcObjPort1']=str(service['udp']['begin'])
                    sonicwall_config['services'][service_name]['svcObjPort2']=str(service['udp']['end'])
                    sonicwall_config['services'][service_name]['svcObjUUID']=service['uuid']
                elif 'icmp' in service:
                    sonicwall_config['services'][service_name]['svcObjType']='1'
                    sonicwall_config['services'][service_name]['svcObjIpType']='1'
                    sonicwall_config['services'][service_name]['svcObjPort1']=service['icmp']
                    sonicwall_config['services'][service_name]['svcObjPort2']=service['icmp']
                    sonicwall_config['services'][service_name]['svcObjUUID']=service['uuid']
                elif 'icmpv6' in service:
                    sonicwall_config['services'][service_name]['svcObjType']='99'
                    sonicwall_config['services'][service_name]['svcObjIpType']='99'
                    sonicwall_config['services'][service_name]['svcObjPort1']=service['icmpv6']
                    sonicwall_config['services'][service_name]['svcObjPort2']=''
                    sonicwall_config['services'][service_name]['svcObjUUID']=service['uuid']
                elif 'igmp' in service:
                    sonicwall_config['services'][service_name]['svcObjType']='99'
                    sonicwall_config['services'][service_name]['svcObjIpType']='99'
                    sonicwall_config['services'][service_name]['svcObjPort1']=service['igmp']
                    sonicwall_config['services'][service_name]['svcObjPort2']=''
                    sonicwall_config['services'][service_name]['svcObjUUID']=service['uuid']
                elif 'esp' in service:
                    sonicwall_config['services'][service_name]['svcObjType']='99'
                    sonicwall_config['services'][service_name]['svcObjIpType']='99'
                    sonicwall_config['services'][service_name]['svcObjPort1']=service['esp']
                    sonicwall_config['services'][service_name]['svcObjPort2']=''
                    sonicwall_config['services'][service_name]['svcObjUUID']=service['uuid']
                elif 'gre' in service:
                    sonicwall_config['services'][service_name]['svcObjType']='47'
                    sonicwall_config['services'][service_name]['svcObjIpType']='47'
                    sonicwall_config['services'][service_name]['svcObjPort1']='1' #service['gre']
                    sonicwall_config['services'][service_name]['svcObjPort2']='65535'
                    sonicwall_config['services'][service_name]['svcObjUUID']=service['uuid']
                elif '6over4' in service:
                    sonicwall_config['services'][service_name]['svcObjType']='41'
                    sonicwall_config['services'][service_name]['svcObjIpType']='41'
                    sonicwall_config['services'][service_name]['svcObjPort1']='1' #service['6over4']
                    sonicwall_config['services'][service_name]['svcObjPort2']='1'
                    sonicwall_config['services'][service_name]['svcObjUUID']=service['uuid']
                elif 'ipcomp' in service:
                    sonicwall_config['services'][service_name]['svcObjType']='108'
                    sonicwall_config['services'][service_name]['svcObjIpType']='108'
                    sonicwall_config['services'][service_name]['svcObjPort1']='1'  # service['ipcomp']
                    sonicwall_config['services'][service_name]['svcObjPort2']='1'
                    sonicwall_config['services'][service_name]['svcObjUUID']=service['uuid']
                else:
                    sonicwall_config['services'][service_name]['svcObjType']='99'
                    sonicwall_config['services'][service_name]['svcObjIpType']='99'
                    sonicwall_config['services'][service_name]['svcObjPort1']='99'
                    sonicwall_config['services'][service_name]['svcObjPort2']=''
                    sonicwall_config['services'][service_name]['svcObjUUID']=service['uuid']
                    debug(service)            
                #if sonicwall_config['services'][service_name]['svcObjPort1'] == sonicwall_config['services'][service_name]['svcObjPort2']:  ## if service object type a single port or range
                sonicwall_config['services'][service_name]['svcObjType']='1'
                #else:
                #    sonicwall_config['services'][service_name]['svcObjType']='2'
            
            log('!-- Reading Service Group Objects')
            url='https://{}/api/sonicos/service-groups'.format(ip)
            result=session.get(url=url, data=post_data, verify=False, timeout=options.timeout_sw_api)
            service_groups=json.loads(result.text)
            #log(json.dumps(service_groups['service_groups'], indent=3))
            # {'name': 'HTTP', 'uuid': 'f40b27d6-b8b9-a4fc-0300-c0eae46b8088', 'tcp': {'end': 80, 'begin': 80}}
            #   service_props = ['svcObjId', 'svcObjType', 'svcObjProperties', 'svcObjIpType', 'svcObjPort1', 'svcObjPort2', 'svcObjManagement', 'svcObjHigherPrecedence', 'svcObjComment']
            debug('{:20.20} {:20.20} {}'.format('Length',' Service Groups', len(service_groups['service_groups'])))
            debug(service_groups)
            for service in service_groups['service_groups']:
                #log(service)
                service_name=service['name']
                sonicwall_config['services'][service_name]=OrderedDict()
                sonicwall_config['services'][service_name]['svcObjId']=service_name
                sonicwall_config['services'][service_name]['svcObjType']='2'
                sonicwall_config['services'][service_name]['svcObjIpType']='0'

                sonicwall_config['servicemappings'][service_name]=[]
                if 'service_object' in service:
                    for service_object in service['service_object']:
                        sonicwall_config['servicemappings'][service_name].append(service_object['name'])
                        #log(service_object['name'])
                if 'service_group' in service:
                    for service_group in service['service_group']:
                        #log(service_group['name'])
                        sonicwall_config['servicemappings'][service_name].append(service_group['name'])                        
            
            log('!-- Reading Interface Objects')
            url='https://{}/api/sonicos/interfaces/ipv4'.format(ip)
            result=session.get(url=url, data=post_data, verify=False, timeout=options.timeout_sw_api)
            interfaces_ipv4=json.loads(result.text)
            #log(interfaces_ipv4['interfaces'][0])
            #{'ipv4': {'routed_mode': {}, 'auto_discovery': False, 'flow_reporting': True, 'comment': 'Default LAN', 'name': 'X0', 'port': {'redundancy_aggregation': False}, 'user_login': {'https': False}, 'https_redirect': True, 'cos_8021p': False, 'ip_assignment': {'zone': 'LAN', 'mode': {'static': {'netmask': '255.255.255.0', 'ip': '10.211.129.170', 'gateway': '10.211.129.1'}}}, 'management': {'snmp': False, 'https': True, 'ping': True, 'ssh': True}, 'mtu': 1500, 'multicast': False, 'asymmetric_route': False, 'link_speed': {'auto_negotiate': True}, 'exclude_route': False, 'shutdown_port': False, 'mac': {'default': True}}}
            # interface_props = ['iface_ifnum', 'iface_type', 'iface_name', 'interface_Zone', 'iface_comment', 'iface_static_ip', 'iface_static_mask', 'iface_static_gateway', 'iface_lan_ip', 'iface_lan_mask', 'iface_lan_default_gw', 'iface_mgmt_ip', 'iface_mgmt_netmask', 'iface_mgmt_default_gw', 'iface_static_gateway', 'iface_vlan_tag', 'iface_comment', 'iface_http_mgmt', 
            # 'iface_https_mgmt', 'iface_ssh_mgmt', 'iface_ping_mgmt', 'iface_snmp_mgmt', 'portShutdown']
            interface_num_int=0
            for interface in interfaces_ipv4['interfaces']:
                interface_num=str(interface_num_int)
                debug(interface)
                sonicwall_config['interfaces'][interface_num]=OrderedDict()
                sonicwall_config['interfaces'][interface_num]['iface_name']=interface['ipv4']['name']
                sonicwall_config['interfaces'][interface_num]['iface_ifnum']=str(interface_num)
                sonicwall_config['interfaces'][interface_num]['portShutdown']='0'
                sonicwall_config['interfaces'][interface_num]['interface_Zone']=''
                sonicwall_config['interfaces'][interface_num]['iface_vlan_tag']=''
                sonicwall_config['interfaces'][interface_num]['iface_static_ip']='0.0.0.0'
                sonicwall_config['interfaces'][interface_num]['iface_static_mask']='255.255.255.0'
                sonicwall_config['interfaces'][interface_num]['iface_static_gateway']='255.255.255.0'
                sonicwall_config['interfaces'][interface_num]['iface_lan_ip']='0.0.0.0'
                sonicwall_config['interfaces'][interface_num]['iface_lan_mask']='255.255.255.0'
                sonicwall_config['interfaces'][interface_num]['iface_lan_default_gw']='255.255.255.0'
                sonicwall_config['interfaces'][interface_num]['iface_mgmt_ip']='0.0.0.0'
                sonicwall_config['interfaces'][interface_num]['iface_mgmt_netmask']='255.255.255.0'
                sonicwall_config['interfaces'][interface_num]['iface_mgmt_default_gw']='255.255.255.0'
                sonicwall_config['interfaces'][interface_num]['iface_static_gateway']=''
                sonicwall_config['interfaces'][interface_num]['iface_http_mgmt']='0'
                sonicwall_config['interfaces'][interface_num]['iface_https_mgmt']='0'
                sonicwall_config['interfaces'][interface_num]['iface_ssh_mgmt']='0'
                sonicwall_config['interfaces'][interface_num]['iface_ping_mgmt']='0'
                sonicwall_config['interfaces'][interface_num]['iface_snmp_mgmt']='0'
                
                #sonicwall_config['interfaces'][interface_num][''iface_vlan_tag'']=interface['ipv4']['']
                
                if 'vlan' in interface:
                    sonicwall_config['interfaces'][interface_num]['iface_vlan_tag']=interface['vlan']
                if 'mode' in interface['ipv4']['ip_assignment']:
                    sonicwall_config['interfaces'][interface_num]['interface_Zone']=interface['ipv4']['ip_assignment']['zone']
                    if 'static' in interface['ipv4']['ip_assignment']['mode']:
                        debug('STATIC!!!')
                        sonicwall_config['interfaces'][interface_num]['iface_static_ip']=interface['ipv4']['ip_assignment']['mode']['static']['ip']
                        sonicwall_config['interfaces'][interface_num]['iface_static_mask']=interface['ipv4']['ip_assignment']['mode']['static']['netmask']
                        sonicwall_config['interfaces'][interface_num]['iface_static_gateway']=interface['ipv4']['ip_assignment']['mode']['static']['gateway']
                        
                    
                #sonicwall_config['interfaces'][interface_num]['iface_type']=interface['ipv4']['']
                #sonicwall_config['interfaces'][interface_num]['interface_Zone']=interface['ipv4']['']
                
                
                if 'comment' in interface['ipv4']:
                    sonicwall_config['interfaces'][interface_num]['iface_comment']=interface['ipv4']['comment']
                else:
                    sonicwall_config['interfaces'][interface_num]['iface_comment']=''
                
                
                if 'management' in interface['ipv4']:
                    if 'http' in interface['ipv4']['management']:
                        if interface['ipv4']['management']['http']:
                            sonicwall_config['interfaces'][interface_num]['iface_http_mgmt']='1'
                    if interface['ipv4']['management']['https']:
                        sonicwall_config['interfaces'][interface_num]['iface_https_mgmt']='1'
                    if interface['ipv4']['management']['ssh']:
                        sonicwall_config['interfaces'][interface_num]['iface_ssh_mgmt']='1'
                    if interface['ipv4']['management']['ping']:
                        sonicwall_config['interfaces'][interface_num]['iface_ping_mgmt']='1'
                    if interface['ipv4']['management']['snmp']:
                        sonicwall_config['interfaces'][interface_num]['iface_snmp_mgmt']='1'
                
                if 'shutdown_port' in interface['ipv4']:
                    if interface['ipv4']['shutdown_port']:
                        sonicwall_config['interfaces'][interface_num]['portShutdown']='1'
                else:
                    sonicwall_config['interfaces'][interface_num]['portShutdown']='0'

                #sonicwall_config['interfaces'][interface_num]['uuid']=interface['ipv4']['uuid']  ## no uuid for interfaces

                interface_num_int += 1

            if pbrResult:
                if pbrResult.status_code==200:
                    log('!-- Reading Routing Objects via WebUI table')
                    ## # routing_props = ['pbrObjId', 'pbrObjProperties', 'pbrObjSrc', 'pbrObjDst', 'pbrObjSvc', 'pbrObjGw', 'pbrObjIface', 'pbrObjIfaceName', 'pbrObjMetric', 'pbrObjPriority', 'pbrObjProbe', 'pbrObjComment']
                    pbrindex=0
                    for index, entry in enumerate(json.loads(pbrResult.text)['pbrPolicies'].split('|')[1:]):
                        #log(index, entry)
                        name,properties,metric,distance,distanceAuto,priority,source,destination,service,applicationID,application,tos,tosMask,nexthopNum, \
                        gateway,gatewayVer,iface,ifName,ifaceStatus,gateway2,gatewayVer2,iface2,ifName2,ifaceStatus2,gateway3,gatewayVer3,iface3,ifName3,ifaceStatus3, \
                        gateway4,gatewayVer4,iface4,ifName4,ifaceStatus4,comment,probe,ipver,wxaGroup,uuid,rtype,psp,sdwanGroup,entryIndex = entry.split(',')
                        if ipver=='0':  ## 0 is IPv4 - do not read IPv6 routes at this time
                            #log([x for x in sonicwall_config['addresses']])
                            destination=destination.strip('"')
                            source=source.strip('"')
                            service=service.strip('"')
                            gateway=gateway.strip('"')
                            ifName=ifName.strip('"')
                            if destination=='':  destination='0.0.0.0/0'
                            #log('"{}"'.format(destination))
                            if source in sonicwall_config['addresses']:
                                source='{}/{}'.format(sonicwall_config['addresses'][source]['addrObjIp1'], netmask_to_cidr(sonicwall_config['addresses'][source]['addrObjIp2']))
                            if gateway in sonicwall_config['addresses']:
                                gateway='{}'.format(sonicwall_config['addresses'][gateway]['addrObjIp1'])
                            if destination in sonicwall_config['addresses']:
                                #log('Destination in Address objects - expand it!')
                                #log(expand_address(sonicwall_config['addresses'], destination, sonicwall_config['addressmappings'], inc_group=False))
                                for each_dest in expand_address(sonicwall_config['addresses'], destination, sonicwall_config['addressmappings'], inc_group=False):
                                    #log(each_dest, pbrindex)
                                    sonicwall_config['routing'][pbrindex]=OrderedDict()
                                    sonicwall_config['routing'][pbrindex]['pbrObjId']=name
                                    sonicwall_config['routing'][pbrindex]['pbrObjProperties']=properties
                                    sonicwall_config['routing'][pbrindex]['pbrObjSrc']=source
                                    sonicwall_config['routing'][pbrindex]['pbrObjDst']='{}/{}'.format(sonicwall_config['addresses'][each_dest]['addrObjIp1'], netmask_to_cidr(sonicwall_config['addresses'][each_dest]['addrObjIp2']))
                                    sonicwall_config['routing'][pbrindex]['pbrObjSvc']=service
                                    sonicwall_config['routing'][pbrindex]['pbrObjGw']=gateway
                                    sonicwall_config['routing'][pbrindex]['pbrObjIface']=iface
                                    sonicwall_config['routing'][pbrindex]['pbrObjIfaceName']=ifName
                                    sonicwall_config['routing'][pbrindex]['pbrObjMetric']=metric
                                    sonicwall_config['routing'][pbrindex]['pbrObjPriority']=priority
                                    sonicwall_config['routing'][pbrindex]['pbrObjProbe']=probe
                                    sonicwall_config['routing'][pbrindex]['pbrObjComment']=comment
                                    sonicwall_config['routing'][pbrindex]['pbrObjUUID']=uuid
                                    #log(sonicwall_config['routing'][index]['pbrObjDst'], ipver)
                                    pbrindex += 1            

                            else:
                                #log('Destination not in Address objects - use as is!')
                                #log(destination, pbrindex)
                                sonicwall_config['routing'][pbrindex]=OrderedDict()
                                sonicwall_config['routing'][pbrindex]['pbrObjId']=name
                                sonicwall_config['routing'][pbrindex]['pbrObjProperties']=properties
                                sonicwall_config['routing'][pbrindex]['pbrObjSrc']=source
                                sonicwall_config['routing'][pbrindex]['pbrObjDst']=destination
                                sonicwall_config['routing'][pbrindex]['pbrObjSvc']=service
                                sonicwall_config['routing'][pbrindex]['pbrObjGw']=gateway
                                sonicwall_config['routing'][pbrindex]['pbrObjIface']=iface
                                sonicwall_config['routing'][pbrindex]['pbrObjIfaceName']=ifName
                                sonicwall_config['routing'][pbrindex]['pbrObjMetric']=metric
                                sonicwall_config['routing'][pbrindex]['pbrObjPriority']=priority
                                sonicwall_config['routing'][pbrindex]['pbrObjProbe']=probe
                                sonicwall_config['routing'][pbrindex]['pbrObjComment']=comment
                                sonicwall_config['routing'][pbrindex]['pbrObjUUID']=uuid
                                pbrindex += 1
                            #log(config['sonicwall'])
                            #log(sonicwall_config['routing'][index]['pbrObjDst'], ipver)
                else:
                    pbrResult=None
            
            if pbrResult==None:

                ## only read using API is using WebUI failed
                log('!-- Reading Routing Objects via API')
                url='https://{}/api/sonicos/route-policies/ipv4'.format(ip)
                result=session.get(url=url, data=post_data, verify=False, timeout=options.timeout_sw_api)
                routing_ipv4=json.loads(result.text)
                #log(routing_ipv4['route_policies'][0])
                # {'ipv4': {'source': {'any': True}, 'comment': '', 'interface': 'MGMT', 'name': 'ldap', 'vpn_precedence': False, 'service': {'any': True}, 'uuid': '00000000-0000-0001-0900-c0eae46b8088', 'metric': 1, 'gateway': {'name': 'MGMT Default Gateway'}, 'disable_on_interface_down': True, 'probe': '', 'destination': {'any': True}, 'wxa_group': ''}}
                # routing_props = ['pbrObjId', 'pbrObjProperties', 'pbrObjSrc', 'pbrObjDst', 'pbrObjSvc', 'pbrObjGw', 'pbrObjIface', 'pbrObjIfaceName', 'pbrObjMetric', 'pbrObjPriority', 'pbrObjProbe', 'pbrObjComment']
                ## need more details to read pbrObjSvc value

                route_num_int=0
                for route in routing_ipv4['route_policies']:
                    route_num=str(route_num_int)
                    #debug("ROUTE", route['ipv4']['gateway'])

                    sonicwall_config['routing'][route_num]=OrderedDict()
                    sonicwall_config['routing'][route_num]['pbrObjId']=route['ipv4']['name']
                    sonicwall_config['routing'][route_num]['pbrObjProperties']=''

                    if 'name' in route['ipv4']['source']:
                        sonicwall_config['routing'][route_num]['pbrObjSrc']=route['ipv4']['source']['name']
                    else:
                        sonicwall_config['routing'][route_num]['pbrObjSrc']=''

                    if 'name' in route['ipv4']['destination']:
                        sonicwall_config['routing'][route_num]['pbrObjDst']=route['ipv4']['destination']['name']
                    elif 'group' in route['ipv4']['destination']:
                        sonicwall_config['routing'][route_num]['pbrObjDst']=route['ipv4']['destination']['group']
                    else:
                        sonicwall_config['routing'][route_num]['pbrObjDst']=''
                    try:   
                        if 'name' in route['ipv4']['gateway']:                    
                            sonicwall_config['routing'][route_num]['pbrObjGw']=route['ipv4']['gateway']['name']
                            #debug("ROUTE2", route['ipv4']['gateway'])
                        else:
                            sonicwall_config['routing'][route_num]['pbrObjGw']=''        
                    except:
                        sonicwall_config['routing'][route_num]['pbrObjGw']='0.0.0.0'
                        #log(route['ipv4'])
                    
                    sonicwall_config['routing'][route_num]['pbrObjIface']=route['ipv4']['interface']
                    sonicwall_config['routing'][route_num]['pbrObjIfaceName']=route['ipv4']['interface']
                    sonicwall_config['routing'][route_num]['pbrObjMetric']=str(route['ipv4']['metric'])
                    sonicwall_config['routing'][route_num]['pbrObjPriority']=''
                    sonicwall_config['routing'][route_num]['pbrObjProbe']=route['ipv4']['probe']
                    sonicwall_config['routing'][route_num]['pbrObjComment']=route['ipv4']['comment']
                    sonicwall_config['routing'][route_num]['pbrObjUUID']=route['ipv4']['uuid']
                    sonicwall_config['routing'][route_num]['pbrObjSvc']=''
                    route_num_int += 1
                
                ## Set default route to WAN/X1 interface
                for interface_index in sonicwall_config['interfaces']:
                    #log(interface_index, sonicwall_config['interfaces'][interface_index]['iface_name'], sonicwall_config['interfaces'][interface_index]['portShutdown'])
                    if sonicwall_config['interfaces'][interface_index]['iface_name']=='X1' and sonicwall_config['interfaces'][interface_index]['portShutdown']=='0':
                        sonicwall_config['routing'][route_num]=OrderedDict()
                        sonicwall_config['routing'][route_num]['pbrObjId']='Default Route'
                        sonicwall_config['routing'][route_num]['pbrObjProperties']=''
                        sonicwall_config['routing'][route_num]['pbrObjSrc']=''
                        sonicwall_config['routing'][route_num]['pbrObjDst']='0.0.0.0'
                        sonicwall_config['routing'][route_num]['pbrObjGw']=sonicwall_config['interfaces'][interface_index]['iface_static_gateway']
                        sonicwall_config['routing'][route_num]['pbrObjIface']='X1'
                        sonicwall_config['routing'][route_num]['pbrObjIfaceName']='X1'
                        sonicwall_config['routing'][route_num]['pbrObjMetric']='10'
                        sonicwall_config['routing'][route_num]['pbrObjPriority']=''
                        sonicwall_config['routing'][route_num]['pbrObjProbe']=''
                        sonicwall_config['routing'][route_num]['pbrObjComment']='Auto-Added Default Route'
                        sonicwall_config['routing'][route_num]['pbrObjUUID']=''
                        sonicwall_config['routing'][route_num]['pbrObjSvc']=''
                        #log(sonicwall_config['routing'][route_num])
                        break
                #log(json.dumps(sonicwall_config['routing'], indent=4))

            log('!-- Reading Zone Objects')
            url='https://{}/api/sonicos/zones'.format(ip)
            result=session.get(url=url, data=post_data, verify=False, timeout=options.timeout_sw_api)
            zones=json.loads(result.text)
            #log(zones['zones'][0])
            # {'create_group_vpn': False, 'intrusion_prevention': True, 'name': 'LAN', 'client': {'anti_virus': False, 'content_filtering': False}, 'auto_generate_access_rules': {'allow_from_to_equal': True, 'allow_to_lower': True, 'allow_from_higher': True, 'deny_from_lower': True}, 'dpi_ssl_client': True, 'sslvpn_access': False, 'guest_services': {}, 'interface_trust': True, 'uuid': '2ecd17a0-73de-dc8b-0a00-c0eae46b8088', 'ssl_control': False, 'gateway_anti_virus': True, 'security_type': 'trusted', 'app_control': True, 'anti_spyware': True, 'dpi_ssl_server': False}
            # zone_props = ['zoneObjId', 'zoneObjComment']
            for zone in zones['zones']:
                zone_name=zone['name']
                sonicwall_config['zones'][zone_name]=OrderedDict()
                sonicwall_config['zones'][zone_name]['zoneObjId']=zone_name
                sonicwall_config['zones'][zone_name]['zoneObjComment']=''
                sonicwall_config['zones'][zone_name]['zoneObjUUID']=zone['uuid']

            sonicwall_config['usedzones']=[]
            for interface in sonicwall_config['interfaces']:
                if sonicwall_config['interfaces'][interface]['interface_Zone']!='':
                    sonicwall_config['usedzones'].append(sonicwall_config['interfaces'][interface]['interface_Zone'])
        else:
            log('Unable to retrieve configuration via API')
        ## Add IPset property to groups
        for addr in sonicwall_config['addresses']:
            if sonicwall_config['addresses'][addr]['addrObjType']=='8':
                sonicwall_config['addresses'][addr]['IPSet']=IPSet([])
                for groupmember in expand_address(sonicwall_config['addresses'], addr, sonicwall_config['addressmappings']):
                    debug(groupmember)
                    debug(sonicwall_config['addresses'][groupmember])
                    for network in sonicwall_config['addresses'][groupmember]['IPv4Networks']:
                        sonicwall_config['addresses'][addr]['IPSet'].add(str(network))
    else:
        log('!-- API not enabled for target device {} Configuration not loaded.'.format(ip))

    sonicwall_config['config']['name']='' # context  ## CHANGEME (how do I get firewall name)
    sonicwall_config['config']['version']=''
    sonicwall_config['config']['fw_type']='sw65'
    sonicwall_config['config']['mgmtip']=ip

    if api_enabled and revert_api:
        sw_disable_api(ip, username, password)
        api_status=sw_get_api_status(ip, username, password)
        if api_status:
            log('!-- Sonicwall API disablement failed')
        else:
            log('!-- Sonicwall API disablement successful')
    
    try:
        url='https://{}/api/sonicos/auth'.format(ip)
        session.delete(url=url, verify=False, timeout=options.timeout_sw_webui)
    except:
        pass


    return sonicwall_config

def load_xml(infile, memoryconfig=None):

    ## Load Panorama configuration .xml file
    ## Loading Shared objects not fully implemented CHANGEME (load policies)
    ## DONE Detect Pano vs Palo config and load appropriately
    ## DONE Pano should have xpath /config/mgt-config/devices

    def load_addresses(address_list):
        
        from collections import OrderedDict
        
        return_address = OrderedDict()
        
        for address in address_list:
            current_address =  address.get('name')
            return_address[current_address]=OrderedDict()
            return_address[current_address]['addrObjId'] = current_address
            return_address[current_address]['addrObjIdDisp'] = ''
            return_address[current_address]['addrObjType'] = ''
            return_address[current_address]['addrObjZone'] = ''
            return_address[current_address]['addrObjProperties'] = '14'
            return_address[current_address]['addrObjIp1'] = ''
            return_address[current_address]['addrObjIp2'] = ''
            return_address[current_address]['addrObjComment'] = ''
            return_address[current_address]['addrObjColor'] = ''
            return_address[current_address]['IPv4Networks'] = [ipaddress.IPv4Network(u'255.255.255.255/32')]
            
            for address_tags in address.findall('.'):
            
                for item in address_tags.iter():
                    if item.tag in ['ip-netmask', 'ip-range', 'description', 'fqdn']:
                        if item.tag.lower() == 'ip-netmask':
                            if re.findall('/',item.text):
                                ipaddr,mask = item.text.split('/')
                                if mask == '32':
                                    return_address[current_address]['addrObjType'] = '1'
                                    return_address[current_address]['addrObjIp1'] = ipaddr
                                    return_address[current_address]['addrObjIp2'] = '255.255.255.255'
                                elif int(mask) < 32 :
                                    return_address[current_address]['addrObjType'] = '4'
                                    return_address[current_address]['addrObjIp2'] = cidr_to_netmask(mask)
                                    return_address[current_address]['addrObjIp1'] = ipaddr
                                else:
                                    return_address[current_address]['addrObjType'] = '66' # placeholder for IPv6 Addresses
                                try:
                                    return_address[current_address]['IPv4Networks'] = [ipaddress.IPv4Network(item.text,strict=False)]
                                except:
                                    pass
                            else:
                                return_address[current_address]['addrObjIp1'] = item.text
                                return_address[current_address]['addrObjIp2'] = '255.255.255.255'
                                return_address[current_address]['addrObjType'] = '1'
                                try:
                                    return_address[current_address]['IPv4Networks'] = [ipaddress.IPv4Network(item.text+'/32',strict=False)]
                                except:
                                    pass
                        elif item.tag.lower() == 'ip-range':
                            range_start, range_end = item.text.split('-')
                            return_address[current_address]['addrObjIp1'] = range_start
                            return_address[current_address]['addrObjIp2'] = range_end
                            return_address[current_address]['addrObjType'] = '2'
                            return_address[current_address]['IPv4Networks'] = [ipaddress.IPv4Network(u'255.255.255.254/32')]  ## why 255.255.255.254/32??
                            try:
                                return_address[current_address]['IPv4Networks'] = [ipaddr for ipaddr in ipaddress.summarize_address_range(ipaddress.IPv4Address(range_start),ipaddress.IPv4Address(range_end))]
                            except:
                                pass
                        elif item.tag.lower() == 'fqdn':
                            return_address[current_address]['fqdn'] = item.text
                            return_address[current_address]['IPv4Networks'] = [ipaddress.IPv4Network(u'255.255.255.254/32')]
                            return_address[current_address]['addrObjType'] = '89'  ## Set a type not used by sonicwall
                            
                        elif item.tag.lower() == 'description':
                            return_address[current_address]['addrObjIdDisp'] = item.text 
                            return_address[current_address]['addrObjIdComment'] = item.text 
    
        return return_address
    
    def load_address_groups(address_list):
        
        return_address_group = OrderedDict()
        addr_mappings = OrderedDict()
        for address in address_list:
            current_address =  address.get('name')
            return_address_group[current_address] = OrderedDict()
            return_address_group[current_address]['addrObjId'] = current_address
            return_address_group[current_address]['addrObjIdDisp'] = ''
            return_address_group[current_address]['addrObjType'] = '8'
            return_address_group[current_address]['addrObjZone'] = ''
            return_address_group[current_address]['addrObjProperties'] = '14'
            return_address_group[current_address]['addrObjIp1'] = ''
            return_address_group[current_address]['addrObjIp2'] = ''
            return_address_group[current_address]['addrObjComment'] = ''
            return_address_group[current_address]['IPv4Networks'] = []
            addr_mappings[current_address] = []
            if address.find('description') != None:  
                return_address_group[current_address]['addrObjIdDisp'] = address.find('description').text
                return_address_group[current_address]['addrObjComment'] = address.find('description').text
            for address_group_member in address.findall('./static/member'):
                addr_mappings[current_address].append(address_group_member.text)
        return return_address_group, addr_mappings
        
    def load_services(service_list):

        return_service=OrderedDict()
        for service in service_list:
            current_service = service.get('name')
            return_service[current_service] = OrderedDict()
            return_service[current_service]['svcObjId'] = current_service
            return_service[current_service]['svcObjType'] = '1'
            return_service[current_service]['svcObjProperties'] = '14'
            return_service[current_service]['svcObjIpType'] = '1'
            return_service[current_service]['svcObjPort1'] = ''
            return_service[current_service]['svcObjPort2'] = ''
            return_service[current_service]['svcObj'] = '0'
            return_service[current_service]['svcObjManagement'] = ''
            return_service[current_service]['svcObjHigherPrecedence'] = ''
            return_service[current_service]['svcObjComment'] = '' # root.find('./devices/entry/device-group/entry[@name=\''+current_group+'\']/service/entry[@name=\''+current_service+'\']').findtext('description')
            if service.find('description') != None:  
                return_service[current_service]['svcObjComment'] = service.find('description').text
            if service.findall('./protocol/tcp'):
                return_service[current_service]['svcObjIpType'] = '6'
                port = service.find('./protocol/tcp').findtext('port')
            elif service.findall('./protocol/udp'):
                return_service[current_service]['svcObjIpType'] = '17'
                port = service.find('./protocol/udp').findtext('port')
            
            if re.findall(',', port): ## list of ports
                return_service[current_service]['svcObjPort1'], return_service[current_service]['svcObjPort2'] = (None, None)
                return_service[current_service]['svcObjPortSet'] = port.split(',')
                debug('PORTSET: ', current_service, return_service[current_service]['svcObjPortSet'])
                return_service[current_service]['svcObjPort1'] = '0'
                return_service[current_service]['svcObjPort2'] = '0'
                return_service[current_service]['svcObjType'] = '4'
            elif re.findall('-', port):  ## Port range
                return_service[current_service]['svcObjType'] = '1'
                return_service[current_service]['svcObjPort1'], return_service[current_service]['svcObjPort2'] = port.split('-')
            else: ## Single port
                return_service[current_service]['svcObjType'] = '1'
                return_service[current_service]['svcObjPort1'] = port
                return_service[current_service]['svcObjPort2'] = port
        return return_service

    def load_service_groups(service_list):

        return_service = OrderedDict()
        svc_mappings = OrderedDict()
        for service in service_list: 
            current_service = service.get('name')
            return_service[current_service] = OrderedDict()
            return_service[current_service]['svcObjId'] = current_service
            return_service[current_service]['svcObjType'] = '2'
            return_service[current_service]['svcObjProperties'] = '14'
            return_service[current_service]['svcObjIpType'] = '0'
            return_service[current_service]['svcObjPort1'] = ''
            return_service[current_service]['svcObjPort2'] = ''
            return_service[current_service]['svcObjManagement'] = ''
            return_service[current_service]['svcObjHigherPrecedence'] = ''
            return_service[current_service]['svcObjComment'] = ''
            svc_mappings[current_service] = []
            if service.find('description') != None:  
                return_service[current_service]['svcObjComment'] = service.find('description').text
            for service_group_member in service.findall('./members/member'):
                svc_mappings[current_service].append(service_group_member.text)
        return return_service, svc_mappings

    def load_policies(policy_list):
        
        policy_index = 0
        return_policy=OrderedDict()

        for policy in policy_list:
            
            disabled = policy.find('.').findtext('disabled')
            if disabled:
                disabled = disabled.lower()
            if not (disabled == 'yes' and options.skip_disabled):
                current_policy = policy.get('name')
                return_policy[policy_index] = OrderedDict()
                return_policy[policy_index]['policyName'] = current_policy
                return_policy[policy_index]['policyAction'] = ''
                return_policy[policy_index]['policySrcZone'] = []
                return_policy[policy_index]['policyDstZone'] = []
                return_policy[policy_index]['policySrcNet'] = []
                return_policy[policy_index]['policyDstNet'] = []
                return_policy[policy_index]['policyDstSvc'] = []
                return_policy[policy_index]['policyDstApps'] = []
                return_policy[policy_index]['policyLog'] = ''
                return_policy[policy_index]['policyEnabled'] = '1'
                return_policy[policy_index]['policyProps'] = '0'
                return_policy[policy_index]['policyNum'] = None
                return_policy[policy_index]['policyUiNum'] = None
                return_policy[policy_index]['policySrcNegate'] = True if policy.find('.').findtext('negate-source') == 'yes' else False
                return_policy[policy_index]['policyDstNegate'] = True if policy.find('.').findtext('negate-destination') == 'yes' else False
                return_policy[policy_index]['policySvcNegate'] = False
                return_policy[policy_index]['policyComment'] = policy.find('.').findtext('description')
                if return_policy[policy_index]['policyComment']==None: return_policy[policy_index]['policyComment']='' # Set Comment to blank if not found
                return_policy[policy_index]['policyLogSetting'] = policy.find('.').findtext('log-setting')
                if return_policy[policy_index]['policyLogSetting']==None: return_policy[policy_index]['policyLogSetting']='' # Set Log Setting to blank if not found
                return_policy[policy_index]['policyLogStart'] = policy.find('.').findtext('log-start')
                if return_policy[policy_index]['policyLogStart']==None: return_policy[policy_index]['policyLogStart']='' # Set Log Setting to blank if not found
                return_policy[policy_index]['policyLogEnd'] = policy.find('.').findtext('log-end')
                if return_policy[policy_index]['policyLogEnd']==None: return_policy[policy_index]['policyLogEnd']='' # Set Log Setting to blank if not found

                disabled = policy.find('.').findtext('disabled')
                action = policy.find('.').findtext('action')
                if disabled == 'yes':
                    return_policy[policy_index]['policyEnabled'] = '0'
                if action.lower() == 'allow':
                    return_policy[policy_index]['policyAction'] = '2'
                elif action == 'deny':
                    return_policy[policy_index]['policyAction'] = '0'
                elif action.lower() == 'drop':
                    return_policy[policy_index]['policyAction'] = '1'
                for member in policy.findall('./to/member'):
                    return_policy[policy_index]['policyDstZone'].append(member.text)
                for member in policy.findall('./from/member'):
                    return_policy[policy_index]['policySrcZone'].append(member.text)
                for member in policy.findall('./source/member'):
                    return_policy[policy_index]['policySrcNet'].append(member.text)
                for member in policy.findall('./destination/member'):
                    return_policy[policy_index]['policyDstNet'].append(member.text)
                for member in policy.findall('./service/member'):
                    return_policy[policy_index]['policyDstSvc'].append(member.text)
                for member in policy.findall('./application/member'):
                    return_policy[policy_index]['policyDstApps'].append(member.text)
                policy_index = policy_index + 1         
        return return_policy

    def load_nat(policy_list, interfaces):

        policy_index = 0
        return_nat=OrderedDict()
        
        for policy in policy_list:
            disabled = policy.find('.').findtext('disabled')
            if disabled:
                disabled = disabled.lower()
            if not (disabled == 'yes' and options.skip_disabled):
                current_policy = policy.get('name')
                return_nat[policy_index] = OrderedDict()
                return_nat[policy_index]['natPolicyName'] = current_policy
                return_nat[policy_index]['natPolicySrcZone'] = []
                return_nat[policy_index]['natPolicyDstZone'] = []
                return_nat[policy_index]['natPolicyOrigSrc'] = []
                return_nat[policy_index]['natPolicyOrigDst'] = []
                return_nat[policy_index]['natPolicyOrigSvc'] = []
                return_nat[policy_index]['natPolicyTransSrc'] = []
                return_nat[policy_index]['natPolicyTransDst'] = []
                return_nat[policy_index]['natPolicyTransSvc'] = []
                return_nat[policy_index]['natPolicySrcIface'] = []
                return_nat[policy_index]['natPolicyDstIface'] = []
                return_nat[policy_index]['natPolicyEnabled'] = '1'
                return_nat[policy_index]['natPolicyProperties'] = '0'
                return_nat[policy_index]['natPolicyComment'] = policy.find('.').findtext('description')
                if return_nat[policy_index]['natPolicyComment']==None: return_nat[policy_index]['natPolicyComment']='' # Set Comment to blank if not found
                disabled = policy.find('.').findtext('disabled')
                if disabled == 'yes':
                    return_nat[policy_index]['natPolicyEnabled'] = '0'
                for member in policy.findall('./to/member'):
                    return_nat[policy_index]['natPolicyDstZone'].append(member.text)
                for member in policy.findall('./from/member'):
                    return_nat[policy_index]['natPolicySrcZone'].append(member.text)
                for member in policy.findall('./source/member'):
                    return_nat[policy_index]['natPolicyOrigSrc'].append(member.text)
                for member in policy.findall('./destination/member'):
                    return_nat[policy_index]['natPolicyOrigDst'].append(member.text)
                for member in policy.findall('./service/member'):
                    return_nat[policy_index]['natPolicyOrigSvc'].append(member.text)

                #### Need to figure out how to determine translated values based on NAT type set in config
                if policy.find('.').findtext('source-translation'): 
                    if policy.find('./source-translation').findtext('dynamic-ip-and-port'): 
                        if policy.find('./source-translation/dynamic-ip-and-port').findtext('translated-address'):
                            for member in policy.findall('./source-translation/dynamic-ip-and-port/translated-address/member'):
                                return_nat[policy_index]['natPolicyTransSrc'].append(member.text)
                        if policy.find('./source-translation/dynamic-ip-and-port').findtext('interface-address'): 
                            int_name=policy.find('./source-translation/dynamic-ip-and-port/interface-address').findtext('interface')
                            if int_name in interfaces: 
                                    return_nat[policy_index]['natPolicyTransSrc']=[interfaces[int_name]['iface_static_ip']]
                            else: 
                                return_nat[policy_index]['natPolicyTransSrc']='UNKNOWN'
                            if policy.find('./source-translation/dynamic-ip-and-port/interface-address').findtext('ip'): 
                                return_nat[policy_index]['natPolicyTransSrc']=[policy.find('./source-translation/dynamic-ip-and-port/interface-address/ip').text]
                    if policy.find('./source-translation').findtext('dynamic-ip'): 
                        if policy.find('./source-translation/dynamic-ip').findtext('translated-address'):
                            for member in policy.findall('./source-translation/dynamic-ip/translated-address/member'):
                                return_nat[policy_index]['natPolicyTransSrc'].append(member.text)
                            if policy.find('./source-translation/dynamic-ip').findtext('fallback'):  
                                log('WARNING: FALLBACK settings not supoprted in source-translation dynamic-ip ')
                    if policy.find('./source-translation').findtext('static-ip'): 
                        if policy.find('./source-translation/static-ip').findtext('translated-address'):
                            return_nat[policy_index]['natPolicyTransSrc']=[policy.find('./source-translation/static-ip/translated-address').text]
                if policy.find('.').findtext('destination-translation'): 
                    if policy.find('./destination-translation').findtext('translated-address'):
                        return_nat[policy_index]['natPolicyTransDst']=[policy.find('./destination-translation/translated-address').text]
                    if policy.find('./destination-translation').findtext('translated-port'):
                        return_nat[policy_index]['natPolicyTransSvc']=[policy.find('./destination-translation/translated-port').text]
                if policy.find('.').findtext('dynamic-destination-translation'): 
                    log('dynamic-destination-translation set')
                    if policy.find('./dynamic-destination-translation').findtext('translated-address'):
                        return_nat[policy_index]['natPolicyTransDst']=[policy.find('./dynamic-destination-translation/translated-address').text]
                    if policy.find('./dynamic-destination-translation').findtext('translated-port'):
                        return_nat[policy_index]['natPolicyTransSvc']=[policy.find('./dynamic-destination-translation/translated-port').text]


                policy_index = policy_index + 1   
        return return_nat
    
    def load_zones(zone_list):

        return_zones=OrderedDict()
        #if root.find(zone_base)!=None:
        #zone_props = ['zoneObjId', 'zoneObjComment']

        for zone in zone_list:
            zone_name=zone.get('name')
            return_zones[zone_name]=OrderedDict()
            return_zones[zone_name]['zoneObjId']=zone_name
            return_zones[zone_name]['zoneObjComment']='Zone Comment'
            return_zones[zone_name]['zoneObjMembers']=[]
            #print(zone.get('name'))
            for interface in zone.findall('.//member'):
                #print(interface.text)
                    return_zones[zone_name]['zoneObjMembers'].append(interface.text)
                
        return return_zones
    
    def load_variables(variable_list):

        variables={}
        for variable in variable_list:
            if variable:
                variables[variable.get('name')]=variable.find('.//ip-netmask').text
            #debug('variable_name', variable.get('name'))
            #debug('variable_def', variable.find('.//ip-netmask').text)
        return variables

    def load_interface(interface_base):
        
        return_interface=OrderedDict()
       
        index=0
        #print(root.findall(interface_base))
        if root.find(interface_base)!=None:
            for interface_type in root.find(interface_base):
                for interface_names in root.findall(interface_base + '/' + interface_type.tag + '/entry'):
                    interface_name=interface_names.get('name')
                    return_interface[interface_name]=OrderedDict()
                    return_interface[interface_name]['iface_ifnum']=str(index)
                    return_interface[interface_name]['iface_type']=interface_type.tag
                    return_interface[interface_name]['iface_name']=interface_name
                    return_interface[interface_name]['interface_Zone']='' # this would get set when reading zones
                    return_interface[interface_name]['iface_comment' ]=''
                    return_interface[interface_name]['iface_static_ip']=''
                    return_interface[interface_name]['iface_static_mask']=''
                    return_interface[interface_name]['iface_static_gateway']=''
                    return_interface[interface_name]['iface_lan_ip']=''
                    return_interface[interface_name]['iface_lan_mask']=''
                    return_interface[interface_name]['iface_lan_default_gw']=''
                    return_interface[interface_name]['iface_mgmt_ip']=''
                    return_interface[interface_name]['iface_mgmt_netmask']=''
                    return_interface[interface_name]['iface_mgmt_default_gw']=''
                    return_interface[interface_name]['iface_vlan_tag']=''
                    return_interface[interface_name]['portShutdown']=''
                    index += 1
                    comment=root.find(interface_base + '/' + interface_type.tag + '/entry[@name="' + interface_name + '"]/comment')
                    if comment!=None: return_interface[interface_name]['iface_comment' ]=comment.text
                    for interface in root.findall(interface_base + '/' + interface_type.tag + '/entry[@name="' + interface_name + '"]'):
                        for interface_attribs in interface:
                            if interface_type.tag in ['ethernet', 'aggregate-ethernet'] and interface_attribs.tag.lower()=='layer3':
                                ip=root.find(interface_base + '/' +  interface_type.tag + '/entry[@name="' + interface_name + '"]/' + interface_attribs.tag + '/ip/entry[@name]')                                
                                if ip!=None:
                                    if ip.get('name') in return_variables: 
                                        ipname=return_variables[ip.get('name')]
                                    else:
                                        ipname=ip.get('name')
                                    if re.findall('/', ipname):
                                        return_interface[interface_name]['iface_static_ip'], return_interface[interface_name]['iface_static_mask'] = ipname.split('/')
                                        return_interface[interface_name]['iface_static_mask']=cidr_to_netmask(return_interface[interface_name]['iface_static_mask'])
                                    else:
                                        return_interface[interface_name]['iface_static_ip'], return_interface[interface_name]['iface_static_mask'] = '0.0.0.0', '0'
                                if interface_type.tag=='aggregate-ethernet': # get ip addresses for sub-interfaces
                                    for sub_interfaces in root.findall(interface_base + '/' +  interface_type.tag + '/entry[@name="' + interface_name + '"]/layer3/units/entry[@name]'):
                                        sub_interface=sub_interfaces.get('name')
                                        return_interface[sub_interface]=OrderedDict()
                                        return_interface[sub_interface]['iface_ifnum']=str(index)
                                        return_interface[sub_interface]['iface_type']=interface_type.tag
                                        return_interface[sub_interface]['iface_name']=sub_interface
                                        return_interface[sub_interface]['interface_Zone']='' # this would get set when reading zones
                                        return_interface[sub_interface]['iface_comment' ]=''
                                        return_interface[sub_interface]['iface_static_ip']=''
                                        return_interface[sub_interface]['iface_static_mask']=''
                                        return_interface[sub_interface]['iface_static_gateway']=''
                                        return_interface[sub_interface]['iface_lan_ip']=''
                                        return_interface[sub_interface]['iface_lan_mask']=''
                                        return_interface[sub_interface]['iface_lan_default_gw']=''
                                        return_interface[sub_interface]['iface_mgmt_ip']=''
                                        return_interface[sub_interface]['iface_mgmt_netmask']=''
                                        return_interface[sub_interface]['iface_mgmt_default_gw']=''
                                        return_interface[sub_interface]['iface_vlan_tag']=''
                                        return_interface[sub_interface]['portShutdown']=''
                                        index += 1
                                        ip=root.find(interface_base + '/' + interface_type.tag + '/entry[@name="' + interface_name + '"]/' + interface_attribs.tag + '/units/entry[@name="' + sub_interface + '"]/ip/entry[@name]')
                                        tag=root.find(interface_base + '/' + interface_type.tag + '/entry[@name="' + interface_name + '"]/' + interface_attribs.tag + '/units/entry[@name="' + sub_interface + '"]/tag')
                                        comment=root.find(interface_base + '/' + interface_type.tag + '/entry[@name="' + interface_name + '"]/' + interface_attribs.tag + '/units/entry[@name="' + sub_interface + '"]/comment')
                                        if ip!=None: 
                                            if ip.get('name') in return_variables: 
                                                ipname=return_variables[ip.get('name')]
                                            else:
                                                ipname=ip.get('name')
                                            if re.findall('/', ipname):
                                                return_interface[sub_interface]['iface_static_ip'], return_interface[sub_interface]['iface_static_mask'] =ipname.split('/')
                                                return_interface[sub_interface]['iface_static_mask']=cidr_to_netmask(return_interface[sub_interface]['iface_static_mask'])
                                            else:
                                                return_interface[sub_interface]['iface_static_ip'], return_interface[sub_interface]['iface_static_mask'] = '0.0.0.0', '0'
                                        if tag!=None: return_interface[sub_interface]['iface_vlan_tag']=tag.text
                                        if comment!=None: return_interface[sub_interface]['iface_comment' ]=comment.text



        return return_interface
    

    def load_interface2(interface_base):
        
        return_interface=OrderedDict()
       
        index=0
        if root.findall(interface_base)!=None:
            for interface_type in root.find(interface_base):
                print(interface_type)
                for interface_names in root.findall(interface_base + '/' + interface_type.tag + '/entry'):
                    interface_name=interface_names.get('name')
                    print(interface_name)
                    return_interface[interface_name]=OrderedDict()
                    return_interface[interface_name]['iface_ifnum']=str(index)
                    return_interface[interface_name]['iface_type']=interface_type.tag
                    return_interface[interface_name]['iface_name']=interface_name
                    return_interface[interface_name]['interface_Zone']='' # this would get set when reading zones
                    return_interface[interface_name]['iface_comment' ]=''
                    return_interface[interface_name]['iface_static_ip']=''
                    return_interface[interface_name]['iface_static_mask']=''
                    return_interface[interface_name]['iface_static_gateway']=''
                    return_interface[interface_name]['iface_lan_ip']=''
                    return_interface[interface_name]['iface_lan_mask']=''
                    return_interface[interface_name]['iface_lan_default_gw']=''
                    return_interface[interface_name]['iface_mgmt_ip']=''
                    return_interface[interface_name]['iface_mgmt_netmask']=''
                    return_interface[interface_name]['iface_mgmt_default_gw']=''
                    return_interface[interface_name]['iface_vlan_tag']=''
                    return_interface[interface_name]['portShutdown']=''
                    index += 1
                    comment=root.find(interface_base + '/' + interface_type.tag + '/entry[@name="' + interface_name + '"]/comment')
                    if comment!=None: return_interface[interface_name]['iface_comment' ]=comment.text
                    for interface in root.findall(interface_base + '/' + interface_type.tag + '/entry[@name="' + interface_name + '"]'):
                        for interface_attribs in interface:
                            if interface_type.tag in ['ethernet', 'aggregate-ethernet'] and interface_attribs.tag=='layer3':
                                ip=root.find(interface_base + '/' +  interface_type.tag + '/entry[@name="' + interface_name + '"]/' + interface_attribs.tag + '/ip/entry[@name]')
                                if ip!=None: 
                                    if re.findall('/', ip.get('name')):
                                        return_interface[interface_name]['iface_static_ip'], return_interface[interface_name]['iface_static_mask'] = ip.get('name').split('/')
                                    else:
                                        return_interface[sub_interface]['iface_static_ip'], return_interface[sub_interface]['iface_static_mask'] = '0.0.0.0', '0'
                                if interface_type.tag=='aggregate-ethernet': # get ip addresses for sub-interfaces
                                    for sub_interfaces in root.findall(interface_base + '/' +  interface_type.tag + '/entry[@name="' + interface_name + '"]/layer3/units/entry[@name]'):
                                        sub_interface=sub_interfaces.get('name')
                                        return_interface[sub_interface]=OrderedDict()
                                        return_interface[sub_interface]['iface_ifnum']=str(index)
                                        return_interface[sub_interface]['iface_type']=interface_type.tag
                                        return_interface[sub_interface]['iface_name']=sub_interface
                                        return_interface[sub_interface]['interface_Zone']='' # this would get set when reading zones
                                        return_interface[sub_interface]['iface_comment' ]=''
                                        return_interface[sub_interface]['iface_static_ip']=''
                                        return_interface[sub_interface]['iface_static_mask']=''
                                        return_interface[sub_interface]['iface_static_gateway']=''
                                        return_interface[sub_interface]['iface_lan_ip']=''
                                        return_interface[sub_interface]['iface_lan_mask']=''
                                        return_interface[sub_interface]['iface_lan_default_gw']=''
                                        return_interface[sub_interface]['iface_mgmt_ip']=''
                                        return_interface[sub_interface]['iface_mgmt_netmask']=''
                                        return_interface[sub_interface]['iface_mgmt_default_gw']=''
                                        return_interface[sub_interface]['iface_vlan_tag']=''
                                        return_interface[sub_interface]['portShutdown']=''
                                        index += 1
                                        ip=root.find(interface_base + '/' + interface_type.tag + '/entry[@name="' + interface_name + '"]/' + interface_attribs.tag + '/units/entry[@name="' + sub_interface + '"]/ip/entry[@name]')
                                        tag=root.find(interface_base + '/' + interface_type.tag + '/entry[@name="' + interface_name + '"]/' + interface_attribs.tag + '/units/entry[@name="' + sub_interface + '"]/tag')
                                        comment=root.find(interface_base + '/' + interface_type.tag + '/entry[@name="' + interface_name + '"]/' + interface_attribs.tag + '/units/entry[@name="' + sub_interface + '"]/comment')
                                        if ip!=None: 
                                            if ip.get('name') in return_addresses:
                                                return_interface[sub_interface]['iface_static_ip'], return_interface[sub_interface]['iface_static_mask'] = return_address[ip.get('name')]['addrObjIp1'], return_address[ip.get('name')]['addrObjIp2']
                                            else:
                                                if re.findall('/', ip.get('name')):
                                                    return_interface[sub_interface]['iface_static_ip'], return_interface[sub_interface]['iface_static_mask'] = ip.get('name').split('/')
                                                else:
                                                    return_interface[sub_interface]['iface_static_ip'], return_interface[sub_interface]['iface_static_mask'] = '0.0.0.0', '0'
                                        if tag!=None: return_interface[sub_interface]['iface_vlan_tag']=tag.text
                                        if comment!=None: return_interface[sub_interface]['iface_comment' ]=comment.text
        else:
            print('no interfaces found')
            print('')


        return return_interface
    
    
    def load_vrouters(vrouter_base):

        return_vrouter=OrderedDict()

        if root.find(vrouter_base)!=None:
            for vrouter in root.find(vrouter_base):
                vrouter_name=vrouter.get('name')
                return_vrouter[vrouter_name]=OrderedDict()
                if root.find(vrouter_base + '/entry[@name="' + vrouter_name + '"]/routing-table/ip/static-route'):
                    for static_routes in root.find(vrouter_base + '/entry[@name="' + vrouter_name + '"]/routing-table/ip/static-route'):
                        static_name=static_routes.get('name')
                        return_vrouter[vrouter_name][static_name]=OrderedDict()
                        #return_vrouter[vrouter_name][static_name]['nexthop']=''
                        return_vrouter[vrouter_name][static_name]['destination']=''
                        return_vrouter[vrouter_name][static_name]['metric']=''
                        return_vrouter[vrouter_name][static_name]['bfd']=''
                        
                        for vrouter_attribs in root.find(vrouter_base + '/entry[@name="' + vrouter_name + '"]/routing-table/ip/static-route/entry[@name="' + static_name + '"]'):
                            #debug(vrouter_attribs.tag)
                            if vrouter_attribs.tag.lower()=='nexthop':
                                return_vrouter[vrouter_name][static_name]['nexthops']=[]
                                for nexthop in root.find(vrouter_base + '/entry[@name="' + vrouter_name + '"]/routing-table/ip/static-route/entry[@name="' + static_name + '"]/nexthop'):
                                    return_vrouter[vrouter_name][static_name]['nexthops'].append(nexthop.text)
                            elif vrouter_attribs.tag.lower()=='destination':
                                return_vrouter[vrouter_name][static_name]['destination']=vrouter_attribs.text
                            elif vrouter_attribs.tag.lower()=='bfd':
                                return_vrouter[vrouter_name][static_name]['bfd']=vrouter_attribs.text
                            elif vrouter_attribs.tag.lower()=='metric':
                                return_vrouter[vrouter_name][static_name]['metric']=vrouter_attribs.text

        return return_vrouter

    import xml.etree.ElementTree as et
    import ipaddress
    from collections import OrderedDict
    import ipaddress
    import re
    from netaddr import IPSet
    
    return_config = OrderedDict()

    addr_mappings = OrderedDict()
    svc_mappings = OrderedDict()

    if memoryconfig:
        root=et.fromstring(memoryconfig) 
        #exit(1)
    else:
        panorama=et.parse(infile) 
        root=panorama.getroot()
    
    if root.findall('./mgt-config/devices') != []:
        pan_config=True
        log('!-- Loading Panorama XML file')
    else: 
        pan_config=False
        log('!-- Loading Palo Alto XML file')
    
    if pan_config==True:  # loop through all device groups for Panorama
        for templates in root.findall('./devices/entry/template/entry'):
            
            template=templates.get('name')

            return_config[template] = OrderedDict()
            log('!-- Reading Template : ' + template)

    ##      LOAD VARIABLES FROM XML
            log('  |-- Variable Objects             ', end='')
            variable_list=root.findall('./devices/entry[@name="localhost.localdomain"]/template/entry[@name=\'' + template +  '\']/variable/entry')
            if variable_list:
                return_variables = load_variables(variable_list)
            else:
                return_variables = []

    ##      LOAD VROUTERS FROM XML
            log('  |-- Loading VRouters', end='')
            return_vrouters=load_vrouters('./devices/entry[@name="localhost.localdomain"]/template/entry[@name="' + template +  '"]/config/devices/entry[@name="localhost.localdomain"]/network/virtual-router')
            #log(return_vrouters)

    ##      LOAD INTERFACES FROM XML
            log('  |-- Interface Objects             ', end='')
            return_interface = load_interface('./devices/entry[@name="localhost.localdomain"]/template/entry[@name=\'' + template +  '\']/config/devices/entry[@name=\'localhost.localdomain\']/network/interface')
            #debug(root.findall('./devices/entry[@name="localhost.localdomain"]/template/entry[@name="' + current_group +  '"]/config/devices/entry[@name="localhost.localdomain"]/network/interface'))
            #log(return_interface)

    ##      LOAD ZONES FROM XML
            log('  |-- Zone Objects             ', end='')
            zone_list=root.findall('./devices/entry[@name="localhost.localdomain"]/template/entry[@name=\'' + template +  '\']/config/devices/entry[@name=\'localhost.localdomain\']/vsys/entry[@name=\'vsys1\']/zone/entry')
            return_zones = load_zones(zone_list)

    ##      ASSIGN ZONES TO INTERFACES
            log('!-- Assigning Zones')
            if return_zones:
                for zone in return_zones:
                    #print('Zone: ', zone)
                    for zone_member in return_zones[zone]['zoneObjMembers']:
                        for interface in return_interface:
                            #log('return interface: ', interface)
                            if return_interface[interface]['iface_name'] == zone_member:
                                return_interface[interface]['interface_Zone']=zone
            
            return_config[template]['config']=defaultdict()
            return_config[template]['config']['name']=template
            return_config[template]['config']['fw_type']='panorama'
            return_config[template]['config']['version']=''
            if options.panoramaip: 
                return_config[template]['config']['mgmtip']=options.panoramaip
            else:
                return_config[template]['config']['mgmtip']=None            
            return_config[template]['interfaces']=return_interface
            return_config[template]['zones']=return_zones
            return_config[template]['vrouters']=return_vrouters
            return_config[template]['addresses']={}
        
        for device_groups in root.findall('./devices/entry/device-group/entry'):
            
            return_addresses = OrderedDict()
            return_service = OrderedDict()
            return_policy = OrderedDict()
            return_nat = OrderedDict()
        
            current_group = device_groups.get('name')
            return_addresses = OrderedDict()

            addr_mappings = OrderedDict()
            svc_mappings = OrderedDict()

            log('!-- Reading Device-Group : ' + current_group)
            
            logprofiles = []
            for logs in root.findall('./devices/entry/device-group/entry[@name=\''+current_group+'\']/log-settings/profiles/entry'):
                logprofiles.append(logs.get('name'))
                
    ##      LOAD ADDRESSES FROM XML
            log('  |-- Address Objects        \r', end=' ')
            address_list=root.findall('./devices/entry/device-group/entry[@name=\''+current_group+'\']/address/entry')
            return_addresses=load_addresses(address_list)
        
    ##      LOAD ADDRESS GROUPS FROM XML
            log('  |-- Address-Group Objects  \r', end=' ')
            address_list=root.findall('./devices/entry/device-group/entry[@name=\''+current_group+'\']/address-group/entry')
            tmp_addresses=OrderedDict()
            if address_list != []:
                tmp_addresses, addr_mappings=load_address_groups(address_list)
            return_addresses.update(tmp_addresses)
            
    ##      LOAD SERVICES FROM XML
            log('  |-- Service Objects        \r', end=' ')
            service_list=root.findall('./devices/entry/device-group/entry[@name=\''+current_group+'\']/service/entry')
            return_service=load_services(service_list)
            
    ##      LOAD SERVICES GROUPS FROM XML
            log('  |-- Service Group Objects  \r', end=' ')
            service_list = root.findall('./devices/entry/device-group/entry[@name=\''+current_group+'\']/service-group/entry')
            tmp_services = OrderedDict()
            if service_list != []: 
                tmp_services, svc_mappings=load_service_groups(service_list)
            return_service.update(tmp_services)

    ##      LOAD POLICIES FROM XML   
            log('  |-- Policy Objects         \r', end='')
            policy_list = root.findall('./devices/entry/device-group/entry[@name=\''+current_group+'\']/pre-rulebase/security/rules/entry')
            return_policy = load_policies(policy_list)
    
    ##      LOAD NAT POLICIES FROM XML
            log('  |-- NAT Objects             \r', end='')
            policy_list = root.findall('./devices/entry/device-group/entry[@name=\''+current_group+'\']/rulebase/nat/rules/entry')
            return_nat = load_nat(policy_list, return_interface)

            ## Assign loaded values to return variables

            if current_group not in return_config:
                return_config[current_group] = OrderedDict()
            return_config[current_group]['config']=defaultdict()
            return_config[current_group]['config']['name']=current_group
            return_config[current_group]['config']['fw_type']='panorama'
            return_config[current_group]['config']['version']=''
            if options.panoramaip: 
                return_config[current_group]['config']['mgmtip']=options.panoramaip
            else:
                return_config[current_group]['config']['mgmtip']=None

            return_config[current_group]['addresses']=return_addresses
            return_config[current_group]['addressesV6']={}
            return_config[current_group]['services']=return_service
            return_config[current_group]['policies']=return_policy
            return_config[current_group]['nat']=return_nat
            return_config[current_group]['apps']={}
            return_config[current_group]['addressmappings']=addr_mappings
            return_config[current_group]['servicemappings']=svc_mappings
            
            ## Placeholder keys for future use
            return_config[current_group]['zones']={}

            return_config[current_group]['routing']=OrderedDict()
            return_config[current_group]['logprofiles']=logprofiles

    ## READ SHARED OBJECTS (panorama only)

        ## Re-initialize variables used above

        return_addresses = OrderedDict()
        return_service = OrderedDict()
        return_policy = OrderedDict()
        addr_mappings = OrderedDict()

        log('!-- Reading Shared Objects : ')
        log('  |-- Address Objects  \r', end=' ')
        
        logprofiles = []

        for logs in root.findall('./shared/log-settings/profiles/entry'):    
            logprofiles.append(logs.get('name'))

    ##  READ SHARED ADDRESS OBJECTS
        address_list=root.findall('./shared/address/entry')
        return_addresses=load_addresses(address_list)
            
    ##  LOAD SHARED ADDRESS GROUPS FROM XML
        log('  |-- Address-Group Objects  \r', end=' ')
        addr_mappings=OrderedDict()
        address_list=root.findall('./shared/address-group/entry')
        tmp_addresses=OrderedDict()

        if address_list != []:
            tmp_addresses, addr_mappings=load_address_groups(address_list)
        return_addresses.update(tmp_addresses)

    ##  LOAD SHARED SERVICE FROM XML    
        log('  |-- Service Objects        \r', end=' ')
        service_list=root.findall('./shared/service/entry')
        return_service=load_services(service_list)

    ##  LOAD SHARED SERVICE GROUPS FROM XML   
        log('  |-- Service Group Objects  \r', end=' ')
        svc_mappings = OrderedDict()
        service_list = root.findall('./shared/service-group/entry')
        tmp_services = OrderedDict()
        
        if service_list != []: 
            tmp_services, svc_mappings=load_service_groups(service_list)
        return_service.update(tmp_services)
    
        return_config['shared'] = OrderedDict()
        return_config['shared']['config']=defaultdict()
        return_config['shared']['config']['name']='shared'
        return_config['shared']['config']['fw_type']='panorama'
        return_config['shared']['config']['version']=''
        if options.panoramaip: 
            return_config['shared']['config']['mgmtip']=options.panoramaip
        else:
            return_config['shared']['config']['mgmtip']=None
        #debug('return_addresses')
        return_config['shared']['addresses']=return_addresses
        return_config['shared']['addressesV6']={}
        return_config['shared']['services']=return_service
        return_config['shared']['policies']=OrderedDict()  #return_policy
        return_config['shared']['nat']=OrderedDict()
        return_config['shared']['apps']={}
        return_config['shared']['addressmappings']=addr_mappings
        return_config['shared']['servicemappings']=svc_mappings
        return_config['shared']['logprofiles']=logprofiles  # move this to 'config'
        return_config['shared']['vrouters']={}


        ## This is a search for "temp" objects - these are IP addresses directly input into policies without referencing an address object
        '''    
        for c in return_config: # context
            for p in return_config[c]['policies']: # policy 
                for s in return_config[c]['policies'][p]['policySrcNet']:
                    if s not in return_config[c]['addresses'] and s not in return_config['shared']['addresses'] and s.lower()!='any':
                        debug(c + ':' + return_config[c]['policies'][p]['policyName'] + ':' + s + ' not found')    
                for d in return_config[c]['policies'][p]['policyDstNet']:
                    if d not in return_config[c]['addresses'] and d not in return_config['shared']['addresses'] and d.lower()!='any':
                        debug(c + ':' + return_config[c]['policies'][p]['policyName'] + ':' + d + ' not found')  
        '''

        return return_config
        

    else:  # load Palo Alto Config
        return_addresses = OrderedDict()
        return_service = OrderedDict()
        return_policy = OrderedDict()
        return_interface = OrderedDict()
        return_variables = []

        current_group = 'paloalto'
        return_addresses = OrderedDict()

        addr_mappings = OrderedDict()
        svc_mappings = OrderedDict()
        
        log('!-- Reading Device-Group : ' + current_group)
        logprofiles = []
        for logs in root.findall('./shared/log-settings/profiles/entry'):
            #log(logs.get('name'))
            logprofiles.append(logs.get('name'))

        ## interfaces
        interface_list=root.findall('./devices/entry[@name="localhost.localdomain"]/network/interface/ethernet')

def expand_address(address_dict, address_object, address_map, inc_group=False):

    ## Takes an address group object (by name) and expands it into a list of all of its individual address objects

    expanded_addresses = []
    if address_object in address_dict:  
        if 'addrObjType' in address_dict[address_object]:
            if address_dict[address_object]['addrObjType'] != '8':
                expanded_addresses.append(address_object)
            else:
                if inc_group:
                    expanded_addresses.append(address_object)
                if address_object in address_map:
                    #for group_members in address_map[address_dict[address_object]['addrObjId']]:
                    for group_members in address_map[address_object]:
                        for group_member in expand_address(address_dict,group_members,address_map, inc_group):
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
                            for group_member in expand_address(config['shared']['addresses'],group_members,config['shared']['addressesmappings'], inc_group):
                                expanded_addresses.append(group_member)
            

    return expanded_addresses;


def exec_fw_command(target, fw_type, commands, syntax='cli', policylens=None, delay=None, use_session=True, use_apikey=False, dryrun=False, sw_objects=None):  # add sw_sesssion, enable_api and commit options -- what is policy lens for?
    
    ## in theory, for checkpoint, commands could include multiple CMAs.  We should build a list of all the CMAs in a set of commands, then generate a sid and uid for each
    

    valid_commands=['create_address',
                    'modify_address',
                    'create_rule',
                    'modify_rule',
                    'create_service',
                    'modify_service',
                    'raw_command' ]
    #all_params=['context', 'ip1', 'ip2', 'name', 'members', 'comment', 'color', 'type', 'props', 'zone', 'srczone', 'dstzone', 'service', 'app', 'cmdtype', 'rulename', 'rulenum']
    
    retries=3
    result=True
    #sw_objects={'address_objects': {'ipv4': [], 'ipv6': [], 'fqdn': []}, 'address_groups': {'ipv4': [], 'ipv6': [], 'fqdn': []}, 'service_objects': [], 'service_groups': [] }
    sw_objects=None
    if fw_type.lower() in ['sonicwall', 'palo', 'paloalto', 'pano', 'sw65', 'checkpoint'] and syntax!='cli':
        session = requests.Session()
        session.mount('https://' + target, sw.DESAdapter())
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
        if not options.web and (options.username == None or options.password == None):
            options.username, options.password = get_creds()
        if fw_type.lower()=='sonicwall':
            response=sw.do_login(session, options.username, options.password, target, True)
            apikey=None
        elif fw_type.lower() in ['sw65']:
            tries=0
            success=False
            while tries < retries and not success:
                tries += 1
                try:
                    url='https://{}/api/sonicos/auth'.format(target)
                    session.headers=OrderedDict([('User-Agent', 'python-requests/2.18.4'), ('Accept', '*/*'), ('Accept-Encoding', 'gzip, deflate'), ('Connection', 'keep-alive')])
                    post_data=None
                    #auth = requests.auth.HTTPBasicAuth(options.username, options.password) -- replaced with manually setting headers myself since python requests basic auth was not handling special characters correctly
                    response_code=None
                    login_tries=0
                    apikey=None
                    while response_code != 200 and login_tries < 1:
                        login_tries+=1
                        response=session.post(url=url, headers={'authorization': "Basic " + base64.b64encode('{}:{}'.format(options.username, options.password).encode()).decode()}, verify=False, timeout=options.timeout_sw_webui_login)
                        response_code=response.status_code
                        #log('LOGIN RESULT', response.text)
                        apikey=True
                    if response_code != 200:
                        session=None
                        apikey=None
                        log('!-- Login failed')
                    else:  
                        if not sw_objects:
                            ## build sonicwall objects list - this is needed to determine object type for when they need to be added to other objects
                            ## get addresses_objects, address_groups, address_fqdn, services_objects, service_groups for ipv4, ipv6, fqdn
                            ## verify we are in config mode 
                            #log('building sw_objects')
                            sw_objects=get_sw_objects(target, options.username, options.password, fw_type, session)
                    success=True
                except Exception as e:
                    log('An exception occured when trying to log in to Sonicwall : {}'.format(e))

        elif fw_type.lower() in ['palo', 'pano', 'paloalto'] and use_session:
            try:
                key=session.get('https://' + target + '/api/?type=keygen&user=' + options.username + '&password=' + quote(options.password), verify=False, stream=True, timeout=options.timeout_palo_api)
                if len(re.findall("status = 'success'", key.text)) == 0:
                    log('Unable to execute configuration commands - Login Failed')
                    debug(key.text)
                    return False
                apikey = re.sub(r'.*<key>(.*)</key>.*',r'\1',key.text)
            except:
                apikey=None
        elif fw_type.lower() in ['checkpoint']:
            debug('!-- Logging into Checkpoint R80 API to get SID and UID')
            apikey, session, message = ckpt_login(target, options.context[0], options.username, options.password)
            if not apikey:
                debug('!-- Login to Checkpoint R80 API failed')
                session=None
                apikey=None
            else:
                debug('!-- Login to Checkpoint R80 API successful - Retreived SID {} and UID {}'.format(apikey, session))
                pass
                #session=options.context[0]

        else:  # what is this here for?
            session=None
            apikey=True

    else:
        session=None
        apikey=None
    #debug(apikey)
    #debug(session)

    if apikey or fw_type.lower() not in ['palo', 'paloalto', 'pano', 'sw65'] or syntax.lower()=='cli':
        #
        tries=0
        success=False
        debug('COMMANDS', commands)
        while tries < retries and not success:
            tries += 1
            #log('starting push -- try : {}'.format(tries))        
            try:
                successful_commands = 0
                for command, params in commands:
                    debug('COMMAND', command)
                    debug('PARAMS', params)
                    #        for param in all_params: #set defalt value for all unset params - no validation is done at this time that the right params are passed for each cmdtype
                    #            if param not in command:
                    #                if param=='members':
                    #                    command[param]=[]
                    #                elif param=='color':
                    #                    command['color']='black'
                    #                else:
                    #                    command[param]=None    
                    
                    if 'comment' not in params: #should provide proper handling of missing comment in functions below instead of setting this for everything CHANGE_ME
                        params['comment']=''
                    if command=='create_address':
                        result=create_address_obj(target, session, apikey, fw_type, syntax, params, sw_objects) 
                    elif command=='modify_address':
                        result=modify_address_obj(target, session, apikey, fw_type, syntax, params, sw_objects)
                    elif command=='modify_address_group':
                        result=modify_address_obj(target, session, apikey, fw_type, syntax, params, sw_objects)
                    elif command=='create_rule': 
                        result=create_rule_obj(target, session, apikey, fw_type, syntax, params, sw_objects)
                    elif command=='modify_rule': 
                        result=modify_rule_obj(target, session, apikey, fw_type, syntax, params, sw_objects)
                    elif command=='create_service': 
                        result=create_service_obj(target, session, apikey, fw_type, syntax, params, sw_objects) 
                    elif command=='modify_service': 
                        result=modify_service_obj(target, session, apikey, fw_type, syntax, params, sw_objects) 
                    else:
                        return 'Unknown Command'
                    if syntax.lower() !='cli':
                        debug('{},{},{},"{}",{}'.format(target,fw_type,command,params,result))
                    if delay:
                        debug('Sleeping for {} seconds'.format(delay))
                        time.sleep(delay)
                success=result==True
                if success:
                    successful_commands += 1
            except Exception as e:
                log('An exception occured when trying to perform exec_fw_command : {}'.format(e))

        ## Add sonicwall log-out / commit routines
        tries=0
        success=False
        if successful_commands>0:
            #log('attempting commit')
            if fw_type.lower() in ['sw65']:
                while tries < retries and not success:
                    tries += 1
                    try:
                        commit_result=session.get('https://{}/api/sonicos/config/pending'.format(target), data=None, verify=False, timeout=options.timeout_sw_webui)
                        debug(commit_result.text)
                        if json.loads(commit_result.text)!={}:
                            debug('!-- Commiting pending changes')
                            commit_result=session.post('https://{}/api/sonicos/config/pending'.format(target), data=None, verify=False, timeout=options.timeout_sw_webui_post)
                            debug(commit_result.text)
                            if 'status' in json.loads(commit_result.text):
                                success=True
                            if not json.loads(commit_result.text)['status']['success']:
                                result=False, json.loads(commit_result.text)['status']['info'][0]['message']
                        else:
                            debug('!-- No Changes made - Skipping commit')
                            success=True
                        debug('!-- Logging out of API')
                        url='https://{}/api/sonicos/auth'.format(target)
                        session.delete(url=url, verify=False, timeout=options.timeout_sw_webui)
                    except Exception as e:
                        log('An exception occured when trying to commit Sonicwall config : {}'.format(e))
            elif fw_type.lower() == 'checkpoint' and syntax.lower()=='api':
                if result==True: 
                    debug('result before publish', result)
                    publish_result = ckpt_api_call(target, 443, "publish", {}, apikey)
                    debug("publish result: " + json.dumps(publish_result.text))
                    if 'task-id' not in json.loads(publish_result.text):
                        result=False, 'Publish Failed'
                        debug('!-- Changes failed -- discarding changes')
                        discard_result = ckpt_api_call(target, 443, "discard", {'uid': session}, apikey)
                        debug('discard result', discard_result)
                else:
                    debug('!-- Changes failed -- discarding changes')
                    discard_result = ckpt_api_call(target, 443, "discard", {'uid': session}, apikey)
                    debug('discard result', discard_result)
                debug('!-- Logging out of Checkpoint API')
                logout_result = ckpt_api_call(target, 443, "logout", {}, apikey)
                debug("logout result: " + json.dumps(logout_result.text))
    else:
        return False, 'no API key'
    #log('result', result)
    return result


def get_zone(context, ip, config):

    try:
        ip=ip.split('/')[0]
        log_info('Searching {} for address : {}'.format(context, ip)) 
        log_info('-' *100)
    #        for item in config[context]:
    #            print(item)
        if 'routing' in config[context]: 
            log_info('routing found in config')
            matchlen = -1
            
            for interface in config[context]['interfaces']:
                log_info('interface', interface)
                if config[context]['interfaces'][interface]['iface_lan_ip']!='0.0.0.0':
                    if ip in netaddr.IPNetwork('{}/{}'.format(config[context]['interfaces'][interface]['iface_lan_ip'],netmask_to_cidr(config[context]['interfaces'][interface]['iface_lan_mask']))):
                        debug('matches lan', config[context]['interfaces'][interface]['interface_Zone'])
                        return config[context]['interfaces'][interface]['interface_Zone']    
                if config[context]['interfaces'][interface]['iface_static_ip']!='0.0.0.0':
                    #log(config[context]['interfaces'][interface]['iface_static_ip'])
                    debug(ip)
                    if ip in netaddr.IPNetwork('{}/{}'.format(config[context]['interfaces'][interface]['iface_static_ip'],netmask_to_cidr(config[context]['interfaces'][interface]['iface_static_mask']))):
                        debug('matches static', config[context]['interfaces'][interface]['interface_Zone'])
                        return config[context]['interfaces'][interface]['interface_Zone']    
                if config[context]['interfaces'][interface]['iface_mgmt_ip']!='0.0.0.0':
                    #log(config[context]['interfaces'][interface]['iface_mgmt_ip'])
                    if ip in netaddr.IPNetwork('{}/{}'.format(config[context]['interfaces'][interface]['iface_mgmt_ip'],netmask_to_cidr(config[context]['interfaces'][interface]['iface_mgmt_netmask']))):
                        debug('matches mgmt', config[context]['interfaces'][interface]['interface_Zone'])
                        return config[context]['interfaces'][interface]['interface_Zone']    
            next_hop=None
            next_hop_ip=None
            next_hop_iface=None
            next_hop_ifacenum=None
            next_hop_ifacename=None
            for route in config[context]['routing']:
                log_info('route', route)
                route_dest=config[context]['routing'][route]['pbrObjDst']
                if route_dest=='': 
                    route_dest='0.0.0.0'
                log_info('Route Destination :', route_dest)
                if config[context]['routing'][route]['pbrObjSrc']=="":
                    if route_dest in config[context]['addresses']:
                        #print(config[context]['addresses'][route_dest])
                        #log_info(config[context]['addresses'][route_dest]['addrObjType'])
                        if config[context]['addresses'][route_dest]['addrObjType'] == '8':
                            #log_info(config[context]['addresses'][route_dest])
                            log_info('Route Destination is a group, checking each member object')
                            for route_dest_addr in expand_address(config[context]['addresses'], route_dest, config[context]['addressmappings']):
                                if route_dest_addr in config[context]['addresses']:
                                    log_info(route_dest_addr)
                                    #print(ip)
                                    if config[context]['addresses'][route_dest_addr]['addrObjType']=='2':
                                        route_destination=netaddr.IPRange(config[context]['addresses'][route_dest_addr]['addrObjIp1'], config[context]['addresses'][route_dest_addr]['addrObjIp2'])
                                    else:
                                        route_destination=netaddr.IPNetwork('{}/{}'.format(config[context]['addresses'][route_dest_addr]['addrObjIp1'], config[context]['addresses'][route_dest_addr]['addrObjIp2']))
                                    if netaddr.IPAddress(ip) in route_destination:
                                    #if netaddr.IPAddress(ip) in netaddr.IPNetwork('{}/{}'.format(config[config[context]['addresses']['addrObjIp1'], netmask_to_cidr(config[context]['interfaces'][interface]['iface_lan_mask']))):
                                        #config[context]['addresses'][route_dest_addr]['IPSet']:
                                        debug('Matched to {}/{}'.format(config[context]['addresses'][route_dest_addr]['addrObjIp1'], config[context]['addresses'][route_dest_addr]['addrObjIp2']))
                                        if netmask_to_cidr(config[context]['addresses'][route_dest_addr]['addrObjIp2']) > matchlen:
                                            #log(config[context]['routing'][route])
                                            matchlen=netmask_to_cidr(config[context]['addresses'][route_dest_addr]['addrObjIp2'])
                                            next_hop=config[context]['routing'][route]['pbrObjGw']
                                            next_hop_ifacenum=config[context]['routing'][route]['pbrObjIface']
                                            debug('Nexthop : ', next_hop)
                                            debug(config[context]['routing'][route])
                                            if next_hop in config[context]['addresses']:
                                                debug('Next hop object found in addresses')
                                                next_hop_ip=config[context]['addresses'][next_hop]['addrObjIp1']
                                            else:
                                                next_hop_ip=next_hop
                                            if next_hop_ip=='':
                                                if config[context]['routing'][route]['pbrObjIface'] in [config[context]['interfaces'][x]['iface_name'] for x in config[context]['interfaces']]:
                                                    for x in config[context]['interfaces']:
                                                        if config[context]['routing'][route]['pbrObjIface'] == config[context]['interfaces'][x]['iface_name']:
                                                            if config[context]['interfaces'][x]['iface_lan_ip']!='0.0.0.0':
                                                                next_hop_ip=config[context]['interfaces'][x]['iface_lan_default_gw']
                                                            else:
                                                                next_hop_ip=config[context]['interfaces'][x]['iface_static_gateway']
                                            log_info('Searched address found in destination group: "{}" - MatchLength {} Nexthop {} {}'.format(urllib.parse.unquote(route_dest), matchlen, next_hop, next_hop_ip))
                                            ## THIS IS THE CORRECT GET_ZONE

                                        else:
                                            log_info('Skipping - not longest match')
                                else:
                                    log_info('Address group not found in context')
                        elif config[context]['addresses'][route_dest]['addrObjType'] == '2':
                            if netaddr.IPAddress(ip) in netaddr.IPRange(config[context]['addresses'][route_dest]['addrObjIp1'], config[context]['addresses'][route_dest]['addrObjIp2']):
                            #if ip in config[context]['addresses'][route_dest]['IPSet']:
                                log_info('Searched address found in destination range address object')
                                if netmask_to_cidr(config[context]['addresses'][route_dest]['addrObjIp2']) > matchlen:
                                    matchlen=32
                                    next_hop=config[context]['routing'][route]['pbrObjGw']
                                    next_hop_ifacenum=config[context]['routing'][route]['pbrObjIface']
                                    if next_hop in config[context]['addresses']:
                                        next_hop_ip=config[context]['addresses'][next_hop]['addrObjIp1']
                                    else:
                                        next_hop_ip=next_hop
                                else:
                                    log_info('Skipping - not longest match')
                        else:
                            #if 'IPSet' in config[context]['addresses'][route_dest]:
                            if netaddr.IPAddress(ip) in netaddr.IPNetwork('{}/{}'.format(config[context]['addresses'][route_dest]['addrObjIp1'], config[context]['addresses'][route_dest]['addrObjIp2'])):
                            #if ip in config[context]['addresses'][route_dest]['IPSet']:
                                log_info('Searched address found in destination address')
                                if netmask_to_cidr(config[context]['addresses'][route_dest]['addrObjIp2']) > matchlen:
                                    matchlen=netmask_to_cidr(config[context]['addresses'][route_dest]['addrObjIp2'])
                                    next_hop=config[context]['routing'][route]['pbrObjGw']
                                    next_hop_ifacenum=config[context]['routing'][route]['pbrObjIface']
                                    if next_hop in config[context]['addresses']:
                                        next_hop_ip=config[context]['addresses'][next_hop]['addrObjIp1']
                                    else:
                                        next_hop_ip=next_hop
                                else:
                                    log_info('Skipping - not longest match')
                            #else:
                            #    log('WARNING - Route destinations with Range objects not yet supported - need to add IPSet property to Range address objects - {}-{}'.format(config[context]['addresses'][route_dest]['addrObjIp1'], config[context]['addresses'][route_dest]['addrObjIp2']))
                            #print(next_hop)
                            #print(next_hop_ip)
                    elif len(route_dest.split('/'))==2:
                        log_info('Route destination is not in address objects')
                        try:
                            if netaddr.IPAddress(ip) in netaddr.IPNetwork(route_dest):
                                network, mask = route_dest.split('/')
                                if int(mask) >= matchlen:
                                    
                                    matchlen=int(mask)
                                    next_hop=config[context]['routing'][route]['pbrObjGw']
                                    next_hop_ifacenum=str(config[context]['routing'][route]['pbrObjIface'])
                                    if 'pbrObjIfaceName' in config[context]['routing'][route]:
                                        next_hop_ifacename=config[context]['routing'][route]['pbrObjIfaceName']
                                    else:
                                        next_hop_ifacename=''
                                    log_info('MATCH1 "{}" "{}" "{}" "{}"'.format( network, mask, config[context]['routing'][route]['pbrObjGw'], config[context]['routing'][route]['pbrObjIface'], ))
                                if next_hop in config[context]['addresses']:
                                    next_hop_ip=config[context]['addresses'][next_hop]['addrObjIp1']
                                else:
                                    next_hop_ip=next_hop
                        except Exception as e:
                            log(e)
                            log('Route destination not in network/mask format')
                    elif route_dest == '0.0.0.0' and matchlen < 0:  # route is a default route
                        matchlen=0
                        next_hop=config[context]['routing'][route]['pbrObjGw']
                        next_hop_ifacenum=config[context]['routing'][route]['pbrObjIface']
                        if 'pbrObjIfaceName' in config[context]['routing'][route]: 
                            next_hop_ifacename=config[context]['routing'][route]['pbrObjIfaceName']     
                        else:
                             next_hop_ifacename=''
                        if next_hop in config[context]['addresses']:
                            next_hop_ip=config[context]['addresses'][next_hop]['addrObjIp1']
                        else:
                            next_hop_ip=next_hop
                        log_info('Default Route!')

                    #print(config[context]['interfaces'])
            log_info('Matchlen', matchlen)
            
            if next_hop_ifacenum != None:
                for interface in config[context]['interfaces']:
                    #log('"{}" "{}" "{}" "{}"'.format(config[context]['interfaces'][interface]['iface_ifnum'], next_hop_ifacenum, config[context]['interfaces'][interface]['iface_name'], next_hop_ifacename))
                    if config[context]['interfaces'][interface]['iface_name'] == next_hop_ifacename: # or config[context]['interfaces'][interface]['iface_name'] == next_hop_ifacen:
                        #log("-" *180)
                        #log('!!!!{}!!!!!!'.format(config[context]['interfaces'][interface]['iface_name']))
                        #log("-" *180)
                        #log(config[context]['interfaces'][interface]['interface_Zone'])
                        return config[context]['interfaces'][interface]['interface_Zone']

            if matchlen != -1:
                if next_hop_ip=='' : 
                    next_hop_ip='0.0.0.0'
                log_info('NEXTHOP', next_hop, next_hop_ip, next_hop_ifacenum)

                for interface in config[context]['interfaces']:
                    if config[context]['interfaces'][interface]['iface_lan_ip']!='0.0.0.0':
                        if netaddr.IPAddress(next_hop_ip) in netaddr.IPNetwork('{}/{}'.format(config[context]['interfaces'][interface]['iface_lan_ip'],netmask_to_cidr(config[context]['interfaces'][interface]['iface_lan_mask']))):
                            #print('{} - {}/{}'.format(config[context]['interfaces'][interface]['iface_name'],config[context]['interfaces'][interface]['iface_lan_ip'],config[context]['interfaces'][interface]['iface_lan_mask']))
                            #print('ROUTE MATCH - Searched address {} is in Zone : {} Interface Name: {} Interface Address {}/{}'.format(ip, config[context]['interfaces'][interface]['interface_Zone'], config[context]['interfaces'][interface]['iface_name'], config[context]['interfaces'][interface]['iface_lan_ip'],netmask_to_cidr(config[context]['interfaces'][interface]['iface_lan_mask'])))
                            return config[context]['interfaces'][interface]['interface_Zone']
                    elif config[context]['interfaces'][interface]['iface_static_ip']!='0.0.0.0':
                        #log(netaddr.IPAddress(next_hop_ip))
                        #log(config[context]['interfaces'][interface]['iface_static_ip'], config[context]['interfaces'][interface]['iface_static_mask'])
                        if netaddr.IPAddress(next_hop_ip) in netaddr.IPNetwork('{}/{}'.format(config[context]['interfaces'][interface]['iface_static_ip'],netmask_to_cidr(config[context]['interfaces'][interface]['iface_static_mask']))):
                            ##print('{} - {}/{}'.format(config[context]['interfaces'][interface]['iface_name'],config[context]['interfaces'][interface]['iface_static_ip'],config[context]['interfaces'][interface]['iface_static_mask']))
                            #print('ROUTE MATCH - Searched address {} is in Zone : {} Interface Name: {} Interface Address {}/{}'.format(ip, config[context]['interfaces'][interface]['interface_Zone'], config[context]['interfaces'][interface]['iface_name'], config[context]['interfaces'][interface]['iface_static_ip'],netmask_to_cidr(config[context]['interfaces'][interface]['iface_static_mask'])))
                            return config[context]['interfaces'][interface]['interface_Zone']
                    elif config[context]['interfaces'][interface]['iface_mgmt_ip']!='0.0.0.0':
                        if netaddr.IPAddress(next_hop_ip) in netaddr.IPNetwork('{}/{}'.format(config[context]['interfaces'][interface]['iface_mgmt_ip'],netmask_to_cidr(config[context]['interfaces'][interface]['iface_mgmt_netmask']))):
                            #print('{} - {}/{}'.format(config[context]['interfaces'][interface]['iface_name'],config[context]['interfaces'][interface]['iface_mgmt_ip'],config[context]['interfaces'][interface]['iface_mgmt_netmask']))
                            #print('ROUTE MATCH - Searched address {} is in Zone : {} Interface Name: {} Interface Address {}/{}'.format(ip, config[context]['interfaces'][interface]['interface_Zone'], config[context]['interfaces'][interface]['iface_name'], config[context]['interfaces'][interface]['iface_mgmt_ip'],netmask_to_cidr(config[context]['interfaces'][interface]['iface_mgmt_netmask'])))
                            return config[context]['interfaces'][interface]['interface_Zone']
                else:  # as a last resort, try getting static gateway from interface config -- these are auto added rules and not part of the pbr config
                    if next_hop_ip=='0.0.0.0':
                        return 'WAN'
                    log_info('Trying to see if ip is on same net as interface')
                    for interface in config[context]['interfaces']:
                        if config[context]['interfaces'][interface]['iface_lan_ip']!='0.0.0.0':
                            if ip in netaddr.IPNetwork('{}/{}'.format(config[context]['interfaces'][interface]['iface_lan_ip'],netmask_to_cidr(config[context]['interfaces'][interface]['iface_lan_mask']))):
                                return config[context]['interfaces'][interface]['interface_Zone']
                            
                    #return None
            
            else:  # check if ip address is on same subnet as interfaces - lan_ip should likely be done before checking pbr, static_ip should likely be done after
                #log_info('Trying to see if ip is on same net as interface')
                for interface in config[context]['interfaces']:
                    if config[context]['interfaces'][interface]['iface_lan_ip']!='0.0.0.0':
                        if ip in netaddr.IPNetwork('{}/{}'.format(config[context]['interfaces'][interface]['iface_lan_ip'],netmask_to_cidr(config[context]['interfaces'][interface]['iface_lan_mask']))):
                            return config[context]['interfaces'][interface]['interface_Zone']
                for interface in config[context]['interfaces']:
                    if config[context]['interfaces'][interface]['iface_static_ip']!='0.0.0.0':
                        #if ip in netaddr.IPNetwork('{}/{}'.format(config[context]['interfaces'][interface]['iface_static_ip'],netmask_to_cidr(config[context]['interfaces'][interface]['iface_static_mask']))):
                        return config[context]['interfaces'][interface]['interface_Zone']

        else:
            log_info('Routing not in config')
    except Exception as e:
        debug(e, e.__traceback__.tb_lineno)
        return None    
    return None

def get_sw_objects(target, username, password, fw_type, session=None):

    sw_objects={'address_objects': {'ipv4': [], 'ipv6': [], 'fqdn': []}, 'address_groups': {'ipv4': [], 'ipv6': [], 'fqdn': []}, 'service_objects': [], 'service_groups': [] }
    if session==None:
        session = requests.Session()
        session.mount('https://' + target, sw.DESAdapter())
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
        if not options.web and (options.username == None or options.password == None):
            options.username, options.password = get_creds()
        if fw_type.lower()=='sonicwall':
            response=sw.do_login(session, options.username, options.password, target, True)
            apikey=None
        elif fw_type.lower() in ['sw65']:
            url='https://{}/api/sonicos/auth'.format(target)
            session.headers=OrderedDict([('User-Agent', 'python-requests/2.18.4'), ('Accept', '*/*'), ('Accept-Encoding', 'gzip, deflate'), ('Connection', 'keep-alive')])
            post_data=None
            #auth = requests.auth.HTTPBasicAuth(options.username, options.password) -- replaced with manually setting headers myself since python requests basic auth was not handling special characters correctly
            response_code=None
            login_tries=0
            while response_code != 200 and login_tries < 1:
                try:
                    login_tries+=1
                    response=session.post(url=url, headers={'authorization': "Basic " + base64.b64encode('{}:{}'.format(options.username, options.password).encode()).decode()}, verify=False, timeout=options.timeout_sw_webui_login)
                    response_code=response.status_code
                    #debug('LOGIN RESULT', response.text)
                except:
                    pass
            apikey=None
            
            if response_code != 200:
                session=None
                apikey=None
                log('!-- Login failed')

    elif session != None:
        #log(session)
        debug('!-- Checking if in configuration mode')
        url='https://{}/api/sonicos/address-objects/ipv4'.format(target)
        #post_data={}
        post_data={  'address_object' : {
                    'ipv4':     {
                        'name' : 'api_test_object',
                        'zone' : 'LAN',
                        'host': { 'ip': '192.168.255.254' }}}}
        result=session.post(url=url, json=post_data, verify=False, timeout=options.timeout_sw_webui_post)
        #log(result)
        #log(json.loads(result.text))
        if not json.loads(result.text)['status']['success']:
            if not json.loads(result.text)['status']['cli']['configuring']:
                #log('result',result.text)
                return False, 'Not in config mode'

        url='https://{}/api/sonicos/address-objects/ipv4'.format(target)
        result=session.get(url=url, data=post_data, verify=False, timeout=options.timeout_sw_api)
        #log(result)
        addresses_ipv4=json.loads(result.text)
        for address_object in [address['ipv4']['name'] for address in addresses_ipv4['address_objects']]:
            sw_objects['address_objects']['ipv4'].append(address_object)

        url='https://{}/api/sonicos/address-objects/fqdn'.format(target)
        result=session.get(url=url, data=post_data, verify=False, timeout=options.timeout_sw_api)
        addresses_fqdn=json.loads(result.text)
        if 'address_objects' in addresses_fqdn:
            for address_object in [address['fqdn']['name'] for address in addresses_fqdn['address_objects']]:
                sw_objects['address_objects']['fqdn'].append(address_object)

        url='https://{}/api/sonicos/address-groups/ipv4'.format(target)
        result=session.get(url=url, data=post_data, verify=False, timeout=options.timeout_sw_api)
        addresses_ipv4=json.loads(result.text)
        for address_object in [address['ipv4']['name'] for address in addresses_ipv4['address_groups']]:
            sw_objects['address_groups']['ipv4'].append(address_object)
        
        url='https://{}/api/sonicos/address-groups/ipv6'.format(target)
        result=session.get(url=url, data=post_data, verify=False, timeout=options.timeout_sw_api)
        addresses_ipv6=json.loads(result.text)
        for address_object in [address['ipv6']['name'] for address in addresses_ipv6['address_groups']]:
            sw_objects['address_groups']['ipv6'].append(address_object)

        url='https://{}/api/sonicos/service-objects'.format(target)
        result=session.get(url=url, data=post_data, verify=False, timeout=options.timeout_sw_api)
        services=json.loads(result.text)
        for service_object in [service['name'] for service in services['service_objects']]:
            sw_objects['service_objects'].append(service_object)

        url='https://{}/api/sonicos/service-groups'.format(target)
        result=session.get(url=url, data=post_data, verify=False, timeout=options.timeout_sw_api)
        services=json.loads(result.text)
        for service_object in [service['name'] for service in services['service_groups']]:
            sw_objects['service_groups'].append(service_object)
        
        #url='https://{}/api/sonicos/auth'.format(target)
        #session.delete(url=url, verify=False)

    return sw_objects

def get_zones2(context, address_obj, tmpconfig=None):

    zones=[]

    if tmpconfig:
        config=tmpconfig

    for address in expand_address(config[context]['addresses'], address_obj, config[context]['addressmappings']):  #expand_address(config[context]['addresses'], route_dest, config[context]['addressmappings']):
        for network in config[context]['addresses'][address]['IPv4Networks']:
            tmp_zones=get_zone2(context, '{}'.format(network), config)
            for tmp_zone in tmp_zones:
                if tmp_zone not in zones:
                    zones.append(tmp_zone)
    return zones


def load_sonicwall(infile, skipdisabled, memoryconfig=None):

    from collections import defaultdict
    from netaddr import IPSet

    configfilename = "config_python.txt"
    address_props = ['addrObjId', 'addrObjIdDisp', 'addrObjType', 'addrObjZone', 'addrObjProperties', 'addrObjIp1', 'addrObjIp2', 'addrObjComment']
    addressfqdn_props = ['addrObjFqdnId', 'addrObjFqdnType', 'addrObjFqdnZone', 'addrObjFqdnProperties', 'addrObjFqdn']
    service_props = ['svcObjId', 'svcObjType', 'svcObjProperties', 'svcObjIpType', 'svcObjPort1', 'svcObjPort2', 'svcObjManagement', 'svcObjHigherPrecedence', 'svcObjComment']
    zone_props = ['zoneObjId', 'zoneObjComment']
    policy_props = ['policyAction', 'policySrcZone', 'policyDstZone', 'policySrcNet', 'policyDstNet', 'policyDstSvc', 'policyDstApps', 'policyComment', 'policyLog', 'policyEnabled', 'policyProps' ]
    interface_props = ['iface_ifnum', 'iface_type', 'iface_name', 'interface_Zone', 'iface_comment', 'iface_static_ip', 'iface_static_mask', 'iface_static_gateway', 'iface_lan_ip', 'iface_lan_mask', 'iface_lan_default_gw', 'iface_mgmt_ip', 'iface_mgmt_netmask', 'iface_mgmt_default_gw', 'iface_static_gateway', 'iface_vlan_tag', 'iface_comment', 'iface_http_mgmt', 'iface_https_mgmt', 'iface_ssh_mgmt', 'iface_ping_mgmt', 'iface_snmp_mgmt', 'portShutdown']
    routing_props = ['pbrObjId', 'pbrObjProperties', 'pbrObjSrc', 'pbrObjDst', 'pbrObjSvc', 'pbrObjGw', 'pbrObjIface', 'pbrObjIfaceName', 'pbrObjMetric', 'pbrObjPriority', 'pbrObjProbe', 'pbrObjComment']
    nat_props = [ 'natPolicyOrigSrc', 'natPolicyOrigDst', 'natPolicyOrigSvc', 'natPolicyTransSrc', 'natPolicyTransDst', 'natPolicyTransSvc', 'natPolicySrcIface', 'natPolicyDstIface', 'natPolicyEnabled', 'natPolicyComment', 'natPolicyProperties', 'natPolicyName' ]
    addressV6_props = ['addrObjV6Id', 'addrObjV6IdDisp', 'addrObjV6Type', 'addrObjV6Zone', 'addrObjV6Properties', 'addrObjV6Ip1', 'addrObjV6Ip2', 'addrObjV6PrefixLen']
    policyV6_props = ['policyActionV6', 'policySrcZoneV6', 'policyDstZoneV6', 'policySrcNetV6', 'policyDstNetV6', 'policyDstSvcV6', 'policyCommentV6', 'policyLogV6', 'policyEnabledV6', 'policyPropsV6' ]

    app_props = [] #  - future use for palo alto configurations
    sonicwall_config = defaultdict(dict)
    
    log('!-- Converting SonicWall configuration file')
    if not memoryconfig:
        if not convert_exp_file(infile, configfilename, memoryconfig):
            log('Conversion Failed')
            return False 

    import re
    from urllib.parse import unquote as url_unquote
    if memoryconfig==None:
        with open (configfilename) as working_file:  
            config = working_file.read()
    else:
        config=memoryconfig

    #print(config)

    sonicwall_config['config']['name']=re.findall('firewallName=.*', config)[0].split('=')[1]
    sonicwall_config['config']['version']=re.findall('buildNum=.*', config)[0].split('=')[1].split('-')[0]
    sonicwall_config['config']['fw_model']=url_unquote(re.findall('shortProdName=.*', config)[0].split('=')[1].split('-')[0])
    #log('!-- Sonicwall version found : ' + sonicwall_config['config']['version'], level=logging.INFO)
    sonicwall_config['config']['fw_type']='sonicwall'
    if options.sonicwallip: 
        sonicwall_config['config']['mgmtip']=options.sonicwallip
    else:
        sonicwall_config['config']['mgmtip']=None
    #working_file.close()

    log('!-- Reading Group Mappings')
    # MAY NEED TO DECLARE THESE FIRST?
    sonicwall_config['addressmappings'] = generate_group_mappings(config,'addro')
    sonicwall_config['servicemappings'] = generate_group_mappings(config,'so')
    log('!-- Reading Address Objects')
    sonicwall_config['addresses'] = migrate('addrObj', config, address_props)
    sonicwall_config['addresses'] = add_IPv4Network(sonicwall_config['addresses'])
    for address in sonicwall_config['addresses']:  ## Add empty comment for all sonicwall address objects
       sonicwall_config['addresses'][address]['addrObjComment']=''
       sonicwall_config['addresses'][address]['addrObjColor']=''
       if sonicwall_config['addresses'][address]['addrObjType']=='1':
            sonicwall_config['addresses'][address]['addrObjIp2']='255.255.255.255' # Force netmask for host objects to /32, as some built in types have this set to 0.0.0.0
    
    sonicwall_config['addressesfqdn'] = migrate('addrObjFqdn', config, addressfqdn_props)
    sonicwall_config['addressesV6'] = migrate('addrObjV6', config, addressV6_props)

    ## Rename IPv6 keys to match IPv4 objects
    for address in sonicwall_config['addressesV6']:
        sonicwall_config['addressesV6'][address]['addrObjId']=sonicwall_config['addressesV6'][address].pop('addrObjV6Id')
        sonicwall_config['addressesV6'][address]['addrObjIdDisp']=sonicwall_config['addressesV6'][address].pop('addrObjV6IdDisp')
        sonicwall_config['addressesV6'][address]['addrObjType']=sonicwall_config['addressesV6'][address].pop('addrObjV6Type')
        sonicwall_config['addressesV6'][address]['addrObjZone']=sonicwall_config['addressesV6'][address].pop('addrObjV6Zone')
        sonicwall_config['addressesV6'][address]['addrObjProperties']=sonicwall_config['addressesV6'][address].pop('addrObjV6Properties')
        sonicwall_config['addressesV6'][address]['addrObjIp1']=sonicwall_config['addressesV6'][address].pop('addrObjV6Ip1')
        sonicwall_config['addressesV6'][address]['addrObjIp2']=sonicwall_config['addressesV6'][address].pop('addrObjV6Ip2')
        sonicwall_config['addressesV6'][address]['addrObjPrefixLen']=sonicwall_config['addressesV6'][address].pop('addrObjV6PrefixLen')
    


    ## Add IPset property to groups
    for addr in sonicwall_config['addresses']:
        if sonicwall_config['addresses'][addr]['addrObjType']=='8':
            sonicwall_config['addresses'][addr]['IPSet']=IPSet([])
            for groupmember in expand_address(sonicwall_config['addresses'], addr, sonicwall_config['addressmappings']):
                for network in sonicwall_config['addresses'][groupmember]['IPv4Networks']:
                    sonicwall_config['addresses'][addr]['IPSet'].add(str(network))
    
    
    log('!-- Reading Service Objects')
    sonicwall_config['services'] = migrate('svcObj', config, service_props)
    for service_name in sonicwall_config['services']: ## add svcSrcPort property to all objects
        sonicwall_config['services'][service_name]['svcObjSrcPort']='0'
    

    log('!-- Reading Policy Objects')
    ## Need to used old numerically index migrate routing for policies (WHY?)
    sonicwall_config['policies'] = migrate_orig('policy',config,policy_props, skipdisabled=False)  
    sonicwall_config['policies'] = policy_objects_to_list(sonicwall_config['policies'],['policySrcZone','policyDstZone','policySrcNet','policyDstNet','policyDstSvc'])  

    log('!-- Generating IPv6 Policy Objects')
    sonicwall_config['policiesV6'] = migrate_orig('policy', config, policyV6_props, skipdisabled=skipdisabled)
    
    ## Rename IPv6 keys to match IPv4 objects
    for policy in sonicwall_config['policiesV6']:
        sonicwall_config['policiesV6'][policy]['policyAction']=sonicwall_config['policiesV6'][policy].pop('policyActionV6')
        sonicwall_config['policiesV6'][policy]['policySrcZone']=sonicwall_config['policiesV6'][policy].pop('policySrcZoneV6')
        sonicwall_config['policiesV6'][policy]['policyDstZone']=sonicwall_config['policiesV6'][policy].pop('policyDstZoneV6')
        sonicwall_config['policiesV6'][policy]['policySrcNet']=sonicwall_config['policiesV6'][policy].pop('policySrcNetV6')
        sonicwall_config['policiesV6'][policy]['policyDstNet']=sonicwall_config['policiesV6'][policy].pop('policyDstNetV6')
        sonicwall_config['policiesV6'][policy]['policyComment']=sonicwall_config['policiesV6'][policy].pop('policyCommentV6')
        sonicwall_config['policiesV6'][policy]['policyLog']=sonicwall_config['policiesV6'][policy].pop('policyLogV6')
        sonicwall_config['policiesV6'][policy]['policyEnabled']=sonicwall_config['policiesV6'][policy].pop('policyEnabledV6')
        sonicwall_config['policiesV6'][policy]['policyProps']=sonicwall_config['policiesV6'][policy].pop('policyPropsV6')
        sonicwall_config['policiesV6'][policy]['policyDstSvc']=sonicwall_config['policiesV6'][policy].pop('policyDstSvcV6')

    if options.expandcheckpoint:  ## change this to an argparse option
        for policy in sonicwall_config['policies']:
            if sonicwall_config['policies'][policy]['policySrcNet'][0][0:11].lower()=='importchkpt':
                sonicwall_config['policies'][policy]['policySrcNet']=sonicwall_config['addressmappings'][sonicwall_config['policies'][policy]['policySrcNet'][0]]
            if sonicwall_config['policies'][policy]['policyDstNet'][0][0:11].lower()=='importchkpt':
                sonicwall_config['policies'][policy]['policyDstNet']=sonicwall_config['addressmappings'][sonicwall_config['policies'][policy]['policyDstNet'][0]]
            if sonicwall_config['policies'][policy]['policyDstSvc'][0][0:11].lower()=='importchkpt':
                sonicwall_config['policies'][policy]['policyDstSvc']=sonicwall_config['servicemappings'][sonicwall_config['policies'][policy]['policyDstSvc'][0]]
    

    ## Sonicwall does not have a "Name" for policies, but need to add it as a placeholder for PA compatibility
    for policy in sonicwall_config['policies']:
        sonicwall_config['policies'][policy]['policyName']="Empty"
        sonicwall_config['policies'][policy]['policyNum']=''
        sonicwall_config['policies'][policy]['policyUiNum']=''


    log('!-- Reading NAT Policy Objects')
    sonicwall_config['nat'] = migrate_orig('natPolicy', config,nat_props)
    sonicwall_config['nat'] = policy_objects_to_list(sonicwall_config['nat'],['natPolicyOrigSrc', 'natPolicyOrigDst', 'natPolicyOrigSvc', 'natPolicyTransSrc', 'natPolicyTransDst', 'natPolicyTransSvc'])
    for policy in sonicwall_config['nat']:
        sonicwall_config['nat'][policy]['natPolicyName']="Empty"
        sonicwall_config['nat'][policy]['natPolicyNum']=''
        sonicwall_config['nat'][policy]['natPolicyUiNum']=''


    log('!-- Reading Zone Objects')
    sonicwall_config['zones'] = migrate('zoneObj',config,zone_props)
        
    log('!-- Reading Interface Objects')
    sonicwall_config['interfaces'] = migrate('iface',config,interface_props)
        
    log('!-- Reading Routing Objects')
    sonicwall_config['routing'] = migrate('pbrObj',config,routing_props)

    sonicwall_config['usedzones']=[]
    for interface in sonicwall_config['interfaces']:
         if sonicwall_config['interfaces'][interface]['interface_Zone']!='':
             sonicwall_config['usedzones'].append(sonicwall_config['interfaces'][interface]['interface_Zone'])
    
    all_zones=[]
    for zone in sonicwall_config['zones']:
        all_zones.append(sonicwall_config['zones'][zone]['zoneObjId'])

    sonicwall_config['apps']={} # empty dictionary as sonicwall does not use applications in rules
    
    return sonicwall_config;
