import base64
import re
import time
from datetime import datetime
from urllib.parse import quote

import requests
import urllib3
from requests.adapters import HTTPAdapter
from requests.packages.urllib3.util.ssl_ import create_urllib3_context

from ... import NetworkLogs


def _init_(self, options):
    self.log = NetworkLogs().log
    self.sc = NetworkLogs().sc
    self.ss = NetworkLogs().ss
    self.debug = NetworkLogs().debug
    self.options = options

def get_palo_config_https(self, host, outfile, username='admin', password='password'):


    class DESAdapter(HTTPAdapter):
        """
        A TransportAdapter that re-enables 3DES support in Requests.
        """

        def init_poolmanager(self, *args, **kwargs):
            # context = create_urllib3_context(ciphers=CIPHERS)
            context = create_urllib3_context()
            kwargs['ssl_context'] = context
            return super(DESAdapter, self).init_poolmanager(*args, **kwargs)

        def proxy_manager_for(self, *args, **kwargs):
            context = create_urllib3_context()

            kwargs['ssl_context'] = context
            return super(DESAdapter, self).proxy_manager_for(*args, **kwargs)

    self.log("!-- Retrieving Palo Alto/Panorama configuration file from host : " + host)
    session = requests.Session()
    session.mount(host, DESAdapter())
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    # key=session.get('https://' + host + '/api/?type=keygen&user=' + username + '&password=' + quote(password), verify=False, stream=True, timeout=options.timeout_palo_api)
    # key=session.get('https://' + host + '/api/?type=keygen&user=' + username + '&password=' + quote(password), verify=False, stream=True, timeout=options.timeout_palo_api)
    # key = re.sub(r'.*<key>(.*)</key>.*',r'\1',key.text)
    # config=session.get('https://' + host + '/api/?type=export&category=configuration&key=' + key, verify=False, stream=True, timeout=options.timeout_palo_api)
    # debug(username, password)
    # config=session.get('https://' + host + '/api/?type=op&cmd=<show><config><merged></merged></config></show>&key=' + key, verify=False, stream=True, timeout=options.timeout_palo_api)
    # config=session.get('https://' + host + '/api/?type=export&category=configuration', auth=(username, quote(password)), verify=False, stream=True, timeout=options.timeout_palo_api)
    config = session.get('https://' + host + '/api/?type=export&category=configuration', headers={
        'authorization': "Basic " + base64.b64encode('{}:{}'.format(username, password).encode()).decode()},
                         verify=False, stream=True, timeout=self.options.timeout_palo_api)
    # outfile=open(outfile,'w', encoding='utf-8')
    # outfile.write(config.text)
    # outfile.close()
    if config.status_code != 200:
        self.log('!-- Retrieval of configuration failed')
        self.debug(config.text)
        return False
    return config.text


def send_palo_apicmd(self, session, target, url, apikey, retries=1, retrydelay=10, dryrun=False):

    success = False
    tries = 0
    self.debug('{} URL: {}'.format(str(datetime.now()), quote(url, safe='?=/&%')))
    if not dryrun:
        while not success and tries < (retries + 1):
            tries += 1
            if session == None:
                if apikey:
                    response = requests.get('https://{}{}&key={}'.format(target, quote(url, safe='?=/&%'), apikey),
                                            verify=False)
                else:
                    response = requests.get('https://{}{}'.format(target, quote(url, safe='?=/&%')), verify=False,
                                            headers={'authorization': "Basic " + base64.b64encode(
                                                '{}:{}'.format(self.options.username, self.options.password).encode()).decode()})
            else:
                if apikey:
                    response = session.get('https://{}{}&key={}'.format(target, quote(url, safe='?=/&%'), apikey),
                                           verify=False)
                else:
                    response = requests.get('https://{}{}'.format(target, quote(url, safe='?=/&%')), verify=False,
                                            headers={'authorization': "Basic " + base64.b64encode(
                                                '{}:{}'.format(self.options.username, self.options.password).encode()).decode()})
            if len(re.findall('success', response.text)) == 0:
                self.debug(url)
                self.debug(quote(url, safe='?=/&%'))
                self.debug(response.text)
                self.debug('API Command failed, attempt #{}. Retrying in {} seconds'.format(tries, retrydelay))
                # log('',level=logging.ERROR)
                # log(url,level=logging.ERROR)
                # log(response.text,level=logging.ERROR)
                # exit (1)
                # return response.text
            else:
                success = True
                break
            time.sleep(retrydelay)

        if not success:
            return response.text
    else:
        return True
    return success
