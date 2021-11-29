#!/usr/bin/python3

## Sonicwall python library - currently any script that uses this, a link in that scripts local dir is made to point to the "master" sonicwall.py file.  I need to find out the proper way/location to place a python
## library for importing later
## 3/7/2019 - dologin returns false if params 
## 8/15/2019 - preempt option was not working correctly for do_login

## create session
## do login
## get URL
## logoff
## get table


hex_chr = "0123456789abcdef"

'''CIPHERS = (
    'ECDH+AESGCM:DH+AESGCM:ECDH+AES256:DH+AES256:ECDH+AES128:DH+AES:ECDH+HIGH:'
    'DH+HIGH:ECDH+3DES:DH+3DES:RSA+AESGCM:RSA+AES:RSA+HIGH:RSA+3DES:!aNULL:'
    '!eNULL:!MD5'
)
'''
CIPHERS = (
    'ALL'
)
from requests.adapters import HTTPAdapter

class DESAdapter(HTTPAdapter):
    #from requests.packages.urllib3.util.ssl_ import create_urllib3_context
    
    """
    A TransportAdapter that re-enables 3DES support in Requests.
    """
    def init_poolmanager(self, *args, **kwargs):
        context = create_urllib3_context(ciphers=CIPHERS)
        kwargs['ssl_context'] = context
        return super(DESAdapter, self).init_poolmanager(*args, **kwargs)

    def proxy_manager_for(self, *args, **kwargs):
        context = create_urllib3_context(ciphers=CIPHERS)
        kwargs['ssl_context'] = context
        return super(DESAdapter, self).proxy_manager_for(*args, **kwargs)
        
def rhex(num):

  str = ""
  for j in range(4):
        str += hex_chr[(num >> (j * 8 + 4)) & 0x0F] + hex_chr[(num >> (j * 8)) & 0x0F]
  return str

def str2blks_MD5(str):

    nblk = ((len(str) + 8) >> 6) + 1
    blks = []
    for i in range (nblk * 16):
        blks.extend([0])
    for i in range(len(str)):
        blks[i >> 2] |= ord(str[i]) << ((i % 4) * 8)
        if (blks[i >> 2] & 0x80000000):
            blks[i >> 2] = -0x100000000 + blks[i >> 2]
    i=i+1
    blks[i >> 2] |= 0x80 << ((i % 4) * 8)
    if (blks[i >> 2] & 0x80000000):
        blks[i >> 2] = -0x100000000 + blks[i >> 2] 
    blks[nblk * 16 - 2] = len(str) * 8
    return blks

def bytes2blks_MD5(bytes):

    nblk = ((len(bytes) + 8) >> 6) + 1
    blks = []
    for i in range(nblk * 16):
        blks.extend([0])
    for i in range(len(bytes)):
        blks[i >> 2] |= bytes[i] << ((i % 4) * 8)
        if (blks[i >> 2] & 0x80000000):
            blks[i >> 2] = -0x100000000 + blks[i >> 2]
    i=i+1
    blks[i >> 2] |= 0x80 << ((i % 4) * 8)
    if (blks[i >> 2] & 0x80000000):
        blks[i >> 2] = -0x100000000 + blks[i >> 2]
    blks[nblk * 16 - 2] = len(bytes) * 8

    return blks

def add(x, y):

    lsw = (x & 0xFFFF) + (y & 0xFFFF)
    msw = (x >> 16) + (y >> 16) + (lsw >> 16)
    return ((msw << 16) | (lsw & 0xFFFF))  & 0xffffffff

def rol(num, cnt):
    # WAS return (num << cnt) | (num >>> (32 - cnt))
    return (num << cnt) | (num >> (32 - cnt)) & 0xffffffff

def cmn(q, a, b, x, s, t):
    return add(rol(add(add(a, q), add(x, t)), s), b) & 0xffffffff

def ff(a, b, c, d, x, s, t):
    return cmn((b & c) | ((~b) & d) & 0xffffffff, a, b, x, s, t) & 0xffffffff

def gg(a, b, c, d, x, s, t):
    return cmn((b & d) | (c & (~d)) & 0xffffffff, a, b, x, s, t) & 0xffffffff

def hh(a, b, c, d, x, s, t):
    return cmn(b ^ c ^ d, a, b, x, s, t) & 0xffffffff

def ii(a, b, c, d, x, s, t):
    return cmn(c ^ (b | (~d) & 0xffffffff), a, b, x, s, t) & 0xffffffff

def calcMD5(str):
    import hashlib
    #return hashlib.md5(str.encode('utf-8')).hexdigest()
    return doCalcMD5(str2blks_MD5(str))

def calcMD5_2(str):
    import hashlib
    buf = ''
    for i in range(len(str)):
        buf = buf + (chr(str[i]))
    h = hashlib.new('md5')
    h.update(buf.encode('utf-8'))
    h.hexdigest()
    return doCalcMD5(bytes2blks_MD5(str))

def doCalcMD5(x):

#    import hashlib
#    return hashlib.md5(x.encode('utf-8')).hexdigest()

  a =  1732584193
  b = -271733879
  c = -1732584194
  d =  271733878

  for i in range(0,len(x),16):

        olda = a
        oldb = b
        oldc = c
        oldd = d

        a = ff(a, b, c, d, x[i+ 0], 7 , -680876936)
        d = ff(d, a, b, c, x[i+ 1], 12, -389564586)
        c = ff(c, d, a, b, x[i+ 2], 17,  606105819)
        b = ff(b, c, d, a, x[i+ 3], 22, -1044525330)
        a = ff(a, b, c, d, x[i+ 4], 7 , -176418897)
        d = ff(d, a, b, c, x[i+ 5], 12,  1200080426)
        c = ff(c, d, a, b, x[i+ 6], 17, -1473231341)
        b = ff(b, c, d, a, x[i+ 7], 22, -45705983)
        a = ff(a, b, c, d, x[i+ 8], 7 ,  1770035416)
        d = ff(d, a, b, c, x[i+ 9], 12, -1958414417)
        c = ff(c, d, a, b, x[i+10], 17, -42063)
        b = ff(b, c, d, a, x[i+11], 22, -1990404162)
        a = ff(a, b, c, d, x[i+12], 7 ,  1804603682)
        d = ff(d, a, b, c, x[i+13], 12, -40341101)
        c = ff(c, d, a, b, x[i+14], 17, -1502002290)
        b = ff(b, c, d, a, x[i+15], 22,  1236535329)

        a = gg(a, b, c, d, x[i+ 1], 5 , -165796510)
        d = gg(d, a, b, c, x[i+ 6], 9 , -1069501632)
        c = gg(c, d, a, b, x[i+11], 14,  643717713)
        b = gg(b, c, d, a, x[i+ 0], 20, -373897302)
        a = gg(a, b, c, d, x[i+ 5], 5 , -701558691)
        d = gg(d, a, b, c, x[i+10], 9 ,  38016083)
        c = gg(c, d, a, b, x[i+15], 14, -660478335)
        b = gg(b, c, d, a, x[i+ 4], 20, -405537848)
        a = gg(a, b, c, d, x[i+ 9], 5 ,  568446438)
        d = gg(d, a, b, c, x[i+14], 9 , -1019803690)
        c = gg(c, d, a, b, x[i+ 3], 14, -187363961)
        b = gg(b, c, d, a, x[i+ 8], 20,  1163531501)
        a = gg(a, b, c, d, x[i+13], 5 , -1444681467)
        d = gg(d, a, b, c, x[i+ 2], 9 , -51403784)
        c = gg(c, d, a, b, x[i+ 7], 14,  1735328473)
        b = gg(b, c, d, a, x[i+12], 20, -1926607734)

        a = hh(a, b, c, d, x[i+ 5], 4 , -378558)
        d = hh(d, a, b, c, x[i+ 8], 11, -2022574463)
        c = hh(c, d, a, b, x[i+11], 16,  1839030562)
        b = hh(b, c, d, a, x[i+14], 23, -35309556)
        a = hh(a, b, c, d, x[i+ 1], 4 , -1530992060)
        d = hh(d, a, b, c, x[i+ 4], 11,  1272893353)
        c = hh(c, d, a, b, x[i+ 7], 16, -155497632)
        b = hh(b, c, d, a, x[i+10], 23, -1094730640)
        a = hh(a, b, c, d, x[i+13], 4 ,  681279174)
        d = hh(d, a, b, c, x[i+ 0], 11, -358537222)
        c = hh(c, d, a, b, x[i+ 3], 16, -722521979)
        b = hh(b, c, d, a, x[i+ 6], 23,  76029189)
        a = hh(a, b, c, d, x[i+ 9], 4 , -640364487)
        d = hh(d, a, b, c, x[i+12], 11, -421815835)
        c = hh(c, d, a, b, x[i+15], 16,  530742520)
        b = hh(b, c, d, a, x[i+ 2], 23, -995338651)

        a = ii(a, b, c, d, x[i+ 0], 6 , -198630844)
        d = ii(d, a, b, c, x[i+ 7], 10,  1126891415)
        c = ii(c, d, a, b, x[i+14], 15, -1416354905)
        b = ii(b, c, d, a, x[i+ 5], 21, -57434055)
        a = ii(a, b, c, d, x[i+12], 6 ,  1700485571)
        d = ii(d, a, b, c, x[i+ 3], 10, -1894986606)
        c = ii(c, d, a, b, x[i+10], 15, -1051523)
        b = ii(b, c, d, a, x[i+ 1], 21, -2054922799)
        a = ii(a, b, c, d, x[i+ 8], 6 ,  1873313359)
        d = ii(d, a, b, c, x[i+15], 10, -30611744)
        c = ii(c, d, a, b, x[i+ 6], 15, -1560198380)
        b = ii(b, c, d, a, x[i+13], 21,  1309151649)
        a = ii(a, b, c, d, x[i+ 4], 6 , -145523070)
        d = ii(d, a, b, c, x[i+11], 10, -1120210379)
        c = ii(c, d, a, b, x[i+ 2], 15,  718787259)
        b = ii(b, c, d, a, x[i+ 9], 21, -343485551)

        a = add(a, olda) 
        b = add(b, oldb)
        c = add(c, oldc)
        d = add(d, oldd)
  return rhex(a) + rhex(b) + rhex(c) + rhex(d)

def xor(dataArray, patternArray):
        strResult = ''
        if len(dataArray) != len(patternArray):
                return strResult;
        
        for i in range(len(dataArray)):
                dat = parseInt(dataArray[i])
                pat = parseInt(patternArray[i])
                xorVal = (dat ^ pat)
                strResult = strResult + urllib.parse.quote(chr(xorVal),encoding="raw_unicode_escape")
       
        return strResult;


def setEncryptSeed(strPassPhrase, randomNumber):
        strInternalPageSeedHash = ''
        if (len(strPassPhrase) > 0):
            strInternalPageSeedHash = calcMD5(randomNumber + strPassPhrase)
            return strInternalPageSeedHash;
        
        return;
        
def setEncryptSeed2(strPassPhrase, randomNumber):
        strInternalPageSeedHash = ''
        if (len(strPassPhrase) > 0):
            strInternalPageSeedHash = calcMD5_2(getChars(randomNumber + strPassPhrase))
            return strInternalPageSeedHash;
        
        return;
        
def verifyPassword(strPassPhrase, randonNumber1, randomNumber2):
        strInternalPageHash = ''
        if (len(strPassPhrase) > 0):
                strInternalPageHash = calcMD5(randonNumber1 + strPassPhrase)
                setEncryptSeed(strPassPhrase, randomNumber2)
        
        return strInternalPageHash;

'''
def encryptUserPassword(strPassword, randomNumber):
        var strPageSeedHash = new String(getCookie("PageSeed"))
        if (strPageSeedHash == null) return("Error")
        return changePassword(strPageSeedHash, randomNumber, strPassword, strPassword)

def changePassword(strEncSeed, randomNumber, strNewPassword, strConfirmPassword):
        var strNewPasswordXOR = new String()
        var newPasswordArray = new Array()
        var oldPasswordHashArray = new Array()
        for (var i=0; i<33; i++) {
                newPasswordArray[i] = 0
                oldPasswordHashArray[i] = 0
        }

        var uriNewPasswd = getChars(strNewPassword)
        var uriEncSeed = getChars(strEncSeed)
        for (var j = i = 0; i < 33; i++, j++) {
                if (j >= uriEncSeed.length) j = 0
                var v1 = (i < uriNewPasswd.length) ? uriNewPasswd[i] : 0
                var v2 = 256 - uriEncSeed[j]
                newPasswordArray[i] = v1 ^ v2
        }

        var strOldPassHash = new String(calcMD5_2(getChars(randomNumber).concat(uriEncSeed)))
        for (i=0; i<strOldPassHash.length; i++) {
                oldPasswordHashArray[i] = strOldPassHash.charCodeAt(i)
        }
        strNewPasswordXOR = xor(oldPasswordHashArray, newPasswordArray)
        return strNewPasswordXOR
}

def extractRandNum(randNumHash, pageSeed):
        var strSessId = new String(getCookie("SessId"))
        if (strSessId == null) return
        var strSessIdSeedHash = new String(calcMD5_2(getChars(strSessId).concat(getChars(pageSeed))))
        var sessIdSeedHashArray = new Array()
        var randNumHashArray = new Array()
        for (var i = 0; i < 32; i++) {
                sessIdSeedHashArray[i] = strSessIdSeedHash.charCodeAt(i)
                randNumHashArray[i] = parseInt(randNumHash.substr(i*2, 2), 16)
        }
        var rNum = xor(sessIdSeedHashArray, randNumHashArray)
        return rNum
'''

def chapDigest(strId, strPass, strChal):
    
    import binascii
    
    id = getBytes(strId)
    
    passwd=getChars(strPass)
    chal = []
    chal = binascii.unhexlify(strChal)
    chal = getBytes(strChal)
    inBuff = id + passwd + chal
    strDigest = str(calcMD5_2(inBuff))
    return strDigest

def getBytes(str):

    buf = []
    j = 0
    for i in range(0,len(str),2):
        buf.append(int(str[i:i+2], base=16))
    return buf


def getChars(str):

    import urllib.parse as urllib
    buf = []
    uriStr = urllib.quote(str, safe='~@#$&()*!+=:;,.?/\'')  
    count = 0

    for i in range(0,len(uriStr),1):
            if uriStr[i]=='%':
            
                    buf.append(int(uriStr[i+1:i+3], base=16))
                    i+=2
            else:
                    buf.append(ord(uriStr[i]))
    
    return buf;

def open_session(host):

    get_headers = {
    'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8',
    'Accept-Language': 'en-US',
    'Upgrade-Insecure-Requests': '1',
    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; WOW64; Trident/7.0; rv:11.0) like Gecko',
    'Accept-Encoding': 'gzip, deflate',
    'Host': host,
    'Connection': 'keep-alive',
    'Cookie': 'temp=temp'
    }
    
    session = requests.Session()
    session.headers=get_headers
    session.mount(host, DESAdapter()) ##
    #session.mount(host)

    return session;

def get_params(session):
    
    get_headers = {
    'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8',
    'Accept-Language': 'en-US',
    'Upgrade-Insecure-Requests': '1',
    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; WOW64; Trident/7.0; rv:11.0) like Gecko',
    'Accept-Encoding': 'gzip, deflate',
    'Host': host,
    'Connection': 'keep-alive',
    'Cookie': 'temp=temp'
    }
    
    url='https://' + host + '/auth1.html'
    session.headers=get_headers
    params = get_url(session, url)

    return param1, param2;
    
    
def get_interfaces():

    url='https://' + device + '/netInterfaces.html'
    response = get_url(session,url)
    if response:
        data=response.content
        try:
            tl = pandas.read_html(data,match='MGMT')
            #print (tl)
            df=tl[0]
            df=df.iloc[:,[0,1,4]]
            print (df.to_string(line_width=120, index=False, na_rep='',header=False))
        except:
            print ("Interface Table not Found")
            return True;
    else:
        print ("Get Interfaces Page Failed")
        return False;
    
def get_url(session, url, timeout=30):

    try:
        response = session.get(url, verify=False, stream=True, timeout=timeout)
    except requests.exceptions.RequestException as e:
        #sys.exit (e)
        #print(e)
        return None;
    return response;
    

def get_loglevel():

    url='https://' + device + '/logCategoriesView.html'        
    response = get_url(session, url)
    
    if response:
    
        data=response.content
        try:
            selected=re.findall(r'SELECTED.*',re.findall(r'priorityLogThreshold.*?</table>',response.text,re.DOTALL)[0])[0]                
            value=re.sub(r'.*SELECTED>(.*?)<.*',r'\1',selected,re.DOTALL)
            print ("Logging Level : " + value)
        except:
            print ("Value not Found")
            return False;
        
    else:
    
        url='https://' + device + '/configureLog.html'
        response = get_url(session, url)
        
        if response:
    
            data=response.content
            #print (response.text)
            try:
                selected=re.findall(r'LOG_LOGGING_LEVEL.*',response.text)[0]
                #print (selected)
                value=re.sub(r'.*LOG_LOGGING_LEVEL = (.).*',r'\1',selected,re.DOTALL)
                print ("Logging Level : " + SYSLOG_LEVELS[int(value)])
            except:
                print ("Value not Found")
        #print (response.text)
        else:
            print ("Get Syslog level failed?")
            return False;
    
def get_syslog_servers(session, device):
        
    url='https://' + device + '/logSyslogView.html'
    response = get_url(session, url)
    if response:
        data=response.content
        try:
            tl = pandas.read_html(data,match='Server Name')
            df=tl[0]
            #print (df.to_string(index=False, na_rep='',header=False))
            for table in tl:
                #print(table)
                #print(table[0][1])
                #print(len(table))
                for row in range(1,len(table)-1):
                    #print(type(row))
                    print(table[0][row], table[1][row])
                    print('-'*100)
        except Exception as e:
            print(e)
            print ("Syslog Table not Found")
            return True;
    else:
        print ("Get Syslog Page Failed")
        return False;

def get_licenses():

    url='https://' + device + '/activationView.html'        
    response = get_url(session, url)
    if response:
        data=response.content
        try:
            tl = pandas.read_html(data,match='Expiration')
            df=tl[0]
            print (df.to_string(line_width=120, index=False, na_rep='', header=False))
        except:
            print ("License Table not Found")
    else:
        print ("Get License Page Failed")
        return False;
            
def do_login(session, username, pwd, host, preempt=False, timeout=10):

    ## Add support to preempt config session using preempt value
    import json
    import re
    import binascii
    import hashlib

    
    post_headers = defaultdict(dict)
    get_headers = defaultdict(dict)
    
    get_headers = {
    'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8',
    'Accept-Language': 'en-US',
    'Upgrade-Insecure-Requests': '1',
    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; WOW64; Trident/7.0; rv:11.0) like Gecko',
    'Accept-Encoding': 'gzip, deflate',
    'Host': host,
    'Connection': 'keep-alive'
    #'Cookie': 'temp=temp; SessId=' + sessId + '; PageSeed=' + pageseed + '; curUrl=systemStatusView.html; curUsr=admin',
    #'Referer': 'https://' + host + '/outlookView.htm'
    }
    
    session.headers=get_headers
    #print(session.cookies.items())
    url='https://' + host + '/auth1.html' ##
    params = get_url(session, url)
    #print(session.cookies.items())
    #print(params.cookies.items())
    if params==None: 
        #print('No Params found')
        return False; ## added 3/7/2019
    data=codecs.decode(params.content,encoding='utf-8')
    ## Get data from initial connection to perform authentication
    try:
        param1=re.findall(r'param1.*?\>',data)[0].split('"')[2]
        param2=re.findall(r'param2.*?\>',data)[0].split('"')[2]
    except:
        return False
    #print(re.findall(r'sessId.*?\>',data))
    #print(data)
    try:
        sessId=re.findall(r'sessId.*?\>',data)[0].split('"')[2]
    except:
        sessId=None
    id=re.findall(r'name="id" va.*?\>',data)[0].split('"')[3]
  
    pageseed=setEncryptSeed(pwd,param2) #param2

    if param1 != '':
        digest=chapDigest(id,pwd,param1)
        sendpwd=''
    else:
        digest=''
        sendpwd=pwd

    if re.findall(r'swlStore-6.5.0',params.text):
        swl_65=True
    else:
        swl_65=False

    #post_headers['Cookie']='SessId='+ sessId + '; PageSeed=' + pageseed + '; secure'
    #post_headers['Cookie']='SessId='+ sessId + '; PageSeed=' + pageseed 
    post_headers['Connection']='Keep-Alive'
    post_headers['User-Agent']='Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/59.0.3071.115 Safari/537.36'
    post_headers['Referer']='https://' + host + '/activationView.html'
    post_headers['Content-Type']='application/x-www-form-urlencoded'
    post_headers['Origin']='https://' + host

    #get_headers['Cookie'] = 'temp=temp; SessId=' + sessId + '; PageSeed=' + pageseed + '; curUrl=systemStatusView.html; curUsr=admin'
    get_headers['Referer'] = 'https://' + host + '/outlookView.htm'

    
    url='https://' + host + '/auth.cgi' ##

    if not sessId:
       sessId='1CEB682A765173000FE236812A3677891C92C38' 

    if sessId:
        reqdata = OrderedDict([  ('param1', param1), 
                                        ('param2', param2),
                                        ('id', id), 
                                        ('sessId', sessId), 
                                        ('select2', 'English'), 
                                        ('uName', username),
                                        ('pass', sendpwd),
                                        ('digest',digest)])
        get_headers['Cookie'] = 'temp=temp; SessId=' + sessId + '; PageSeed=' + pageseed + '; curUrl=systemStatusView.html; curUsr=admin'
        post_headers['Cookie']='SessId='+ sessId + '; PageSeed=' + pageseed + '; secure'

    session.headers=get_headers
    try:
        response = session.post(url, verify=False, data=reqdata, headers=post_headers, stream=True, timeout=timeout)
        #print(response.text)
        if swl_65:
            sessIdStr = re.findall(r'var sessIdStr = ".*', response.text)[0].split('"')[1]
            sessIdLen = int(sessIdStr.split(':')[1][0:2], 16)
            randStr = sessIdStr.split(':')[0]
            cipher =  sessIdStr.split(':')[1][2:]
            pwdStr = binascii.hexlify(pwd.encode()).decode()
            pageSeedStr = binascii.hexlify(pageseed.encode()).decode()
            md = hashlib.sha1(binascii.unhexlify(randStr + pageSeedStr + pwdStr)).hexdigest().upper()
            sess=''
            for i in range(sessIdLen):
                #print(i)
                #print(cipher[i*2:i*2+2])
                v1 = int(cipher[i*2:i*2+2], 16)
                v2 = int(md[i*2:i*2+2], 16)
                vx = v1 ^  v2
                s='{:X}'.format(vx)
                #.upper()
                #str(vx).upper()
                #print(s)
                if len(s) == 1:
                    sess += '0' + s
                else:
                    sess += s
                #print(sess)

            session.headers.update({'Cookie': 'temp=; SessId={}'.format(sess)})

        if not re.findall(r'redirecting.*management.html',response.text):
            if re.findall(r'dynAdminPreempt.html',response.text):
                

                if not preempt:
                    #print ("Requesting non-config mode")
                    url='https://' + host + '/adminPreemptNonConfig.html'  ##
                    response = get_url(session, url, timeout=timeout)
                    #print(response)
                    #print(response.text)
                    if response:
                        return 'Nonconfig'
                else:
                    #print ("Requesting config mode")
                    url='https://' + host + '/adminPreemptOK.html'  ##
                    response = get_url(session, url, timeout=timeout)
                    if response:
                        return 'config'
                    
            else:   
                # Not redirected to management and not prompted to preempt existing session, assume login failed
                return False
    except Exception as e:
        #print(e)
        #print('Post failed for login')
        return False
    return True

def do_logout(session, host, timeout=10):

    url='https://' + host + '/logout.html'        ##
    response = get_url(session, url)
    session.get(url, verify=False, stream=True, timeout=timeout)
    #print (response)
    return True
    
def get_config(host, username, pwd, preempt=False):
    
   
    session = requests.Session()
    session.mount('https://' + host, DESAdapter()) ##
    #session.mount('https://' + host, HTTPAdapter()) ##
    if do_login(session, username, pwd, host, preempt):
        filename = get_url(session, 'https://' + host + '/export.html')
        filename = re.findall(r'location.*',filename.text)[0]
        filename = re.sub(r'.*location\.href.*\"(.*.exp)\".*',r'\1',filename)
        config = get_url(session, 'https://' + host + filename, timeout=10)
        do_logout(session, host)    
        return config
    
    return False

def upload_firmware(host, username, password, firmwarefile):
    
    import json

    post_headers = defaultdict(dict)
    

    session = requests.Session()
    session.mount('https://' + host, DESAdapter())
    #session.mount(host, HTTPAdapter())
    if do_login(session, username, password, host, True):
        post_headers = defaultdict(dict)
        #post_headers['Cookie']='SessId='+ sessId + '; PageSeed=' + pageseed + '; secure'
        post_headers['Connection']='Keep-Alive'
        post_headers['User-Agent']='Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/59.0.3071.115 Safari/537.36'
        post_headers['Referer']='https://' + host + '/uploadNew.html'
        #post_headers['Content-Type']='multipart/form-data; boundary=---------------------------18467633426500'
        post_headers['Origin']='https://' + host
        #post_headers['Content-Length']='74967987'

        post_headers['Accept']='text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8'
        post_headers['Accept-Encoding']='gzip, deflate, br'
        post_headers['Accept-Language']='en-US,en;q=0.5'
        post_headers['Host']=host
        post_headers['Upgrade-Insecure-Requests']='1'

        response=get_url(session, 'https://' + host + '/uploadNew.html')
        csrf=re.findall(r'csrfToken.*"',response.text)[0].split('value=')[1].split('"')[1]
        response=get_url(session, 'https://' + host + '/getJsonData.json?_=1265891166962&dataSet=alertStatus')
        #print(response.text)
        resp_json=json.loads(response.text)
        active=(resp_json['svrrpNodeState'].lower()=='active' or resp_json['svrrpHaMode'].lower()=='standalone')

        #active['svrrpNodeState'].lower()=='active')
        if active:
            fwfile={'name': (firmwarefile, open(firmwarefile, 'rb'), 'application/octet-stream')}
            fwdata={'csrfToken', csrf}
            #content=OrderedDict()
            content=OrderedDict([('csrfToken', (None, csrf)), ('firmware', (firmwarefile, open(firmwarefile, 'rb'), 'application/octet-stream'))])
            command='https://' + host + '/upload.cgi?safeMode=1'
            try: 
                response=session.post(command, verify=False, files=content, timeout=3600, headers=post_headers) #, auth=(username, password))# , headers=post_headers ) # auth=(options.pushusername, options.pushpassword)
                do_logout(session, host)    
            except requests.exceptions.RequestException as e:
                print (e)
                return False
            try:
                if re.findall('Firmware uploaded successfully', response.text):
                    return True
            except:
                try:
                    print(response.text)
                except:
                    pass
                return False
        else:
            do_logout(session, host)
            return 'not_active'

    return False

def backup(host, username, password): #, firmwarefile):
    
    import json
    
    post_headers = defaultdict(dict)
    

    session = requests.Session()
    session.mount('https://' + host, DESAdapter())
    #session.mount(host, HTTPAdapter())
    if do_login(session, username, password, host, True):
        post_headers = defaultdict(dict)
        post_headers['Connection']='Keep-Alive'
        post_headers['User-Agent']='Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/59.0.3071.115 Safari/537.36'
        post_headers['Referer']='https://' + host + '/systemSettingsView.html'
        post_headers['Origin']='https://' + host

        post_headers['Accept']='text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8'
        post_headers['Accept-Encoding']='gzip, deflate, br'
        post_headers['Accept-Language']='en-US,en;q=0.5'
        post_headers['Host']=host
        post_headers['Upgrade-Insecure-Requests']='1'

        response=get_url(session, 'https://' + host + '/systemSettingsView.html')
        csrf=re.findall(r'csrfToken.*"',response.text)[0].split('value=')[1].split('"')[1]
        response=get_url(session, 'https://' + host + '/getJsonData.json?_=1265891166962&dataSet=alertStatus')
        resp_json=json.loads(response.text)
        active=(resp_json['svrrpNodeState'].lower()=='active' or resp_json['svrrpHaMode'].lower()=='standalone')
        if active:
            content=OrderedDict([('csrfToken', (None, csrf))])
            command='https://' + host + '/backup.cgi'
            #print(command)
            try: 
                response=session.post(command, verify=False, data=content, timeout=600, headers=post_headers) #, auth=(username, password))# , headers=post_headers ) # auth=(options.pushusername, options.pushpassword)
                #print(response)
                #print(response.text)
                do_logout(session, host)    
            except requests.exceptions.RequestException as e:
                print (e)
                return False
            if re.findall('created successfully', response.text):
                return True
        else:
            return 'not_active'
    return False

def get_tsr(host, username, password): #, firmwarefile):
    
    import json
    
    post_headers = defaultdict(dict)
    

    session = requests.Session()
    session.mount('https://' + host, DESAdapter())
    #session.mount(host, HTTPAdapter())
    if do_login(session, username, password, host, True):
        post_headers = defaultdict(dict)
        post_headers['Connection']='Keep-Alive'
        post_headers['User-Agent']='Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/59.0.3071.115 Safari/537.36'
        post_headers['Referer']='https://' + host + '/systemSettingsView.html'
        post_headers['Origin']='https://' + host

        post_headers['Accept']='text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8'
        post_headers['Accept-Encoding']='gzip, deflate, br'
        post_headers['Accept-Language']='en-US,en;q=0.5'
        post_headers['Host']=host
        post_headers['Upgrade-Insecure-Requests']='1'

        response=get_url(session, 'https://' + host + '/systemSettingsView.html')
        #print(response.text)
        csrf=re.findall(r'csrfToken.*"',response.text)[0].split('value=')[1].split('"')[1]
        content= {      'csrfToken': csrf,
                        'tsr_VPNKeys': '1',
                        'tsr_ARPCache': '1',
                        'tsr_DHCPSBindings': '1',
                        'tsr_IKEInfo': '1',
                        'tsr_SPNCrashLog': '1',
                        'tsr_CurrUsers': '1',
                        'tsr_InactiveUsers': '1',
                        'tsr_CurrUserDetail': '1',
                        'tsr_IpnetStackInfo': '1',
                        'tsr_toggle': '1',
                        'tsr_GeoIPCache': '1',
                        'tsr_NbrDiscover': '1',
                        'tsr_DHCPv6': '1',
                        'tsr_PrintDebugInfo': '1',
                        'refresh_page': 'systemToolsView.html',
                        'cgiaction': 'none' }
                    

        command='https://' + host + '/main.cgi'#?csrfToken=' + csrf + '&cgiaction=none&file=upload&cbox_diag=&cbox_fwAutoUpdate=&cbox_fwAutoDownload=&cbox_fipsMode=&cbox_ndppMode='
        print('!-- Getting Tech Support file')
        response=session.post(command, verify=False, data=content, timeout=20)#, headers=post_headers)

        response=get_url(session, 'https://' + host + '/systemToolsView.html')
        try:
            tsr_file=re.findall(r'parent.frames\["dwnldFrm"\].*', response.text)[0].split('/')[1].split('"')[0]
        except:
            pass
        #print(tsr_file)
        response=get_url(session, 'https://' + host + '/' + tsr_file, timeout=600)
        #print(response)
        with open(host + '.tech_support.wri', 'w') as outfile:
            outfile.write(response.text)
        #print(len(response.text))
        #response=get_url(session, 'https://' + host + '/getJsonData.json?_=1265891166962&dataSet=alertStatus')
        #print(response.text)
        
        #resp_json=json.loads(response.text) #https://10.215.16.63/systemToolsView.html
        #active=(resp_json['svrrpNodeState'].lower()=='active' or resp_json['svrrpHaMode'].lower()=='standalone')
        '''
        if active:
            content=OrderedDict([('csrfToken', (None, csrf))])
            command='https://' + host + '/backup.cgi'
            #print(command)
            try: 
                response=session.post(command, verify=False, data=content, timeout=600, headers=post_headers) #, auth=(username, password))# , headers=post_headers ) # auth=(options.pushusername, options.pushpassword)
                #print(response)
                #print(response.text)
                do_logout(session, host)    
            except requests.exceptions.RequestException as e:
                print (e)
                return False
            if re.findall('created successfully', response.text):
                return True
        else:
            return 'not_active'
        '''

    return False

## BEGIN MAIN
    
import urllib3
#import ssl
import re
import codecs
from collections import defaultdict, OrderedDict
import requests
import pandas
import sys
from requests.packages.urllib3.util.ssl_ import create_urllib3_context

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

#post_headers = defaultdict(dict)
#get_headers = defaultdict(dict)
