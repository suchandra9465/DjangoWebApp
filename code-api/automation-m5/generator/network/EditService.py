import urllib
import json

from urllib.parse import quote
from xml.sax.saxutils import escape
from collections import defaultdict, OrderedDict
from ...generator import NetworkLogs
from .sonicwall import LoadService as SLS
from .paloaulto import LoadService as PLS

class EditNetworkService:

    def _init_(self, options):
        self.log = NetworkLogs().log
        self.sc = NetworkLogs().sc
        self.ss = NetworkLogs().ss
        self.debug = NetworkLogs().debug
        self.options = options
        self.sw = SLS.SonicWallService(self.options, self.config)
        self.getPaloService = PLS.LoadService(self.options)

    def modify_address_obj(self, target, session, apikey, fw_type, syntax, params, sw_objects=None):

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

                if params['action'].lower() == 'addmembers':
                    self.log('{}address-group ipv4 "{}"'.format(prefix, params['addressname']))
                    for member in params['members']:
                        self.log('{}address-object ipv4 "{}"'.format(prefix, member))
                    self.log('{}exit'.format(prefix))
                elif params['action'].lower() == 'delmembers':
                    self.log('{}address-group ipv4 "{}"'.format(prefix, params['addressname']))
                    for member in params['members']:
                        self.log('{}no address-object ipv4 "{}"'.format(prefix, member))
                    self.log('{}exit').format(prefix)
                elif params['action'].lower() == 'delete':
                    if params['addresstype'] == 'group':
                        self.log('{}no address-group ipv4 "{}"'.format(prefix, params['addressname']))
                    else:
                        self.log('{}no address-group ipv4 "{}"'.format(prefix, params['addressname']))
                else:
                    return 'Unknown Action'
                return True
            elif syntax.lower() in ['webui', 'api']:
                # for value, action in actions:
                if params['action'].lower() == 'addmembers':
                    for member in params['members']:
                        postdata = {'addro_atomToGrp_0': member,
                                    'addro_grpToGrp_0': params['addressname']
                                    }
                        url = 'https://' + target + '/main.cgi'
                        result = self.sw.send_sw_webcmd(session, url, postdata)
                elif params['action'].lower() == 'delmembers':
                    for member in params['members']:
                        postdata = {'addro_atomToGrp_-3': member,
                                    'addro_grpToGrp_-3': params['addressname']
                                    }
                        url = 'https://' + target + '/main.cgi'
                        result = self.sw.send_sw_webcmd(session, url, postdata)
                elif params['action'].lower() == 'delete':
                    postdata = {'addrObjId_-3': params['addressname']}
                    url = 'https://' + target + '/main.cgi'
                    result = self.sw.send_sw_webcmd(session, url, postdata)
                else:
                    return 'Unknown Action'
                    # return unknown action type
            else:
                return 'Unknown action "{}" specified for Sonicwall'.format(syntax)

        if fw_type == 'sw65':
            if syntax.lower() == 'api':

                post_data = {'address_group': {}}

                if params['action'].lower() == 'addmembers':
                    url = 'https://{}/api/sonicos/address-groups/ipv4/name/{}'.format(target, params['addressname'])
                    members = []
                    members_added = False
                    for address_object in params['members']:
                        members_added = True
                        if address_object in sw_objects['address_objects']['ipv4']:
                            url = 'https://{}/api/sonicos/address-groups/ipv4/name/{}'.format(target,
                                                                                              params['addressname'])
                            if 'ipv4' not in post_data['address_group']:
                                post_data['address_group']['ipv4'] = {}
                            if 'address_object' in post_data['address_group']['ipv4']:
                                post_data['address_group']['ipv4']['address_object']['ipv4'].append(
                                    {'name': address_object})
                            else:
                                post_data['address_group']['ipv4']['address_object'] = {
                                    'ipv4': [{'name': address_object}]}

                    for address_object in params['members']:
                        members_added = True
                        if address_object in sw_objects['address_objects']['fqdn']:
                            url = 'https://{}/api/sonicos/address-groups/ipv6/name/{}'.format(target,
                                                                                              params['addressname'])
                            if 'ipv6' not in post_data['address_group']:
                                post_data['address_group']['ipv6'] = {}
                            if 'address_object' in post_data['address_group']['ipv6']:
                                post_data['address_group']['ipv6']['address_object']['fqdn'].append(
                                    {'name': address_object})
                            else:
                                post_data['address_group']['ipv6']['address_object'] = {
                                    'fqdn': [{'name': address_object}]}

                    for address_object in params['members']:
                        members_added = True
                        if address_object in sw_objects['address_groups']['ipv4']:
                            url = 'https://{}/api/sonicos/address-groups/ipv4/name/{}'.format(target,
                                                                                              params['addressname'])
                            if 'ipv4' not in post_data['address_group']:
                                post_data['address_group']['ipv4'] = {}
                            if 'address_group' in post_data['address_group']['ipv4']:
                                post_data['address_group']['ipv4']['address_group']['ipv4'].append(
                                    {'name': address_object})
                            else:
                                post_data['address_group']['ipv4']['address_group'] = {
                                    'ipv4': [{'name': address_object}]}

                            # post_data['address_group']['ipv4']['address_group']['ipv4'].append({'name': address_object}) #.append({'name': address_object})
                    # if post_data['address_group']['ipv4']['address_object']['ipv4'] != [] or post_data['address_group']['ipv4']['address_group']['ipv4'] != []:
                    # if post_data['address_group']['ipv4']['address_group']['ipv4'] != []:
                    if members_added == True:
                        # post_data['address_group']['ipv4']['address_object']['ipv4']=members
                        result = session.put(url=url, json=post_data, verify=False,
                                             timeout=self.options.timeout_sw_webui_post)
                        self.debug(url)
                        self.debug(post_data)
                        self.debug(result.text)
                        if not json.loads(result.text)['status']['success']:
                            result = False, json.loads(result.text)['status']['info'][0]['message']
                        else:
                            result = True
                elif params['action'].lower() == 'rename':
                    url = 'https://{}/api/sonicos/address-groups/ipv4/name/{}'.format(target, params['addressname'])
                    post_data['address_group'] = {'ipv4': {'name': params['newaddressname']}}
                    result = session.put(url=url, json=post_data, verify=False, timeout=self.options.timeout_sw_webui_post)
                    self.debug(result)
                    self.debug(result.text)
                    if not json.loads(result.text)['status']['success']:
                        result = False, json.loads(result.text)['status']['info'][0]['message']
                    else:
                        result = True
                elif params['action'].lower() == 'delmembers':
                    url = 'https://{}/api/sonicos/address-groups/ipv4/name/{}'.format(target, params['addressname'])
                    members = []
                    members_added = False
                    for address_object in params['members']:
                        members_added = True
                        if address_object in sw_objects['address_objects']['ipv4']:
                            if 'address_object' in post_data['address_group']['ipv4']:
                                post_data['address_group']['ipv4']['address_object']['ipv4'].append(
                                    {'name': address_object})
                            else:
                                post_data['address_group']['ipv4']['address_object'] = [
                                    {'ipv4': {'name': address_object}}]
                    for address_object in params['members']:
                        members_added = True
                        if address_object in sw_objects['address_groups']['ipv4']:
                            if 'address_group' in post_data['address_group']['ipv4']:
                                post_data['address_group']['ipv4']['address_group']['ipv4'].append(
                                    {'name': address_object})
                            else:
                                post_data['address_group']['ipv4']['address_group'] = [
                                    {'ipv4': {'name': address_object}}]

                            # post_data['address_group']['ipv4']['address_group']['ipv4'].append({'name': address_object})
                            # #.append({'name': address_object})
                    # if post_data['address_group']['ipv4']['address_object']['ipv4'] != [] or
                    # post_data['address_group']['ipv4']['address_group']['ipv4'] != []:
                    # if post_data['address_group']['ipv4']['address_group']['ipv4'] != []:

                    if members_added == True:
                        result = session.delete(url=url, json=post_data, verify=False)
                        self.debug(post_data)
                        self.debug(result.text)
                        if not json.loads(result.text)['status']['success']:
                            result = False, json.loads(result.text)['status']['info'][0]['message']
                        else:
                            result = True
                elif params['action'].lower() == 'delete':
                    if params['addresstype'] in ['group', '8']:
                        url = 'https://{}/api/sonicos/address-groups/ipv4/name/{}'.format(target, params['addressname'])
                    else:
                        url = 'https://{}/api/sonicos/address-objects/ipv4/name/{}'.format(target,
                                                                                           params['addressname'])
                    self.debug(url)
                    result = session.delete(url=url, json=None, verify=False)
                    self.debug(result.text)
                    if not json.loads(result.text)['status']['success']:
                        result = False, json.loads(result.text)['status']['info'][0]['message']
                    else:
                        result = True
                else:
                    return 'Unknown Action'

        elif fw_type == 'checkpoint':
            if syntax.lower() == 'cli':
                # for value, action in actions:
                if params['action'].lower() == 'addmembers':
                    for member in params['members']:
                        self.log('{}addelement network_objects {} \'\' network_objects:{}'.format(prefix,
                                                                                                  params['addressname'],
                                                                                                  member))
                elif params['action'].lower() == 'delmembers':
                    for member in params['members']:
                        self.log('{}rmelement network_objects {} \'\' network_objects:{}'.format(prefix,
                                                                                                 params['addressname'],
                                                                                                 member))
                elif params['action'].lower() == 'color':
                    self.log(
                        '{}modify network_objects {} color {}'.format(prefix, params['addressname'], params['color']))
                elif params['action'].lower() == 'comment':
                    self.log('{}modify network_objects {} comments "{}"'.format(prefix, params['addressname'],
                                                                                params['comments']))
                elif params['action'].lower() == 'delete':
                    self.log('{}delete network_objects {}'.format(prefix, params['addressname']))
                else:
                    return 'Unknown Action'
                    # return unknown action type
            if syntax.lower() == 'api':
                self.debug('modify ckpt addr via api')
                post_data = None
                if 'addressname' in params:
                    post_data = {'name': params['addressname']}
                if 'uuid' in params:
                    post_data = {'uuid': params['uuid']}

                if post_data:
                    if params['action'].lower == 'delete':
                        if params['addresstype'].lower() in ['1', 'host']:
                            post_command = 'delete-host'
                        if params['addresstype'].lower() in ['2', 'range']:
                            post_command = 'delete-address-range'
                        if params['addresstype'].lower() in ['4', 'network']:
                            post_command = 'delete-network'
                        if params['addresstype'].lower() in ['8', 'group']:
                            post_command = 'delete-group'
                    else:
                        if params['addresstype'].lower() in ['1', 'host']:
                            post_command = 'set-host'
                            if 'ip1' in params:
                                post_data['ip-address'] = params['ip1']
                        if params['addresstype'].lower() in ['2', 'range']:
                            post_command = 'set-address-range'
                            if 'ip1' in params and 'ip2' in params:
                                post_data['ip-address-first'] = params['ip1']
                                post_data['ip-address-last'] = params['ip2']
                        if params['addresstype'].lower() in ['4', 'network']:
                            post_command = 'set-network'
                            if 'ip1' in params and 'ip2' in params:
                                post_data['subnet'] = params['ip1']
                                post_data['subnet-mask'] = params['ip2']
                        if params['addresstype'].lower() in ['8', 'group']:
                            post_command = 'set-group'
                            if params['action'] == 'delmembers' and 'members' in params:
                                post_data['members'] = {'remove': params['members']}
                            if params['action'] == 'addmembers' and 'members' in params:
                                post_data['members'] = {'add': params['members']}
                        if 'tags' in params:
                            post_data['tags'] = params['tags']
                        if 'comments' in params:
                            post_data['comments'] = params['comments']
                        if 'comment' in params:
                            post_data['comments'] = params['comment']
                        if 'color' in params:
                            post_data['color'] = params['color']
                        if 'rename' in params:
                            post_data['new-name'] = params['rename']

                    result = self.service.ckpt_api_call(target, 443, post_command, post_data, apikey)
                    self.debug('modify addr', result)
                    if result.status_code != 200:
                        self.debug(result.text)
                        result = False, json.loads(result.text)['message']
                    else:
                        result = True
        elif fw_type in ['palo', 'pano', 'paloalto']:
            if syntax.lower() in ['webui', 'api']:
                url = None
                if fw_type in ['palo', 'paloalto']:
                    object_base = "/config/devices/entry[@name='localhost.localdomain']/vsys/entry[@name='vsys1']"
                elif fw_type == 'pano':
                    if params['context'] == 'shared':
                        object_base = "/config/shared"
                    else:
                        object_base = "/config/devices/entry[@name='localhost.localdomain']/device-group/entry[@name='{}']".format(
                            params['context'])

                if params['action'].lower() == 'addmembers':
                    if params['addresstype'] in ['8', 'group', 'addressgroup']:
                        memberlist = ''
                        for member in params['members']:
                            memberlist = memberlist + '<member>{}</member>'.format(member)
                        if memberlist != '':
                            url = '/api/?type=config&action=set&xpath={}/address-group/entry[@name=\'{}\']/static&element={}'.format(
                                object_base, params['addressname'], memberlist)
                            result = self.getPaloService.send_palo_apicmd(session, target, url, apikey)
                elif params['action'].lower() == 'delmembers':
                    if params['addresstype'] in ['8', 'group', 'addressgroup']:
                        memberlist = ''
                        for member in params['members']:
                            # memberlist=memberlist+'<member>{}</member>'.format(member)
                            # if memberlist!='':
                            url = '/api/?type=config&action=delete&xpath={}/address-group/entry[@name=\'{}\']/static/member[text()="{}"]'.format(
                                object_base, params['addressname'], member)
                            result = self.getPaloService.send_palo_apicmd(session, target, url, apikey)
                elif params['action'].lower() == 'comment':
                    if params['addresstype'] in ['8', 'group', 'addressgroup']:
                        url = '/api/?type=config&action=set&xpath={}/address-group/entry[@name=\'{}\']&element=<description>{}</description>'.format(
                            object_base, params['addressname'], quote(params['comment'], safe=''))
                        result = self.getPaloService.send_palo_apicmd(session, target, url, apikey)
                    else:
                        url = '/api/?type=config&action=set&xpath={}/address/entry[@name=\'{}\']&element=<description>{}</description>'.format(
                            object_base, params['addressname'], quote(params['comment'], safe=''))
                        result = self.getPaloService.send_palo_apicmd(session, target, url, apikey)
                elif params['action'].lower() == 'tags':
                    if params['addresstype'] in ['8', 'group', 'addressgroup']:
                        for tag in params['tags']:
                            url = '/api/?type=config&action=set&xpath={}/address-group/entry[@name=\'{}\']/tag&element=<member>{}</member>'.format(
                                object_base, params['addressname'], tag)
                            result = self.getPaloService.send_palo_apicmd(session, target, url, apikey)
                    else:
                        for tag in params['tags']:
                            url = '/api/?type=config&action=set&xpath={}/address/entry[@name=\'{}\']/tag&element=<member>{}</member>'.format(
                                object_base, params['addressname'], tag)
                            result = self.getPaloService.send_palo_apicmd(session, target, url, apikey)
                elif params['action'].lower() == 'delete':
                    if params['addresstype'] in ['8', 'group']:
                        url = '/api/?type=config&action=delete&xpath={}/address-group/entry[@name=\'{}\']'.format(
                            object_base, params['addressname'])
                        result = self.getPaloService.send_palo_apicmd(session, target, url, apikey)
                    else:  # if params['addresstype'] in ['1', '2', '4', 'host', 'range', 'network']:
                        url = '/api/?type=config&action=delete&xpath={}/address/entry[@name=\'{}\']'.format(object_base,
                                                                                                            params[
                                                                                                                'addressname'])
                        result = self.getPaloService.send_palo_apicmd(session, target, url, apikey)
            elif syntax.lower() == 'cli':
                cmds = []
                if fw_type.lower() in ['palo', 'paloalto']:
                    cmd_base = ''
                elif fw_type.lower() == 'pano':
                    if params['context'] == 'shared':
                        cmd_base = 'shared '
                    else:
                        cmd_base = 'device-group "{}"'.format(params['context'])
                if params['action'].lower() == 'addmembers':
                    for member in params['members']:
                        cmds.append(
                            '{}set {}address-group {} static "{}"'.format(prefix, cmd_base, params['addressname'],
                                                                          member))
                elif params['action'].lower() == 'delmembers':
                    for member in params['members']:
                        if params['addresstype'] in ['1', 'host']:
                            cmds.append(
                                '{}delete {}address-group {} static "{}"'.format(prefix, cmd_base,
                                                                                 params['addressname'],
                                                                                 member))
                        else:
                            cmds.append(
                                '{}delete {}address-group {} static "{}"'.format(prefix, cmd_base,
                                                                                 params['addressname'],
                                                                                 member))
                elif params['action'].lower() == 'comment':
                    if params['addresstype'] in ['1', '2', '4', 'host', 'range', 'network']:
                        cmds.append(
                            '{}set {}address {} description "{}"'.format(prefix, cmd_base, params['addressname'],
                                                                         params['comment']))
                    else:
                        cmds.append(
                            '{}set {}address-group {} description "{}"'.format(prefix, cmd_base, params['addressname'],
                                                                               params['comment']))
                elif params['action'].lower() == 'tag':
                    tags = '[ '
                    for tag in params['tags']:
                        tags += tag + " "
                    tags += ']'
                    if params['addresstype'] in ['1', '2', '4', 'host', 'range', 'network']:
                        cmds.append('{}set {}address {} tag {}'.format(prefix, cmd_base, params['addressname'], tags))
                    else:
                        cmds.append(
                            '{}set {}address-group {} tag {}'.format(prefix, cmd_base, params['addressname'], tags))
                elif params['action'].lower() == 'delete':
                    if params['addresstype'] in ['1', '2', '4', 'host', 'range', 'network']:
                        cmds.append('{}delete {}address {}'.format(prefix, cmd_base, params['addressname']))
                    elif params['addresstype'] in ['8', 'group']:
                        cmds.append('{}delete {}address-group {}'.format(prefix, cmd_base, params['addressname']))
                for cmd in cmds:
                    self.log(cmd)
                return True
            else:
                return 'Unsupported syntax type: {} specified for Palo/Pano config'.format(syntax)
        else:
            pass
            # return unknown firewall type
        return result

    def modify_service_obj(self, target, session, apikey, fw_type, syntax, params, sw_objects=None):

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
                # for param in params:
                if params['action'].lower() == 'addmembers':
                    self.log('{}service-group "{}"'.format(prefix, params['servicename']))
                    for member in params['members']:
                        self.log('{}service-object"{}"'.format(prefix, member))
                    self.log('{}exit').format(prefix)
                elif params['action'].lower() == 'delmembers':
                    self.log('{}service-group "{}"'.format(prefix, params['servicename']))
                    for member in params['members']:
                        self.log('{}no service-object "{}"'.format(prefix, member))
                    self.log('{}exit').format(prefix)
                elif params['action'].lower() == 'delete':
                    if params['servicetype'] == 'group':
                        self.log('{}no service-group "{}"'.format(prefix, params['servicename']))
                    else:
                        self.log('{}no service-object "{}"'.format(prefix, params['servicename']))
                # elif params['action'].lower()=='':
                else:
                    return 'Unknown Action'
                return True
            elif syntax.lower() in ['webui', 'api']:
                # for value, action in actions:
                if params['action'].lower() == 'addmembers':
                    for member in params['members']:
                        postdata = {'so_atomToGrp_0': member,
                                    'so_grpToGrp_0': params['servicename']
                                    }
                        url = 'https://' + target + '/main.cgi'
                        result = self.sw.send_sw_webcmd(session, url, postdata)
                elif params['action'].lower() == 'delmembers':
                    for member in params['members']:
                        postdata = {'so_atomToGrp_-3': member,
                                    'so_grpToGrp_-3': params['servicename']
                                    }
                        url = 'https://' + target + '/main.cgi'
                        result = self.sw.send_sw_webcmd(session, url, postdata)
                elif params['action'].lower() == 'delete':
                    postdata = {'svcObjId_-3': params['servicename']}
                    url = 'https://' + target + '/main.cgi'
                    result = self.sw.send_sw_webcmd(session, url, postdata)
                else:
                    return 'Unknown Action'
                    # return unknown action type
            else:
                return 'Unknown action "{}" specified for Sonicwall'.format(syntax)
        if fw_type == 'sw65':
            if syntax.lower() == 'api':
                if params['action'].lower() == 'addmembers':
                    url = 'https://{}/api/sonicos/service-groups/name/{}'.format(target, params['servicename'])
                    object_members = []
                    group_members = []
                    members = []
                    post_data = {'service_group': {'name': params['servicename'], 'service_object': members}}
                    for service_object in params['members']:
                        if service_object in sw_objects['service_objects']:
                            members.append({'name': service_object})
                    for service_object in params['members']:
                        if service_object in sw_objects['service_groups']:
                            members.append({'group': service_object})
                    # if object_members != [] or group_members != [] or members != []:
                    #        #post_data={'service_groups': [{ 'service_object': object_members] }}
                    if members != []:
                        post_data['service_group']['service_object'] = members  # ['service_object']=object_members
                        # if group_members != []:
                        #    post_data['service_group']['service_group']=group_members #['service_object']=object_members
                        result = session.put(url=url, json=post_data)
                        self.debug(url)
                        self.debug(post_data)
                        self.debug(result.text)
                        if not json.loads(result.text)['status']['success']:
                            result = False, json.loads(result.text)['status']['info'][0]['message']
                        else:
                            result = True
                    else:
                        result = False, 'no valid member objects'
                elif params['action'].lower() == 'delmembers':
                    url = 'https://{}/api/sonicos/service-groups/name/{}'.format(target, params['servicename'])
                    object_members = []
                    group_members = []
                    members = []
                    post_data = {'service_group': {'name': params['servicename'], 'service_object': members}}
                    for service_object in params['members']:
                        if service_object in sw_objects['service_objects']:
                            members.append({'name': service_object})
                    for service_object in params['members']:
                        if service_object in sw_objects['service_groups']:
                            members.append({'group': service_object})
                    # if object_members != [] or group_members != []:
                    if members != []:
                        post_data['service_group']['service_object'] = members  # ['service_object']=object_members
                        # if group_members != []:
                        #    post_data['service_group']['service_group']=members #['service_object']=object_members
                        self.debug(url)
                        self.debug(post_data)
                        result = session.delete(url=url, json=post_data)
                        self.debug(result.text)
                        if not json.loads(result.text)['status']['success']:
                            result = False, json.loads(result.text)['status']['info'][0]['message']
                        else:
                            result = True
                    else:
                        result = False, 'no valid member objects'

                elif params['action'].lower() == 'delete':
                    if params['servicetype'] in ['group', '2']:
                        url = 'https://{}/api/sonicos/service-groups/name/{}'.format(target, params['servicename'])
                    else:
                        url = 'https://{}/api/sonicos/service-objects/name/{}'.format(target, params['servicename'])
                    self.debug(url)
                    result = session.delete(url=url, json=None)
                    self.debug(result.text)
                    if not json.loads(result.text)['status']['success']:
                        result = False, json.loads(result.text)['status']['info'][0]['message']
                    else:
                        result = True
                else:
                    return 'Unknown Action'

        elif fw_type == 'checkpoint':
            if syntax.lower() == 'cli':
                # for value, action in actions:
                if params['action'].lower() == 'addmembers':
                    for member in params['members']:
                        self.log(
                            '{}addelement services {} \'\' services:{}'.format(prefix, params['servicename'], member))
                elif params['action'].lower() == 'delmembers':
                    for member in params['members']:
                        self.log(
                            '{}rmelement services {} \'\' services:{}'.format(prefix, params['servicename'], member))
                elif params['action'].lower() == 'color':
                    self.log('{}modify services {} color {}'.format(prefix, params['servicename'], params['color']))
                elif params['action'].lower() == 'comment':
                    self.log('{}modify netwoservicesrk_objects {} comments "{}"'.format(prefix, params['servicename'],
                                                                                        params['comments']))
                elif params['action'].lower() == 'delete':
                    self.log('{}delete services {}'.format(prefix, params['servicename']))
                else:
                    return 'Unknown Action'
                    # return unknown action type
            if syntax.lower() == 'api':
                self.debug('modify ckpt svc via api')
                post_data = None
                if 'servicename' in params:
                    post_data = {'name': params['servicename']}
                if 'uuid' in params:
                    post_data = {'uuid': params['uuid']}
                if post_data:
                    if params['action'].lower() == 'delete':
                        if params['servicetype'].lower() in ['1',
                                                             'service']:  ## need to know what kind of service object to delete
                            if 'protocol' in params:
                                if params['protocol'].lower() in ['tcp', '6']:
                                    post_command = 'delete-service-tcp'
                                elif params['protocol'].lower() in ['udp', '17']:
                                    post_command = 'delete-service-udp'
                                elif params['protocol'].lower() in ['icmp', '1']:
                                    post_command = 'delete-service-icmp'
                                elif params['protocol'].lower() in ['icmp6', 'icmpv6', '58']:
                                    post_command = 'delete-service-icmp6'
                                elif params['protocol'].lower() in ['sctp', '132']:
                                    post_command = 'delete-service-sctp'
                                elif params['protocol'].lower() in ['other', '255']:
                                    post_command = 'delete-service-other'
                                    post_data['ip-protocol'] = params['port1']
                                elif params['protocol'].lower() in ['dce-rpc']:
                                    post_command = 'delete-service-dce-rpc'
                                elif params['protocol'].lower() in ['rpc']:
                                    post_command = 'delete-service-rpc'
                                elif params['protocol'].lower() in ['gtp']:
                                    post_command = 'delete-service-gtp'
                                elif params['protocol'].lower() in ['citrix-tcp']:
                                    post_command = 'delete-service-citrix-tcp'
                                elif params['protocol'].lower() in ['compound-tcp']:
                                    post_command = 'delete-service-compound-tcp'
                        elif params['servicetype'].lower() in ['2', 'group']:
                            post_command = 'delete-service-group'
                    elif params['action'] == 'delmembers' and 'members' in params:
                        post_command = 'set-service-group'
                        post_data['members'] = {'remove': params['members']}
                    elif params['action'] == 'addmembers' and 'members' in params:
                        post_command = 'set-service-group'
                        post_data['members'] = {'add': params['members']}
                    else:
                        if 'protocol' in params:
                            if params['protocol'].lower() in ['tcp', '17']:
                                post_command = 'set-service-tcp'
                            if params['protocol'].lower() in ['udp', '6']:
                                post_command = 'set-service-udp'
                        if 'port1' and 'port2' in params:
                            post_data['port'] = '{}-{}'.format(params['port1'], params['port2'])
                        elif 'port1' in params:
                            post_data['port'] = params['port1']
                        if 'tags' in params:
                            post_data['tags'] = params['tags']
                        if 'comments' in params:
                            post_data['comments'] = params['comments']
                        if 'comment' in params:
                            post_data['comments'] = params['comment']
                        if 'color' in params:
                            post_data['color'] = params['color']
                        if 'rename' in params:
                            post_data['new-name'] = params['rename']

                    result = self.service.ckpt_api_call(target, 443, post_command, post_data, apikey)
                    self.debug('modify addr', result)
                    if result.status_code != 200:
                        self.debug(result.text)
                        result = False, json.loads(result.text)['message']
                    else:
                        result = True
        elif fw_type in ['palo', 'pano', 'paloalto']:
            if syntax.lower() in ['webui', 'api']:
                if fw_type in ['palo', 'paloalto']:
                    object_base = "/config/devices/entry[@name='localhost.localdomain']/vsys/entry[@name='vsys1']"
                elif fw_type == 'pano':
                    if params['context'] == 'shared':
                        object_base = "/config/shared"
                    else:
                        object_base = "/config/devices/entry[@name='localhost.localdomain']/device-group/entry[@name='{}']".format(
                            params['context'])
                if params['action'].lower() == 'addmembers':
                    if params['servicetype'] in ['2', 'group']:
                        memberlist = ''
                        for member in params['members']:
                            memberlist = memberlist + '<member>{}</member>'.format(member)
                        if memberlist != '':
                            url = '/api/?type=config&action=set&xpath={}/service-group/entry[@name=\'{}\']/members&element={}'.format(
                                object_base, params['servicename'], memberlist)
                            result = self.getPaloService.send_palo_apicmd(session, target, url, apikey)
                elif params['action'].lower() == 'delmembers':
                    # memberlist=''
                    for member in params['members']:
                        # memberlist=memberlist+'<member>{}</member>'.format(member)
                        # if memberlist!='':
                        url = '/api/?type=config&action=delete&xpath={}/service-group/entry[@name=\'{}\']/members/member[text()="{}"]'.format(
                            object_base, params['servicename'], member)
                        result = self.getPaloService.send_palo_apicmd(session, target, url, apikey)
                elif params['action'].lower() == 'comment':  # comments not supported for svc groups
                    if params['servicetype'] in ['2', 'group']:
                        url = '/api/?type=config&action=set&xpath={}/service-group/entry[@name=\'{}\']&element=<description>{}</description>'.format(
                            object_base, params['servicename'], quote(params['comment'], safe=''))
                        result = self.getPaloService.send_palo_apicmd(session, target, url, apikey)
                    else:
                        url = '/api/?type=config&action=set&xpath={}/service/entry[@name=\'{}\']&element=<description>{}</description>'.format(
                            object_base, params['servicename'], quote(params['comment'], safe=''))
                        result = self.getPaloService.send_palo_apicmd(session, target, url, apikey)
                elif params['action'].lower() == 'addtags':
                    for tag in params['tags']:
                        if params['servicetype'] in ['1', 'service']:
                            url = '/api/?type=config&action=set&xpath={}/service/entry[@name=\'{}\']/tag&element=<member>{}</member>'.format(
                                object_base, params['servicename'], tag)
                            result = self.getPaloService.send_palo_apicmd(session, target, url, apikey)
                        elif params['servicetype'] in ['2', 'group']:
                            url = '/api/?type=config&action=set&xpath={}/service-group/entry[@name=\'{}\']/tag&element=<member>{}</member>'.format(
                                object_base, params['servicename'], tag)
                            result = self.getPaloService.send_palo_apicmd(session, target, url, apikey)
                elif params['action'].lower() == 'delete':
                    if params['servicetype'] in ['2', 'group']:
                        url = '/api/?type=config&action=delete&xpath={}/service-group/entry[@name=\'{}\']'.format(
                            object_base, params['servicename'])
                        result = self.getPaloService.send_palo_apicmd(session, target, url, apikey)
                    else:  # if params['servicetype'] in ['1', '2', '4', 'host', 'range', 'network']:
                        url = '/api/?type=config&action=delete&xpath={}/service/entry[@name=\'{}\']'.format(object_base,
                                                                                                            params[
                                                                                                                'servicename'])
                        result = self.getPaloService.send_palo_apicmd(session, target, url, apikey)
            elif syntax.lower() == 'cli':
                cmds = []
                if fw_type.lower() in ['palo', 'paloalto']:
                    cmd_base = ''
                elif fw_type.lower() == 'pano':
                    if params['context'] == 'shared':
                        cmd_base = 'shared '
                    else:
                        cmd_base = 'device-group "{}"'.format(params['context'])
                if params['action'].lower() == 'addmembers':
                    for member in params['members']:
                        cmds.append(
                            '{}set {}service-group {} static "{}"'.format(prefix, cmd_base, params['servicename'],
                                                                          member))
                elif params['action'].lower() == 'delmembers':
                    for member in params['members']:
                        if params['servicetype'] in ['1', 'host']:
                            cmds.append(
                                '{}delete {}service-group {} static "{}"'.format(prefix, cmd_base,
                                                                                 params['servicename'],
                                                                                 member))
                        else:
                            cmds.append(
                                '{}delete {}service-group {} static "{}"'.format(prefix, cmd_base,
                                                                                 params['servicename'],
                                                                                 member))
                elif params['action'].lower() == 'comment':
                    if params['servicetype'] in ['1', 'service']:
                        cmds.append(
                            '{}set {}service {} description "{}"'.format(prefix, cmd_base, params['servicename'],
                                                                         quote(params['comment'], safe='')))
                    # else: # not supported for svc groups
                    #    cmds.append('{}set {}service-group {} description "{}"'.format(prefix, cmd_base, params['servicename'], quote(params['comment'], safe='')))
                elif params['action'].lower() == 'tag':
                    tags = '[ '
                    for tag in params['tags']:
                        tags += tag + " "
                    tags += ']'
                    if params['servicetype'] in ['1', 'service']:
                        cmds.append('{}set {}service {} tag {}'.format(prefix, cmd_base, params['servicename'], tags))
                    else:
                        cmds.append(
                            '{}set {}service-group {} tag {}'.format(prefix, cmd_base, params['servicename'], tags))
                elif params['action'].lower() == 'delete':
                    if params['servicetype'] in ['1', 'service']:
                        cmds.append('{}delete {}service {}'.format(prefix, cmd_base, params['servicename']))
                    elif params['servicetype'] in ['2', 'group']:
                        cmds.append('{}delete {}service-group {}'.format(prefix, cmd_base, params['servicename']))
                for cmd in cmds:
                    self.log(cmd)
                return True
            else:
                return 'Unsupported syntax type: {} specified for Palo/Pano config'.format(syntax)
        else:
            pass
            # return unknown firewall type
        return result

    def modify_rule_obj(self, target, session, apikey, fw_type, syntax, params, sw_objects=None):

        result = False

        if 'comment' in params and fw_type.lower() in ['palo', 'pano', 'paloalto'] and syntax.lower() in ['webui',
                                                                                                          'api']:
            self.debug(params['comment'])
            params['comment'] = escape(params['comment'])
            self.debug(params['comment'])

        if syntax.lower() == 'cli':
            result = True
            if 'prefix' in params:
                prefix = params['prefix']
            else:
                prefix = '{}CLI:'.format(fw_type.upper())

        # actions is a set of action, value

        if fw_type == 'sonicwall':
            if syntax.lower() == 'cli':
                # rule_cmd=
                # source, dest, comment, action, priority
                if params['action'].lower() == 'comment':
                    self.log(
                        '{}access-rule from "{srczone}" to "{dstzone}" action "{action}" source address {source} service {service} destination address {destination}'.format(
                            prefix, srczone=params['srczones'][0], dstzone=params['dstzones'][0],
                            action=params['polaction'],
                            source=params['sources'][0], destination=params['dests'][0], service=params['services'][0]))
                    self.log('{}comment "{}"'.format(prefix, params['comment']))
                    self.log('{}exit'.format(prefix))
                elif params['action'].lower() == 'delete':
                    self.log(
                        '{}no access-rule from "{srczone}" to "{dstzone}" action "{action}" source address {source} service {service} destination address {destination}'.format(
                            prefix, srczone=params['srczones'][0], dstzone=params['dstzones'][0],
                            action=params['polaction'],
                            source=params['sources'][0], destination=params['dests'][0], service=params['services'][0]))
                elif params['action'].lower() == 'enable':
                    self.log(
                        '{}access-rule from "{srczone}" to "{dstzone}" action "{action}" source address {source} service {service} destination address {destination}'.format(
                            prefix, srczone=params['srczones'][0], dstzone=params['dstzones'][0],
                            action=params['polaction'],
                            source=params['sources'][0], destination=params['dests'][0], service=params['services'][0]))
                    self.log('{}enable'.format(prefix))
                    self.log('{}exit'.format(prefix))
                elif params['action'].lower() == 'disable':
                    self.log(
                        '{}access-rule from "{srczone}" to "{dstzone}" action "{action}" source address {source} service {service} destination address {destination}'.format(
                            prefix, srczone=params['srczones'][0], dstzone=params['dstzones'][0],
                            action=params['polaction'],
                            source=params['sources'][0], destination=params['dests'][0], service=params['services'][0]))
                    self.log('{}no enable'.format(prefix))
                    self.log('{}exit'.format(prefix))
            elif syntax.lower() in ['webui', 'api']:
                if params['action'].lower() == 'delmembers':
                    pass  # not supported
                elif params['action'].lower() == 'addmembers':
                    pass  # not supported
                elif params['action'].lower() == 'comment':
                    pass
                elif params['action'].lower() == 'enable':
                    pass
                elif params['action'].lower() == 'disable':
                    pass  # have not been unable to get this to work properly

                elif params['action'].lower() == 'delete':
                    if params['services'][0].lower() in ['any', ['any']]:
                        service = ''
                    else:
                        service = params['services'][0]
                    if params['srczones'][0].lower() in ['any', ['any']]:
                        srczone = ''
                    else:
                        srczone = params['srczones'][0]
                    if params['dstzones'][0].lower() in ['any', ['any']]:
                        dstzone = ''
                    else:
                        dstzone = params['dstzones'][0]
                    if params['sources'][0].lower() in ['any', ['any']]:
                        source = ''
                    else:
                        source = params['sources'][0]
                    if params['dests'][0].lower() in ['any', ['any']]:
                        dest = ''
                    else:
                        dest = params['dests'][0]
                    postdata = {'policyAction_-3': params['polaction'],
                                'policySrcIf_-3': '4294967295',
                                'policyDstIf_-3': '4294967295',
                                'policySrcSvc_-3': '',
                                'policyDstSvc_-3': service,
                                'policySrcZone_-3': srczone,
                                'policyDstZone_-3': dstzone,
                                'policySrcNet_-3': source,
                                'policyDstNet_-3': dest
                                }
                    url = 'https://' + target + '/main.cgi'
                    result = self.sw.send_sw_webcmd(session, url, postdata)
            else:
                return 'Unknown syntax "{}" specified for Sonicwall'.format(syntax)

        elif fw_type == 'sw65':
            self.debug(params)
            if syntax.lower() == 'api':
                if 'uuid' in params:
                    post_data = {'access_rule': {'ipv4': {}}}
                else:
                    post_data = {'access_rule': {'ipv4': {}}}

                # if modifying rule without UUID, only a few params can be changed - comment, tcp urgent, logging, enabled
                if params['action'].lower() == 'comment':
                    post_data['access_rule']['ipv4']['comment'] = "'{}'".format(params['comment'])

                elif params['action'].lower() == 'logging':
                    if str(params['logging']).lower() in ['1', 'yes', 'enable', 'enabled', 'true']:
                        post_data['access_rule']['ipv4']['logging'] = True
                    else:
                        post_data['access_rule']['ipv4']['logging'] = False

                elif params['action'].lower() in ['enable']:
                    post_data['access_rule']['ipv4']['enable'] = True
                elif params['action'].lower() in ['disable']:
                    post_data['access_rule']['ipv4']['enable'] = False

                if params['action'].lower() in ['delete', 'comment', 'logging', 'enable',
                                                'disable'] and 'uuid' not in params:
                    if params['services'][0].lower() in ['any', ['any']]:
                        post_data['access_rule']['ipv4']['service'] = {'any': True}
                    else:
                        if params['services'][0] in sw_objects['service_objects']['ipv4']:
                            post_data['access_rule']['ipv4']['service'] = {'name': params['services'][0]}
                        elif params['services'][0] in sw_objects['service_groups']['ipv4']:
                            post_data['access_rule']['ipv4']['service'] = {'group': params['services'][0]}

                    if params['srczones'][0].lower() in ['any', ['any']]:
                        post_data['access_rule']['ipv4']['from'] = 'any'  # {'address': {'any': True}}
                    else:
                        post_data['access_rule']['ipv4']['from'] = params['srczones'][0]

                    if params['dstzones'][0].lower() in ['any', ['any']]:
                        post_data['access_rule']['ipv4']['to'] = 'any'  # {'address': {'any': True}}
                    else:
                        post_data['access_rule']['ipv4']['to'] = params['dstzones'][0]

                    if params['sources'][0].lower() in ['any', ['any']]:
                        post_data['access_rule']['ipv4']['source'] = {'address': {'any': True}}
                    else:
                        if params['sources'][0] in sw_objects['address_objects']['ipv4']:
                            post_data['access_rule']['ipv4']['source'] = {'address': {'name': params['sources'][0]}}
                        elif params['sources'][0] in sw_objects['address_groups']['ipv4']:
                            post_data['access_rule']['ipv4']['source'] = {'address': {'group': params['sources'][0]}}

                    if params['dests'][0].lower() in ['any', ['any']]:
                        post_data['access_rule']['ipv4']['destination'] = {'address': {'any': True}}
                    else:
                        if params['dests'][0] in sw_objects['address_objects']['ipv4']:
                            post_data['access_rule']['ipv4']['destination'] = {'address': {'name': params['dests'][0]}}
                        elif params['dests'][0] in sw_objects['address_groups']['ipv4']:
                            post_data['access_rule']['ipv4']['destination'] = {'address': {'group': params['dests'][0]}}

                    if params['polaction'].lower() in ['1', 'drop', 'discard']:
                        post_data['access_rule']['ipv4']['action'] = 'discard'
                    elif params['polaction'].lower() in ['2', 'allow', 'pass', 'accept']:
                        post_data['access_rule']['ipv4']['action'] = 'allow'
                    elif params['polaction'].lower() in ['0', 'deny']:
                        post_data['access_rule']['ipv4']['action'] = 'deny'

                if 'uuid' in params:

                    if params['action'].lower() == 'enable':
                        post_data['access_rule']['ipv4']['enable'] = True
                    elif params['action'].lower() == 'disable':
                        post_data['access_rule']['ipv4']['enable'] = False

                    if 'polaction' in params:
                        if params['polaction'].lower() in ['1', 'drop', 'discard']:
                            post_data['access_rule']['ipv4']['action'] = 'discard'
                        elif params['polaction'].lower() in ['2', 'allow', 'pass', 'accept']:
                            post_data['access_rule']['ipv4']['action'] = 'allow'
                        elif params['polaction'].lower() in ['0', 'deny']:
                            post_data['access_rule']['ipv4']['action'] = 'deny'

                    # if 'enabled' in params:
                    #    if params['enabled'].lower() in ['1', 'enable', 'enabled', True]:
                    #        post_data['access_rule']['ipv4']['enable'] = True

                    if 'services' in params:
                        if params['services'][0].lower() in ['any', ['any']]:
                            post_data['access_rule']['ipv4']['service'] = {'any': True}
                        elif params['services'][0] in sw_objects['service_objects']:
                            post_data['access_rule']['ipv4']['service'] = {'name': params['services'][0]}
                        elif params['services'][0] in sw_objects['service_groups']:
                            post_data['access_rule']['ipv4']['service'] = {'group': params['services'][0]}

                    if 'srczones' in params:
                        if params['srczones'][0].lower() in ['any', ['any']]:
                            post_data['access_rule']['ipv4']['from'] = 'any'  # {'any': True}
                        else:
                            post_data['access_rule']['ipv4']['from'] = params['srczones'][0]

                    if 'dstzones' in params:
                        if params['dstzones'][0].lower() in ['any', ['any']]:
                            post_data['access_rule']['ipv4']['to'] = 'any'  # {'any': True}
                        else:
                            post_data['access_rule']['ipv4']['to'] = params['dstzones'][0]

                    if 'sources' in params:
                        if params['sources'][0].lower() in ['any', ['any']]:
                            post_data['access_rule']['ipv4']['source'] = {}
                            post_data['access_rule']['ipv4']['source'] = {'address': {'any': True}}
                        elif params['sources'][0] in sw_objects['address_objects']['ipv4']:
                            post_data['access_rule']['ipv4']['source'] = {}
                            post_data['access_rule']['ipv4']['source'] = {}['address'] = {'name': params['sources'][0]}
                        elif params['sources'][0] in sw_objects['address_groups']['ipv4']:
                            post_data['access_rule']['ipv4']['source'] = {}
                            post_data['access_rule']['ipv4']['source']['address'] = {'group': params['sources'][0]}

                    if 'dests' in params:
                        # 'destination': {'address': {'group': 'All Interface IPv6 Addresses'}}
                        # 'destination': {'group': 'test_group'}
                        if params['dests'][0].lower() in ['any', ['any']]:
                            post_data['access_rule']['ipv4']['destination'] = {}
                            post_data['access_rule']['ipv4']['destination'] = {'address': {'any': True}}
                        elif params['dests'][0] in sw_objects['address_objects']['ipv4']:
                            post_data['access_rule']['ipv4']['destination'] = {}
                            post_data['access_rule']['ipv4']['destination']['address'] = {'name': params['dests'][0]}
                        elif params['dests'][0] in sw_objects['address_groups']['ipv4']:
                            post_data['access_rule']['ipv4']['destination'] = {}
                            post_data['access_rule']['ipv4']['destination']['address'] = {'group': params['dests'][0]}
                if 'uuid' in params:
                    url = 'https://{}/api/sonicos/access-rules/ipv4/uuid/{}'.format(target, params['uuid'])
                else:
                    url = 'https://{}/api/sonicos/access-rules/ipv4'.format(target)
                self.debug(url, post_data)
                if params['action'].lower() in ['delete', 'delmembers']:
                    result = session.delete(url=url, json=post_data)
                else:
                    result = session.put(url=url, json=post_data)

                self.debug(result.text)
                if not json.loads(result.text)['status']['success']:
                    result = False, json.loads(result.text)['status']['info'][0]['message']
                else:
                    result = True

        elif fw_type == 'checkpoint':
            # for source, action in source_actions:
            # for action, value, param in actions:

            if syntax.lower() == 'cli':
                if params['action'].lower() == 'delmembers':
                    command = 'rmelement'
                elif params['action'].lower() == 'addmembers':
                    command = 'addelement'
                elif params['action'].lower() == 'comment':
                    command = 'modify'
                elif params['action'].lower() == 'enable':
                    command = 'modify'
                    value = 'false'
                elif params['action'].lower() == 'disable':
                    command = 'modify'
                    value = 'true'
                if params['action'].lower() in ['delmembers', 'addmembers']:
                    if 'sources' in params:
                        for member in params['sources']:
                            if member.lower() == 'any':
                                table = 'globals'
                                member = 'Any'
                            else:
                                table = 'network_objects'
                            self.log('{}{} fw_policies {} rule:{}:{}:\'\' {}:{}'.format(prefix, command,
                                                                                        params['policyname'],
                                                                                        params['policynum'], 'src',
                                                                                        table,
                                                                                        member))
                    if 'dests' in params:
                        for member in params['dests']:
                            if member.lower() == 'any':
                                table = 'globals'
                                member = 'Any'
                            else:
                                table = 'network_objects'
                            self.log('{}{} fw_policies {} rule:{}:{}:\'\' {}:{}'.format(prefix, command,
                                                                                        params['policyname'],
                                                                                        params['policynum'], 'dst',
                                                                                        table,
                                                                                        member))
                elif params['action'].lower() == 'comment':
                    self.log('{}{} fw_policies {} rule:{}:comments "{}"'.format(prefix, command, params['policyname'],
                                                                                params['policynum'], params['comment']))
                elif params['action'].lower() in ['enable', 'disable']:
                    self.log('{}modify fw_policies {} rule:{}:disabled {}'.format(prefix, params['policyname'],
                                                                                  params['policynum'], value))
                elif params['action'].lower() in ['delete']:
                    self.log(
                        '{}rmbyindex fw_policies {} rule {}'.format(prefix, params['policyname'], params['policynum']))
                else:
                    return 'Unknown Action'

            if syntax.lower() == 'api':
                pass

        elif fw_type in ['palo', 'pano', 'paloalto']:
            if syntax.lower() == 'cli':
                if fw_type.lower() in ['palo', 'paloalto']:
                    cmd_base = 'rulebase'
                elif fw_type.lower() == 'pano':
                    if params['context'] == 'shared':
                        cmd_base = 'shared pre-rulebase'
                    else:
                        cmd_base = 'device-group "{}" pre-rulebase'.format(params['context'])
                if params['action'].lower() == 'delmembers':
                    if 'sources' in params:
                        members = ' '
                        for member in params['sources']:
                            members += member + ' '
                        self.log(
                            '{}delete {} security rules "{}" source [{}]'.format(prefix, cmd_base, params['policyname'],
                                                                                 members))
                    if 'dests' in params:
                        members = ' '
                        for member in params['dests']:
                            members += member + ' '
                        self.log('{}delete {} security rules "{}" destination [{}]'.format(prefix, cmd_base,
                                                                                           params['policyname'],
                                                                                           members))
                elif params['action'].lower() == 'addmembers':
                    if 'sources' in params:
                        members = ' '
                        for member in params['sources']:
                            members += member + ' '
                        self.log(
                            '{}set {} security rules "{}" source [{}]'.format(prefix, cmd_base, params['policyname'],
                                                                              members))
                    if 'dests' in params:
                        members = ' '
                        for member in params['dests']:
                            members += member + ' '
                        self.log('{}set {} security rules "{}" destination [{}]'.format(prefix, cmd_base,
                                                                                        params['policyname'],
                                                                                        members))
                elif params['action'].lower() == 'comment':
                    self.log(
                        '{}set {} security rules "{}" description "{}'.format(prefix, cmd_base, params['policyname'],
                                                                              params['comment']))
                elif params['action'].lower() == 'enable':
                    self.log('{}set {} security rules "{}" disable no'.format(prefix, cmd_base, params['policyname'],
                                                                              params['comment']))
                elif params['action'].lower() == 'disable':
                    self.log('{}set {} security rules "{}" disable yes'.format(prefix, cmd_base, params['policyname'],
                                                                               params['comment']))
                elif params['action'].lower() == 'delete':
                    self.log('{}delete {} security rules "{}"'.format(prefix, cmd_base, params['policyname']))
                else:
                    return 'Unknown Action'
            elif syntax.lower() in ['webui', 'api']:
                url = None
                if fw_type in ['palo', 'paloalto']:
                    object_base = "/config/devices/entry[@name='localhost.localdomain']/vsys/entry[@name='vsys1']/rulebase/security/rules"
                elif fw_type == 'pano':
                    if params['context'] == 'shared':
                        object_base = "/config/shared/pre-rulebase/security/rules"
                    else:
                        object_base = "/config/devices/entry[@name='localhost.localdomain']/device-group/entry[@name='{}']/pre-rulebase/security/rules".format(
                            params['context'])

                if params['action'].lower() == 'setmembers':
                    if 'dstzones' in params:
                        members = ''
                        for member in params['dstzones']:
                            members += '<member>{}</member>'.format(member)
                        # url='/api/?type=config&action=delete&xpath={}/&element=<entry name=\'{}\'><to>{}</to></entry>'.format(object_base, params['policyname'], members)
                        # url='/api/?type=config&action=edit&xpath={}/entry[@name=\'{}\']<to>{}</to></entry>'.format(object_base, params['policyname'], members)
                        url = '/api/?type=config&action=edit&xpath={}/entry[@name=\'{}\']/to&element=<to>{}</to>'.format(
                            object_base, params['policyname'], members)
                    if 'srczones' in params:
                        members = ''
                        for member in params['srczones']:
                            members += '<member>{}</member>'.format(member)
                        # url='/api/?type=config&action=delete&xpath={}/&element=<entry name=\'{}\'><from>{}</from></entry>'.format(object_base, params['policyname'], members)
                        # url='/api/?type=config&action=edit&xpath={}/entry[@name=\'{}\']<to>{}</to></entry>'.format(object_base, params['policyname'], members)
                        url = '/api/?type=config&action=edit&xpath={}/entry[@name=\'{}\']/from&element=<from>{}</from>'.format(
                            object_base, params['policyname'], members)
                        #

                elif params['action'].lower() == 'delmembers':
                    if 'sources' in params:
                        for member in params['sources']:
                            url = '/api/?type=config&action=delete&xpath={}/entry[@name=\'{}\']/source/member[text()="{}"]'.format(
                                object_base, params['policyname'], member)
                            result = self.getPaloService.send_palo_apicmd(session, target, url, apikey)
                        # members=' '
                        # for member in params['sources']:
                        #    members+=member+'<member>{}</member>'.format(member)
                        # url='/api/?type=config&action=delete&xpath={}&key={}&element=<entry name=\'{}\'><source>{}</source></entry>'.format(object_base, apikey, params['policyname'], members)
                    if 'dests' in params:
                        for member in params['dests']:
                            url = '/api/?type=config&action=delete&xpath={}/entry[@name=\'{}\']/destination/member[text()="{}"]'.format(
                                object_base, params['policyname'], member)
                            result = self.getPaloService.send_palo_apicmd(session, target, url, apikey)
                        # members=' '
                        # for member in params['dests']:
                        #    members+=member+'<member>{}</member>'.format(member)
                        # url='/api/?type=config&action=delete&xpath={}&key={}&element=<entry name=\'{}\'><destination>{}</destination></entry>'.format(object_base, apikey, params['policyname'], members)
                    if 'services' in params:
                        for member in params['services']:
                            url = '/api/?type=config&action=delete&xpath={}/entry[@name=\'{}\']/service/member[text()="{}"]'.format(
                                object_base, params['policyname'], member)
                            result = self.getPaloService.send_palo_apicmd(session, target, url, apikey)
                        # members=''
                        # for member in params['services']:
                        #    members+=member+'<member>{}</member>'.format(member)
                        # url='/api/?type=config&action=delete&xpath={}&key={}&element=<entry name=\'{}\'><service>{}</service></entry>'.format(object_base, apikey, params['policyname'], members)
                    if 'tags' in params:
                        for member in params['tags']:
                            url = '/api/?type=config&action=delete&xpath={}/entry[@name=\'{}\']/tag/member[text()="{}"]'.format(
                                object_base, params['policyname'], member)
                            result = self.getPaloService.send_palo_apicmd(session, target, url, apikey)
                        # members=''
                        # for member in params['tags']:
                        #    members+='<member>{}</member>'.format(member)
                        # url='/api/?type=config&action=delete&xpath={}&key={}&element=<entry name=\'{}\'><tag>{}</tag></entry>'.format(object_base, apikey, params['policyname'], members)
                    if 'dstzones' in params:
                        members = ''
                        for member in params['dstzones']:
                            members += '<member>{}</member>'.format(member)
                        # url='/api/?type=config&action=delete&xpath={}&element=<entry name=\'{}\'><to>{}</to></entry>'.format(object_base, params['policyname'], members)
                        url = '/api/?type=config&action=delete&xpath={}/entry[@name=\'{}\'><to>{}</to></entry>'.format(
                            object_base, params['policyname'], members)
                    if 'srczones' in params:
                        members = ''
                        for member in params['srczones']:
                            members += '<member>{}</member>'.format(member)
                        # url='/api/?type=config&action=delete&xpath={}&element=<entry name=\'{}\'><from>{}</from></entry>'.format(object_base, params['policyname'], members)
                        url = '/api/?type=config&action=delete&xpath={}/entry[@name=\'{}\'><to>{}</to></entry>'.format(
                            object_base, params['policyname'], members)

                        # url=None
                elif params['action'].lower() == 'addmembers':
                    if 'sources' in params:
                        members = ''
                        for member in params['sources']:
                            members += '<member>{}</member>'.format(member)
                        url = '/api/?type=config&action=set&xpath={}/entry[@name=\'{}\']/source&element={}'.format(
                            object_base, params['policyname'], members)
                        url = '/api/?type=config&action=set&xpath={}&element=<entry name=\'{}\'><source>{}</source></entry>'.format(
                            object_base, params['policyname'], members)
                    if 'dests' in params:
                        members = ''
                        for member in params['dests']:
                            members += '<member>{}</member>'.format(member)
                        url = '/api/?type=config&action=set&xpath={}&element=<entry name=\'{}\'><destination>{}</destination></entry>'.format(
                            object_base, params['policyname'], members)
                    if 'services' in params:
                        members = ''
                        for member in params['services']:
                            members += '<member>{}</member>'.format(member)
                        url = '/api/?type=config&action=set&xpath={}&element=<entry name=\'{}\'><service>{}</service></entry>'.format(
                            object_base, params['policyname'], members)
                    if 'tags' in params:
                        members = ''
                        for member in params['tags']:
                            members += '<member>{}</member>'.format(member)
                        url = '/api/?type=config&action=set&xpath={}&element=<entry name=\'{}\'><tag>{}</tag></entry>'.format(
                            object_base, params['policyname'], members)
                    if 'dstzones' in params:
                        members = ''
                        for member in params['dstzones']:
                            members += '<member>{}</member>'.format(member)
                        url = '/api/?type=config&action=set&xpath={}&element=<entry name=\'{}\'><to>{}</to></entry>'.format(
                            object_base, params['policyname'], members)
                    if 'srczones' in params:
                        members = ''
                        for member in params['srczones']:
                            members += '<member>{}</member>'.format(member)
                        url = '/api/?type=config&action=set&xpath={}&element=<entry name=\'{}\'><from>{}</from></entry>'.format(
                            object_base, params['policyname'], members)
                elif params['action'].lower() == 'comment':
                    url = '/api/?type=config&action=set&xpath={}&element=<entry name=\'{}\'><description>{}</description></entry>'.format(
                        object_base, params['policyname'], quote(params['comment'], safe=''))
                    # url='/api/?type=config&action=set&xpath={}/service-group/entry[@name=\'{}\']&element=<description>{}</description>&key={}'.format(target, object_base, params['servicename'], params['comment'], apikey)
                elif params['action'].lower() == 'log-setting':
                    self.log(params)
                    url = '/api/?type=config&action=set&xpath={}&element=<entry name=\'{}\'><log-setting>{}</log-setting></entry>'.format(
                        object_base, params['policyname'], params['log-setting'])
                elif params['action'].lower() == 'log-start':
                    url = '/api/?type=config&action=set&xpath={}&element=<entry name=\'{}\'><log-start>{}</log-start></entry>'.format(
                        object_base, params['policyname'], params['log-start'])
                elif params['action'].lower() == 'log-end':
                    url = '/api/?type=config&action=set&xpath={}&element=<entry name=\'{}\'><log-end>{}</log-end></entry>'.format(
                        object_base, params['policyname'], params['log-end'])

                elif params['action'].lower() == 'enable':
                    url = '/api/?type=config&action=set&xpath={}&element=<entry name=\'{}\'><disabled>no</disabled></entry>'.format(
                        object_base, params['policyname'])
                elif params['action'].lower() == 'disable':
                    url = '/api/?type=config&action=set&xpath={}&element=<entry name=\'{}\'><disabled>yes</disabled></entry>'.format(
                        object_base, params['policyname'])
                elif params['action'].lower() == 'delete':
                    url = '/api/?type=config&action=delete&xpath={}&element=<entry name=\'{}\'>'.format(object_base,
                                                                                                        params[
                                                                                                            'policyname'])
                else:
                    return 'Unknown Action'
                if url:
                    # print(url)
                    result = self.getPaloService.send_palo_apicmd(session, target, url, apikey)
                    self.debug('SEND_CMD_RESULT', result)
                # url='/api/?type=config&action=set&xpath={}&key={}&element=<entry name=\'{}\'><source>{}</source><destination>{}</destination><service>{}</service><application>{}</application><action>{}</action><log-end>{}</log-end><log-start>{}</log-start><from>{}</from><to>{}</to></entry>'.format(object_base, apikey, params['rulename'], srcaddr, dstaddr, services, applications, action, log_end, log_start, srczones, dstzones)

        else:
            pass
            # return unknown firewall type
        return result
