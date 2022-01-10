import argparse
import cgi
import urllib3
import sys
import time
import pickle
import cgitb
import xlsxwriter  # needed to be installed

import NetworkLogs
import Logging
from network import Service
from collections import defaultdict, OrderedDict

class DellAuto:

    def _init_(self):
        self.log = NetworkLogs().log
        self.sc = NetworkLogs().sc
        self.ss = NetworkLogs().ss
        self.debug = NetworkLogs().debug
        self.service = Service()

    timestamp = int(time.time())
    timestr = str(timestamp)

    form = cgi.FieldStorage()
    config = defaultdict(dict)

    cmdarg = []


    def process_cmd_args(self):
        def file_list(listtype='text'):
            class customAction(argparse.Action):
                def __call__(self, parser, args, values, option_string=None):
                    import os
                    from netaddr import IPSet
                    if listtype == 'ipset':
                        returnlist = IPSet([])
                    else:
                        returnlist = []
                    for value in values:
                        try:
                            if os.path.basename(value[0]) == '@':
                                for i in file_to_list(value[1:]):
                                    if listtype.lower() == 'ipset':
                                        returnlist.add(i.rstrip())
                                    else:
                                        returnlist.append(i.rstrip())

                            else:
                                if listtype.lower() == 'ipset':
                                    returnlist.add(value.rstrip())
                                else:
                                    returnlist.append(value)
                        except:
                            ## something went wrong
                            pass

                    setattr(args, self.dest, returnlist)

            # print(customAction)
            return customAction

        options = argparse.ArgumentParser(description=' Description', epilog='Epilog')
        options.add_argument('-i', '--i', help='input SonicWall configuration filename', type=str, metavar='filename',
                             dest='sonicwall')
        options.add_argument('-p', '--p', '--sonicwallip', '--ipaddr',
                             help='import config from the IP address of SonicWall device', type=str, metavar='IP Address',
                             dest='sonicwallip')
        options.add_argument('-pp', '--pp', '--sonicwall_api_ip', '--swapi',
                             help='import config via API from the IP address of SonicWall device', type=str,
                             metavar='IP Address', dest='sonicwall_api_ip')
        options.add_argument('--gms', help='import config from the IP address of SonicWall device', type=str,
                             metavar='IP Address', dest='gms')
        options.add_argument('-P', '--P', '--panoramaip', help='import config from the IP address of Panorama server', type=str,
                             metavar='IP Address', dest='panoramaip')
        options.add_argument('-I', help='input Panorama configuration filename', type=str, metavar='filename', dest='panorama')
        options.add_argument('-o', '--outfile', help='output configuration filename', type=str, metavar='filename',
                             dest='outfile')
        options.add_argument('-c', '--devicegroup', nargs='+',
                             help='device-group for search operations (use "any" to search all)',
                             metavar='device-group name(s)', default='', action=file_list(), type=str, dest='context')
        options.add_argument('--policynames', nargs='+',
                             help='policyname for search (--rulematch) operations and tuples (--tuples) generation ',
                             metavar='device-group name(s)', default=[''], action=file_list(), type=str, dest='policynames')
        options.add_argument('-a', nargs='+', help='(Overlapping) address object search (specify IP Address)', type=str,
                             metavar='IPAddr', dest='ipaddr')
        options.add_argument('-A', nargs='+', help='(Exact) address object search (specify IP Address)', type=str,
                             metavar='IPAddr', dest='exactipaddr')
        options.add_argument('-s', nargs='+', help='service object search (specify service protocol and port ie: tcp/23',
                             type=str, metavar='Protocol/Port', dest='service')
        options.add_argument('-S', nargs='+',
                             help='(Exact) service object search (specify service protocol and port ie: tcp/23', type=str,
                             metavar='Protocol/Port', dest='exactservice')
        options.add_argument('-e', nargs='+', help='expand an address object', type=str, metavar='object name', dest='address')
        options.add_argument('-E', nargs='+', help='expand an address object (Verbose)', type=str, metavar='object name',
                             dest='address_verbose')
        options.add_argument('-x', nargs='+', help='expand a service object', type=str, metavar='object name',
                             dest='exp_service')
        options.add_argument('-X', nargs='+', help='expand a service object (Verbose)', type=str, metavar='object name',
                             dest='service_verbose')
        options.add_argument('-z', '--z', action='store_false', default=True, help='do not match 0.0.0.0/0 network on IP searches',
                             dest='zero_network')
        options.add_argument('-Z', '--Z', action='store_false', default=True, help='do not match "any" service on rulematch',
                             dest='zero_service')
        options.add_argument('-N', action='store_true', default=False, help='interactive mode (NOT IMPLEMENTED)',
                             dest='interactive')
        options.add_argument('--cp', action='store_true', default=False, help='load checkpoint config', dest='checkpoint')
        options.add_argument('--cpapi', type=str, help='load checkpoint config via API', dest='checkpoint_api')
        options.add_argument('--checkpointpol', '--cppol', nargs='?', help='specify filename for Checkpoint Security Policies',
                             default='Security_Policy.xml', type=str, metavar='filename', dest='checkpointpol')
        options.add_argument('--checkpointobj', '--cpobj', nargs='?', help='specify filename for Checkpoint Network Objects',
                             default='network_objects.xml', type=str, metavar='filename', dest='checkpointobj')
        options.add_argument('--checkpointsvc', '--cpsvc', nargs='?', help='specify filename for Checkpoint Service Objects',
                             default='services.xml', type=str, metavar='filename', dest='checkpointsvc')
        options.add_argument('--checkpointnat', '--cpnat', nargs='?', help='specify filename for Checkpoint NAT Policy Objects',
                             default='NAT_Policy.xml', type=str, metavar='filename', dest='checkpointnat')
        options.add_argument('--checkpointroute', '--cproute', nargs='?', help='specify filename for Checkpoint Routing',
                             default=None, type=str, metavar='filename', dest='checkpointroute')
        options.add_argument('--routesearch', nargs='+', help='search firewall routing tables for host/network', default=None, type=str, metavar='filename', dest='routesearch')
        options.add_argument('--fixzones', nargs='?', help='fix zones for rules for specified device-group', default=None,
                             type=str, metavar='device-group', dest='fixzones')
        options.add_argument('--fixzones2', nargs='?', help='fix zones for rules for specified device-group', default=None,
                             type=str, metavar='device-group', dest='fixzones2')
        options.add_argument('--fixzones3', nargs='?', help='fix zones for rules for specified device-group', default=None,
                             type=str, metavar='device-group', dest='fixzones3')
        options.add_argument('--fwtype', nargs='?',
                             help='Firewall type for some options.grouptarget routines ("sonicwall", "palo", "pano", "checkpoint"',
                             default=None, type=str, metavar='firewall-type', dest='fwtype')
        options.add_argument('--checkpointcontext', nargs='?', help='specify context name for Checkpoint config',
                             default='checkpoint', type=str, metavar='string', dest='checkpointcontext')
        options.add_argument('--renamecontext', nargs='?', help='specify context name for Checkpoint config', default=None,
                             type=str, metavar='string', dest='renamecontext')
        options.add_argument('--includepolicies', nargs='+',
                             help='whitelist of checkpoint policies to include when loading .xml config', default=['all'],
                             metavar='list of string', dest='includepolicies')
        options.add_argument('-t', '--tuples', type=str, metavar='filename', help='generate tuples file', dest='tuplefile')
        options.add_argument('--load', nargs='+', type=str, metavar='filename', help='load config from disk', dest='loadconfig')
        options.add_argument('--save', type=str, metavar='filename', help='save config to disk', dest='saveconfig')
        options.add_argument('--saveexp', action='store_true', default=False, help='save exported config file to disk',
                             dest='saveexp')
        options.add_argument('--cipmatch', nargs='+', help='perform matching of individual source networks for IP Schema',
                             metavar='list of IP networks/hosts', type=str, dest='cipmatch')
        options.add_argument('--cipaudit', nargs='+', help='perform matching of individual source networks for IP Schema',
                             metavar='list of IP networks/hosts', type=str, dest='cipaudit')
        options.add_argument('--cipload', type=str, metavar='filename', help='load change matches from disk', dest='cipload')
        options.add_argument('--cipsave', type=str, metavar='filename', help='save change matches to disk', dest='cipsave')
        options.add_argument('--cipreviewin', nargs='?', default='', type=str, metavar='filename',
                             help='csv/tab file with ChangeIP changes', dest='cipreviewin')
        options.add_argument('--cipsubmit', nargs='?', default='', type=str, metavar='filename',
                             help='show page for ChangeIP Submit', dest='cipsubmit')
        options.add_argument('--cipdbedit', action='store_true', default=False,
                             help='generate dbedit commands from ChangeIP matching', dest='cipdbedit')
        options.add_argument('--cipswedit', action='store_true', default=False,
                             help='push cipmatch changes directly to sonicwall', dest='cipswedit')
        options.add_argument('--rename', action='store_true', default=False, help='rename an address-group object',
                             dest='rename')
        options.add_argument('--cipblacklist', nargs='+', help='list of blacklisted policies (do not check)',
                             metavar='Policy Names', default=[], type=str, dest='cipblacklist')
        options.add_argument('--cipshowskipped', action='store_true', default=False, help='include skipped matches in results',
                             dest='cipshowskipped')
        options.add_argument('--cipskippartial', action='store_true', default=False,
                             help='exclude processing partial matches (added for speed due to st pete change for 152.16.136.0/24 network)',
                             dest='cipskippartial')
        options.add_argument('--inverseload', type=str, metavar='filename', help='load inverse matches from disk',
                             dest='inverseload')
        options.add_argument('--inversesave', type=str, metavar='filename', help='save inverse matches to disk',
                             dest='inversesave')
        options.add_argument('--inversecomment', type=str, metavar='filename', default='',
                             help='add comment to inverse match disabled rules', dest='inversecomment')
        options.add_argument('--inverseallrules', action='store_true', default=False,
                             help='perform inverse disable/delete for all rules, not just allow rules', dest='inverseallrules')
        options.add_argument('--policysearch', nargs='+', help='search policies for IP address', metavar='IP Address', type=str,
                             dest='policysearch')
        options.add_argument('--rulematch', nargs='+', help='given source,dest,service find matching rules',
                             metavar='source,dest,prot/port', action=file_list(), type=str, dest='rulematch')
        options.add_argument('--rulemodify', nargs='?', help='given source,dest,service find matching rules',
                             metavar='source,dest,prot/port', type=str, dest='rulemodify')
        options.add_argument('--excludeaddresses', nargs='+',
                             help='exclude these address objects from rulematch search (case sensitive)',
                             metavar='address name', action=file_list(), default=[], type=str, dest='excludeaddress')
        options.add_argument('--excludesrcnetworks', nargs='+', help='exclude these source networks from rulematch search',
                             metavar='network name', action=file_list(), default=[], type=str, dest='excludesrcnetwork')
        options.add_argument('--excludedstnetworks', nargs='+', help='exclude these destination networks from rulematch search',
                             metavar='network name', action=file_list(), default=[], type=str, dest='excludedstnetwork')
        options.add_argument('--batch', nargs='+', help='batch processing of commands', metavar='list of commands or @filename',
                             type=str, dest='batch')  # not yet implemented
        options.add_argument('--inversematch', nargs='+', help='perform "inverse" rule matching',
                             metavar='list of IP networks/hosts', type=str, action=file_list(), dest='inversematch')
        options.add_argument('--inversesingle', action='store_true', default=False,
                             help='for inverse matching, perform matching on one network at a time rather than as a group',
                             dest='inversesingle')
        options.add_argument('--vrouter', help='Virtual Router Name (used in .xml output config', type=str, metavar='string',
                             dest='vrouter', default='VRouter')
        options.add_argument('--logprofile', help='Logprofile name to use for readxlsmigrations and readxls', type=str,
                             metavar='string', dest='logprofile')
        options.add_argument('--securityprofile', help='Security profile name to use for migrations', type=str,
                             metavar='string', dest='securityprofile')
        options.add_argument('--ruletag', help='Tag to add to created rules', type=str, metavar='string', dest='ruletag')
        options.add_argument('--tuplezone', '-tz',
                             help='limit tuple creation to specified source,destination zones (default is All,All)', type=str,
                             metavar='string', dest='tuplezone', default='all,all')
        options.add_argument('--device-group', help='Device Group/Template Name (used in .xml output config', type=str,
                             metavar='string', dest='devicegroup_name', default='Default Device Group')
        options.add_argument('--mappings', nargs='+', help='interface mappings', type=str, metavar='filename',
                             default=['@./interfaces.map'], dest='mappings')
        options.add_argument('--unused', action='store_true', default=False, help='find unused objects', dest='find_unused')
        options.add_argument('--show-unused', action='store_true', default=False,
                             help='show unused objects (will set find used to true)', dest='show_unused')
        ## consider changing default, and then rename this to keep-unused
        options.add_argument('--remove-unused', action='store_true', default=False,
                             help='remove unused objects (will set find used to true)', dest='remove_unused')
        options.add_argument('--show-dupes', action='store_true', default=False, help='show duplicate objects',
                             dest='show_dupes')
        ## consider changing default, and then rename this to keep-dupes
        options.add_argument('--remove-dupes', action='store_true', default=False, help='remove duplicate objects',
                             dest='remove_dupes')
        options.add_argument('--show-devicegroups', action='store_true', default=False,
                             help='show device groups from Panorama configuration', dest='show_devicegroups')
        options.add_argument('--show-templates', action='store_true', default=False,
                             help='show templates from Panorama configuration', dest='show_templates')
        options.add_argument('--skip-disabled', action='store_true', default=False, help='do not load disabled rules',
                             dest='skip_disabled')
        options.add_argument('--exclude-partial', action='store_true', default=False,
                             help='exclude partial matches from matches (currently implemented in CIP match only)',
                             dest='exclude_partial')
        options.add_argument('--show-mismatched', action='store_true', default=False, help='show service mismatches',
                             dest='show_mismatch')
        options.add_argument('--skip-userid', action='store_false', default=True,
                             help='do not include user_id config in output', dest='userid')
        options.add_argument('--dump-config', action='store_true', default=False,
                             help='dump config into an Excel (.xlsx) spreadsheet', dest='dump_config')
        options.add_argument('--show-logprofiles', action='store_true', default=False,
                             help='show log profiles for each device-group', dest='show_logprofiles')
        options.add_argument('--web', '--Submit', action='store_true', default=False, help='enable "web" mode', dest='web')
        options.add_argument('--sccm', action='store_true', default=False,
                             help='Compare "SCCM Servers object in Device group to shared', dest='sccm')
        options.add_argument('--setlogprofile', type=str, help='change log profile setting', dest='setlogprofile')
        options.add_argument('--csv', type=str, help='enable "csv" mode (only used for rulematch currently)', dest='csv')
        options.add_argument('--html', action='store_true', default=False,
                             help='enable "html" mode (only used for rulematch currently)', dest='html')
        options.add_argument('--push', action='store_true', default=False, help='push configuration to panorama', dest='push')
        options.add_argument('--inversedisable', action='store_true', default=False,
                             help='enable "generate report to disable rules from inverse match results', dest='inversedisable')
        options.add_argument('--inversedelete', action='store_true', default=False,
                             help='enable "generate report to delete rules from inverse match results', dest='inversedelete')
        options.add_argument('--inversestats', action='store_true', default=False,
                             help='show report output only, do not execute commands for inverse matching', dest='inversestats')
        options.add_argument('--inverseexecute', nargs='?', const='', type=str, help='execute commands for inverse matching',
                             dest='inverseexecute')
        options.add_argument('--inversepartial', action='store_true', default=False,
                             help='include partial matches in command generation', dest='inversepartial')
        options.add_argument('--inverseaddressdelete', action='store_true', default=False,
                             help='remove address matches from inverse results', dest='inverseaddressdelete')
        options.add_argument('--dbedit', nargs='+', type=str, metavar='context',
                             help='create dbedit objects from a particular config', dest='dbedit')
        options.add_argument('--pan8', action='store_true', default=False, help='target device for config push is pan8',
                             dest='pan8')
        options.add_argument('--username', type=str, help=argparse.SUPPRESS, dest='username')
        options.add_argument('--password', type=str, help=argparse.SUPPRESS, dest='password')
        options.add_argument('--pushusername', type=str, help=argparse.SUPPRESS, dest='pushusername')
        options.add_argument('--pushpassword', type=str, help=argparse.SUPPRESS, dest='pushpassword')
        options.add_argument('--pushnotemplate', action='store_true', default=False,
                             help='do not create or push template/template stack', dest='pushnotemplate')
        options.add_argument('--getconfigs', nargs='+', type=str, help='run Nexpose routines', action=file_list(),
                             dest='getconfigs')
        options.add_argument('--nexpose', '--bulkaddresses', type=str, help='run Nexpose routines', dest='nexpose')
        options.add_argument('--nexposesvc', '--bulkservices', type=str, help='run Nexpose routines', dest='nexposesvc')
        options.add_argument('--nexposerule', '--bulkrules', type=str, nargs='+', help='run Nexpose routines',
                             action=file_list(), dest='nexposerule')
        options.add_argument('--skipzone', action='store_true', default=False,
                             help='do not compute zone for bulk address object creation (for adding objects to group)',
                             dest='skipzone')
        options.add_argument('--addgroupmember', type=str, nargs='+', help='add address object to group', dest='addgroupmember')
        options.add_argument('--matchtypes', type=str, nargs='+', default=['all'],
                             help='what match types to include in rulematch results', dest='matchtypes')
        options.add_argument('--devicestoadd', type=str, metavar='device list',
                             help='list of device serial numbers to add to devgroup/template for panorama push',
                             dest='devicetoadd')
        options.add_argument('--pushfile', type=str, metavar='filename', help='filename to push to panorama', dest='pushfile')
        options.add_argument('--puship', type=str, metavar='IP Address', help='IP address of Panorama server for comamnd push',
                             dest='puship')
        options.add_argument('--firewall', type=str, metavar='String', help='Firewall type (used for HTML forms)',
                             dest='firewall')
        options.add_argument('--expandcheckpoint', action='store_true', default=False,
                             help='When reading Sonicwall configuration, expand "ImportChkpt" group objects into members',
                             dest='expandcheckpoint')
        options.add_argument('--logging', type=int, default=Logging.NOTICE, dest='logging')
        options.add_argument('--timeout_sw_webui', type=int, default=30, dest='timeout_sw_webui')
        options.add_argument('--timeout_sw_api', type=int, default=30, dest='timeout_sw_api')
        options.add_argument('--timeout_sw_webui_post', type=int, default=120, dest='timeout_sw_webui_post')
        options.add_argument('--timeout_sw_webui_login', type=int, default=30, dest='timeout_sw_webui_login')
        options.add_argument('--timeout_palo_api', type=int, default=60, dest='timeout_palo_api')
        options.add_argument('-q', '--quiet', action='store_const', const=Logging.NONE, dest='logging')
        options.add_argument('-v', help='Verbose (Informational) logging level', action='store_const', const=Logging.INFO,
                             dest='logging')
        options.add_argument('--debug', help='Debug level logging', action='store_const', const=Logging.DEBUG, dest='logging')
        options.add_argument('--file', nargs='+', help='test for custom action for filespec', metavar='filename meta',
                             default='', action=file_list(), type=str, dest='filename')
        options.add_argument('--ipset', nargs='+', help='test for custom action for filespec', metavar='filename meta',
                             action=file_list('ipset'), type=str, dest='iplist')
        options.add_argument('--readxls', help='preliminary work for converting xls to ruleset', metavar='filename meta',
                             type=str, dest='readxls')
        options.add_argument('--readxls_notshared',
                             help='preliminary work for converting xls to ruleset - putting objects into shared',
                             action='store_false', default=True, dest='readxls_shared')
        options.add_argument('--pushobjects', action='store_true', default=False, help='push address and service objects',
                             dest='pushobjects')
        options.add_argument('--pushrules', action='store_true', default=False, help='push rules', dest='pushrules')
        options.add_argument('--getidp', action='store_true', default=False, help='Get Sonicwall IDP page details',
                             dest='getidp')
        options.add_argument('--zonemaps', nargs='+', help='Zone mapping details when reading XML file',
                             metavar='xlszone,fwzone,policynametext', type=str, dest='zonemaps')
        options.add_argument('--fixzonemaps', nargs='+', help='Zone mapping details when fixing converted Expedition zones',
                             metavar='interface,oldzone,newzone', type=str, action=file_list(), dest='fixzonemaps')
        options.add_argument('--rulelist', nargs='+', help='', metavar='', type=str, action=file_list(), dest='rulelist')
        options.add_argument('--migratezones', nargs='+', help='Zone mapping details when migrating SW to Palo',
                             metavar='sw_zone,palo_zone', type=str, action=file_list(), dest='migratezones')
        options.add_argument('--nick', type=str, help='update logprofiles', dest='nick')
        options.add_argument('--readonly', help='enable readonly for Nexpose address routines', action='store_true',
                             default=False, dest='readonly')
        options.add_argument('--testing', help='enable block of code for Testing new routines', action='store_true',
                             default=False, dest='testing')
        options.add_argument('--gordon', action='store_true', default=False, help='get list of users', dest='gordon')
        options.add_argument('--management', action='store_true', default=False, help='get interface management properties',
                             dest='management')
        options.add_argument('--secureid', action='store_true', default=False,
                             help='update all rules with RSA secureid details', dest='secureid')
        options.add_argument('--movecheckpoint', action='store_true', default=False,
                             help='Generate dbedit commands to move Checkpoint policy to a new CMA', dest='movecheckpoint')
        options.add_argument('--emcroute', nargs='+', type=str, help='Update EMC public network routes internally',
                             dest='emcroute')
        options.add_argument('--comment', type=str, default=argparse.SUPPRESS,
                             help='Comment for bulk object/rule creation (when supported by target)', dest='comment')
        options.add_argument('--sw_upload_fw', help='upload SonicWall firmware file', action='store_true', default=False,
                             dest='sw_upload_fw')
        options.add_argument('--sw_backup', help='perform "Create Backup" on  SonicWall', action='store_true', default=False,
                             dest='sw_backup')
        options.add_argument('--sw_audit', help='audit SonicWall configuration', action='store_true', default=False,
                             dest='sw_audit')
        options.add_argument('--sw_reboot', help='reboot SonicWall using uploaded firmware', action='store_true', default=False,
                             dest='sw_reboot')
        options.add_argument('--sw_failover', help='Force failover on Sonicwall', action='store_true', default=False,
                             dest='sw_failover')
        options.add_argument('--sw_get_tsr', help='upload SonicWall firmware file', action='store_true', default=False,
                             dest='sw_get_tsr')
        options.add_argument('--sw_enable_api', help='', action='store_true', default=False, dest='sw_enable_api')
        options.add_argument('--sw_revert_api', help='', action='store_true', default=False, dest='sw_revert_api')
        options.add_argument('--fixcomments', nargs='+', help='list of address objects that need comment updated',
                             metavar='IP Address', action=file_list(), type=str, dest='fixcomments')
        options.add_argument('--grouptargets', '--targets', nargs='+',
                             help='list of Sonicwall IP addresses to make group changes to', metavar='IP Address',
                             action=file_list(), type=str, dest='grouptargets')
        options.add_argument('--groupaddresses', nargs='+', help='list of IP addresses to add to group', metavar='IP address',
                             action=file_list(), type=str, dest='groupaddresses')
        options.add_argument('--groupmaster', nargs='+', help='list of master group candidate names -- uses first name only',
                             metavar='group names', action=file_list(), type=str, dest='groupmaster')
        options.add_argument('--groupusemaster', action='store_true', default=False,
                             help='place addresses directly into master group rather than subgroups', dest='groupusemaster')
        options.add_argument('--groupservices', nargs='+', help='list of services to add to group', metavar='IP address',
                             action=file_list(), type=str, dest='groupservices')
        options.add_argument('--testcreate', action='store_true', default=False, help='testing', dest='testcreate')
        options.add_argument('--testdelete', action='store_true', default=False, help='testing', dest='testdelete')
        options.add_argument('--testmodify', action='store_true', default=False, help='testing', dest='testmodify')
        options.add_argument('--dmz', action='store_true', default=False, help='testing', dest='dmz')
        options.add_argument('--uuid', type=str, nargs="*", default=None, help='testing', action=file_list(), dest='uuid')
        options.add_argument('--ldap', nargs='+', help='testing', dest='ldap')
        options.add_argument('--recheck', nargs='+', help='list of IP addresses to log into', metavar='IP Address',
                             action=file_list(), type=str, dest='recheck')
        return options

    timestamp = int(time.time())
    timestr = str(timestamp)

    form = cgi.FieldStorage()
    config = defaultdict(dict)
    parser = process_cmd_args()

    cmdarg = []

    for el in form:
        if form.getlist(el) != ['false'] and not form[el].filename:  # do not add parameter if it has a filename value
            cmdarg.extend([str('--' + str(el))])
        for values in form.getlist(el):
            if isinstance(values, str):
                for value in str(values).split('\r\n'):
                    if str(value) != 'true' and str(value) != 'false' and str(
                            value).lower() != 'submit':  # do not append values for boolean options
                        cmdarg.extend([str(value)])

    if 'Submit' in form:
        options = parser.parse_args(cmdarg)
    else:
        options = parser.parse_args()

    if options.web:
        tabs2 = OrderedDict()
        prevtab = None
        if options.web != None:
            tabs2.update({'console': {'description': 'Console', 'download': True, 'textarea': 'readonly',
                                      'tabtype': 'textarea', 'prevtab': None}})
        if options.rulematch:
            tabs2.update({'rulematch': {'description': 'Matching Rules', 'download': True, 'textarea': 'readonly',
                                        'tabtype': 'table', 'prevtab': list(tabs2)[-1]}})
        if options.outfile != None:
            tabs2.update({'outfile': {'description': 'Configuration Push', 'download': True, 'textarea': 'readonly',
                                      'tabtype': 'textarea', 'prevtab': list(tabs2)[-1]}})
        if options.puship != None:
            tabs2.update({'push': {'description': 'Push Results', 'download': True, 'textarea': 'readonly',
                                   'tabtype': 'textarea', 'prevtab': list(tabs2)[-1]}})
        if options.inversedisable:
            tabs2.update({'disable': {'description': 'Disable Report', 'download': True, 'textarea': 'readonly',
                                      'tabtype': 'textarea', 'prevtab': list(tabs2)[-1]}})
        if options.inversedelete:
            tabs2.update({'delete': {'description': 'Delete Report', 'download': True, 'textarea': 'readonly',
                                     'tabtype': 'textarea', 'prevtab': list(tabs2)[-1]}})
        if options.inverseaddressdelete:
            tabs2.update({'address': {'description': 'Address Cleanup Report', 'download': True, 'textarea': 'readonly',
                                      'tabtype': 'textarea', 'prevtab': list(tabs2)[-1]}})
        if options.inversedisable or options.inversedelete or options.inverseaddressdelete:
            tabs2.update({'command': {'description': 'Commands', 'download': True, 'textarea': 'readonly',
                                      'tabtype': 'textarea', 'prevtab': list(tabs2)[-1]}})
        if options.inverseexecute != None or options.pushrules or options.pushobjects:
            tabs2.update({'exec': {'description': 'Command Execution', 'download': True, 'textarea': 'readonly',
                                   'tabtype': 'textarea', 'prevtab': list(tabs2)[-1]}})
        if options.inversestats:
            tabs2.update({'stats': {'description': 'Stats', 'download': True, 'textarea': 'readonly',
                                    'tabtype': 'textarea', 'prevtab': list(tabs2)[-1]}})
        if options.cipmatch:
            tabs2.update({'report': {'description': 'Report', 'download': True, 'textarea': 'readonly',
                                     'tabtype': 'textarea', 'prevtab': list(tabs2)[-1]}})
            tabs2.update({'reviewout': {'description': 'Review Out', 'download': True, 'textarea': '',
                                        'tabtype': 'textarea', 'prevtab': list(tabs2)[-1]}})
        if options.cipsubmit:
            tabs2.update({'submitchanges': {'description': 'Submit', 'download': False, 'textarea': 'readonly',
                                            'tabtype': 'textarea', 'prevtab': list(tabs2)[-1]}})
        if options.cipdbedit:
            tabs2.update({'reviewin': {'description': 'Review In', 'download': True, 'textarea': 'readonly',
                                       'tabtype': 'textarea', 'prevtab': list(tabs2)[-1]}})
            tabs2.update({'report': {'description': 'Report', 'download': True, 'textarea': 'readonly',
                                     'tabtype': 'textarea', 'prevtab': list(tabs2)[-1]}})
            tabs2.update({'commands': {'description': 'Commands', 'download': True, 'textarea': 'readonly',
                                       'tabtype': 'textarea', 'prevtab': list(tabs2)[-1]}})
        if options.dump_config:
            tabs2.update({'Download': {'description': 'Download', 'download': False, 'textarea': 'readonly',
                                       'tabtype': 'table', 'prevtab': list(tabs2)[-1]}})
        if options.readxls:
            tabs2.update({'ReadXLS': {'description': 'XLS Conversion', 'download': True, 'textarea': 'readonly',
                                      'tabtype': 'textarea', 'prevtab': list(tabs2)[-1]}})
        if options.nexpose:
            tabs2.update({'Validation': { 'description': 'Bulk Address Validation', 'download': False, 'textarea': 'readonly', 'tabtype': 'textarea',   'prevtab': list(tabs2)[-1]}})
            tabs2.update({'BulkAddress': { 'description': 'Bulk Address Creation', 'download': False, 'textarea': 'readonly', 'tabtype': 'textarea',   'prevtab': list(tabs2)[-1]}})
        if options.routesearch!=None:
            for network in list(set(options.routesearch)):
                try:
                    network_to_search=IPNetwork(network)
                    tabs2.update({network.replace('.','_'): { 'description': network, 'download': False, 'textarea': 'readonly', 'tabtype': 'table', 'prevtab': list(tabs2)[-1]}})
                except:
                    # Don't create tabs for invalid IPs
                    pass

    contexts = []

    customops = parser.parse_args()

    customops.firewall_name = 'CHANGEME'
    customops.rule_profile_setting = 'Svc_Segmentation'  # Dell_Corp_Profile_Group

    customops.log_forward_profile_name = 'AMER-Dell-Standard-Logging'

    customops.snmp_traps = 'AMER-Dell-Standard-SMNP_Traps'
    customops.logging = 'AMER-Dell-Standard-Logging'  ## ??
    customops.base_rule_name = 'SonicWallImportRule'
    customops.devicegroup_name = 'Services Segmentation External'  ## Austin_PC1_Corp_Internal
    customops.devicegroup_name = 'Bangalore'
    customops.int_mgmt_profile = 'Dell'  ##  ??
    customops.logsettings = OrderedDict([('AMER-Dell-Standard-Logging', OrderedDict([('Splunk',
                                                                                      {'server': '10.143.0.231',
                                                                                       'port': '514',
                                                                                       'transport': 'UDP',
                                                                                       'format': 'BSD',
                                                                                       'facility': 'LOG_USER'}),
                                                                                     ('SecureWorksCTA',
                                                                                      {'server': '143.166.6.185',
                                                                                       'port': '514',
                                                                                       'transport': 'UDP',
                                                                                       'format': 'BSD',
                                                                                       'facility': 'LOG_USER'})])),
                                         ('SecureWorksCTA', OrderedDict([('SecureWorksCTA',
                                                                          {'server': '143.166.6.185', 'port': '514',
                                                                           'transport': 'UDP', 'format': 'BSD',
                                                                           'facility': 'LOG_USER'})]))
                                         ])

    customops.trapprofiles = {'AMER-Dell-Standard-SMNP_Traps': {
        'AUSPWSWORAP01': {'ip': '10.177.202.136', 'community': '1bigbox'}
    }
    }
    customops.domain = 'dell.com'
    customops.dnsservers = ('10.8.8.8', '10.7.7.7')
    customops.secureproxy = OrderedDict([('host', 'anonproxy.us.dell.com'), ('port', '80')])
    customops.timezone = 'America/Chicago'
    customops.ntpservers = ('143.166.255.32', '143.166.226.32')
    customops.updateserver = 'updates.paloaltonetworks.com'
    customops.snmpsettings = {'community': '1bigbox', 'contact': 'Security-Network-L3',
                              'location': 'PC1 MDF-R11-R2 U213-16'}
    customops.loginbanner = '''*****************************************
               ''' + customops.firewall_name + '''
    *****************************************
    This node is the property of Dell Inc.

    *****************************************
    UNAUTHORIZED ACCESS PROHIBITED
    *****************************************'''

    ## Overwrite defaults

    customops.logsettings = OrderedDict([('AMER-Dell-Standard-Logging', OrderedDict([('APAC-Splunk',
                                                                                      {'server': '10.93.131.112',
                                                                                       'port': '514',
                                                                                       'transport': 'UDP',
                                                                                       'format': 'BSD',
                                                                                       'facility': 'LOG_USER'}),
                                                                                     ('SecureWorksCTA',
                                                                                      {'server': '143.166.6.186',
                                                                                       'port': '514',
                                                                                       'transport': 'UDP',
                                                                                       'format': 'BSD',
                                                                                       'facility': 'LOG_USER'})])),
                                         ('SecureWorksCTA', OrderedDict([('SecureWorksCTA',
                                                                          {'server': '143.166.6.186', 'port': '514',
                                                                           'transport': 'UDP', 'format': 'BSD',
                                                                           'facility': 'LOG_USER'})]))
                                         ])
    customops.snmpsettings = {'community': '1bigbox', 'contact': 'Security-Network-L3', 'location': 'Bangalore BGL4'}
    customops.rule_profile_setting = 'Svc_Segmentation'
    customops.rule_profile_setting = 'Dell_Corp_Profile_Group'  ## for corp firewalls
    customops.log_forward_profile_name = 'AMER-Dell-Standard-Logging'
    customops.log_forward_profile_name = 'Dell-AMER-Logging-Profile'  ## for corp firewalls
    customops.snmp_traps = 'AMER-Dell-Standard-SMNP_Traps'
    customops.logging = 'AMER-Dell-Standard-Logging'
    customops.base_rule_name = 'SonicWallImportRule'
    customops.devicegroup_name = 'BGL4 Services Segmentation'

    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)  # suppress SSL warnings

    if options.securityprofile:
        customops.rule_profile_setting = options.securityprofile.lstrip().rstrip()

    if options.logprofile:
        customops.log_forward_profile_name = options.logprofile.lstrip().rstrip()

    if "ipaddr" in form:  # check if program was called from web form

        cgitb.enable()  ## enable traceback output
        customops.devicegroup_name = form['devicegroup'].value

    if "puship" in form:
        cgitb.enable()
        customops.devicegroup_name = form['devicegroup'].value

    if "Submit" in form:
        options.web = True

        sys.stdout.write("Transfer-Encoding: chunked\r\n")
        sys.stdout.write("Content-Type: text/html\r\n")
        sys.stdout.flush()

        log('''
        <html>
        <head>
        <link rel="stylesheet" href="/lab/css/forms.css">
        </head>
        <style type="text/css">
    .container { width: 400px; border: 3px solid #f7c; }
    .textareaContainer {
        display: block;
        border: 3px solid #38c;
        padding: 10px;
    }
    textarea { width: 100%; margin: 2; padding: 2; border-width: 1; }

    /* Style the tab */
    .tab {
        overflow: hidden;
        border: 1px solid #ccc;
        background-color: #f1f1f1;
    }

    /* Style the buttons inside the tab */
    .tab button {
        background-color: inherit;
        float: left;
        border: none;
        outline: none;
        cursor: pointer;
        padding: 14px 16px;
        transition: 0.3s;
        font-size: 17px;
    }

    /* Change background color of buttons on hover */
    .tab button:hover {
        background-color: #ddd;
    }

    /* Create an active/current tablink class */
    .tab button.active {
        background-color: #ccc;
    }

    /* Style the tab content */
    .tabcontent {
        display: none;
        padding: 6px 12px;
        border: 1px solid #ccc;
        border-top: none;
        animation: fadeEffect 3s;
    }

    @keyframes fadeEffect {
        from {opacity: 0;}
        to {opacity: 1;}
    }
    
body {
  font-family: "Helvetica Neue", Helvetica, Arial;
  font-size: 14px;
  line-height: 20px;
  font-weight: 400;
  color: #3b3b3b;
  -webkit-font-smoothing: antialiased;
  font-smoothing: antialiased;
  background: #6699ff;
}
@media screen and (max-width: 580px) {
  body {
    font-size: 16px;
    line-height: 22px;
  }
}

.wrapper {
  margin: 0 auto;
  padding: 40px;
  max-width: 800px;
}

.table {
  margin: 0 0 40px 0;
  width: 100%;
  box-shadow: 0 1px 3px rgba(0, 0, 0, 0.2);
  display: table;
}
@media screen and (max-width: 580px) {
  .table {
    display: block;
  }
}

.row {
  display: table-row;
  background: #f6f6f6;
}
.row:nth-of-type(odd) {
  background: #e9e9e9;
}
.row.header {
  font-weight: 900;
  color: #ffffff;
  background: #cccccc;
}
.row.green {
  background: #27ae60;
}
.row.blue {
  background: #2980b9;
}
@media screen and (max-width: 580px) {
  .row {
    padding: 14px 0 7px;
    display: block;
  }
  .row.header {
    padding: 0;
    height: 6px;
  }
  .row.header .cell {
    display: none;
  }
  .row .cell {
    margin-bottom: 10px;
  }
  .row .cell:before {
    margin-bottom: 3px;
    content: attr(data-title);
    min-width: 98px;
    font-size: 10px;
    line-height: 10px;
    font-weight: bold;
    text-transform: uppercase;
    color: #969696;
    display: block;
  }
}

.cell {
  padding: 6px 12px;
  display: table-cell;
}
@media screen and (max-width: 580px) {
  .cell {
    padding: 2px 16px;
    display: block;
  }
}

    </style>


    <div class="tab">
    ''')
        for tabname in tabs2:
            # label=''
            log('''<button class="tablinks" onclick="openTab(event, \'''' + tabname + '''\')" id="''' + tabname + '''_tab">''' +
                tabs2[tabname]['description'] + '''</button>''')

            # <button class="tablinks" onclick="openTab(event, 'Report')">Report</button>
            # <button class="tablinks" onclick="openTab(event, 'Commands')">Commands</button>
        sys.stdout.flush()
        log('''</div>

    <script>
    function openTab(evt, tabName) {
        var i, tabcontent, tablinks;
        tabcontent = document.getElementsByClassName("tabcontent");
        for (i = 0; i < tabcontent.length; i++) {
            tabcontent[i].style.display = "none";
        }
        tablinks = document.getElementsByClassName("tablinks");
        for (i = 0; i < tablinks.length; i++) {
            tablinks[i].className = tablinks[i].className.replace(" active", "");
        }
        document.getElementById(tabName).style.display = "block";
        evt.currentTarget.className += " active";
    }

    // Get the element with id="defaultOpen" and click on it
    document.getElementById("console_tab").click();


    </script>

    ''')
        sys.stdout.flush()
        import re
        set_web_tab('console')
        ## fix this so it does not display password
        log(re.sub(r'(--pas.*?) \'.*?\'', r"\1 '*****'", str(cmdarg)),
            level=logging.DEBUG)  ## re.sub(r'--pas.*? --', '', str(cmdarg))

    networkService = NetworkService(parser)

    if options.web and 'loadconfig' in form:
        options.loadconfig = [timestr + '.config']
        open(options.loadconfig[0], 'wb').write(form['loadconfig'].file.read())

    if options.loadconfig:

        config = OrderedDict()

        for configfile in options.loadconfig:
            log("!-- Loading config : " + configfile)
            infile = open(configfile, 'rb')
            tmp = pickle.load(infile)
            infile.close()
            # The following conditional is in place for backwards compatibility for old configurations saved that only contained the "config" elements before "customops" was added
            if 'config' in tmp:
                config.update(tmp['config'])
                customops = tmp['custom']
            else:
                # config=tmp
                config.update(tmp)

        contexts = []

        # generate list of contexts
        if not options.context:
            options.context = ['all']

        if str.lower(options.context[0]) == 'all':
            for device_groups in config:
                contexts.append(device_groups)
        else:
            contexts = options.context

        for context in contexts:
            if config[context]['config']['fw_type'] == 'sonicwall':
                config[context]['usedzones'] = []
                for interface in config[context]['interfaces']:
                    if config[context]['interfaces'][interface]['interface_Zone'] != '':
                        config[context]['usedzones'].append(config[context]['interfaces'][interface]['interface_Zone'])
                all_zones = []
                for zone in config[context]['zones']:
                    all_zones.append(config[context]['zones'][zone]['zoneObjId'])
            else:
                config[context]['usedzones'] = []
                if 'zones' in config[context]:
                    for zone in config[context]['zones']:
                        if zone != 'default':
                            config[context]['usedzones'].append(config[context]['zones'][zone]['zoneObjId'])

        if options.checkpointroute:
            for context in config:
                if config[context]['config']['fw_type'].lower() == 'checkpoint':
                    self.log('!-- Loading routes for context : {}'.format(context))
                    config[context]['routing'], config[context]['interfaces'], config[context][
                        'zones'] = load_checkpoint_routing(options.checkpointroute)

    if options.panoramaip:
        if not options.web and (options.username == None or options.password == None):
            options.username, options.password = get_creds()
        palo_xml = get_palo_config_https(options.panoramaip, 'config.panorama.temp', options.username, options.password)
        if palo_xml:
            if options.logging == Logging.DEBUG:
                with open(options.panoramaip + '.xml', 'w') as outfile:
                    outfile.write(palo_xml)
            config = load_xml('', palo_xml)
            palo_xml = None
            # options.panorama='config.panorama.temp'

        if not options.context:
            options.context = ['all']
        if str.lower(options.context[0]) == 'all':
            for device_groups in config:
                contexts.append(device_groups)
        else:
            contexts = options.context

    if options.sonicwall_api_ip:
        # self.log("!-- Retrieving sonicwall config")
        if not options.web and (options.username == None or options.password == None):
            options.username, options.password = get_creds()
        config['sonicwall'] = load_sonicwall_api(options.sonicwall_api_ip, options.username, options.password)
        if not options.context:
            options.context = ['sonicwall']
        for context in options.context:
            contexts.append(context)

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
        # for context in config:
        #    self.log(context)

    if options.sonicwallip:
        # self.log("!-- Retrieving sonicwall config")
        if not options.web and (options.username == None or options.password == None):
            options.username, options.password = get_creds()
        config = get_sonicwall_exp(options.sonicwallip)

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

    if options.web and 'cipreviewin' in form:
        if form['cipreviewin'].filename != '':
            options.cipreviewin = timestr + '.cipreview'
            open(options.cipreviewin, 'wb').write(form['cipreviewin'].file.read())

    if options.web and 'readxls' in form:
        if form['readxls'].filename != '':
            self.log('readxls filename set')
            self.log('\'' + str(form['readxls'].filename) + '\'')
            options.readxls = "readxls.xlsx"
            open(options.readxls, 'wb').write(form['readxls'].file.read())

    if options.web and 'load' in form:
        if form['load'].filename != '':
            self.log('load config filename set')
            self.log('\'' + str(form['load'].filename) + '\'')
            options.loadfile = "webtemp.config"

    if options.includepolicies != ['all']:
        import os

        newlist = []
        for policy in options.includepolicies:
            if len(os.path.basename(policy)) > 0:
                if os.path.basename(policy[0]) == '@':
                    for i in file_to_list(policy[1:]):
                        if i[0] != '#':
                            newlist.append(i.rstrip().lstrip())
                else:
                    newlist.append(policy)
        options.includepolicies = newlist

    if options.web and 'checkpointpol' in form and 'checkpointobj' in form and 'checkpointsvc' in form and 'checkpointnat' in form:
        if form['checkpointpol'].filename != '':
            self.log('checkpoint policy filename set')
            self.log('\'' + str(form['checkpointpol'].filename) + '\'')
            options.checkpointpol = "Security_Policy.xml"
            open(options.checkpointpol, 'wb').write(form['checkpointpol'].file.read())
            if form['checkpointobj'].filename != '':
                self.log('checkpoint object filename set')
                self.log(str(form['checkpointobj'].filename))
                options.checkpointobj = "network_objects.xml"
                open(options.checkpointobj, 'wb').write(form['checkpointobj'].file.read())
                if form['checkpointsvc'].filename != '':
                    self.log('checkpoint service filename set')
                    self.log(str(form['checkpointsvc'].filename))
                    options.checkpointsvc = "services.xml"
                    open(options.checkpointsvc, 'wb').write(form['checkpointsvc'].file.read())
                    if form['checkpointnat'].filename != '':
                        self.log('checkpoint nat filename set')
                        self.log(str(form['checkpointnat'].filename))
                        options.checkpointnat = "NAT_Policy.xml"
                        open(options.checkpointnat, 'wb').write(form['checkpointnat'].file.read())
                        if not options.context:
                            options.context = [options.checkpointcontext]
                        for context in options.context:
                            contexts.append(context)
                        config[options.checkpointcontext] = load_checkpoint(secobj=options.checkpointpol,
                                                                            natobj=options.checkpointnat,
                                                                            svcobj=options.checkpointsvc,
                                                                            netobj=options.checkpointobj,
                                                                            routeobj=options.checkpointroute)
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

    if options.show_devicegroups:
        if options.loadconfig:
            for context in contexts:
                self.log(context)
        elif not options.panorama:
            self.log("ERROR! Panorama configuration not specified with -I or -P flags", level=logging.ERROR)
            exit(1)
        else:
            show_devicegroups(options.panorama)

    if options.show_templates:
        if not options.panorama:
            self.log("ERROR! Panorama configuration not specified with -I or -P flags", level=logging.ERROR)
            exit(1)
        else:
            show_templates(options.panorama)

    if options.checkpoint_api:
        # options.checkpoint_api='128.221.62.90'
        # options.context=['CMA-SBS2']
        if not options.web and (not options.username or not options.password):
            options.username, options.password = get_creds()
        # options.username='jmiller'
        # options.password='password'
        for context in options.context:
            config[context] = load_checkpoint_api(options.checkpoint_api, context, options.username, options.password)
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

            contexts.append(context)

    # this was moved to loading before panorama due to init 'shared' to empty dictionaries
    if options.checkpoint:

        if not options.context:
            options.context = [options.checkpointcontext]
        for context in options.context:
            contexts.append(context)

        if not options.checkpointpol: options.checkpointpol = "Security_Policy.xml"
        if not options.checkpointnat: options.checkpointnat = "NAT_Policy.xml"
        if not options.checkpointsvc: options.checkpointsvc = "services.xml"
        if not options.checkpointobj: options.checkpointobj = "network_objects.xml"
        config[options.checkpointcontext] = load_checkpoint(secobj=options.checkpointpol, natobj=options.checkpointnat,
                                                            svcobj=options.checkpointsvc, netobj=options.checkpointobj,
                                                            routeobj=options.checkpointroute)
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

    # Add IPSet property to groups -- This has do be done outside load_xml because 'shared' objects are not
    # defined until after returning and expand_address uses global config['shared'] dict
    if options.panorama:

        config = load_xml(options.panorama)

        from netaddr import IPSet

        for context in config:
            debug(context)
            for addr in config[context]['addresses']:
                if config[context]['addresses'][addr]['addrObjType'] == '8':
                    config[context]['addresses'][addr]['IPSet'] = IPSet([])
                    for groupmember in expand_address(config[context]['addresses'], addr,
                                                      config[context]['addressmappings']):
                        if groupmember in config[context]['addresses']:
                            for network in config[context]['addresses'][groupmember]['IPv4Networks']:
                                config[context]['addresses'][addr]['IPSet'].add(str(network))
                        elif groupmember in config['shared']['addresses']:
                            for network in config['shared']['addresses'][groupmember]['IPv4Networks']:
                                config[context]['addresses'][addr]['IPSet'].add(str(network))

        if not options.context:
            options.context = ['all']
        if str.lower(options.context[0]) == 'all':
            for device_groups in config:
                contexts.append(device_groups)
        else:
            contexts = options.context

    if options.sonicwall:
        # self.log(options.sonicwall)
        tmpconfig = load_sonicwall(options.sonicwall, options.skip_disabled)  # CHANGEME boolean value for skip-disabled

        if tmpconfig:
            if options.context != '':
                tmpcontext = options.context[0]
            else:
                tmpcontext = tmpconfig['config']['name']
            config[tmpcontext] = tmpconfig
            if not options.context:
                options.context = [tmpcontext]
            for context in options.context:
                contexts.append(context)
            tmpconfig = None

            # Initialize shared objects to empty
        else:
            self.log('Loading Sonicwall Config failed')

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

    if options.renamecontext:
        if 'sonicwall' in config:
            config[options.renamecontext] = config.pop('sonicwall')

    if options.saveconfig:
        # only save if config has something more than shared
        if len(config) > 1:
            self.log("!-- Saving config")
            import pickle

            outfile = open(options.saveconfig, 'wb')
            tmp = OrderedDict()
            tmp['config'] = config
            tmp['custom'] = customops
            result = pickle.dump(tmp, outfile)
            outfile.close()

    if options.address:
        for context, parent, addr_name, addr_def in search_address(options.address, contexts):
            self.log('{},{},{},{}'.format(context, parent, addr_name, addr_def))

    if options.exp_service:
        # (DONE)- Do this for specified contexts
        # Output for this should be better.  Perhaps printing a tree, or at least if each object is an address or group
        for service in options.exp_service:
            # self.log('')
            # self.log('-' * 120)
            for context in contexts:
                if 'servicemappings' in config[context]:
                    services = expand_service(config[context]['services'], service, config[context]['servicemappings'],
                                              False)
                    if services:
                        # self.log('Context: ' + context)
                        # self.log('-' * 120)
                        for item in services:
                            prot = get_prot_of(config[context]['services'], item)
                            portlist = get_ports_of(config[context]['services'], item)
                            self.log('{},{},{},{},{}'.format(context, service, item, prot, str(portlist)))
                            # svcPortSet FIX -- output for this should either be port1, port1-port2 or a
                            # list for each item in the set

    if options.ipaddr:
        find_ip_address(config, options.ipaddr, contexts)

    if options.ipaddr:
        search_ip(options.ipaddr, contexts)

    if options.exactipaddr:
        find_ip_address(config, options.exactipaddr, contexts, True)

    if options.policysearch:
        for context in contexts:
            self.log('context: ' + context)
            if context != 'shared':
                find_ip_address_in_policy(config[context]['policies'], config[context]['addresses'],
                                          config[context]['addressmappings'], options.policysearch)
                # change "find_ip_address_in_policy" to only return results

    # options.rulemodify='TACACS-SERVERS,drmplics01.drm.amer.dell.com,banplics01.blr.apac.dell.com,crkplics01.crk.emea.dell.com'
    if options.rulematch:
        if options.web:
            set_web_tab('rulematch')
        find_matching_rules2(config, config['shared'], options.rulematch, contexts, options.rulemodify)
        # change "find_ip_address_in_policy" to only return results

    if options.service:
        find_service(config, options.service, contexts)

    if options.exactservice:
        find_service(config, options.exactservice, contexts, True)

    # iterate through each of the selected contexts
    # do this before creating address/service mappings
    if options.show_dupes or options.remove_dupes:

        self.log("!-- Finding Duplicate Objects")
        for c in contexts:
            if config[c]['config']['fw_type'] == 'sonicwall':
                # duplicates=find_dupes(config['sonicwall'])  ## need to remove hardcoded contextname
                print(c)
                duplicates = find_dupes(config[c])
                break

    if options.show_dupes:
        for index in duplicates['addresses']:
            self.log('{:60.60} : {:60.60}'.format(index, duplicates['addresses'][index]))

        for index in duplicates['services']:
            self.log('{:60.60} : {:60.60}'.format(index, duplicates['services'][index]))

    if options.remove_dupes:
        self.log("!-- Renaming Duplicate Objects in Policies")
        replacements = remove_dupes(duplicates, c)

    if options.show_unused:  ##FIXSHARED
        self.log("!-- Finding Unused Objects (Single-Pass)")
        for context in contexts:
            self.log(context)
            self.log('-' * 120)
            if context != "shared":
                unused = find_unused2(config[context], context)
                if len(unused["addresses"]) > 0 or len(unused["addressgroups"]) > 0:
                    for address in unused["addresses"]:
                        self.log("address," + context + "," + address)
                    for address in unused["addressgroups"]:
                        self.log("addressgroup," + context + "," + address)
                    for service in unused["services"]:
                        self.log("service," + context + "," + service)
                    for service in unused["servicegroups"]:
                        self.log("servicegroup," + context + "," + service)
                    for address in unused["addresses"]:
                        create_address_obj('', '', '', 'checkpoint', 'cli',
                                           {'addresstype': config[context]['addresses'][address]['addrObjType'],
                                            'addressname': config[context]['addresses'][address]['addrObjId'],
                                            'ip1': config[context]['addresses'][address]['addrObjIp1'],
                                            'ip2': config[context]['addresses'][address]['addrObjIp2'],
                                            'color': config[context]['addresses'][address]['addrObjColor'],
                                            'comment': config[context]['addresses'][address]['addrObjComment']})
                        pass
                    for address in unused["addressgroups"]:
                        create_address_obj('', '', '', 'checkpoint', 'cli',
                                           {'addresstype': config[context]['addresses'][address]['addrObjType'],
                                            'addressname': config[context]['addresses'][address]['addrObjId'],
                                            'ip1': config[context]['addresses'][address]['addrObjIp1'],
                                            'ip2': config[context]['addresses'][address]['addrObjIp2'],
                                            'color': config[context]['addresses'][address]['addrObjColor'],
                                            'comment': config[context]['addresses'][address]['addrObjComment'],
                                            'members': [x for x in config[context]['addressmappings'][address]]})
                        pass
                    for service in unused["services"]:
                        create_service_obj('', '', '', 'checkpoint', 'cli',
                                           {'servicetype': config[context]['services'][service]['svcObjType'],
                                            'servicename': config[context]['services'][service]['svcObjId'],
                                            'port1': config[context]['services'][service]['svcObjPort1'],
                                            'port2': config[context]['services'][service]['svcObjPort2'],
                                            'protocol': config[context]['services'][service]['svcObjIpType'],
                                            'color': config[context]['services'][service]['svcObjColor'],
                                            'comment': config[context]['services'][service]['svcObjComment']})

                    for service in unused["servicegroups"]:
                        create_service_obj('', '', '', 'checkpoint', 'cli',
                                           {'servicetype': config[context]['services'][service]['svcObjType'],
                                            'servicename': config[context]['services'][service]['svcObjId'],
                                            'color': config[context]['services'][service]['svcObjColor'],
                                            'comment': config[context]['services'][service]['svcObjComment'],
                                            'members': [x for x in config[context]['servicemappings'][service]]})

    if options.remove_unused:

        # For now, only remove unused objects for the sonicwall context, as this is intended to be used for migration purposes only.
        # The show_unused routine will check against all contexts, for the sake of running reports.
        # The while loop is used to run multiple passes, until there is no change in the number of address+service objects, OR
        # there are no changes to the address mappings.  The first pass will likely not have any changes to the address mappings

        # address mappings are primarily a collection of address objects.  since those address objects are part of an address group,
        # on the first pass, they will not be considered unused, and the address group will remain unchanged.  however, on the first
        # pass, some address groups will be removed, which will then cause some address objects to be unused during the second
        # pass.  this will then result in the address mappings being modified.  i dont believe that on the first pass any mapping
        # could be modified, as all its members should be marked as being in use.

        tmpaddr = OrderedDict()
        tmpsvc = OrderedDict()
        tmpaddrmap = OrderedDict()
        tmpsvcmap = OrderedDict()

        import inflect  # had to be installed

        passstr = inflect.engine()

        for context in contexts:
            if config[context]['config']['fw_type'] == "sonicwall":
                start = 0
                passnum = 1
                while start != (len(config[context]['addresses']) + len(config[context]['services'])):
                    start = len(config[context]['addresses']) + len(config[context]['services'])
                    ## create dictionary of unused addresses, services, addressgroups and servicegroups
                    self.log("!-- Finding Unused Objects - " + passstr.ordinal(passnum) + " pass")
                    unused = find_unused(config[context], context)
                    self.log('!-- Found ' + str(
                        len(unused['addresses']) + len(unused['addressgroups']) + len(unused['services']) + len(
                            unused['servicegroups'])) + ' Objects to be removed.')
                    self.log("!-- Removing Unused Objects - " + passstr.ordinal(passnum) + " pass")
                    ## update address objects

                    for address in config[context]['addresses']:
                        if address in unused['addresses'] or address in unused['addressgroups']:
                            pass
                            self.log('removing address item : ' + address, level=logging.INFO)
                        else:
                            tmpaddr[address] = config[context]['addresses'][address]
                    config[context]['addresses'] = tmpaddr

                    # remove unused objects from address maps

                    for address in config[context]['addressmappings']:
                        mapsize = len(config[context]['addressmappings'][address])
                        config[context]['addressmappings'][address] = list(
                            (set(config[context]['addressmappings'][address]) - set(unused["addresses"])) - set(
                                unused["addressgroups"]))
                        if mapsize != len(config[context]['addressmappings'][address]):
                            start = 0  # force another check since an group was modifed

                    for service in config[context]['services']:
                        if service in unused["services"] or service in unused["servicegroups"]:
                            pass
                            self.log('removing service item : ' + service, level=logging.INFO)
                        else:
                            tmpsvc[service] = config[context]['services'][service]
                    config[context]['services'] = tmpsvc

                    for service in config[context]['servicemappings']:
                        mapsize = len(config[context]['servicemappings'][service])
                        config[context]['servicemappings'][service] = list(
                            (set(config[context]['servicemappings'][service]) - set(unused["services"])) - set(
                                unused["servicegroups"]))
                        if mapsize != len(config[context]['servicemappings'][service]):
                            start = 0  # force another check since an group was modifed

                    passnum += 1

    if options.show_mismatch:
        import re

        for context in contexts:
            for service in config[context]['services']:
                if re.findall('tcp', config[context]['services'][service]['svcObjId'].lower()) != []:
                    if config[context]['services'][service]['svcObjIpType'] not in ['0', '6']:
                        self.log('{:40.40s} {:5.5s} {:10.10s} {:10.10s}'.format(config[context]['services'][service]['svcObjId'],
                                                                           config[context]['services'][service][
                                                                               'svcObjIpType'],
                                                                           config[context]['services'][service][
                                                                               'svcObjPort1'],
                                                                           config[context]['services'][service][
                                                                               'svcObjPort2']))
                if re.findall('udp', config[context]['services'][service]['svcObjId'].lower()) != []:
                    if config[context]['services'][service]['svcObjIpType'] not in ['0', '17']:
                        self.log('{:40.40s} {:5.5s} {:10.10s} {:10.10s}'.format(config[context]['services'][service]['svcObjId'],
                                                                           config[context]['services'][service][
                                                                               'svcObjIpType'],
                                                                           config[context]['services'][service][
                                                                               'svcObjPort1'],
                                                                           config[context]['services'][service][
                                                                               'svcObjPort2']))

    if options.dump_config:
        dump_config(config, contexts)
        if options.web:
            import shutil

            set_web_tab('Download')
            for context in contexts:
                shutil.move('/var/www/html/lab/cgi-bin/' + context + '.xlsx',
                            '/var/www/html/dumpconfig/' + context + '.xlsx')
                if context.lower() != 'shared':
                    self.log('<a href="/dumpconfig/' + context + '.xlsx">Download ' + context + '</a>')

    if options.tuplefile:
        self.log('!-- Creating tuples')
        self.log(options.tuplezone)
        create_tuples(config, options.tuplefile, options.tuplezone, contexts, options.policynames)

    # push a sonicwall migrated config to panorama
    if options.push:
        import requests
        import urllib.parse
        import re

        if options.web:
            set_web_tab('push')

        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
        pushsession = requests.Session()
        pushsession.mount(options.puship, DESAdapter())
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
        if options.outfile:
            self.log(options.outfile)
            options.pushfile = options.outfile

        command = 'https://' + options.puship + '/api/?type=op&cmd=<show><system><info></info></system></show>'
        response = pushsession.post(command, verify=False, headers={'authorization': "Basic " + base64.b64encode(
            '{}:{}'.format(options.username, options.password).encode()).decode()})
        swver = re.search(r"\<sw-version\>(.*)\</sw-version\>", response.text, flags=re.MULTILINE)
        # self.log(response.text)
        if swver != None:
            if swver.group(1)[0] in ['8', '9']:
                options.pan8 = True
                self.log('Panorama 8 or 9 detected')
            elif swver.group(1)[0] not in ['8', '9']:
                options.pan8 = False
                self.log('Panorama 7 detected')
        fileonly = options.pushfile.split('/')[-1]
        command = 'https://' + options.puship + '/api/?type=import&category=configuration'
        self.log(command)
        configfile = {'file': open(options.pushfile, 'rb')}
        response = pushsession.post(command, verify=False, files=configfile, headers={
            'authorization': "Basic " + base64.b64encode(
                '{}:{}'.format(options.username, options.password).encode()).decode()})
        # log (response.text)
        pushcommands = [('https://' + options.puship + '/api/?type=config&action=set&xpath=' + urllib.parse.quote_plus(
            "/config/devices/entry[@name='localhost.localdomain']/device-group") + "&element=<entry%20name=\"" + customops.devicegroup_name + '\"></entry>',
                         'Creating Device Group JEFF')]
        if not options.pushnotemplate:
            pushcommands.append((
                'https://' + options.puship + '/api/?type=config&action=set&xpath=' + urllib.parse.quote_plus(
                    "/config/devices/entry[@name='localhost.localdomain']/template") + "&element=<entry%20name=\"" + customops.devicegroup_name + "\"></entry>",
                'Creating Template'))

        if options.pan8 and not options.pushnotemplate:
            pushcommands.append((
                'https://' + options.puship + '/api/?type=config&action=set&xpath=' + urllib.parse.quote_plus(
                    "/config/devices/entry[@name='localhost.localdomain']/template-stack") + "&element=<entry%20name=\"" + customops.devicegroup_name + "_Stack\"></entry>",
                'Creating Template Stack'))
            ## ADD TEMPLATE TO TEMPLATE-STACK
        else:
            # pushcommands.append()
            pass

        for device in options.devicetoadd.split(','):
            pushcommands.append((
                'https://' + options.puship + '/api/?type=config&action=set&xpath=' + '/config/mgt-config' + "&element=<devices><entry name=\'" + device + "\'/></devices>",
                'Adding device "' + device + '" to Panorama'))
            pushcommands.append((
                'https://' + options.puship + '/api/?type=config&action=set&xpath=' + urllib.parse.quote_plus(
                    "/config/devices/entry[@name='localhost.localdomain']/device-group/entry[@name=\"" + customops.devicegroup_name + "\"]") + "&element=<devices><entry name=\'" + device + "\'/></devices>",
                'Adding device "' + device + '" to device-group'))
            if not options.pushnotemplate:
                if options.pan8:
                    pushcommands.append((
                        'https://' + options.puship + '/api/?type=config&action=set&xpath=' + urllib.parse.quote_plus(
                            "/config/devices/entry[@name='localhost.localdomain']/template-stack/entry[@name=\"" + customops.devicegroup_name + "_Stack\"]") + "&element=<devices><entry name=\'" + device + "\'/></devices>",
                        'Adding device "' + device + '" to template stack'))
                else:
                    pushcommands.append((
                        'https://' + options.puship + '/api/?type=config&action=set&xpath=' + urllib.parse.quote_plus(
                            "/config/devices/entry[@name='localhost.localdomain']/template/entry[@name=\"" + customops.devicegroup_name + "\"]") + "&element=<devices><entry name=\'" + device + "\'/></devices>",
                        'Adding device "' + device + '" to template'))
                pushcommands.append((
                    'https://' + options.puship + '/api/?type=config&action=set&xpath=' + urllib.parse.quote_plus(
                        "/config/devices/entry[@name=\"localhost.localdomain\"]/template/entry[@name=\"" + customops.devicegroup_name + "\"]") + "&element=<settings/>",
                    'Setting vsys mode'))

        pushcommands.append((
            'https://' + options.puship + '/api/?type=op&cmd=<load><config><partial><mode>replace</mode><from>' + fileonly + '</from><from-xpath>' + urllib.parse.quote_plus(
                "/config/devices/entry[@name=\"localhost.localdomain\"]/device-group/entry[@name=\"" + customops.devicegroup_name + "\"]/address") + '</from-xpath><to-xpath>' + urllib.parse.quote_plus(
                "/config/devices/entry[@name=\"localhost.localdomain\"]/device-group/entry[@name=\"" + customops.devicegroup_name + "\"]/address") + '</to-xpath></partial></config></load>',
            'Importing Address objects'))
        pushcommands.append((
            'https://' + options.puship + '/api/?type=op&cmd=<load><config><partial><mode>replace</mode><from>' + fileonly + '</from><from-xpath>' + urllib.parse.quote_plus(
                "/config/devices/entry[@name=\"localhost.localdomain\"]/device-group/entry[@name=\"" + customops.devicegroup_name + "\"]/address-group") + '</from-xpath><to-xpath>' + urllib.parse.quote_plus(
                "/config/devices/entry[@name=\"localhost.localdomain\"]/device-group/entry[@name=\"" + customops.devicegroup_name + "\"]/address-group") + '</to-xpath></partial></config></load>',
            'Importing Address Group objects'))
        pushcommands.append((
            'https://' + options.puship + '/api/?type=op&cmd=<load><config><partial><mode>replace</mode><from>' + fileonly + '</from><from-xpath>' + urllib.parse.quote_plus(
                "/config/devices/entry[@name=\"localhost.localdomain\"]/device-group/entry[@name=\"" + customops.devicegroup_name + "\"]/service") + '</from-xpath><to-xpath>' + urllib.parse.quote_plus(
                "/config/devices/entry[@name=\"localhost.localdomain\"]/device-group/entry[@name=\"" + customops.devicegroup_name + "\"]/service") + '</to-xpath></partial></config></load>',
            'Importing Service objects'))
        pushcommands.append((
            'https://' + options.puship + '/api/?type=op&cmd=<load><config><partial><mode>replace</mode><from>' + fileonly + '</from><from-xpath>' + urllib.parse.quote_plus(
                "/config/devices/entry[@name=\"localhost.localdomain\"]/device-group/entry[@name=\"" + customops.devicegroup_name + "\"]/service-group") + '</from-xpath><to-xpath>' + urllib.parse.quote_plus(
                "/config/devices/entry[@name=\"localhost.localdomain\"]/device-group/entry[@name=\"" + customops.devicegroup_name + "\"]/service-group") + '</to-xpath></partial></config></load>',
            'Importing Service Group objects'))
        pushcommands.append((
            'https://' + options.puship + '/api/?type=op&cmd=<load><config><partial><mode>replace</mode><from>' + fileonly + '</from><from-xpath>' + urllib.parse.quote_plus(
                "/config/shared/log-settings") + '</from-xpath><to-xpath>' + urllib.parse.quote_plus(
                "/config/devices/entry[@name=\"localhost.localdomain\"]/template/entry[@name=\"" + customops.devicegroup_name + "\"]/config/shared/log-settings") + '</to-xpath></partial></config></load>',
            'Creating Template Log settings'))
        if options.pan8:
            pushcommands.append((
                'https://' + options.puship + '/api/?type=op&cmd=<load><config><partial><mode>replace</mode><from>' + fileonly + '</from><from-xpath>' + urllib.parse.quote_plus(
                    "/config/pan8/log-settings") + '</from-xpath><to-xpath>' + urllib.parse.quote_plus(
                    "/config/devices/entry[@name=\"localhost.localdomain\"]/device-group/entry[@name=\"" + customops.devicegroup_name + "\"]/log-settings") + '</to-xpath></partial></config></load>',
                'Creating Device-Group Log settings for Pan8'))
        else:
            pushcommands.append((
                'https://' + options.puship + '/api/?type=op&cmd=<load><config><partial><mode>replace</mode><from>' + fileonly + '</from><from-xpath>' + urllib.parse.quote_plus(
                    "/config/pan7/log-settings") + '</from-xpath><to-xpath>' + urllib.parse.quote_plus(
                    "/config/devices/entry[@name=\"localhost.localdomain\"]/device-group/entry[@name=\"" + customops.devicegroup_name + "\"]/log-settings") + '</to-xpath></partial></config></load>',
                'Creating Device-Group Log settings for Pan7'))
        pushcommands.append((
            'https://' + options.puship + '/api/?type=op&cmd=<load><config><partial><mode>replace</mode><from>' + fileonly + '</from><from-xpath>' + urllib.parse.quote_plus(
                "/config/devices/entry[@name=\"localhost.localdomain\"]/device-group/entry[@name=\"" + customops.devicegroup_name + "\"]/profile-group") + '</from-xpath><to-xpath>' + urllib.parse.quote_plus(
                "/config/devices/entry[@name=\"localhost.localdomain\"]/device-group/entry[@name=\"" + customops.devicegroup_name + "\"]/profile-group") + '</to-xpath></partial></config></load>',
            'Creating Security Profile Group'))
        pushcommands.append((
            'https://' + options.puship + '/api/?type=op&cmd=<load><config><partial><mode>replace</mode><from>' + fileonly + '</from><from-xpath>' + urllib.parse.quote_plus(
                "/config/devices/entry[@name=\"localhost.localdomain\"]/device-group/entry[@name=\"" + customops.devicegroup_name + "\"]/pre-rulebase") + '</from-xpath><to-xpath>' + urllib.parse.quote_plus(
                "/config/devices/entry[@name=\"localhost.localdomain\"]/device-group/entry[@name=\"" + customops.devicegroup_name + "\"]/pre-rulebase") + '</to-xpath></partial></config></load>',
            'Importing Pre-Rules (Security and NAT)'))
        # pushcommands.append(('https://' + options.puship + '/api/?type=op&cmd=<load><config><partial><mode>replace</mode><from>' + fileonly + '</from><from-xpath>' + urllib.parse.quote_plus("/config/devices/entry[@name=\"localhost.localdomain\"]/device-group/entry[@name=\"" + customops.devicegroup_name + "\"]/pre-rulebase") + '</from-xpath><to-xpath>' + urllib.parse.quote_plus("/config/devices/entry[@name=\"localhost.localdomain\"]/device-group/entry[@name=\"" + customops.devicegroup_name + "\"]/pre-rulebase") + '</to-xpath></partial></config></load>', 'Importing NAT Rules'))
        if not options.pushnotemplate:
            pushcommands.append((
                'https://' + options.puship + '/api/?type=op&cmd=<load><config><partial><mode>replace</mode><from>' + fileonly + '</from><from-xpath>' + urllib.parse.quote_plus(
                    "/config/devices/entry[@name=\'localhost.localdomain\']/network") + '</from-xpath><to-xpath>' + urllib.parse.quote_plus(
                    "/config/devices/entry[@name=\'localhost.localdomain\']/template/entry[@name=\'" + customops.devicegroup_name + "\']/config/devices/entry[@name=\'localhost.localdomain\']/network") + '</to-xpath></partial></config></load>',
                'Importing Network Configuration'))
            pushcommands.append((
                'https://' + options.puship + '/api/?type=op&cmd=<load><config><partial><mode>replace</mode><from>' + fileonly + '</from><from-xpath>' + urllib.parse.quote_plus(
                    "/config/devices/entry[@name=\'localhost.localdomain\']/vsys/entry[@name=\'vsys1\']/import") + '</from-xpath><to-xpath>' + urllib.parse.quote_plus(
                    "/config/devices/entry[@name=\'localhost.localdomain\']/template/entry[@name=\'" + customops.devicegroup_name + "\']/config/devices/entry[@name=\'localhost.localdomain\']/vsys/entry[@name=\'vsys1\']/import") + '</to-xpath></partial></config></load>',
                'Creating "imports" section'))
            if options.userid:
                pushcommands.append((
                    'https://' + options.puship + '/api/?type=op&cmd=<load><config><partial><mode>replace</mode><from>' + fileonly + '</from><from-xpath>' + urllib.parse.quote_plus(
                        "/config/devices/entry[@name=\'localhost.localdomain\']/vsys/entry[@name=\'vsys1\']/user-id-agent") + '</from-xpath><to-xpath>' + urllib.parse.quote_plus(
                        "/config/devices/entry[@name=\'localhost.localdomain\']/template/entry[@name=\'" + customops.devicegroup_name + "\']/config/devices/entry[@name=\'localhost.localdomain\']/vsys/entry[@name=\'vsys1\']/user-id-agent") + '</to-xpath></partial></config></load>',
                    'Creating User-ID Agent configuration'))
            pushcommands.append((
                'https://' + options.puship + '/api/?type=op&cmd=<load><config><partial><mode>replace</mode><from>' + fileonly + '</from><from-xpath>' + urllib.parse.quote_plus(
                    "/config/devices/entry[@name=\'localhost.localdomain\']/vsys/entry[@name=\'vsys1\']/zone") + '</from-xpath><to-xpath>' + urllib.parse.quote_plus(
                    "/config/devices/entry[@name=\'localhost.localdomain\']/template/entry[@name=\'" + customops.devicegroup_name + "\']/config/devices/entry[@name=\'localhost.localdomain\']/vsys/entry[@name=\'vsys1\']/zone") + '</to-xpath></partial></config></load>',
                'Importing Zones'))
            pushcommands.append((
                'https://' + options.puship + '/api/?type=op&cmd=<load><config><partial><mode>replace</mode><from>' + fileonly + '</from><from-xpath>' + urllib.parse.quote_plus(
                    "/config/devices/entry[@name=\'localhost.localdomain\']/deviceconfig") + '</from-xpath><to-xpath>' + urllib.parse.quote_plus(
                    "/config/devices/entry[@name=\"localhost.localdomain\"]/template/entry[@name=\"" + customops.devicegroup_name + "\"]/config/devices/entry[@name=\"localhost.localdomain\"]/deviceconfig") + '</to-xpath></partial></config></load>',
                'Importing Deviceconfig'))
            pushcommands.append((
                'https://' + options.puship + '/api/?type=config&action=set&xpath=' + urllib.parse.quote_plus(
                    "/config/devices/entry[@name=\"localhost.localdomain\"]/template/entry[@name=\"" + customops.devicegroup_name + "\"]/settings") + "&element=<default-vsys>vsys1</default-vsys>",
                'Setting default vsys for template to vsys1'))
            if options.pan8:
                pushcommands.append((
                    'https://' + options.puship + '/api/?type=config&action=set&xpath=' + urllib.parse.quote_plus(
                        "/config/devices/entry[@name=\"localhost.localdomain\"]/template-stack/entry[@name=\"" + customops.devicegroup_name + "_Stack\"]/templates") + "&element=<member>" + customops.devicegroup_name + "</member>",
                    'Assign template to template-stack'))
        '''<request cmd="set" obj="/config/devices/entry[@name='localhost.localdomain']/template/entry[@name='BGL4 Services Segmentation']/settings" cookie="3251106346790311"><default-vsys>vsys1</default-vsys></request>'''

        self.log('!-- Importing configuration to Panorama device: ' + options.puship)
        sys.stdout.flush()
        import re

        for command, desc in pushcommands:
            self.log(desc)
            sys.stdout.flush()
            response = pushsession.get(command, verify=False, headers={'authorization': "Basic " + base64.b64encode(
                '{}:{}'.format(options.username, options.password).encode()).decode()}, timeout=300)
            if len(re.findall('success', response.text)) == 0:
                self.log('', level=logging.ERROR)
                self.log("!-- Error pushing command : ", level=logging.ERROR)
                self.log(command, level=logging.ERROR)
                self.log(response.text, level=logging.ERROR)
                sys.stdout.flush()
                exit(1)
            else:
                self.log('--> Success!')
                sys.stdout.flush()
        self.log('!-- Importing completed')

    if options.inversematch:
        import re
        import requests

        self.log('!-- Performing Inverse Matching networks : ' + str(options.inversematch))
        inverse_results = inverse_match(options.inversematch)

    if options.cipload:

        import pickle

        self.log("!-- Loading ChangeIP matches")
        try:
            infile = open(options.cipload, 'rb')
            change_results = pickle.load(infile)
            infile.close()
        except:
            self.log('Error loading saved ChangeIP file - Exiting script')
            change_results = None

    if options.cipmatch:
        import re
        import requests

        self.log('!-- Performing ChangeIP Search')
        change_results = cip_match4(options.cipmatch)
        cip_report2(change_results, options.cipshowskipped)
        if options.cipsave:
            self.log("!-- Saving ChangeIP matches")
            if options.cipsave == '%TIMESTAMP%':
                options.cipsave = timestr + '.cipsave'
            import pickle

            outfile = open(options.cipsave, 'wb')
            result = (pickle.dump(change_results, outfile))
            outfile.close()
        cip_match_reviewout(change_results)

    if options.cipreviewin:
        if options.web: set_web_tab('reviewin')
        change_results = cip_match_reviewin(options.cipreviewin, change_results)
        cip_report2(change_results, options.cipshowskipped)

    if options.cipdbedit:
        if options.web: set_web_tab('commands')
        cip_match_dbedit(change_results)

    if options.cipswedit:
        if options.web: set_web_tab('commands')
        cip_match_dbedit(change_results, options.sonicwallip, 'webui', showresults=True)

    if options.inverseload:  # CHANGEME move inverse save and load to config save/load as config['context']['matches']
        import pickle

        self.log("!-- Loading inversematches")
        infile = open(options.inverseload, 'rb')
        inverse_results = pickle.load(infile)
        infile.close()

        ## generate list of contexts
        contexts = []
        if not options.context:
            for context in inverse_results:
                contexts.append(context)
        else:
            contexts = options.context

    if options.inversematch or options.inverseload:

        if options.inversedisable and options.inversedelete:
            self.log('Can not perform inverse disable and delete in a single pass')
            exit(1)  ## change this to a return once this is made into a function
        inverse_cmds = OrderedDict()

        if options.inversedisable or options.inversedelete:
            inverse_cmds['rules'], stats = inverse_rule_cleanup(inverse_results)
            for context in contexts:
                if context in stats:
                    inverse_results[context]['policy_cleanup_stats'] = stats[context]
                else:
                    inverse_results[context]['policy_cleanup_stats'] = [None, None, None, None]

        if options.inverseaddressdelete:
            inverse_cmds['addresses'], stats = inverse_address_cleanup(inverse_results)
            for context in contexts:
                if context in stats:
                    inverse_results[context]['address_cleanup_stats'] = stats[context]
                else:
                    inverse_results[context]['address_cleanup_stats'] = [None, None, None]

        self.log('-' * 180)
        self.log('Effected Policies')
        self.log('-' * 180)
        for context in contexts:
            for ep in inverse_results[context]['effected_policies']:
                self.log(ep)
        self.log('-' * 180)
        if options.inverseexecute == '':
            if options.sonicwallip:
                options.inverseexecute = options.sonicwallip
            elif options.panoramaip:
                options.inverseexecute = options.panoramaip

        if options.web:
            set_web_tab('command')
            inverse_newexec(options.username, options.password, '', inverse_cmds, noexec=True)

    # inverse_exec has been replaced with newexec, so the following function can most likely be removed - the method to exec has been completely redone.
    if options.inverseexecute != None and options.inversematch:
        if options.web:
            set_web_tab('exec')
        inverse_newexec(options.username, options.password, options.inverseexecute, inverse_cmds)
    elif options.inverseexecute == '' and options.inversematch:
        self.log('Target IP Address Needed')

        ## Find objects related to an address object

    if options.inversestats:  # work in progress as I am still determining what stats to collect

        if options.web: set_web_tab('stats')

        try:
            for context in contexts:
                self.log('-' * 180)
                self.log(context)
                self.log('-' * 180)
                self.log('Policy Stats    : {:10} {:10} {:10}'.format(*inverse_results[context]['policy_stats']))
                self.log('Address Stats   : {:10} {:10} {:10}'.format(*inverse_results[context]['addr_stats']))
                self.log('Policy Cleanup  : {:10} {:10} {:10} {:10}'.format(*inverse_results[context]['policy_cleanup_stats']))
        except:
            pass

    if options.readxls:
        shared_base = ''
        devgroup_base = ''

        self.log('')
        self.log('Reading XLS file')
        if not options.zonemaps:
            self.log('--zonemap option must be specified if using --readxls option')

        else:
            import pandas as pd

            import urllib
            import requests
            import re
            # import ipaddress
            from netaddr import IPSet, IPRange, IPNetwork, IPAddress

            df = pd.read_excel(options.readxls)
            pushcommands = []
            panoip = options.panoramaip
            log_profile = options.logprofile

            new_objects = OrderedDict()
            new_objects['services'] = OrderedDict()
            new_objects['addresses'] = OrderedDict()
            header_found = False
            rule_index = 0

            zone_map = {}

            for zonemap in options.zonemaps:
                zonemap = zonemap.replace(', ', ',').replace(' ,', ',')
                xls, fwzone, policytext = zonemap.split(',')
                zone_map[xls.lower()] = {}
                zone_map[xls.lower()]['fwzone'] = fwzone
                zone_map[xls.lower()]['policytext'] = policytext
                # debug(xls, fwzone, policytext)

            policynames = {}
            for context in contexts:
                policynames[context] = []
                for policy in config[context]['policies']:
                    policynames[context].append(config[context]['policies'][policy]['policyName'])

            if options.readxls_shared:
                object_base = "/config/shared"
                config_dict = config['shared']
            else:
                object_base = "/config/devices/entry[@name='localhost.localdomain']/device-group/entry[@name='" + context + "']"
                config_dict = config[context]
            prerule_base = "/config/devices/entry[@name='localhost.localdomain']/device-group/entry[@name='" + context + "']"

            if options.web: set_web_tab('ReadXLS')
            sys.stdout.flush()
            for index, row in df.iterrows():
                src_zone = str(row[2]).rstrip().lstrip().lower()
                src_group = str(row[3]).rstrip().lstrip()
                src_groups = [x.rstrip().lstrip() for x in
                              str(row[3]).rstrip().lstrip().replace('\r', '').replace('\t', '').split('\n')]
                src_ips = [x.rstrip().lstrip() for x in
                           str(row[4]).rstrip().lstrip().replace('\r', '').replace('\t', '').split('\n')]
                src_dns = [x.rstrip().lstrip() for x in
                           str(row[6]).rstrip().lstrip().replace('\r', '').replace('\t', '').split('\n')]
                dst_zone = str(row[8]).rstrip().lstrip().lower()
                dst_group = str(row[9]).rstrip().lstrip()
                dst_groups = [x.rstrip().lstrip() for x in
                              str(row[9]).rstrip().lstrip().replace('\r', '').replace('\t', '').split('\n')]
                dst_ips = [x.rstrip().lstrip() for x in
                           str(row[10]).rstrip().lstrip().replace('\r', '').replace('\t', '').split('\n')]
                dst_dns = [x.rstrip().lstrip() for x in
                           str(row[12]).rstrip().lstrip().replace('\r', '').replace('\t', '').split('\n')]
                dst_ports = str(row[15]).rstrip().lstrip().replace(' ', '').replace('\n', ',').replace('\r', '').replace(
                    '\t', '').split(',')

                if header_found == True:

                    ## while the use of context is "safe" within the if statement below, I should likely ensure that the context is correct based on options.context

                    ## create addresses before processing rules
                    if src_zone.lower() == 'address':  ## also add support to expand group
                        self.log('Address group creation requested')
                        if len(src_groups) != 1:
                            self.log('Source Group column must contain only 1 name')
                        else:
                            if src_group.lower() in [x.lower() for x in
                                                     config[context]['addresses']] or src_group.lower() in [y.lower() for y
                                                                                                            in config[
                                                                                                                'shared'][
                                                                                                                'addresses']] or src_group.lower() in [
                                z.lower() for z in new_objects['addresses']]:
                                self.log('Address group already exists in config')
                            else:
                                self.log('Creating address group : ' + src_group)
                                rule_srcs = []
                                for index1, src_ip in enumerate(src_ips):
                                    src_ip_found = False
                                    for address in config[context]['addresses']:
                                        if config[context]['addresses'][address]['addrObjIp1'] == src_ip:
                                            self.log('Source IP found in device objects')
                                            src_ip_found = address
                                            break
                                    if src_ip_found == False:
                                        for address in config['shared']['addresses']:
                                            if config['shared']['addresses'][address]['addrObjIp1'] == src_ip:
                                                self.log('Source IP found in shared objects')
                                                src_ip_found = address
                                    if src_ip_found == False:
                                        for address in new_objects['addresses']:
                                            if new_objects['addresses'][address]['addrObjIp1'] == src_ip:
                                                self.log('Source IP found in newly added objects')
                                                src_ip_found = address
                                    if src_ip_found == False:
                                        if src_ip in ['1']:  # ['','*','nan']:
                                            src_ip_found = 'any'
                                        else:
                                            try:
                                                tmp = IPAddress(src_ip)
                                                new_addr_obj = src_dns[index1] + '-' + src_ip  # 'H-'+src_ip
                                                index2 = 1
                                                while new_addr_obj in config_dict['addresses']:
                                                    new_addr_obj = src_dns[index1] + '-' + src_ip + '_' + str(index2)
                                                    index2 += 1
                                                # self.log(new_addr_obj)
                                                new_objects['addresses'][new_addr_obj] = {}
                                                new_objects['addresses'][new_addr_obj]['addrObjIp1'] = src_ip
                                                new_objects['addresses'][new_addr_obj]['addrObjIp2'] = '255.255.255.255'
                                                new_objects['addresses'][new_addr_obj]['addrObjId'] = new_addr_obj
                                                new_objects['addresses'][new_addr_obj]['addrObjIdDisp'] = new_addr_obj
                                                new_objects['addresses'][new_addr_obj][
                                                    'addrObjComment'] = 'Created for VirtuStream Project'
                                                new_objects['addresses'][new_addr_obj]['addrObjType'] = '1'  # host
                                                new_objects['addresses'][new_addr_obj]['addrObjZone'] = ''  # placeholder
                                                new_objects['addresses'][new_addr_obj][
                                                    'addrObjProperties'] = ''  # placeholder
                                                if options.pushobjects:
                                                    ## add address object
                                                    pushcommands.append((
                                                        'https://' + panoip + '/api/?type=config&action=set&xpath=' + urllib.parse.quote_plus(
                                                            object_base + "/address/entry[@name='" + new_addr_obj + "']") + '&element=<ip-netmask>' + src_ip + '/' + str(
                                                            netmask_to_cidr(
                                                                '255.255.255.255')) + '</ip-netmask><description>Created for VirtuStream Project - PROPEL</description>',
                                                        'Adding address ' + new_addr_obj))
                                                    pushcommands2.append(('create_address',
                                                                          {'addressname': new_addr_obj, 'ip1': src_ip,
                                                                           'ip2': '255.255.255.255', 'addresstype': '1',
                                                                           'zone': None, 'color': 'black',
                                                                           'comment': 'Created for VirtuStream Project - PROPEL'}))
                                                src_ip_found = new_addr_obj
                                                self.log('Creating new source address object: ' + new_addr_obj)
                                            except Exception as e:
                                                ## not a valid ip address
                                                self.log(e)
                                                self.log('Invalid IP address : ' + src_ip)
                                    if src_ip_found:
                                        rule_srcs.append(src_ip_found)
                                new_objects['addresses'][src_group] = {}
                                new_objects['addresses'][src_group]['addrObjType'] = '8'
                                new_objects['addresses'][src_group]['addrObjComment'] = 'Created for VirtuStream Project'
                                new_objects['addresses'][src_group]['addrObjIdDisp'] = src_group
                                new_objects['addresses'][src_group]['addrObjIp1'] = src_ip
                                new_objects['addresses'][src_group]['addrObjIp2'] = '255.255.255.255'
                                new_objects['addresses'][src_group]['addrObjType'] = '1'  # host
                                new_objects['addresses'][src_group]['addrObjZone'] = ''  # placeholder
                                new_objects['addresses'][src_group]['addrObjProperties'] = ''  # placeholder
                                if options.pushobjects:
                                    ## add address group
                                    pushcommands.append((
                                        'https://' + panoip + '/api/?type=config&action=set&xpath=' + urllib.parse.quote_plus(
                                            object_base + "/address-group/entry[@name='" + src_group + "']") + '&element=<static></static>',
                                        'Adding group ' + src_group))
                                ## Add group members to group
                                for src in rule_srcs:
                                    self.log('Adding member to group : ' + src_group + ' : ' + src)
                                    if options.pushobjects:
                                        ## add address group members
                                        pushcommands.append((
                                            'https://' + panoip + '/api/?type=config&action=set&xpath=' + urllib.parse.quote_plus(
                                                object_base + "/address-group/entry[@name='" + src_group + "']/static") + '&element=<member>' + src + '</member>',
                                            'Adding group member : ' + src))
                                rule_srcs = [src_group]

                    elif src_zone.lower() not in [y.lower() for y in zone_map] or dst_zone.lower() not in [x.lower() for x
                                                                                                           in zone_map]:
                        self.log('Source or Destination zone not found in map - SKIPPING row ' + str(index))
                        # else:
                        # == len(src_dns.split('\n')))
                    elif len(src_dns) != len(src_ips):
                        self.log('Number of Source IPs does not match numer of source DNS names given - SKIPPING ROW ' + str(
                            index))
                    elif len(dst_ips) != len(dst_dns):
                        self.log('Number of Source IPs does not match numer of source DNS names given - SKIPPING ROW ' + str(
                            index))
                        # print(index, dst_ports)
                        # print('"index:{:5.5s}" "s_group:{:20.20s}" "s_dns{:20.20s}" "s_ips{:20.20s}" "dst_grp:{:20.20s}" "dst_dns:{:20.20s}" "dst_ips:{:20.20s}" "dst_svc:{:20.20s}"'.format(str(index), src_group, src_dns[0], src_ips[0], dst_group, dst_dns[0], dst_ips[0], dst_ports[0]))
                    else:

                        for context in contexts:
                            # self.log(config[context]['zones'])
                            rule_dsts = []
                            rule_srcs = []
                            rule_svcs = []
                            if len(src_groups) > 1:
                                self.log('Source group contains more than 1 member')
                                tmp_group = []
                                for src_grp in src_groups:
                                    if src_grp.lower() in [x.lower() for x in
                                                           config[context]['addresses']] or src_grp.lower() in [y.lower()
                                                                                                                for y in
                                                                                                                config[
                                                                                                                    'shared'][
                                                                                                                    'addresses']] or src_grp.lower() in [
                                        z.lower() for z in new_objects['addresses']]:
                                        self.log('Source {} found in current config'.format(src_grp))
                                        rule_srcs.append(src_grp)
                                    else:
                                        self.log('ERROR - Source group {} not found in current config'.format(src_grp))

                            elif src_group.lower() in [x.lower() for x in config[context][
                                'addresses']] or src_group == 'any' or src_group.lower() in [y.lower() for y in
                                                                                             config['shared'][
                                                                                                 'addresses']] or src_group.lower() in [
                                z.lower() for z in new_objects['addresses']]:
                                ## Use existing group
                                self.log('Source group found')
                                if src_group.lower() in [x.lower() for x in
                                                         config[context]['addresses']] and src_group not in config[context][
                                    'addresses']:
                                    for x in config[context]['addresses']:
                                        if src_group.lower() == x.lower():
                                            src_group = x
                                            break
                                if src_group.lower() in [x.lower() for x in
                                                         config['shared']['addresses']] and src_group not in \
                                        config['shared']['addresses']:
                                    for x in config['shared']['addresses']:
                                        if src_group.lower() == x.lower():
                                            src_group = x
                                            break
                                rule_srcs.append(src_group)
                            else:
                                ## first check should be to see if by any chance there is an existing group that matches the given IP list exactly and use that (may not do this as the group was not explicitly requested and future changes to that group would effect this rule, perhaps unintentionally)
                                ## build a list of address objects to either a) include in a new group or b) use directly in the rule
                                self.log('Source group NOT found')

                                for index1, src_ip in enumerate(src_ips):
                                    src_ip_found = False
                                    for address in config[context]['addresses']:
                                        if config[context]['addresses'][address]['addrObjIp1'] == src_ip:
                                            self.log('Source IP found in device objects')
                                            src_ip_found = address
                                            break
                                    if src_ip_found == False:
                                        for address in config['shared']['addresses']:
                                            if config['shared']['addresses'][address]['addrObjIp1'] == src_ip:
                                                self.log('Source IP found in shared objects')
                                                src_ip_found = address
                                    if src_ip_found == False:
                                        for address in new_objects['addresses']:
                                            if new_objects['addresses'][address]['addrObjIp1'] == src_ip:
                                                self.log('Source IP found in newly added objects')
                                                src_ip_found = address
                                    if src_ip_found == False:
                                        if src_ip in ['1']:  # ['','*','nan']:
                                            src_ip_found = 'any'
                                        else:
                                            try:
                                                tmp = IPAddress(src_ip)
                                                new_addr_obj = src_dns[index1] + '-' + src_ip  # 'H-'+src_ip
                                                index2 = 1
                                                while new_addr_obj in config_dict['addresses']:
                                                    new_addr_obj = src_dns[index1] + '-' + src_ip + '_' + str(index2)
                                                    index2 += 1
                                                # self.log(new_addr_obj)
                                                new_objects['addresses'][new_addr_obj] = {}
                                                new_objects['addresses'][new_addr_obj]['addrObjIp1'] = src_ip
                                                new_objects['addresses'][new_addr_obj]['addrObjIp2'] = '255.255.255.255'
                                                new_objects['addresses'][new_addr_obj]['addrObjId'] = new_addr_obj
                                                new_objects['addresses'][new_addr_obj]['addrObjIdDisp'] = new_addr_obj
                                                new_objects['addresses'][new_addr_obj][
                                                    'addrObjComment'] = 'Created for VirtuStream Project'
                                                new_objects['addresses'][new_addr_obj]['addrObjType'] = '1'  # host
                                                new_objects['addresses'][new_addr_obj]['addrObjZone'] = ''  # placeholder
                                                new_objects['addresses'][new_addr_obj][
                                                    'addrObjProperties'] = ''  # placeholder
                                                if options.pushobjects:
                                                    ## add address
                                                    pushcommands.append((
                                                        'https://' + panoip + '/api/?type=config&action=set&xpath=' + urllib.parse.quote_plus(
                                                            object_base + "/address/entry[@name='" + new_addr_obj + "']") + '&element=<ip-netmask>' + src_ip + '/' + str(
                                                            netmask_to_cidr(
                                                                '255.255.255.255')) + '</ip-netmask><description>Created for VirtuStream Project - PROPEL</description>',
                                                        'Adding address ' + new_addr_obj))
                                                    pushcommands2.append(('create_address',
                                                                          {'addressname': new_addr_obj, 'ip1': src_ip,
                                                                           'ip2': '255.255.255.255', 'addresstype': '1',
                                                                           'zone': src_zone, 'color': 'black',
                                                                           'comment': 'Created for VirtuStream Project - PROPEL'}))
                                                src_ip_found = new_addr_obj
                                                self.log('Creating new source address object: ' + new_addr_obj)
                                            except Exception as e:
                                                ## not a valid ip address
                                                self.log(e)
                                                self.log('Invalid IP address : ' + src_ip)
                                    if src_ip_found:
                                        rule_srcs.append(src_ip_found)
                                    # Create New Group
                                if src_group.lower() not in ['*', '', 'nan'] and len(
                                        re.findall('n/a', src_group, flags=re.IGNORECASE)) == 0:
                                    ## create new group with members
                                    self.log('Creating new source group : ' + src_group)
                                    new_objects['addresses'][src_group] = {}
                                    new_objects['addresses'][src_group]['addrObjType'] = '8'
                                    new_objects['addresses'][src_group][
                                        'addrObjComment'] = 'Created for VirtuStream Project'
                                    new_objects['addresses'][src_group]['addrObjIdDisp'] = src_group
                                    new_objects['addresses'][src_group]['addrObjIp1'] = src_ip
                                    new_objects['addresses'][src_group]['addrObjIp2'] = '255.255.255.255'
                                    new_objects['addresses'][src_group]['addrObjType'] = '1'  # host
                                    new_objects['addresses'][src_group]['addrObjZone'] = ''  # placeholder
                                    new_objects['addresses'][src_group]['addrObjProperties'] = ''  # placeholder
                                    if options.pushobjects:
                                        ## add address group
                                        pushcommands.append((
                                            'https://' + panoip + '/api/?type=config&action=set&xpath=' + urllib.parse.quote_plus(
                                                object_base + "/address-group/entry[@name='" + src_group + "']") + '&element=<static></static>',
                                            'Adding group ' + src_group))
                                    ## Add group members to group
                                    member_list = []
                                    for src in rule_srcs:
                                        self.log('Adding member to group : ' + src_group + ' : ' + src)
                                        memberlist.append(src)
                                        if options.pushobjects:
                                            ## add address group members
                                            pushcommands.append((
                                                'https://' + panoip + '/api/?type=config&action=set&xpath=' + urllib.parse.quote_plus(
                                                    object_base + "/address-group/entry[@name='" + src_group + "']/static") + '&element=<member>' + src + '</member>',
                                                'Adding group member : ' + src))
                                    if options.pushobjects:
                                        pushcommands2.append(('create_address',
                                                              {'addressname': src_group, 'addresstype': '8', 'zone': None,
                                                               'color': 'black', 'members': member_list,
                                                               'comment': 'Created via ReadXLS Script'}))
                                    rule_srcs = [src_group]
                                else:
                                    self.log('Using Src IP objects directly in rule')
                                    ## Use Src IPs in rule
                                    pass
                            if len(dst_groups) > 1:
                                self.log('Destination group contains more than 1 member')
                                tmp_group = []
                                for dst_grp in dst_groups:
                                    if dst_grp.lower() in [x.lower() for x in
                                                           config[context]['addresses']] or dst_grp.lower() in [y.lower()
                                                                                                                for y in
                                                                                                                config[
                                                                                                                    'shared'][
                                                                                                                    'addresses']] or dst_grp.lower() in [
                                        z.lower() for z in new_objects['addresses']]:
                                        self.log('Destination {} found in current config'.format(dst_grp))
                                        rule_dsts.append(dst_grp)
                                    else:
                                        self.log('ERROR - Destination group {} not found in current config'.format(dst_grp))
                            if dst_group.lower() in [x.lower() for x in config[context][
                                'addresses']] or dst_group == 'any' or dst_group.lower() in [y.lower() for y in
                                                                                             config['shared'][
                                                                                                 'addresses']] or dst_group.lower() in [
                                z.lower() for z in new_objects['addresses']]:
                                ## Use existing group
                                self.log('Destination group found')
                                if dst_group.lower() in [x.lower() for x in
                                                         config[context]['addresses']] and dst_group not in config[context][
                                    'addresses']:
                                    for x in config[context]['addresses']:
                                        if dst_group.lower() == x.lower():
                                            dst_group = x
                                            break
                                if dst_group.lower() in [x.lower() for x in
                                                         config['shared']['addresses']] and dst_group not in \
                                        config['shared']['addresses']:
                                    for x in config['shared']['addresses']:
                                        if dst_group.lower() == x.lower():
                                            dst_group = x
                                            break
                                rule_dsts.append(dst_group)
                            else:
                                self.log('Dest group NOT found')
                                for index1, dst_ip in enumerate(dst_ips):
                                    dst_ip_found = False
                                    for address in config[context]['addresses']:
                                        if config[context]['addresses'][address]['addrObjIp1'] == dst_ip:
                                            dst_ip_found = address
                                            self.log('Dest IP found in device address objects')
                                            break
                                    if dst_ip_found == False:
                                        for address in config['shared']['addresses']:
                                            if config['shared']['addresses'][address]['addrObjIp1'] == dst_ip:
                                                dst_ip_found = address
                                                self.log('Dest IP found in shared objects')
                                    if dst_ip_found == False:
                                        for address in new_objects['addresses']:
                                            if new_objects['addresses'][address]['addrObjIp1'] == dst_ip:
                                                dst_ip_found = address
                                                self.log('Dest IP found in newly added objects')
                                    if dst_ip_found == False:
                                        if dst_ip in []:  # ['','*','nan']:
                                            dst_ip_found = 'any'
                                        else:
                                            try:
                                                tmp = IPAddress(dst_ip)
                                                new_addr_obj = dst_dns[index1] + '-' + dst_ip  # 'H-'+src_ip
                                                index2 = 1
                                                while new_addr_obj in config_dict['addresses']:
                                                    new_addr_obj = dst_dns[index1] + '-' + dst_ip + '_' + str(index2)
                                                    index2 += 1
                                                # self.log(new_addr_obj)
                                                new_objects['addresses'][new_addr_obj] = {}
                                                new_objects['addresses'][new_addr_obj]['addrObjIp1'] = dst_ip
                                                new_objects['addresses'][new_addr_obj]['addrObjIp2'] = '255.255.255.255'
                                                new_objects['addresses'][new_addr_obj]['addrObjId'] = new_addr_obj
                                                new_objects['addresses'][new_addr_obj]['addrObjIdDisp'] = new_addr_obj
                                                new_objects['addresses'][new_addr_obj][
                                                    'addrObjComment'] = 'Created for VirtuStream Project'
                                                new_objects['addresses'][new_addr_obj]['addrObjType'] = '1'  # host
                                                new_objects['addresses'][new_addr_obj]['addrObjZone'] = ''  # placeholder
                                                new_objects['addresses'][new_addr_obj][
                                                    'addrObjProperties'] = ''  # placeholder
                                                if options.pushobjects:
                                                    ## add address
                                                    pushcommands.append((
                                                        'https://' + panoip + '/api/?type=config&action=set&xpath=' + urllib.parse.quote_plus(
                                                            object_base + "/address/entry[@name='" + new_addr_obj + "']") + '&element=<ip-netmask>' + dst_ip + '/' + str(
                                                            netmask_to_cidr(
                                                                '255.255.255.255')) + '</ip-netmask><description>Created for VirtuStream Project - PROPEL</description>',
                                                        'Adding address ' + new_addr_obj))
                                                    pushcommands2.append(('create_address',
                                                                          {'addressname': new_addr_obj, 'ip1': dst_ip,
                                                                           'ip2': '255.255.255.255', 'addresstype': '1',
                                                                           'zone': dst_zone, 'color': 'black',
                                                                           'comment': 'Created for VirtuStream Project - PROPEL'}))
                                                dst_ip_found = new_addr_obj
                                                self.log('Creating new address object : ' + new_addr_obj)
                                            except Exception as e:
                                                self.log(e)
                                                self.log('Invalid dest IP : ' + dst_ip)
                                    if dst_ip_found:
                                        rule_dsts.append(dst_ip_found)
                                    else:
                                        ## Use Dst IPs in rule
                                        self.log('Using Dst IP objects directly in rule')
                                        pass
                                # Create New Group
                                if dst_group.lower() not in ['*', '', 'nan'] and len(
                                        re.findall('n/a', src_group, flags=re.IGNORECASE)) == 0:
                                    ## create new group with members
                                    self.log('Creating new dest group : ' + dst_group)
                                    if options.pushobjects:
                                        ## add address group
                                        pushcommands.append((
                                            'https://' + panoip + '/api/?type=config&action=set&xpath=' + urllib.parse.quote_plus(
                                                object_base + "/address-group/entry[@name='" + dst_group + "']") + '&element=<static></static>',
                                            'Adding group ' + dst_group))
                                    member_list = []
                                    for dst in rule_dsts:
                                        self.log('Adding member to group : ' + dst_group + ' : ' + dst)
                                        if options.pushobjects:
                                            ## add address group members
                                            pushcommands.append((
                                                'https://' + panoip + '/api/?type=config&action=set&xpath=' + urllib.parse.quote_plus(
                                                    object_base + "/address-group/entry[@name='" + dst_group + "']/static") + '&element=<member>' + dst + '</member>',
                                                'Adding group member' + dst))
                                            member_list.append(dst)
                                    if options.pushobjects:
                                        pushcommands2.append(('create_address',
                                                              {'addressname': dst_group, 'addresstype': '8', 'zone': None,
                                                               'color': 'black', 'members': member_list,
                                                               'comment': 'Created via ReadXLS Script'}))

                                    rule_dsts = [dst_group]

                            for port in dst_ports:
                                if port != '':
                                    ports = port.split('-')
                                    if len(ports) > 2:
                                        # print('Bad ports format for :' + port)
                                        exit(1)
                                    dst_port_found = False
                                    for service in config[context]['services']:
                                        if config[context]['services'][service]['svcObjIpType'] == '6':
                                            if config[context]['services'][service]['svcObjType'] == '1':
                                                if len(ports) == 1:
                                                    if config[context]['services'][service]['svcObjPort1'] == ports[0] and \
                                                            config[context]['services'][service]['svcObjPort2'] == ports[0]:
                                                        # print('service port found in context: ' + service)
                                                        dst_port_found = service
                                                elif len(ports) == 2:
                                                    if config[context]['services'][service]['svcObjPort1'] == ports[0] and \
                                                            config[context]['services'][service]['svcObjPort2'] == ports[1]:
                                                        # print('service range found in context: ' + service)
                                                        dst_port_found = service
                                            ## svcPortSet FIX
                                    if dst_port_found == False:
                                        for service in config['shared']['services']:
                                            if config['shared']['services'][service]['svcObjIpType'] == '6':
                                                if config['shared']['services'][service]['svcObjType'] == '1':
                                                    if len(ports) == 1:
                                                        if config['shared']['services'][service]['svcObjPort1'] == ports[
                                                            0] and config['shared']['services'][service]['svcObjPort2'] == \
                                                                ports[0]:
                                                            # print('service port found in shared: ' + service)
                                                            dst_port_found = service
                                                    elif len(ports) == 2:
                                                        if config['shared']['services'][service]['svcObjPort1'] == ports[
                                                            0] and config['shared']['services'][service]['svcObjPort2'] == \
                                                                ports[1]:
                                                            # print('service range found in shared: ' + service)
                                                            dst_port_found = service
                                                ## svcPortSet FIX
                                    if dst_port_found == False:
                                        for service in new_objects['services']:
                                            if new_objects['services'][service]['svcObjIpType'] == '6':
                                                if new_objects['services'][service]['svcObjType'] == '1':
                                                    if len(ports) == 1:
                                                        if new_objects['services'][service]['svcObjPort1'] == ports[0] and \
                                                                new_objects['services'][service]['svcObjPort2'] == ports[0]:
                                                            # print('service port found in new_obj: ' + service)
                                                            dst_port_found = service
                                                    elif len(ports) == 2:
                                                        if new_objects['services'][service]['svcObjPort1'] == ports[0] and \
                                                                new_objects['services'][service]['svcObjPort2'] == ports[1]:
                                                            # print('service range found in new_obj: ' + service)
                                                            dst_port_found = service
                                                ## svcPortSet FIX
                                    if dst_port_found == False:
                                        # debug(str(ports))
                                        if len(ports) == 1:
                                            new_port_obj = 'TCP_' + ports[0]
                                            index2 = 1
                                            while new_port_obj in config_dict['services']:
                                                new_port_obj = 'TCP_' + ports[0] + "_" + str(index2)
                                                index2 += 1
                                            new_objects['services'][new_port_obj] = {}
                                            new_objects['services'][new_port_obj]['svcObjPort1'] = ports[0]
                                            new_objects['services'][new_port_obj]['svcObjPort2'] = ports[0]
                                        elif len(ports) == 2:
                                            new_port_obj = 'TCP_' + ports[0] + '-' + ports[1]
                                            index2 = 1
                                            while new_port_obj in config_dict['services']:
                                                new_port_obj = 'TCP_' + ports[0] + '-' + ports[1] + "_" + str(index2)
                                                index2 += 1
                                            new_objects['services'][new_port_obj] = {}
                                            new_objects['services'][new_port_obj]['svcObjPort1'] = ports[0]
                                            new_objects['services'][new_port_obj]['svcObjPort2'] = ports[1]
                                        # print('Port object not found, creating : ' + new_port_obj)

                                        new_objects['services'][new_port_obj]['svcObjType'] = '1'
                                        new_objects['services'][new_port_obj]['svcObjIpType'] = '6'
                                        new_objects['services'][new_port_obj]['svcObjId'] = new_port_obj
                                        new_objects['services'][new_port_obj][
                                            'svcObjComment'] = 'Created for VirtuStream Project'
                                        dst_port_found = new_port_obj
                                        if len(ports) == 1:
                                            if options.pushobjects:
                                                ## add service
                                                pushcommands.append((
                                                    'https://' + panoip + '/api/?type=config&action=set&xpath=' + urllib.parse.quote_plus(
                                                        object_base + "/service/entry[@name='" + new_port_obj + "']") + '&element=<protocol><tcp><port>' +
                                                    new_objects['services'][new_port_obj][
                                                        'svcObjPort1'] + '</port></tcp></protocol>',
                                                    'Adding service ' + new_port_obj))
                                                pushcommands2.append(('create_service', {'servicename': new_port_obj,
                                                                                         'port1': new_objects['services'][
                                                                                             new_port_obj]['svcObjPort1'],
                                                                                         'servicetype': '1',
                                                                                         'color': 'black',
                                                                                         'comment': 'Created for VirtuStream Project - PROPEL'}))
                                        elif len(ports) == 2:
                                            if options.pushobjects:
                                                ## add service range
                                                pushcommands.append((
                                                    'https://' + panoip + '/api/?type=config&action=set&xpath=' + urllib.parse.quote_plus(
                                                        object_base + "/service/entry[@name='" + new_port_obj + "']") + '&element=<protocol><tcp><port>' +
                                                    new_objects['services'][new_port_obj][
                                                        'svcObjPort1'] + '-' +
                                                    new_objects['services'][new_port_obj][
                                                        'svcObjPort2'] + '</port></tcp></protocol>',
                                                    'Adding service ' + new_port_obj))
                                                pushcommands2.append(('create_service', {'servicename': new_port_obj,
                                                                                         'port1': new_objects['services'][
                                                                                             new_port_obj]['svcObjPort1'],
                                                                                         'port2': new_objects['services'][
                                                                                             new_port_obj]['svcObjPort2'],
                                                                                         'servicetype': '1',
                                                                                         'color': 'black',
                                                                                         'comment': 'Created for VirtuStream Project - PROPEL'}))
                                    rule_svcs.append(dst_port_found)
                            # print('New Rule : ' + str(rule_srcs) + ' : ' + str(rule_dsts) + ': ' + str(rule_svcs))
                            # print('-' * 120)
                            if len(rule_srcs) > 0 and len(rule_dsts) > 0 and len(rule_svcs) > 0:
                                rule_index = 1
                                rule_base = zone_map[src_zone]['policytext'] + '-to-' + zone_map[dst_zone][
                                    'policytext'] + '-'
                                while rule_base.lower() + str(rule_index) in [x.lower() for x in policynames[context]]:
                                    rule_index += 1
                                policynames[context].append(rule_base + str(rule_index))
                                self.log(' New Rule  : ' + rule_base + str(rule_index))
                                self.log('  Sources  : ' + str(rule_srcs))
                                self.log('Src Groups : ' + str(src_groups))
                                self.log('    Dests  : ' + str(rule_dsts))
                                self.log('Dst Groups : ' + str(dst_groups))
                                self.log(' Services  : ' + str(rule_svcs))
                                self.log('-' * 120)
                                # apistring = 'https://' + firewallip + '/api/?key=apikey&type=config&action=set&key=keyvalue&xpath=xpath-value&element='
                                apistring = '<source>'
                                # if rule_srcs==[src_group]:
                                # apistring+= = '<member>' + src_group + '</member>'
                                # else:
                                for source in rule_srcs:
                                    if source:
                                        apistring += '<member>' + source + '</member>'
                                apistring += '</source><destination>'
                                for dest in rule_dsts:
                                    if dest:
                                        apistring += '<member>' + dest + '</member>'
                                apistring += '</destination>'
                                # apistring += '<destination><member>' + dst_group + '</member></destination>'
                                apistring += '<service>'
                                for svc in rule_svcs:
                                    apistring += '<member>' + svc + '</member>'
                                apistring += '</service>'
                                apistring += '<application><member>any</member></application>'
                                apistring += '<action>allow</action>'
                                apistring += '<source-user><member>any</member></source-user>'
                                # apistring += '<option><disable-server-response-inspection>yes-or-no</disable-server-response-inspection></option>'
                                # apistring += '<negate-source>yes-or-no</negate-source>'
                                # apistring += '<negate-destination>yes-or-no</negate-destination>'
                                apistring += '<disabled>yes</disabled>'
                                apistring += '<log-start>no</log-start>'
                                apistring += '<log-end>yes</log-end>'
                                apistring += '<log-setting>' + log_profile + '</log-setting>'
                                apistring += '<profile-setting><group><member>' + options.securityprofile + '</member></group></profile-setting>'
                                apistring += '<tag><member>' + options.ruletag + '</member></tag>'

                                apistring += '<description>Auto-Generated rule for VirtuStream</description>'
                                apistring += '<from><member>' + zone_map[src_zone]['fwzone'] + '</member></from>'
                                apistring += '<to><member>' + zone_map[dst_zone]['fwzone'] + '</member></to>'
                                # print(apistring)
                                if options.pushrules:
                                    ## add rule
                                    pushcommands.append((
                                        'https://' + panoip + '/api/?type=config&action=set&xpath=' + urllib.parse.quote_plus(
                                            prerule_base + "/pre-rulebase/security/rules/entry[@name='" + rule_base + str(
                                                rule_index) + "']") + "&element=" + apistring,
                                        'Adding rule ' + rule_base + str(rule_index)))
                                    pushcommands2.append(('create_address', {'addressname': foundaddr['new_addr'],
                                                                             'ip1': str(foundaddr['new_ip1']),
                                                                             'ip2': str(foundaddr['new_ip2']),
                                                                             'addresstype': foundaddr['type'],
                                                                             'zone': foundaddr['zone'], 'color': dbcolor,
                                                                             'comment': foundaddr['comment']}))
                                rule_index += 1
                            else:
                                self.log('Source, Destination or Services not set - SKIPPING row : ' + str(index))
                if src_group == 'Source Group':
                    header_found = True

            if not options.web:
                options.pushusername, options.pushpassword = get_creds()
            else:
                options.pushusername = options.username
                options.pushpassword = options.password

            pushsession = requests.Session()
            pushsession.mount(panoip, DESAdapter())
            urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

            if options.pushobjects or options.pushrules:
                set_web_tab('exec')
                for command, desc in pushcommands:
                    self.log(desc)
                    sys.stdout.flush()
                    response = pushsession.get(command, verify=False, headers={'authorization': "Basic " + base64.b64encode(
                        '{}:{}'.format(options.username, options.password).encode()).decode()})
                    if len(re.findall('success', response.text)) == 0:
                        self.log('', level=logging.ERROR)
                        self.log("!-- Error pushing command : ", level=logging.ERROR)
                        self.log(command, level=logging.ERROR)
                        self.log(response.text, level=logging.ERROR)
                        sys.stdout.flush()
                        exit(1)
                    else:
                        pass
                        # self.log('--> Success!')
                    # exec_fw_command('10.215.16.60', change[context]['fw_type'], [ pushcommands ],syntax='webui'))
            else:
                self.log('Command execution not enabled')

        # create groups that dont currently exist - and then use that in new rules

        # limitations :    currently only works with hosts for address objects (need to add split '/' to handle masks)
        #                  all services are treated as TCP - to change this, the input format will need to change

    if options.nick:

        import xml.etree.ElementTree as et
        import urllib

        import re

        panorama = et.parse(options.nick)
        root = panorama.getroot()

        for context in options.context:
            self.log('!-- Modifying Device-Group : ' + context)

            logprofiles = []
            for logs in root.findall(
                    './devices/entry/device-group/entry[@name=\'' + context + '\']/log-settings/profiles/entry'):
                logprofiles.append(logs.get('name'))
            self.log('-' * 100)
            self.log('Available Log Profiles')
            self.log('-' * 100)
            for logprofile in logprofiles:
                self.log(logprofile)

            self.log('-' * 100)
            self.log('Policies')
            self.log('-' * 100)
            policy_list = root.findall(
                './devices/entry/device-group/entry[@name=\'' + context + '\']/pre-rulebase/security/rules/entry')
            for policy in policy_list:
                self.log(policy.get('name'))

            panoip = '10.215.19.132'
            panoip = '10.215.18.25'
            new_logprofile = 'AMER-Dell-Standard-Logging'
            # new_logprofile='Splunk'
            pushcommands = []

            options.pushusername, options.pushpassword = get_creds()

            pushsession = requests.Session()
            pushsession.mount(panoip, DESAdapter())
            urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

            for context in options.context:
                for policy in policy_list:
                    # pushcommands.append(('https://' + options.puship + '/api/?type=config&action=set&xpath=' + urllib.parse.quote_plus("/config/devices/entry[@name='localhost.localdomain']/device-group/entry[@name=\"" + customops.devicegroup_name + "\"]") + "&element=<devices><entry name=\'" + device + "\'/></devices>", 'Adding device "' + device + '" to device-group'))
                    pushcommands.append((
                        'https://' + panoip + '/api/?type=config&action=set&xpath=' + urllib.parse.quote_plus(
                            "/config/devices/entry[@name='localhost.localdomain']/device-group/entry[@name='" + context + "']/pre-rulebase/security/rules/entry[@name='" + policy.get(
                                'name') + "']") + "&element=<log-setting>" + new_logprofile + "</log-setting><log-start>no</log-start><log-end>yes</log-end>",
                        'Modifying policy "' + policy.get(
                            'name') + '" to log at session end using log profile ' + new_logprofile))

                for command, desc in pushcommands:
                    self.log(desc)
                    sys.stdout.flush()
                    response = pushsession.get(command, verify=False, headers={'authorization': "Basic " + base64.b64encode(
                        '{}:{}'.format(options.username, options.password).encode()).decode()})
                    if len(re.findall('success', response.text)) == 0:
                        self.log('', level=logging.ERROR)
                        self.log("!-- Error pushing command : ", level=logging.ERROR)
                        self.log(command, level=logging.ERROR)
                        self.log(response.text, level=logging.ERROR)
                        sys.stdout.flush()
                        exit(1)
                    else:
                        pass

    if options.movecheckpoint:

        import copy

        config = {}
        config['source'] = load_checkpoint(secobj=options.checkpointpol, natobj=options.checkpointnat,
                                           svcobj=options.checkpointsvc, netobj=options.checkpointobj)
        # config['dest']=load_checkpoint(secobj=options.destcheckpointpol, natobj=options.destcheckpointnat, svcobj=options.destcheckpointsvc, netobj=options.destcheckpointobj)
        config['dest'] = load_checkpoint(secobj='labs_Security.xml', natobj='labs_NAT.xml', svcobj='labs_services.xml',
                                         netobj='labs_network_objects.xml')
        ## verify that all sources, dests and services have been loaded - some address types are not loaded and can not be moved
        policy_to_move = '##Israel-CoE-AFCC'

        config['shared'] = {}
        config['shared']['addresses'] = {}
        config['shared']['addressmappings'] = {}
        config['shared']['servicemappings'] = {}
        config['shared']['services'] = {}
        config['shared']['policies'] = {}
        config['shared']['nat'] = {}
        config['shared']['config'] = {}
        # config['shared']['']={}

        config['new'] = {}
        config['new']['policies'] = OrderedDict()
        config['new']['addresses'] = OrderedDict()
        config['new']['services'] = OrderedDict()
        config['new']['addressmappings'] = {}
        config['new']['servicemappings'] = {}

        all_addresses = []
        all_services = []

        ## Create svcSet property for every service group

        for context in ['source', 'dest']:
            for policy in config[context]['policies']:
                for service in config[context]['services']:
                    if service.lower() not in ['', 'any'] and config[context]['services'][service]['svcObjType'] == '2':
                        if 'svcSet' not in config[context]['services'][service]:
                            config[context]['services'][service]['svcSet'] = []
                            for member in expand_service(config[context]['services'], service,
                                                         config[context]['servicemappings']):
                                config[context]['services'][service]['svcSet'].append((config[context]['services'][member][
                                                                                           'svcObjIpType'],
                                                                                       config[context]['services'][member][
                                                                                           'svcObjPort1'],
                                                                                       config[context]['services'][member][
                                                                                           'svcObjPort2']))
                        config[context]['services'][service]['svcSet'].sort(key=lambda tup: (tup[0], tup[1], tup[2]))

        ## build list of all address objects used in policies

        for policy in config['source']['policies']:
            if config['source']['policies'][policy]['policyName'] == policy_to_move:
                config['new']['policies'][policy] = copy.deepcopy(config['source']['policies'][policy])
                for member in config['source']['policies'][policy]['policySrcNet']:  # do everything but groups for now.
                    if member.lower() != 'any':
                        if config['source']['addresses'][member]['addrObjType'] in ['8']:
                            source_list = expand_address(config['source']['addresses'], member,
                                                         config['source']['addressmappings'], inc_group=True)
                            source_list.extend([member])  # make sure parent group is included in list
                        else:
                            source_list = [member]
                        for source in source_list:
                            if source not in all_addresses: all_addresses.append(source)
                for member in config['source']['policies'][policy]['policyDstNet']:  # do everything but groups for now.
                    if member.lower() != 'any':
                        if config['source']['addresses'][member]['addrObjType'] in ['8']:
                            dest_list = expand_address(config['source']['addresses'], member,
                                                       config['source']['addressmappings'], inc_group=True)
                            dest_list.extend([member])  # make sure parent group is included in list
                        else:
                            dest_list = [member]
                        for dest in dest_list:
                            if dest not in all_addresses: all_addresses.append(dest)
                for member in config['source']['policies'][policy]['policyDstSvc']:  # do everything but groups for now.
                    if member.lower() != 'any':
                        if config['source']['services'][member]['svcObjType'] in ['2']:
                            service_list = expand_service(config['source']['services'], member,
                                                          config['source']['servicemappings'], inc_group=True)
                            service_list.extend([member])  # make sure parent group is included in list
                        else:
                            service_list = [member]
                        for dest in service_list:
                            if dest not in all_services: all_services.append(dest)

        ## create new address objects and source_to_new mappings

        move_map = {}
        rev_map = {}

        for source in all_addresses:
            source_match = False
            if source.lower() in [x.lower() for x in config['source']['addresses']]:
                # if source not in config['new']['addresses']: ## if address is in new dict, it was already searched, no need to do it again
                for dest in config['dest']['addresses']:
                    if config['source']['addresses'][source]['addrObjType'] != '8':
                        if config['dest']['addresses'][dest]['addrObjType'] != '8':
                            if config['source']['addresses'][source]['addrObjIp1'] == config['dest']['addresses'][dest][
                                'addrObjIp1'] and config['source']['addresses'][source]['addrObjIp2'] == \
                                    config['dest']['addresses'][dest]['addrObjIp2']:
                                self.log('      address match    {:50.50s} {:50.50s} '.format(source, dest))
                                config['new']['addresses'][dest] = copy.deepcopy(config['dest']['addresses'][dest])
                                source_match = True
                                move_map[source] = dest
                                rev_map[dest] = source
                                break
                    elif config['source']['addresses'][source]['addrObjType'] in ['8']:
                        if config['dest']['addresses'][dest]['addrObjType'] in ['8']:
                            if config['source']['addresses'][source]['IPSet'] == config['dest']['addresses'][dest]['IPSet']:
                                self.log('address group match    {:50.50s} {:50.50s} : '.format(source, dest))
                                config['new']['addresses'][dest] = copy.deepcopy(config['dest']['addresses'][dest])
                                source_match = True
                                move_map[source] = dest
                                rev_map[dest] = source
                                break
            if not source_match:
                # debug([x.lower() for x in config['dest']['addresses']])
                if source.lower() in [x.lower() for x in config['dest']['addresses']]:
                    new_key = source + '_NEW'
                else:
                    new_key = source
                self.log(' no match found for     {:50.50s} {:50.50s}'.format(source, new_key))
                move_map[source] = new_key
                rev_map[new_key] = source
                config['new']['addresses'][new_key] = copy.deepcopy(config['source']['addresses'][source])
                config['new']['addresses'][new_key]['addrObjId'] = new_key

        for source in all_services:
            source_match = False
            if source not in config['source']['services']:
                debug('Service not found in config : ' + source)
            if source not in config['new'][
                'services']:  ## if address is in new dict, it was already searched, no need to do it again
                for dest in config['dest']['services']:
                    if config['source']['services'][source]['svcObjType'] != '2':
                        if config['dest']['services'][dest]['svcObjType'] != '2':
                            if config['source']['services'][source]['svcObjPort1'] == config['dest']['services'][dest][
                                'svcObjPort1'] and config['source']['services'][source]['svcObjPort2'] == \
                                    config['dest']['services'][dest]['svcObjPort2'] and \
                                    config['source']['services'][source]['svcObjIpType'] == \
                                    config['dest']['services'][dest]['svcObjIpType']:
                                self.log('      service match    {:50.50s} {:50.50s} '.format(source, dest))
                                config['new']['services'][dest] = copy.deepcopy(config['dest']['services'][dest])
                                source_match = True
                                move_map[source] = dest
                                rev_map[dest] = source
                                break
                    elif config['source']['services'][source]['svcObjType'] in ['2']:
                        if config['dest']['services'][dest]['svcObjType'] in ['2']:
                            if config['source']['services'][source]['svcSet'] == config['dest']['services'][dest]['svcSet']:
                                self.log('service group match    {:50.50s} {:50.50s} : '.format(source, dest))
                                config['new']['services'][dest] = copy.deepcopy(config['dest']['services'][dest])
                                source_match = True
                                move_map[source] = dest
                                rev_map[dest] = source
                                break
            if not source_match:
                if source.lower() in [x.lower() for x in config['dest']['services']]:
                    new_key = source + '_NEW'
                else:
                    new_key = source
                self.log(' no svc match found for  {:50.50s} {:50.50s}'.format(source, new_key))
                move_map[source] = new_key
                rev_map[new_key] = source
                config['new']['services'][new_key] = copy.deepcopy(config['source']['services'][source])
                config['new']['services'][new_key]['svcObjId'] = new_key

        ## create new addressmappings

        ## source to new mappings -- use a IsNew key in source?

        for mapping in config['source']['addressmappings']:
            # if move_map[mapping] in config['new']['addresses']:
            if mapping in move_map:
                self.log('-' * 100)
                self.log('address group {} needs to be updated'.format(mapping))
                config['new']['addressmappings'][move_map[mapping]] = []
                for member in config['source']['addressmappings'][mapping]:
                    config['new']['addressmappings'][move_map[mapping]].append(move_map[member])
                    self.log(member, move_map[member])

        for mapping in config['source']['servicemappings']:
            # if move_map[mapping] in config['new']['addresses']:
            if mapping in move_map:
                self.log('-' * 100)
                self.log('service group {} needs to be updated'.format(mapping))
                config['new']['servicemappings'][move_map[mapping]] = []
                for member in config['source']['servicemappings'][mapping]:
                    config['new']['servicemappings'][move_map[mapping]].append(move_map[member])
                    self.log(member, move_map[member])

                    ## create new DstNet and SrcNet lists for policies

        for policy in config['source']['policies']:
            if config['source']['policies'][policy]['policyName'] == policy_to_move:
                config['new']['policies'][policy]['policySrcNet'] = []
                config['new']['policies'][policy]['policyDstNet'] = []
                config['new']['policies'][policy]['policyDstSvc'] = []
                for member in config['source']['policies'][policy]['policySrcNet']:
                    if member.lower() == 'any':
                        config['new']['policies'][policy]['policySrcNet'].append('Any')
                    else:
                        config['new']['policies'][policy]['policySrcNet'].append(move_map[member])
                for member in config['source']['policies'][policy]['policyDstNet']:
                    if member.lower() == 'any':
                        config['new']['policies'][policy]['policyDstNet'].append('Any')
                    else:
                        config['new']['policies'][policy]['policyDstNet'].append(move_map[member])
                for member in config['source']['policies'][policy]['policyDstSvc']:
                    # print(member)
                    if member.lower() == 'any':
                        config['new']['policies'][policy]['policyDstSvc'].append('Any')
                    else:
                        config['new']['policies'][policy]['policyDstSvc'].append(move_map[member])
                # config['new']['policies'][policy]['policyDstSvc']=copy.deepcopy(config['source']['policies'][policy]['policyDstSvc'])
                if len(config['new']['policies'][policy]['policySrcNet']) != len(
                        config['source']['policies'][policy]['policySrcNet']):
                    print('length of SrcNet does not match')
                if len(config['new']['policies'][policy]['policyDstNet']) != len(
                        config['source']['policies'][policy]['policyDstNet']):
                    print('length of DstNet does not match')
        for mapping in config['new']['addressmappings']:
            if len(config['new']['addressmappings'][mapping]) != len(config['source']['addressmappings'][rev_map[mapping]]):
                print('-' * 100)
                print(mapping + 'does not match ' + rev_map[mapping])

        ## Build dbedit commands

        print('## building dbedit commands')
        for address in config['new']['addresses']:
            if address not in config['dest']['addresses']:
                # print('create address type {} : {}'.format(config['new']['addresses'][address]['addrObjType'], address))
                if config['new']['addresses'][address]['addrObjType'] == '1':
                    self.log('create host_plain ' + address)
                elif config['new']['addresses'][address]['addrObjType'] == '2':
                    self.log('create address_range ' + address)
                elif config['new']['addresses'][address]['addrObjType'] == '4':
                    self.log('create network ' + address)
                elif config['new']['addresses'][address]['addrObjType'] == '8':
                    self.log('create network_object_group ' + address)
                elif config['new']['addresses'][address]['addrObjType'] == '99':
                    self.log('create host_ckp ' + address)
                else:
                    debug('dont know how to create object type : ' + config['new']['addresses'][address]['addrObjType'])

        for service in config['new']['services']:
            if service not in config['dest']['services']:
                # print('create service type {} : {}'.format(config['new']['services'][service]['svcObjType'], service))
                if config['new']['services'][service]['svcObjType'] == '1':
                    if config['new']['services'][service]['svcObjIpType'] == '6':
                        self.log('create tcp_service ' + service)
                    elif config['new']['services'][service]['svcObjIpType'] == '17':
                        self.log('create udp_service ' + service)
                    else:
                        debug('unknown service type : "' + config['new']['services'][service]['svcObjIpType'] + '"')
                if config['new']['services'][service]['svcObjType'] == '2':
                    self.log('create service_group ' + service)
        self.log('create firewall_policy ' + policy_to_move)
        self.log('update_all')
        ## Modify object properties

        for address in config['new']['addresses']:
            if address not in config['dest']['addresses']:
                # print('create address type {} : {}'.format(config['new']['addresses'][address]['addrObjType'], address))
                if config['new']['addresses'][address]['addrObjType'] == '1':
                    self.log('modify network_objects ' + address + ' ipaddr ' + config['new']['addresses'][address][
                        'addrObjIp1'])
                    self.log('modify network_objects ' + address + ' comments "' + config['new']['addresses'][address][
                        'addrObjComment'] + '"')
                    self.log('modify network_objects ' + address + ' color ' + config['new']['addresses'][address][
                        'addrObjColor'])
                elif config['new']['addresses'][address]['addrObjType'] == '2':
                    self.log('modify network_objects ' + address + ' ipaddr_first ' + config['new']['addresses'][address][
                        'addrObjIp1'])
                    self.log('modify network_objects ' + address + ' ipaddr_last ' + config['new']['addresses'][address][
                        'addrObjIp2'])
                    self.log('modify network_objects ' + address + ' comments "' + config['new']['addresses'][address][
                        'addrObjComment'] + '"')
                    self.log('modify network_objects ' + address + ' color ' + config['new']['addresses'][address][
                        'addrObjColor'])
                elif config['new']['addresses'][address]['addrObjType'] == '4':
                    self.log('modify network_objects ' + address + ' ipaddr ' + config['new']['addresses'][address][
                        'addrObjIp1'])
                    self.log('modify network_objects ' + address + ' netmask ' + config['new']['addresses'][address][
                        'addrObjIp2'])
                    self.log('modify network_objects ' + address + ' comments "' + config['new']['addresses'][address][
                        'addrObjComment'] + '"')
                    self.log('modify network_objects ' + address + ' color ' + config['new']['addresses'][address][
                        'addrObjColor'])
                elif config['new']['addresses'][address]['addrObjType'] == '8':
                    self.log('modify network_objects ' + address + ' comments "' + config['new']['addresses'][address][
                        'addrObjComment'] + '"')
                    self.log('modify network_objects ' + address + ' color ' + config['new']['addresses'][address][
                        'addrObjColor'])
                    # self.log('modify network_objects ' + address)
                elif config['new']['addresses'][address]['addrObjType'] == '99':
                    # self.log('modify network_objects ' + address)
                    pass  # do nothing for now

        for service in config['new']['services']:
            if service not in config['dest']['services']:
                # print('create service type {} : {}'.format(config['new']['services'][service]['svcObjType'], service))
                if config['new']['services'][service]['svcObjType'] == '1':
                    self.log('modify services ' + service + ' color ' + config['new']['services'][service]['svcObjColor'])
                    self.log('modify services ' + service + ' port ' + config['new']['services'][service]['svcObjPort1'])
                    self.log('modify services ' + service + ' comments "' + config['new']['services'][service][
                        'svcObjComment'] + '"')
                if config['new']['services'][service]['svcObjType'] == '2':
                    # self.log('modify services ' + service + ' port ' + config['new']['services'][service]['svcObjPort1'])
                    self.log('modify services ' + service + ' comments "' + config['new']['services'][service][
                        'svcObjComment'] + '"')

        for address in config['new']['addresses']:
            if address not in config['dest']['addresses']:
                if config['new']['addresses'][address]['addrObjType'] == '8':
                    for member in config['new']['addressmappings'][address]:
                        self.log('addelement network_objects ' + address + ' \'\' network_objects:' + member)

        for service in config['new']['services']:
            if service not in config['dest']['services']:
                if config['new']['services'][service]['svcObjType'] == '2':
                    for member in config['new']['servicemappings'][service]:
                        self.log('addelement services ' + service + ' \'\' services:' + member)

        index = 0
        for policy in config['new']['policies']:
            # print ('creating policy : ' + str(policy))

            if config['new']['policies'][policy]['policyEnabled'] == '1':
                disabled = 'false'
            else:
                disabled = 'true'
            if config['new']['policies'][policy]['policyAction'] == '0':
                action = 'drop_action:deny'
            elif config['new']['policies'][policy]['policyAction'] == '1':
                action = 'drop_action:drop'
            elif config['new']['policies'][policy]['policyAction'] == '3':  ## changeme
                # action='drop_action:drop'
                pass
            else:  # config['new']['policies'][policy]['policyAction']=='2':
                action = 'accept_action:accept'

            self.log('addelement fw_policies ' + policy_to_move + ' rule security_rule')
            # self.log('update fw_policies ' + policy_to_move)
            # self.log('update')
            self.log('modify fw_policies ' + policy_to_move + ' rule:' + str(index) + ':comments "' +
                config['new']['policies'][policy]['policyComment'] + '"')
            self.log('modify fw_policies ' + policy_to_move + ' rule:' + str(index) + ':disabled ' + disabled)
            self.log('addelement fw_policies ' + policy_to_move + ' rule:' + str(index) + ':action ' + action)
            for source in config['new']['policies'][policy]['policySrcNet']:
                if source.lower() != 'any': self.log("addelement fw_policies " + policy_to_move + " rule:" + str(
                    index) + ":src:'' network_objects:" + source)
            for dest in config['new']['policies'][policy]['policyDstNet']:
                if dest.lower() != 'any': self.log(
                    "addelement fw_policies " + policy_to_move + " rule:" + str(index) + ":dst:'' network_objects:" + dest)
            for service in config['new']['policies'][policy]['policyDstSvc']:
                if service.lower() != 'any': self.log(
                    "addelement fw_policies " + policy_to_move + " rule:" + str(index) + ":services:'' services:" + service)
            index += 1

        self.log('update_all')

        ## not implemented:
        ## service colors
        ## policy colors

        # config['new']['services']=copy.deepcopy(config['source']['services'])  ## temp so that i can dump the config
        # config['new']['servicemappings']=copy.deepcopy(config['source']['servicemappings'])

        # config['new']['addressmappings']=config['source']['addressmappings']
        # config['new']['addresses']=config['source']['addresses']
        ## config['new']=config['source'] - this produced identical tuple files

        # dump_config(config, ['source', 'new'])
        create_tuples(config, 'source.tup', 'all', ['source'], policy_to_move)
        create_tuples(config, 'new.tup', 'all', ['new'], policy_to_move)

    if options.emcroute:

        import urllib
        import ipaddress

        for member in options.emcroute[1].split(','):  # verify all specified subnets are valid
            try:
                tmp = ipaddress.IPv4Network(member)
            except Exception as e:
                debug('Problem with specified destination network -- {}'.format(e))
                debug('Fatal error -- Exiting')
                exit(1)

        for i in config:
            matched_route = False
            if i != 'shared':
                if 'routing' in config[i]:
                    for route in config[i]['routing']:
                        if config[i]['routing'][route]['pbrObjDst'] != '':  # destination = any
                            if ipaddress.IPv4Network(options.emcroute[0]) in \
                                    config[i]['addresses'][config[i]['routing'][route]['pbrObjDst']]['IPv4Networks']:
                                pass
                            sources = expand_address(config[i]['addresses'], config[i]['routing'][route]['pbrObjSrc'],
                                                     config[i]['addressmappings'])
                            dests = expand_address(config[i]['addresses'], config[i]['routing'][route]['pbrObjDst'],
                                                   config[i]['addressmappings'])
                            if config[i]['routing'][route]['pbrObjGw'] != '':
                                gw = config[i]['addresses'][config[i]['routing'][route]['pbrObjGw']]['addrObjIp1']
                            else:
                                gw = 'Blank'
                            maxlen = max(set([len(sources), len(dests)]))

                            for line in range(0, maxlen):
                                if len(sources) == 0:
                                    source = 'any'
                                elif line < len(sources):
                                    source = sources[line]
                                else:
                                    source = ''
                                if len(dests) == 0:
                                    dest = 'any'
                                elif line < len(dests):
                                    dest = dests[line]
                                else:
                                    dest = ''
                                if line == 0:
                                    name = urllib.parse.unquote(config[i]['routing'][route]['pbrObjId'])
                                    iface = urllib.parse.unquote(config[i]['routing'][route]['pbrObjIfaceName'])
                                else:
                                    name = ''
                                    iface = ''
                                if source == '' or source == 'any':  # only match if source is any/blank
                                    if dest in config[i]['addresses']:
                                        if ipaddress.IPv4Network(options.emcroute[0]) in config[i]['addresses'][dest][
                                            'IPv4Networks']:
                                            self.log("EMC-Public-Internal" in expand_address(config[i]['addresses'],
                                                                                        config[i]['routing'][route][
                                                                                            'pbrObjDst'],
                                                                                        config[i]['addressmappings'],
                                                                                        inc_group=True))
                                            matched_route = config[i]['routing'][route]
                                            break
                    if matched_route:
                        dstzone = config[i]['addresses'][expand_address(config[i]['addresses'], matched_route['pbrObjDst'],
                                                                        config[i]['addressmappings'])[0]]['addrObjZone']
                        group_name = "EMC-Public-Internal"
                        gindex = 1
                        while group_name in config[i]['addresses']:
                            group_name = "EMC-Public-Internal_" + str(gindex)
                            gindex += 1
                        gindex = 0
                        group_members = OrderedDict()
                        # log ('Creating Group : ' + group_name)
                        for member in options.emcroute[1].split(
                                ','):  # consider searching for existing network objects first
                            # self.log(options.emcroute[0])
                            # self.log(member)
                            network, mask = member.split('/')
                            group_members[gindex] = {}
                            group_members[gindex]['name'] = 'N-' + network + '-' + mask
                            mindex = 1
                            while group_members[gindex]['name'] == 'N-' + network + '-' + mask in config[i]['addresses']:
                                group_members[gindex]['name'] = 'N-' + network + '-' + mask + '_' + str(mindex)
                                mindex += 1
                            group_members[gindex]['ip1'] = network
                            group_members[gindex]['ip2'] = cidr_to_netmask(mask)
                            group_members[gindex]['zone'] = dstzone
                            # self.log('Adding Group Member : ' + group_members[gindex]['name'])
                            gindex += 1
                        self.log('configure')
                        for idx in group_members:
                            self.log('address-object ipv4 "' + group_members[idx]['name'] + '" network ' + group_members[idx][
                                'ip1'] + ' ' + group_members[idx]['ip2'] + ' zone ' + group_members[idx]['zone'])
                        self.log('commit')
                        self.log('address-group ipv4 "' + group_name + '"')
                        for idx in group_members:
                            self.log('address-object ipv4 "' + group_members[idx]['name'] + '"')
                        self.log('commit')
                        self.log('exit')
                        # modify route via group membership, or add a new rule?
                        # self.log(matched_route['pbrObjDst'])
                        # self.log(config[i]['addresses'][matched_route['pbrObjDst']])
                        if config[i]['addresses'][matched_route['pbrObjDst']]['addrObjType'] == '8':
                            self.log('address-group ipv4 "' + matched_route['pbrObjDst'] + '"')
                            self.log('address-group ipv4 "' + group_name + '"')
                            self.log('commit')
                            self.log('exit')
                        else:
                            if matched_route['pbrObjGw'] in config[i][
                                'addresses']:  ## if dst gw object exists in addresses, add it using name paramter
                                self.log('routing')
                                self.log('policy interface {} metric 1 source any destination group "{}" service any gateway name "{}"'.format(
                                    urllib.parse.unquote(matched_route['pbrObjIfaceName'])[3:], group_name,
                                    urllib.parse.unquote(matched_route['pbrObjGw'])))
                                self.log('comment "EMC-Public-Internal route addition via script - jeff_miller2"')
                                self.log('commit')
                                self.log('exit')
                            else:  # otherwise add the destination as if it is an ip address
                                self.log('routing')
                                self.log('policy interface {} metric 1 source any destination group "{}" service any gateway host "{}"'.format(
                                    urllib.parse.unquote(matched_route['pbrObjIfaceName'])[3:], group_name,
                                    urllib.parse.unquote(matched_route['pbrObjGw'])))
                                self.log('comment "EMC-Public-Internal route addition via script - jeff_miller2"')
                                self.log('commit')
                                self.log('exit')
                        break  # matched address found, changes made, exit loop
                        # print('{:30.30s} {:30.30s} {:30.30s} {:30.30s} {:30.30s}'.format(name, iface, source, dest, gw ))
                        # print ('=' *150)

    if options.batch:
        for cmd in options.batch:
            if cmd[0] == "@":
                cmd = file_to_list(cmd[1:])
            self.log(cmd)

    if options.gordon:
        configfilename = "config_python.txt"

        import re
        import urllib
        import os

        if not os.path.isfile(
                configfilename):  # if file does not exist, exit with error to let calling script know something went wrong
            exit(1)
        with open(configfilename) as working_file:

            config = working_file.read()
            firewallname = re.findall('firewallName=.*', config)[0].split('=')[1]
            for x in re.findall(r'userObjId.*', config):
                username = x.split('=')[1]
                print(firewallname + ',' + urllib.parse.unquote(username), end='')
                groupnums = re.findall(r'uo_atomToGrp.*' + username, config)
                for idx, groupnum in enumerate(groupnums):
                    # print(groupnum.split('=')[0].split('_')[-1])
                    group = re.findall(r'uo_grpToGrp_' + groupnum.split('=')[0].split('_')[-1] + '=.*', config)
                    if idx == 0:
                        print(',' + urllib.parse.unquote(group[0].split('=')[1]), end='')
                    else:
                        print('|' + urllib.parse.unquote(group[0].split('=')[1]), end='')
                print('')

    if options.management:

        for context in config:
            if context != 'shared':
                # log ('=' * 180)
                # log (config[context]['config']['name'])
                '''
                for route in config[context]['routing']:
                    if config[context]['routing'][route]['pbrObjDst'] in ['0.0.0.0', '']:
                        self.log('Default Gateway "[' + config[context]['routing'][route]['pbrObjDst'] + ']" : "' + url_unquote(config[context]['routing'][route]['pbrObjGw']) + '" - ')
                        if config[context]['routing'][route]['pbrObjGw']!='':
                            self.log(config[context]['addresses'][config[context]['routing'][route]['pbrObjGw']]['addrObjIp1'])
                            def_gw=config[context]['addresses'][config[context]['routing'][route]['pbrObjGw']]['addrObjIp1']
                '''
                self.log('-' * 180)
                # self.log('{:20.20s} {:20.20s} {:20.20s} {:20.20s} {:20.20s} {:20.20s} {:20.20s} {:20.20s} {:20.20s} {:20.20s} '.format('Interface', 'Type', 'IP', 'Zone', 'HTTP', 'HTTPS', 'SSH', 'PING', 'SNMP'))
                self.log('{:s},{:s},{:s},{:s},{:s},{:s},{:s},{:s},{:s},{:s}'.format('Firewall', 'Interface', 'Type', 'IP',
                                                                               'Zone', 'HTTP', 'HTTPS', 'SSH', 'PING',
                                                                               'SNMP'))
                self.log('-' * 180)

                for interface in config[context]['interfaces']:
                    # self.log(config[context]['interfaces'][interface])
                    if config[context]['interfaces'][interface]['portShutdown'].lower() == 'off' and \
                            config[context]['interfaces'][interface]['iface_type'] in ['6', '7', '17', '1']:
                        if config[context]['interfaces'][interface]['iface_type'] in ['6', '7']:
                            tmp_ip = config[context]['interfaces'][interface]['iface_lan_ip']
                        elif config[context]['interfaces'][interface]['iface_type'] in ['1']:
                            tmp_ip = config[context]['interfaces'][interface]['iface_static_ip']
                        elif config[context]['interfaces'][interface]['iface_type'] in ['17']:
                            tmp_ip = config[context]['interfaces'][interface]['iface_mgmt_ip']
                        # self.log('{:20.20s} {:20.20s} {:20.20s} {:20.20s} {:20.20s} {:20.20s} {:20.20s} {:20.20s} {:20.20s} {:20.20s} '.format(
                        self.log('{:s},{:s},{:s},{:s},{:s},{:s},{:s},{:s},{:s},{:s}'.format(
                            config[context]['config']['name'],
                            config[context]['interfaces'][interface]['iface_name'],
                            config[context]['interfaces'][interface]['iface_type'],
                            tmp_ip,
                            config[context]['interfaces'][interface]['interface_Zone'],
                            str(config[context]['interfaces'][interface]['iface_http_mgmt'] == '1'),
                            str(config[context]['interfaces'][interface]['iface_https_mgmt'] == '1'),
                            str(config[context]['interfaces'][interface]['iface_ssh_mgmt'] == '1'),
                            str(config[context]['interfaces'][interface]['iface_ping_mgmt'] == '1'),
                            str(config[context]['interfaces'][interface]['iface_snmp_mgmt'] == '1')))

    if options.sw_get_tsr:
        import sonicwall as sw

        for target in options.grouptargets:
            sw.get_tsr(target, options.username, options.password)

    if options.sw_upload_fw or options.sw_backup:
        def run_parallel(targets, max_proc=48):
            from multiprocessing import Pool

            pool = Pool(processes=max_proc)
            pool.map(sw_firmware, targets)  # , chunksize=5)
            pool.close()


        #
        run_parallel(options.grouptargets)

    if options.sw_failover:

        import requests
        import sonicwall as sw
        import re
        import json

        if not options.web and (options.username == None or options.password == None):
            options.username, options.password = get_creds()

        for host in options.grouptargets:
            try:
                self.log('!-- Force failover requested for : ' + host)

                post_headers = defaultdict(dict)
                post_headers['Connection'] = 'Keep-Alive'
                post_headers[
                    'User-Agent'] = 'Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/59.0.3071.115 Safari/537.36'
                post_headers['Referer'] = 'https://' + host + '/haAdvancedConfig.html'
                post_headers['Origin'] = 'https://' + host
                post_headers['Accept'] = 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8'
                post_headers['Accept-Encoding'] = 'gzip, deflate, br'
                post_headers['Accept-Language'] = 'en-US,en;q=0.5'
                post_headers['Host'] = host
                post_headers['Upgrade-Insecure-Requests'] = '1'

                session = requests.Session()
                session.mount('https://' + host, sw.DESAdapter())

                response = sw.do_login(session, options.username, options.password, host,
                                       True)  ## need to be in config mode to request reboot

                response = sw.get_url(session, 'https://' + host + '/haAdvancedConfig.html')
                csrf = re.findall(r'csrfToken.*"', response.text)[0].split('value=')[1].split('"')[1]

                content = {'csrfToken': csrf,
                           'cgiaction': 'forceHaFailover',
                           }

                command = 'https://' + host + '/main.cgi'  # ?csrfToken=' + csrf + '&cgiaction=none&file=upload&cbox_diag=&cbox_fwAutoUpdate=&cbox_fwAutoDownload=&cbox_fipsMode=&cbox_ndppMode='
                self.log('!-- Sending failover command')

                response = session.post(command, verify=False, data=content,
                                        timeout=options.timeout_sw_webui_post)  # , headers=post_headers)
                debug(response.text)
            except Exception as e:
                self.log(e)

    if options.sw_reboot:

        import requests
        import sonicwall as sw
        import re
        import json

        # host = options.sw_reboot
        target_version = "6.5.4.8"  # Only upgrade firewalls not on 6.5.4.8
        # target_version = "6.1.1"

        if not options.web and (options.username == None or options.password == None):
            options.username, options.password = get_creds()

        for host in options.grouptargets:

            self.log('!-- Reboot with uploaded firmware requested for : ' + host)

            post_headers = defaultdict(dict)
            post_headers['Connection'] = 'Keep-Alive'
            post_headers[
                'User-Agent'] = 'Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/59.0.3071.115 Safari/537.36'
            post_headers['Referer'] = 'https://' + host + '/systemSettingsView.html'
            post_headers['Origin'] = 'https://' + host
            post_headers['Accept'] = 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8'
            post_headers['Accept-Encoding'] = 'gzip, deflate, br'
            post_headers['Accept-Language'] = 'en-US,en;q=0.5'
            post_headers['Host'] = host
            post_headers['Upgrade-Insecure-Requests'] = '1'

            session = requests.Session()
            session.mount('https://' + host, sw.DESAdapter())

            response = sw.do_login(session, options.username, options.password, host,
                                   True)  ## need to be in config mode to request reboot

            response = sw.get_url(session, 'https://' + host + '/getJsonData.json?_=1566657857&dataSet=alertStatus')
            # self.log(response.text)
            resp_json = json.loads(response.text)
            active = (resp_json['svrrpNodeState'].lower() == 'active' or resp_json['svrrpHaMode'].lower() == 'standalone')

            if active:
                response = sw.get_url(session, 'https://' + host + '/systemSettingsView.html')
                csrf = re.findall(r'csrfToken.*"', response.text)[0].split('value=')[1].split('"')[1]
                response = sw.get_url(session, 'https://' + host + '/systemStatusView.html',
                                      timeout=options.timeout_sw_webui)
                systemStatusObjects = re.sub(r', ', ',', re.sub(r'\'', '',
                                                                re.sub(r'.*systemStatusObject\((.*?)\);.*', r'\1',
                                                                       response.text, flags=re.DOTALL))).split(',')
                firmwareversion = systemStatusObjects[5]
                self.log('{},{}'.format(firmwareversion, target_version))
                if len(re.findall(target_version, firmwareversion)) == 0:
                    # content=OrderedDict([('csrfToken', (None, csrf)), ('cgiaction', (None, 'None')), ('file', (None, 'Upload'))])
                    content = {'csrfToken': csrf,
                               'cgiaction': 'none',
                               'file': 'upload',
                               'cbox_diag': '',
                               'cbox_fwAutoUpdate': '',
                               'cbox_fwAutoDownload': '',
                               'cbox_fipsMode': '',
                               'cbox_ndppMode': ''}

                    command = 'https://' + host + '/boot.cgi'  # ?csrfToken=' + csrf + '&cgiaction=none&file=upload&cbox_diag=&cbox_fwAutoUpdate=&cbox_fwAutoDownload=&cbox_fipsMode=&cbox_ndppMode='
                    self.log('!-- Sending reboot command')
                    try:
                        response = session.post(command, verify=False, data=content,
                                                timeout=options.timeout_sw_webui_post)  # , headers=post_headers)
                        debug(response.text)
                    except Exception as e:
                        self.log(e)
                else:
                    self.log('!-- Skipping reboot request, already on {}'.format(target_version))
                    exit(1)
            else:
                self.log('!-- Skipping reboot request - not active appliance : ' + host)
                exit(1)
            # print(command)
            # print(csrf)

    if options.nexposerule:

        def run_parallel(targets, max_proc=48):

            from multiprocessing import Pool

            pool = Pool(processes=max_proc)
            results = pool.map(bulk_create_rules, targets)  # , chunksize=5)
            pool.close()
            return results


        if options.grouptargets:
            results = run_parallel(options.grouptargets)
            # self.log(results)
            for itemset in results:
                for target, result, rule_name, action, src_zone, src_address, dst_zone, dst_address, dst_service, comment in itemset:
                    if result != 'Exception':
                        self.log('{},{},{},{},{},{},{},{},{},{}'.format(target, result, rule_name, action, src_zone, src_address,
                                                                   dst_zone, dst_address, dst_service, comment))
                    else:
                        self.log('{},{},{}'.format(target, 'Exception', rule_name))
        else:
            bulk_create_addresses(None)

    if options.fixzones:
        self.log('')
        self.log(options.fixzones)
        # for context in config:
        #    self.log(context)
        if options.fixzones in config:
            # options.username='admin'
            # options.password='snowflake'
            # fwip='10.215.18.81'
            fw = 'pano'
            config[options.fixzones]['routing'], config[options.fixzones]['interfaces'], config[options.fixzones][
                'zones'] = load_checkpoint_routing(options.checkpointroute)
            for interface in config[options.fixzones]['interfaces']:
                if config[options.fixzones]['interfaces'][interface]['iface_name'] == 'eth1-01':
                    config[options.fixzones]['interfaces'][interface]['interface_Zone'] = 'Extranet_DMZ'  ##PS3
                    config[options.fixzones]['interfaces'][interface]['interface_Zone'] = 'Extranet_DMZ'  ##PC1
                if config[options.fixzones]['interfaces'][interface]['iface_name'] == 'eth2-01':
                    config[options.fixzones]['interfaces'][interface]['interface_Zone'] = 'Dell_Corp'  ##PS3
                    config[options.fixzones]['interfaces'][interface]['interface_Zone'] = 'Dell_Corp'  ##PC1
                if config[options.fixzones]['interfaces'][interface]['iface_name'] == 'eth1-02':
                    config[options.fixzones]['interfaces'][interface]['interface_Zone'] = 'External_OSP'  ##PS3
                    config[options.fixzones]['interfaces'][interface]['interface_Zone'] = 'External_OSP'  ##PC1
                if config[options.fixzones]['interfaces'][interface]['iface_name'] == 'bond1':
                    config[options.fixzones]['interfaces'][interface]['interface_Zone'] = 'DTC_DMZ'  ##PS3
                    config[options.fixzones]['interfaces'][interface]['interface_Zone'] = 'DTC_DMZ'  ##PC1
            # self.log(get_zone_old(options.fixzones, '163.244.108.0'))
            # exit(1)
            # self.log(config[options.fixzones]['zones'])
            src_counter = 0
            dst_counter = 0
            for policy in config[options.fixzones]['policies']:
                policy_name = config[options.fixzones]['policies'][policy]['policyName']
                # self.log(config[options.fixzones]['policies'][policy])
                policy_src_zones = []
                policy_dst_zones = []
                new_policy_src_zones = []
                new_policy_dst_zones = []

                for address in config[options.fixzones]['policies'][policy]['policySrcNet']:
                    tmp_src_zones = get_zones(options.fixzones, address)
                    for zone in tmp_src_zones:
                        if zone not in policy_src_zones:
                            policy_src_zones.append(zone)
                policy_src_zones.sort()
                config[options.fixzones]['policies'][policy]['policySrcZone'].sort()
                for zone in policy_src_zones:
                    if zone not in config[options.fixzones]['policies'][policy]['policySrcZone'] and \
                            config[options.fixzones]['policies'][policy]['policySrcZone'] != ['any']:
                        if zone not in new_policy_src_zones:
                            new_policy_src_zones.append(zone)
                        src_counter += 1
                if new_policy_src_zones != []:
                    result = 'Read-Only'
                    result = exec_fw_command(options.panoramaip, fw, [('modify_rule',
                                                                       {'action': 'addmembers', 'policyname': policy_name,
                                                                        'srczones': new_policy_src_zones,
                                                                        'context': options.fixzones})], syntax='api')
                    self.log('Policy {} Orig Src Zones: {} Added Zones: {} Result: {}'.format(policy, config[options.fixzones][
                        'policies'][policy]['policySrcZone'], new_policy_src_zones, result))

                # if (set(config[options.fixzones]['policies'][policy]['policySrcZone']) & set(policy_src_zones) != set(config[options.fixzones]['policies'][policy]['policySrcZone'])) and config[options.fixzones]['policies'][policy]['policySrcZone'] != ['any']:
                #   self.log('Policy {} Src Zones: {} Computed Zones: {}'.format(policy, config[options.fixzones]['policies'][policy]['policySrcZone'], policy_src_zones))

                for address in config[options.fixzones]['policies'][policy]['policyDstNet']:
                    tmp_dst_zones = get_zones(options.fixzones, address)
                    for zone in tmp_dst_zones:
                        if zone not in policy_dst_zones:
                            policy_dst_zones.append(zone)
                policy_dst_zones.sort()
                config[options.fixzones]['policies'][policy]['policyDstZone'].sort()
                # if config[options.fixzones]['policies'][policy]['policyDstZone'] != policy_dst_zones and config[options.fixzones]['policies'][policy]['policyDstZone'] != ['any']:
                for zone in policy_dst_zones:
                    if zone not in config[options.fixzones]['policies'][policy]['policyDstZone'] and \
                            config[options.fixzones]['policies'][policy]['policyDstZone'] != ['any']:
                        if zone not in new_policy_dst_zones:
                            new_policy_dst_zones.append(zone)
                        dst_counter += 1
                if new_policy_dst_zones != []:
                    result = 'Read-Only'
                    result = exec_fw_command(options.panoramaip, fw, [('modify_rule',
                                                                       {'action': 'addmembers', 'policyname': policy_name,
                                                                        'dstzones': new_policy_dst_zones,
                                                                        'context': options.fixzones})], syntax='api')
                    self.log('Policy {} Orig Dst Zones: {} Added Zones: {} Result: {}'.format(policy, config[options.fixzones][
                        'policies'][policy]['policyDstZone'], new_policy_dst_zones, result))
            self.log(src_counter, dst_counter)

            # for policy in config['']

    if options.fixzones3:
        self.log('')
        if options.fixzones3 in config:
            fw = 'pano'

            src_counter = 0
            dst_counter = 0
            for policy in config[options.fixzones3]['policies']:
                policy_name = config[options.fixzones3]['policies'][policy]['policyName']
                # self.log(config[options.fixzones3]['policies'][policy])
                policy_src_zones = []
                policy_dst_zones = []
                new_policy_src_zones = []
                new_policy_dst_zones = []
                if config[options.fixzones3]['policies'][policy]['policySrcNet'] in [['EMC-exclude-dmz'],
                                                                                     ['EMC-exclude-dmz', 'VPN-Clients'],
                                                                                     ['VPN-Clients', 'EMC-exclude-dmz'],
                                                                                     ['EMC-xclude-DMZ'],
                                                                                     ['EMC-xclude-DMZ', 'VPN-Clients'],
                                                                                     ['VPN-Clients', 'EMC-xclude-DMZ']]:
                    for srczone in config[options.fixzones3]['policies'][policy]['policySrcZone']:
                        if srczone != 'Dell_Corp':
                            new_policy_src_zones.append(srczone)
                if config[options.fixzones3]['policies'][policy]['policyDstNet'] in [['EMC-exclude-dmz'],
                                                                                     ['EMC-exclude-dmz', 'VPN-Clients'],
                                                                                     ['VPN-Clients', 'EMC-exclude-dmz'],
                                                                                     ['EMC-xclude-DMZ'],
                                                                                     ['EMC-xclude-DMZ', 'VPN-Clients'],
                                                                                     ['VPN-Clients', 'EMC-xclude-DMZ']]:
                    for dstzone in config[options.fixzones3]['policies'][policy]['policyDstZone']:
                        if dstzone != 'Dell_Corp':
                            new_policy_dst_zones.append(dstzone)
                result = 'Read-Only'
                if new_policy_src_zones != [] and new_policy_src_zones != config[options.fixzones3]['policies'][policy][
                    'policySrcNet']:
                    if list(set(config[options.fixzones3]['policies'][policy]['policySrcZone']) ^ set(
                            new_policy_src_zones)) != []:
                        # result=exec_fw_command(options.panoramaip, fw, [('modify_rule', {'action': 'setmembers', 'policyname': policy_name,
                        # 'srczones': list(set(config[options.fixzones3]['policies'][policy]['policySrcZone']) ^ set(new_policy_src_zones)), 'context': options.fixzones3})], syntax='api')
                        self.log('"Src","{}","{}","{}","{}","{}","{}","{}"'.format(policy,
                                                                              config[options.fixzones3]['policies'][policy][
                                                                                  'policyName'],
                                                                              config[options.fixzones3]['policies'][policy][
                                                                                  'policySrcZone'], new_policy_src_zones,
                                                                              list(set(
                                                                                  config[options.fixzones3]['policies'][
                                                                                      policy]['policySrcZone']) ^ set(
                                                                                  new_policy_src_zones)),
                                                                              config[options.fixzones3]['policies'][policy][
                                                                                  'policySrcNet'], result))
                if new_policy_dst_zones != [] and new_policy_dst_zones != config[options.fixzones3]['policies'][policy][
                    'policyDstNet']:
                    if list(set(config[options.fixzones3]['policies'][policy]['policyDstZone']) ^ set(
                            new_policy_dst_zones)) != []:
                        # result=exec_fw_command(options.panoramaip, fw, [('modify_rule', {'action': 'setmembers', 'policyname': policy_name,
                        # 'dstzones': list(set(config[options.fixzones3]['policies'][policy]['policyDstZone']) ^ set(new_policy_dst_zones)), 'context': options.fixzones3})], syntax='api')
                        self.log('"Src","{}","{}","{}","{}","{}","{}","{}"'.format(policy,
                                                                              config[options.fixzones3]['policies'][policy][
                                                                                  'policyName'],
                                                                              config[options.fixzones3]['policies'][policy][
                                                                                  'policyDstZone'], new_policy_dst_zones,
                                                                              list(set(
                                                                                  config[options.fixzones3]['policies'][
                                                                                      policy]['policyDstZone']) ^ set(
                                                                                  new_policy_dst_zones)),
                                                                              config[options.fixzones3]['policies'][policy][
                                                                                  'policyDstNet'], result))

    if options.fixzones2:
        self.log('')
        # self.log(options.fixzones2)
        # for context in config:
        #    self.log(context)
        if options.fixzones2 in config:
            # options.username='admin'
            # options.password='snowflake'
            # fwip='10.215.18.81'
            fw = 'pano'
            config[options.fixzones2]['routing'], config[options.fixzones2]['interfaces'], config[options.fixzones2][
                'zones'] = load_checkpoint_routing(options.checkpointroute)
            for zonemap in options.fixzonemaps:
                # self.log(zonemap)
                checkpoint_interface, oldzone, newzone = zonemap.split(',')
                for interface in config[options.fixzones2]['interfaces']:
                    if config[options.fixzones2]['interfaces'][interface]['iface_name'] == checkpoint_interface:
                        config[options.fixzones2]['interfaces'][interface]['interface_Zone'] = newzone  ##PS3

            src_counter = 0
            dst_counter = 0
            for policy in config[options.fixzones2]['policies']:
                policy_name = config[options.fixzones2]['policies'][policy]['policyName']
                # self.log(config[options.fixzones2]['policies'][policy])
                policy_src_zones = []
                policy_dst_zones = []
                new_policy_src_zones = []
                new_policy_dst_zones = []

                for address in config[options.fixzones2]['policies'][policy]['policySrcNet']:
                    if address in config[options.fixzones2]['addresses']:
                        tmp_src_zones = get_zones2(options.fixzones2, address)
                        for zone in tmp_src_zones:
                            if zone not in policy_src_zones:
                                policy_src_zones.append(zone)
                policy_src_zones.sort()
                config[options.fixzones2]['policies'][policy]['policySrcZone'].sort()
                for zone in policy_src_zones:
                    if zone not in config[options.fixzones2]['policies'][policy]['policySrcZone'] and \
                            config[options.fixzones2]['policies'][policy]['policySrcZone'] != ['any']:
                        if zone not in new_policy_src_zones:
                            new_policy_src_zones.append(zone)
                        src_counter += 1
                if new_policy_src_zones != []:
                    result = 'Read-Only'
                    result = exec_fw_command(options.panoramaip, fw, [('modify_rule',
                                                                       {'action': 'addmembers', 'policyname': policy_name,
                                                                        'srczones': new_policy_src_zones,
                                                                        'context': options.fixzones2})], syntax='api')
                    self.log('"Src","{}","{}","{}","{}"'.format(policy,
                                                           config[options.fixzones2]['policies'][policy]['policySrcZone'],
                                                           new_policy_src_zones, result))

                # if (set(config[options.fixzones2]['policies'][policy]['policySrcZone']) & set(policy_src_zones) != set(config[options.fixzones2]['policies'][policy]['policySrcZone'])) and config[options.fixzones2]['policies'][policy]['policySrcZone'] != ['any']:
                #   self.log('Policy {} Src Zones: {} Computed Zones: {}'.format(policy, config[options.fixzones2]['policies'][policy]['policySrcZone'], policy_src_zones))

                for address in config[options.fixzones2]['policies'][policy]['policyDstNet']:
                    if address in config[options.fixzones2]['addresses']:
                        tmp_dst_zones = get_zones2(options.fixzones2, address)
                        for zone in tmp_dst_zones:
                            if zone not in policy_dst_zones:
                                policy_dst_zones.append(zone)
                policy_dst_zones.sort()
                config[options.fixzones2]['policies'][policy]['policyDstZone'].sort()
                # if config[options.fixzones2]['policies'][policy]['policyDstZone'] != policy_dst_zones and config[options.fixzones2]['policies'][policy]['policyDstZone'] != ['any']:
                for zone in policy_dst_zones:
                    if zone not in config[options.fixzones2]['policies'][policy]['policyDstZone'] and \
                            config[options.fixzones2]['policies'][policy]['policyDstZone'] != ['any']:
                        if zone not in new_policy_dst_zones:
                            new_policy_dst_zones.append(zone)
                        dst_counter += 1
                if new_policy_dst_zones != []:
                    result = 'Read-Only'
                    result = exec_fw_command(options.panoramaip, fw, [('modify_rule',
                                                                       {'action': 'addmembers', 'policyname': policy_name,
                                                                        'dstzones': new_policy_dst_zones,
                                                                        'context': options.fixzones2})], syntax='api')
                    self.log('"Dst","{}","{}","{}","{}"'.format(policy,
                                                           config[options.fixzones2]['policies'][policy]['policyDstZone'],
                                                           new_policy_dst_zones, result))
            self.log(src_counter, dst_counter)

            # for policy in config['']

    if options.rename:
        renames = [('Splunk_AMER_Indexers', 'SplunkCS_AMER_Indexers'),
                   ('Splunk_APAC_Indexers', 'SplunkCS_APAC_Indexers'),
                   ('Splunk_EMEA_Indexers', 'SplunkCS_EMEA_Indexers'),
                   ('Splunk_HeavyForwarders', 'SplunkCS_HeavyForwarders'),
                   ('Splunk_SearchHeads', 'SplunkCS_SearchHeads'),
                   ('Splunk_DeploymentServers', 'SplunkCS_DeploymentServers'),
                   ('Splunk_AutomationServers', 'SplunkCS_AutomationServers')]
        renames = [('SplunkCS_JumpBoxes', 'SplunkCS_JumpboxServers')]

        for fwip in options.grouptargets:
            try:

                fw = 'sw65'

                # oldname,newname=options.rename.split(',')
                session = requests.Session()
                session.mount('https://' + fwip, sw.DESAdapter())
                response = sw.do_login(session, options.username, options.password, fwip, True)
                if response:
                    sw.do_logout(session, fwip)
                    for oldname, newname in renames:
                        result = exec_fw_command(fwip, fw, [
                            ('modify_address', {'action': 'rename', 'addressname': oldname, 'newaddressname': newname})],
                                                 syntax='api')
                        self.log('{:20.20s} {:40.40s} {:40.40s} {:100.100s}'.format(fwip, oldname, newname, str(result)))
                else:
                    self.log('{:20.20s} {:40.40s} {:40.40s} {:100.100s}'.format(fwip, '', '', 'Login Failed'))
            except Exception as e:
                self.log('{:20.20s} {:40.40s} {:40.40s} {:100.100s}'.format(fwip, '', '', 'Exception Occured'))

    if options.fixcomments and len(config['sonicwall']['addresses']) > 1:
        # target=options.grouptargets[0]
        # comment='RITM5284122 - TASK5885697'
        # commands=[]
        # for address in options.fixcomments:

        #    commands.append(('modify_address', {'addressname': address, 'action': 'comment', 'comment': comment, 'addresstype': '1', 'context': 'shared'}))
        # for command in commands:
        #    self.log(command)
        # self.log(exec_fw_command(target, 'pano', commands, syntax='api'))
        #    #('modify_rule', { 'context': 'shared', 'policyname': cmd['policy_name'], 'action': 'comment', 'comment': cmd['comment'] + options.inversecomment })
        #
        target = options.sonicwall_api_ip

        if 'GLOBAL_SCCM' in config['sonicwall']['addresses']:
            self.log('GLOBAL_SCCM found in addresses -- adding SCCM_DTC')
            result = exec_fw_command(options.sonicwall_api_ip, 'sw65', [
                ('modify_address', {'action': 'addmembers', 'addressname': 'GLOBAL_SCCM', 'members': ['SCCM_DTC']})],
                                     syntax='api')
            self.log(result)
        else:
            self.log('GLOBAL_SCCM *NOT* found in addresses -- No changes needed')
        matches = 0

        session = requests.Session()
        session.mount('https://' + target, sw.DESAdapter())
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
        url = 'https://{}/api/sonicos/auth'.format(target)
        session.headers = OrderedDict(
            [('User-Agent', 'python-requests/2.18.4'), ('Accept', '*/*'), ('Accept-Encoding', 'gzip, deflate'),
             ('Connection', 'keep-alive')])
        post_data = None
        response_code = None
        login_tries = 0
        while response_code != 200 and login_tries < 5:
            login_tries += 1
            response = session.post(url=url, headers={'authorization': "Basic " + base64.b64encode(
                '{}:{}'.format(options.username, options.password).encode()).decode()}, verify=False)
            response_code = response.status_code
            if response_code != 200:
                debug('Login failed, retrying in 10 seconds')
                time.sleep(10)

        if response_code == 200:

            for rule in config['sonicwall']['policies']:
                if 'GLOBAL_SCCM' in config['sonicwall']['policies'][rule]['policySrcNet'] or 'GLOBAL_SCCM' in \
                        config['sonicwall']['policies'][rule]['policyDstNet']:
                    matches += 1
                    rule_to_modify = config['sonicwall']['policies'][rule]['policyUUID']
                    new_comment = config['sonicwall']['policies'][rule]['policyComment'] + ' - TASK5885697 CHG0364799'
                    self.log('GLOBAL_SCCM found in rule {} - updating comments to {}'.format(rule_to_modify, new_comment))
                    url = 'https://{}/api/sonicos/direct/cli'.format(target)
                    session.headers.update({'content-type': 'text/plain'})

                    post_data = 'access-rule ipv4 uuid {}\ncomment "{}"\ncommit\n'.format(rule_to_modify, new_comment)
                    result = session.post(url=url, data=post_data, verify=False)

                    # result=exec_fw_command(target, 'sw65', [('modify_rule', {'action': 'comment', 'comment': new_comment, 'uuid': rule_to_modify})], syntax='api')
                    self.log(result)
            self.log('GLOBAL_SCCM found in {} rules'.format(matches))
            url = 'https://{}/api/sonicos/auth'.format(target)
            session.delete(url=url, verify=False, timeout=options.timeout_sw_api)

    if options.sccm:
        from netaddr import IPSet, IPNetwork

        for context in config:
            log(context)
            ## Add IPSet property to all non group objects
            config[context]['addresses'] = add_IPv4Network(config[context]['addresses'])

            ## Add IPSet property to all group objects
            for addr in config[context]['addresses']:
                if config[context]['addresses'][addr]['addrObjType'] == '8':
                    config[context]['addresses'][addr]['IPSet'] = IPSet([])
                    for groupmember in expand_address(config[context]['addresses'], addr,
                                                      config[context]['addressmappings']):
                        location = None
                        # debug(groupmember)
                        # debug(config[context]['addresses'][groupmember])
                        if groupmember in config[context]['addresses']:
                            location = context
                        elif groupmember in config['shared']['addresses']:
                            location = 'shared'
                        if location:
                            for network in config[location]['addresses'][groupmember]['IPv4Networks']:
                                config[context]['addresses'][addr]['IPSet'].add(str(network))
        fw = 'pano'
        fwip = options.panoramaip
        syntax = 'api'
        commands = []
        for context in config:
            # log(context)
            if context != 'shared':
                # add_IPv4Network(addresses)
                for address in config[context]['addresses']:
                    if address in config['shared']['addresses']:
                        # log(config['shared']['addresses'][address])
                        if config['shared']['addresses'][address]['IPSet'] == config[context]['addresses'][address][
                            'IPSet']:
                            # log('Address object {} matches in Device-Group {} and shared'.format(address, context))
                            log('DUPE:{},{},{}'.format(context, address,
                                                       config[context]['addresses'][address]['addrObjType']))
                            commands.append(('modify_address', {'action': 'delete', 'addressname': address,
                                                                'addresstype': config[context]['addresses'][address][
                                                                    'addrObjType'], 'context': context}))
        if fwip:
            result = exec_fw_command(fwip, fw, commands, syntax=syntax)
            log('Deleting objects', result)

    if options.rulelist:
        for rule in options.rulelist:
            self.log(config['Durham_Core']['policies'][int(rule)]['policyName'])

    if options.testing:
        syntax = 'api'
        fw = 'sw65'
        fwip = '10.215.16.61'
        result = exec_fw_command(fwip, fw, [('create_address',
                                             {'addressname': 'test_fqdn', 'domain': 'www.deleteme.com', 'ttl': '120',
                                              'addresstype': 'fqdn', 'zone': 'LAN', 'color': 'black'})], syntax=syntax)
        self.log(result)

    if options.testcreate:
        for context in contexts:
            if 'policynum' in config[context]['config']:
                for policy in config[context]['config']['policynum']:
                    config[context]['config']['policynum'] = int(config[context]['config']['policynum'])
        testlist = [
            # ('pano', '10.215.19.132', 'shared'),
            # ('pano', '10.215.19.132', 'PTC Services DMZ'),
            # ('pano', '10.215.18.71', 'shared'),
            # ('palo', '10.215.18.81', ''),
            ('sw65', '10.215.16.61', ''),
            # ('sonicwall', '10.215.16.60', ''),
            # ('checkpoint', '', '')
            # ('checkpoint', '128.221.62.90', 'api')
        ]

        # for syntax in ['webui', 'cli']:
        for syntax in ['api']:
            for fw, fwip, context in testlist:

                self.log('-' * 100)
                self.log('{} {} testing'.format(fw, syntax))
                self.log('-' * 100)
                # print(options.username, options.password)
                result = exec_fw_command(fwip, fw, [('create_address', {'addressname': 'test_host', 'ip1': '10.10.10.10',
                                                                        'ip2': '255.255.255.255', 'addresstype': '1',
                                                                        'zone': 'LAN', 'color': 'black',
                                                                        'context': context})], syntax=syntax)
                if syntax in ['webui', 'api']: self.log('{:>60.60}: {}'.format('Create Host', result))
                debug('-' * 180)
                result = exec_fw_command(fwip, fw, [('create_address', {'addressname': 'test_range', 'ip1': '20.20.20.1',
                                                                        'ip2': '20.20.20.11', 'addresstype': '2',
                                                                        'zone': 'LAN', 'color': 'black',
                                                                        'context': context})], syntax=syntax)
                if syntax in ['webui', 'api']: self.log('{:>60.60}: {}'.format('Create Range', result))
                debug('-' * 180)
                result = exec_fw_command(fwip, fw, [('create_address', {'addressname': 'test_network', 'ip1': '30.30.30.0',
                                                                        'ip2': '255.255.255.252', 'addresstype': '4',
                                                                        'zone': 'LAN', 'color': 'black',
                                                                        'context': context})], syntax=syntax)
                if syntax in ['webui', 'api']: self.log('{:>60.60}: {}'.format('Create Network', result))
                debug('-' * 180)
                result = exec_fw_command(fwip, fw, [('create_address',
                                                     {'addressname': 'test_group', 'addresstype': '8', 'zone': 'LAN',
                                                      'color': 'black', 'context': context})], syntax=syntax)
                if syntax in ['webui', 'api']: self.log(
                    '{:>60.60}: {}'.format('Create Address Group missing members param', result))
                debug('-' * 180)
                result = exec_fw_command(fwip, fw, [('create_address',
                                                     {'addressname': 'test_group', 'addresstype': '8', 'zone': 'LAN',
                                                      'color': 'black', 'members': [], 'context': context})], syntax=syntax)
                if syntax in ['webui', 'api']: self.log(
                    '{:>60.60}: {}'.format('Create Address Group empty members param', result))
                debug('-' * 180)
                result = exec_fw_command(fwip, fw, [('create_address',
                                                     {'addressname': 'test_group', 'addresstype': '8', 'zone': 'LAN',
                                                      'color': 'black', 'members': ['test_host2'], 'context': context})],
                                         syntax=syntax)
                if syntax in ['webui', 'api']: self.log(
                    '{:>60.60}: {}'.format('Create Address Group bad address member', result))
                debug('-' * 180)
                result = exec_fw_command(fwip, fw, [('create_address',
                                                     {'addressname': 'test_group', 'addresstype': '8', 'zone': 'LAN',
                                                      'color': 'black', 'members': ['test_host'], 'context': context})],
                                         syntax=syntax)
                if syntax in ['webui', 'api']: self.log('{:>60.60}: {}'.format('Create Address Group', result))
                debug('-' * 180)

                result = exec_fw_command(fwip, fw, [('create_service',
                                                     {'servicename': 'test_service_tcp', 'servicetype': '1',
                                                      'color': 'black', 'protocol': 'tcp', 'port1': '32',
                                                      'context': context})], syntax=syntax)
                if syntax in ['webui', 'api']: self.log('{:>60.60}: {}'.format('Create TCP Service', result))
                debug('-' * 180)
                result = exec_fw_command(fwip, fw, [('create_service',
                                                     {'servicename': 'test_service_udp', 'servicetype': '1',
                                                      'color': 'black', 'protocol': 'udp', 'port1': '44',
                                                      'context': context})], syntax=syntax)
                if syntax in ['webui', 'api']: self.log('{:>60.60}: {}'.format('Create UDP Service', result))
                debug('-' * 180)
                result = exec_fw_command(fwip, fw, [('create_service',
                                                     {'servicename': 'test_service_range', 'servicetype': '1',
                                                      'color': 'black', 'protocol': 'tcp', 'port1': '32', 'port2': '33',
                                                      'context': context})], syntax=syntax)
                if syntax in ['webui', 'api']: self.log('{:>60.60}: {}'.format('Create Service Range', result))
                debug('-' * 180)
                result = exec_fw_command(fwip, fw, [('create_service',
                                                     {'servicename': 'test_service_group', 'servicetype': '2',
                                                      'color': 'black', 'members': ['test_service_range'],
                                                      'context': context})], syntax=syntax)
                if syntax in ['webui', 'api']: self.log('{:>60.60}: {}'.format('Create Service Group', result))
                debug('-' * 180)

                result = exec_fw_command(fwip, fw, [('create_rule',
                                                     {'rulename': 'test_rule', 'policyname': '##rsa-ecom-core',
                                                      'policynum': '1', 'polaction': '1', 'enabled': '1',
                                                      'srczones': ['LAN'], 'dstzones': ['WAN'], 'sources': ['test_host'],
                                                      'dests': ['test_group'], 'services': ['any'], 'comment': 'testing',
                                                      'context': context})], syntax=syntax)
                if syntax in ['webui', 'api']: self.log('{:>60.60}: {}'.format('Create Rule', result))
                debug('-' * 180)

    if options.testmodify:
        for context in contexts:
            if 'policynum' in config[context]['config']:
                for policy in config[context]['config']['policynum']:
                    config[context]['config']['policynum'] = int(config[context]['config']['policynum'])
        testlist = [
            # ('pano', '10.215.19.132', 'shared'),
            # ('pano', '10.215.19.132', 'PTC Services DMZ'),
            # ('palo', '10.215.18.70', ''),
            # ('sonicwall', '10.215.16.60', ''),
            # ('sw65', '10.215.16.61', '')
            ('checkpoint', '128.221.62.90', 'api')
            # ('checkpoint', '', '')
        ]

        # exec_fw_comand syntax options should be cli, dbedit, api, webui, xmlapi

        # for syntax in ['webui', 'cli']:
        for syntax in ['api']:
            for fw, fwip, context in testlist:

                print('-' * 100)
                print('{} {} testing'.format(fw, syntax))
                print('-' * 100)
                # print(options.username, options.password)
                # delmembers addmembers
                ## created rule is LAN, WAN, test_host, test_group, any
                #
                result = exec_fw_command(fwip, fw, [('modify_rule', {'action': 'comment', 'comment': 'Modified Comment',
                                                                     'rulename': 'test_rule',
                                                                     'policyname': '##rsa-ecom-core', 'policynum': '1',
                                                                     'polaction': '1', 'srczones': ['LAN'],
                                                                     'dstzones': ['WAN'], 'sources': ['test_host'],
                                                                     'dests': ['test_group'], 'services': ['any'],
                                                                     'context': context})], syntax=syntax)
                if syntax in ['webui', 'api']: self.log('{:>35.35}: {}'.format('Modify Rule', result))
                result = exec_fw_command(fwip, fw, [('modify_rule',
                                                     {'action': 'logging', 'logging': True, 'comment': 'Modified Comment',
                                                      'rulename': 'test_rule', 'policyname': '##rsa-ecom-core',
                                                      'policynum': '1', 'polaction': '1', 'srczones': ['LAN'],
                                                      'dstzones': ['WAN'], 'sources': ['test_host'],
                                                      'dests': ['test_group'], 'services': ['any'], 'context': context})],
                                         syntax=syntax)
                if syntax in ['webui', 'api']: self.log('{:>35.35}: {}'.format('Modify Rule Logging', result))
                result = exec_fw_command(fwip, fw, [('modify_rule', {'action': 'delmembers', 'comment': 'Modified Comment',
                                                                     'rulename': 'test_rule',
                                                                     'policyname': '##rsa-ecom-core', 'policynum': '1',
                                                                     'polaction': '1', 'srczones': ['LAN'],
                                                                     'dstzones': ['WAN'], 'sources': ['test_range'],
                                                                     'context': context})], syntax=syntax)
                if syntax in ['webui', 'api']: self.log('{:>35.35}: {}'.format('Modify Rule Source', result))
                result = exec_fw_command(fwip, fw, [('modify_rule', {'action': 'delmembers', 'comment': 'Modified Comment',
                                                                     'rulename': 'test_rule',
                                                                     'policyname': '##rsa-ecom-core', 'policynum': '1',
                                                                     'polaction': '1', 'srczones': ['LAN'],
                                                                     'dstzones': ['WAN'], 'dests': ['test_network'],
                                                                     'context': context})], syntax=syntax)
                if syntax in ['webui', 'api']: self.log('{:>35.35}: {}'.format('Modify Rule Dests', result))

                result = exec_fw_command(fwip, fw, [('modify_rule', {'action': 'delmembers', 'comment': 'Modified Comment',
                                                                     'rulename': 'test_rule',
                                                                     'policyname': '##rsa-ecom-core', 'policynum': '1',
                                                                     'polaction': '1', 'srczones': ['LAN'],
                                                                     'dstzones': ['WAN'], 'sources': ['test_host'],
                                                                     'dests': ['test_network'],
                                                                     'services': ['test_service_udp'],
                                                                     'context': context})], syntax=syntax)
                if syntax in ['webui', 'api']: self.log('{:>35.35}: {}'.format('Modify Rule Services', result))
                ## is delmemebrs tehe right action for modifying tags?
                result = exec_fw_command(fwip, fw, [('modify_rule',
                                                     {'action': 'delmembers', 'tags': ['TESTTAG'], 'rulename': 'test_rule',
                                                      'policyname': '##rsa-ecom-core', 'policynum': '1', 'polaction': '1',
                                                      'context': context})], syntax=syntax)
                if syntax in ['webui', 'api']: self.log('{:>35.35}: {}'.format('Modify Rule Tags', result))
                result = exec_fw_command(fwip, fw, [('modify_rule', {'action': 'disable', 'comment': 'Modified Comment',
                                                                     'rulename': 'test_rule',
                                                                     'policyname': '##rsa-ecom-core', 'policynum': '1',
                                                                     'polaction': '1', 'srczones': ['LAN'],
                                                                     'dstzones': ['WAN'], 'sources': ['test_host'],
                                                                     'dests': ['test_group'], 'services': ['any'],
                                                                     'context': context})], syntax=syntax)
                if syntax in ['webui', 'api']: self.log('{:>35.35}: {}'.format('Modify Rule Enabled', result))

                result = exec_fw_command(fwip, fw, [('modify_address', {'action': 'addmembers', 'addressname': 'test_group',
                                                                        'members': ['test_range', 'test_network',
                                                                                    'test_host'],
                                                                        'comment': 'modify comment', 'addresstype': '8',
                                                                        'zone': 'LAN', 'color': 'black',
                                                                        'context': context})], syntax=syntax)
                if syntax in ['webui', 'api']: self.log('{:>35.35}: {}'.format('Modify Address Group AddMembers', result))
                result = exec_fw_command(fwip, fw, [('modify_address', {'action': 'delmembers', 'addressname': 'test_group',
                                                                        'members': ['test_range'],
                                                                        'comment': 'modify comment', 'addresstype': '8',
                                                                        'zone': 'LAN', 'color': 'black',
                                                                        'context': context})], syntax=syntax)
                if syntax in ['webui', 'api']: self.log('{:>35.35}: {}'.format('Modify Address Group DelMembers', result))
                result = exec_fw_command(fwip, fw, [('modify_address',
                                                     {'action': 'color', 'addressname': 'test_host', 'ip1': '10.10.10.10',
                                                      'ip2': '255.255.255.255', 'addresstype': '1', 'zone': 'LAN',
                                                      'color': 'blue', 'context': context})], syntax=syntax)
                if syntax in ['webui', 'api']: self.log('{:>35.35}: {}'.format('Modify Host Color', result))
                result = exec_fw_command(fwip, fw, [('modify_address', {'action': 'comment', 'addressname': 'test_range',
                                                                        'comment': 'modified comment', 'ip1': '20.20.20.1',
                                                                        'ip2': '20.20.20.11', 'addresstype': '2',
                                                                        'zone': 'LAN', 'color': 'black',
                                                                        'context': context})], syntax=syntax)
                if syntax in ['webui', 'api']: self.log('{:>35.35}: {}'.format('Modify Range Comment', result))
                result = exec_fw_command(fwip, fw, [('modify_address',
                                                     {'action': 'tags', 'addressname': 'test_network', 'tags': ['TESTTAG'],
                                                      'ip1': '30.30.30.0', 'ip2': '255.255.255.255', 'addresstype': '4',
                                                      'zone': 'LAN', 'color': 'black', 'context': context})], syntax=syntax)
                if syntax in ['webui', 'api']: self.log('{:>35.35}: {}'.format('Modify Network Tags', result))
                result = exec_fw_command(fwip, fw, [('modify_address',
                                                     {'action': 'tags', 'addressname': 'test_network', 'tags': ['TESTTAG'],
                                                      'ip1': '30.30.30.0', 'ip2': '255.255.255.255', 'addresstype': '4',
                                                      'zone': 'LAN', 'color': 'black', 'context': context})], syntax=syntax)
                if syntax in ['webui', 'api']: self.log('{:>35.35}: {}'.format('Modify Network Tags', result))

                result = exec_fw_command(fwip, fw, [('modify_service',
                                                     {'action': 'addmembers', 'servicename': 'test_service_group',
                                                      'members': ['test_service_tcp', 'test_service_udp'],
                                                      'servicetype': '2', 'color': 'black', 'context': context})],
                                         syntax=syntax)
                if syntax in ['webui', 'api']: self.log('{:>35.35}: {}'.format('Modify Service Group - Addmembers', result))
                result = exec_fw_command(fwip, fw, [('modify_service',
                                                     {'action': 'delmembers', 'servicename': 'test_service_group',
                                                      'members': ['test_service_udp'], 'servicetype': '1', 'color': 'black',
                                                      'protocol': 'tcp', 'port1': '32', 'port2': '33',
                                                      'context': context})], syntax=syntax)
                if syntax in ['webui', 'api']: self.log('{:>35.35}: {}'.format('Modify Service Group - Delmembers', result))

                result = exec_fw_command(fwip, fw, [('modify_service',
                                                     {'action': 'color', 'servicename': 'test_service', 'servicetype': '1',
                                                      'color': 'blue', 'protocol': 'tcp', 'port1': '32',
                                                      'context': context})], syntax=syntax)
                if syntax in ['webui', 'api']: self.log('{:>35.35}: {}'.format('Modify Service Color', result))
                result = exec_fw_command(fwip, fw, [('modify_service', {'action': 'comment', 'servicename': 'test_service',
                                                                        'servicetype': '1', 'comment': 'Modified Comment',
                                                                        'protocol': 'tcp', 'port1': '32',
                                                                        'context': context})], syntax=syntax)
                if syntax in ['webui', 'api']: self.log('{:>35.35}: {}'.format('Modify Service Comment', result))
                result = exec_fw_command(fwip, fw, [('modify_service', {'action': 'addtags', 'servicename': 'test_service',
                                                                        'tags': ['TESTTAG'], 'servicetype': '1',
                                                                        'comment': 'Modified Comment', 'protocol': 'tcp',
                                                                        'port1': '32', 'context': context})], syntax=syntax)
                if syntax in ['webui', 'api']: self.log('{:>35.35}: {}'.format('Modify Service Tag', result))

    if options.testdelete:
        for context in contexts:
            if 'policynum' in config[context]['config']:
                for policy in config[context]['config']['policynum']:
                    config[context]['config']['policynum'] = int(config[context]['config']['policynum'])
        testlist = [
            # ('pano', '10.215.19.132', 'shared'),
            # ('pano', '10.215.19.132', 'PTC Services DMZ'),
            # ('palo', '10.215.18.70', ''),
            # ('sonicwall', '10.215.16.60', ''),
            # ('checkpoint', '', '')
            ('sw65', '10.215.16.61', '')
        ]
        # for syntax in ['webui', 'cli']:
        for syntax in ['api']:
            for fw, fwip, context in testlist:

                print('-' * 100)
                print('{} {} testing'.format(fw, syntax))
                print('-' * 100)
                # print(options.username, options.password)

                ## follwoing is to try deleting an address group already in use
                # result=exec_fw_command(fwip, fw, [('modify_address', {'action': 'delete', 'addressname': 'test_host', 'ip1': '10.10.10.10', 'ip2' : '255.255.255.255', 'addresstype': '1', 'zone': 'LAN', 'color': 'black', 'context': context})], syntax=syntax)
                # if syntax in ['webui', 'api']: print('{:>20.20}: {}'.format('Delete In Use Addr', result))

                result = exec_fw_command(fwip, fw, [('modify_rule', {'action': 'delete', 'rulename': 'test_rule',
                                                                     'policyname': '##rsa-ecom-core', 'policynum': '1',
                                                                     'polaction': '1', 'srczones': ['LAN'],
                                                                     'dstzones': ['WAN'], 'sources': ['test_host'],
                                                                     'dests': ['test_group'], 'services': ['any'],
                                                                     'comment': 'testing', 'context': context})],
                                         syntax=syntax)
                if syntax in ['webui', 'api']: print('{:>20.20}: {}'.format('Delete Rule', result))

                result = exec_fw_command(fwip, fw, [('modify_address',
                                                     {'action': 'delete', 'addressname': 'test_group', 'addresstype': '8',
                                                      'zone': 'LAN', 'color': 'black', 'members': ['test_host'],
                                                      'context': context})], syntax=syntax)
                if syntax in ['webui', 'api']: print('{:>20.20}: {}'.format('Delete Address Group', result))
                result = exec_fw_command(fwip, fw, [('modify_address',
                                                     {'action': 'delete', 'addressname': 'test_host', 'ip1': '10.10.10.10',
                                                      'ip2': '255.255.255.255', 'addresstype': '1', 'zone': 'LAN',
                                                      'color': 'black', 'context': context})], syntax=syntax)
                if syntax in ['webui', 'api']: print('{:>20.20}: {}'.format('Delete Host', result))
                result = exec_fw_command(fwip, fw, [('modify_address',
                                                     {'action': 'delete', 'addressname': 'test_range', 'ip1': '20.20.20.1',
                                                      'ip2': '20.20.20.11', 'addresstype': '2', 'zone': 'LAN',
                                                      'color': 'black', 'context': context})], syntax=syntax)
                if syntax in ['webui', 'api']: print('{:>20.20}: {}'.format('Delete Range', result))
                result = exec_fw_command(fwip, fw, [('modify_address', {'action': 'delete', 'addressname': 'test_network',
                                                                        'ip1': '30.30.30.0', 'ip2': '255.255.255.255',
                                                                        'addresstype': '4', 'zone': 'LAN', 'color': 'black',
                                                                        'context': context})], syntax=syntax)
                if syntax in ['webui', 'api']: print('{:>20.20}: {}'.format('Delete Network', result))

                result = exec_fw_command(fwip, fw, [('modify_service',
                                                     {'action': 'delete', 'servicename': 'test_service_group',
                                                      'servicetype': '2', 'color': 'black', 'members': ['test_service'],
                                                      'context': context})], syntax=syntax)
                if syntax in ['webui', 'api']: print('{:>20.20}: {}'.format('Delete Service Group', result))
                result = exec_fw_command(fwip, fw, [('modify_service',
                                                     {'action': 'delete', 'servicename': 'test_service_range',
                                                      'servicetype': '1', 'color': 'black', 'protocol': 'tcp',
                                                      'port1': '32', 'port2': '33', 'context': context})], syntax=syntax)
                if syntax in ['webui', 'api']: print('{:>20.20}: {}'.format('Delete Service Range', result))
                result = exec_fw_command(fwip, fw, [('modify_service',
                                                     {'action': 'delete', 'servicename': 'test_service_tcp',
                                                      'servicetype': '1', 'color': 'black', 'protocol': 'tcp',
                                                      'port1': '32', 'context': context})], syntax=syntax)
                if syntax in ['webui', 'api']: print('{:>20.20}: {}'.format('Delete Service', result))
                result = exec_fw_command(fwip, fw, [('modify_service',
                                                     {'action': 'delete', 'servicename': 'test_service_udp',
                                                      'servicetype': '1', 'color': 'black', 'protocol': 'tcp',
                                                      'port1': '32', 'context': context})], syntax=syntax)
                if syntax in ['webui', 'api']: print('{:>20.20}: {}'.format('Delete Service', result))

    if options.uuid != None:
        print(options.uuid)
        for context in contexts:
            self.log(context)
            self.log(len(config[context]['policies']))
            for policy in config[context]['policies']:
                # self.log(policy)
                if 'policyUid' in config[context]['policies'][policy]:
                    if config[context]['policies'][policy]['policyAction'] == '0':
                        action = 'deny'
                    elif config[context]['policies'][policy]['policyAction'] == '1':
                        action = 'drop'
                    elif config[context]['policies'][policy]['policyAction'] == '2':
                        action = 'allow'
                    else:
                        action = 'UNKNOWN'
                    # self.log(config[context]['policies'][policy])
                    if options.uuid == [] or config[context]['policies'][policy]['policyUid'] in options.uuid:
                        self.log('{}~{}~{}~{}~{}~{}~{}'.format(config[context]['policies'][policy]['policyName'],
                                                          config[context]['policies'][policy]['policyUid'],
                                                          config[context]['policies'][policy]['policyNum'],
                                                          config[context]['policies'][policy]['policyUiNum'],
                                                          action,
                                                          config[context]['policies'][policy]['policyEnabled'] == '1',
                                                          config[context]['policies'][policy]['policyComment'],

                                                          ))

    if options.dmz:
        import urllib
        import json

        for context in contexts:
            print('!-- ', context)
            if 'interfaces' in config[context]:
                # print(json.dumps(config[context]['interfaces'], indent=4))
                for interface in config[context]['interfaces']:
                    # self.log(config[context]['interfaces'][interface])
                    if urllib.parse.unquote(config[context]['interfaces'][interface]['interface_Zone']) not in ['MGMT', '']:
                        # self.log(interface)
                        if config[context]['interfaces'][interface]['iface_static_ip'] != '0.0.0.0':
                            print('{},{},{},{},{},{}'.format(context,
                                                             urllib.parse.unquote(
                                                                 config[context]['interfaces'][interface]['iface_name']),
                                                             urllib.parse.unquote(config[context]['interfaces'][interface][
                                                                                      'interface_Zone']),
                                                             urllib.parse.unquote(config[context]['interfaces'][interface][
                                                                                      'iface_static_ip']),
                                                             urllib.parse.unquote(config[context]['interfaces'][interface][
                                                                                      'iface_static_mask']),
                                                             urllib.parse.unquote(
                                                                 config[context]['interfaces'][interface]['portShutdown'])
                                                             ))
                        elif config[context]['interfaces'][interface]['iface_lan_ip'] != '0.0.0.0':
                            print('{},{},{},{},{},{}'.format(context,
                                                             urllib.parse.unquote(
                                                                 config[context]['interfaces'][interface]['iface_name']),
                                                             urllib.parse.unquote(config[context]['interfaces'][interface][
                                                                                      'interface_Zone']),
                                                             urllib.parse.unquote(
                                                                 config[context]['interfaces'][interface]['iface_lan_ip']),
                                                             urllib.parse.unquote(config[context]['interfaces'][interface][
                                                                                      'iface_lan_mask']),
                                                             urllib.parse.unquote(
                                                                 config[context]['interfaces'][interface]['portShutdown'])
                                                             ))
                        elif config[context]['interfaces'][interface]['iface_mgmt_ip'] != '0.0.0.0':
                            print('{},{},{},{},{},{}'.format(context,
                                                             urllib.parse.unquote(
                                                                 config[context]['interfaces'][interface]['iface_name']),
                                                             urllib.parse.unquote(config[context]['interfaces'][interface][
                                                                                      'interface_Zone']),
                                                             urllib.parse.unquote(
                                                                 config[context]['interfaces'][interface]['iface_mgmt_ip']),
                                                             urllib.parse.unquote(config[context]['interfaces'][interface][
                                                                                      'iface_mgmt_netmask']),
                                                             urllib.parse.unquote(
                                                                 config[context]['interfaces'][interface]['portShutdown'])

                                                             ))

    if options.ldap:
        import sonicwall as sw
        import re

        binddn_passwords = {
            'cn=servicefwrwemeaprod,ou=service accounts,dc=emea,dc=dell,dc=com'.lower(): 'password1',
            'cn=servicefwrwamerprod,ou=service accounts,dc=amer,dc=dell,dc=com'.lower(): 'password2',
            'cn=servicefwrwapjprod,ou=service accounts,dc=apac,dc=dell,dc=com'.lower(): 'password3'}

        # servicefwrwemeaprod,ou=service accounts,dc=emea,dc=dell,dc=com
        options.username = 'admin'
        # swis_username = input                ("  Solarwinds Username : ")
        # swis_password = getpass.getpass      ("  Solarwinds Password : ")
        # swis_username='jeff_miller2'

        options.password = input('       Admin password : ')
        val_username = input("  Validation Username : ")
        val_password = input("  Validation Password : ")

        import requests
        import json

        npm_server = 'solarwindscs.dell.com'

        verify = False
        if not verify:
            from requests.packages.urllib3.exceptions import InsecureRequestWarning

            requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

        # swis = SwisClient(npm_server, swis_username, swis_password)
        # results = swis.query('''SELECT  O.NodeID, O.Caption as NodeName, O.IPAddress, O.Status, NodeDescription, Asset_State as AssetState, O.IOSVersion as Version, C.Cyber_Security_Classification as Classification
        # FROM Orion.Nodes O
        # INNER JOIN Orion.NodesCustomProperties AS C ON O.NodeID = C.NodeID
        # WHERE C.SNOW_Product_Name like '%Sonic%fire%' AND NodeDescription like '%SonicWALL%' and C.DeviceType = 'Core Controller'
        # ORDER BY NodeName ''')

        # results = swis.query('''SELECT  O.NodeID, O.Caption as NodeName, O.IPAddress, O.Status, NodeDescription, Asset_State as AssetState, O.IOSVersion as Version, C.Cyber_Security_Classification as Classification, C.Region, C.DeviceType
        # FROM Orion.Nodes O
        # INNER JOIN Orion.NodesCustomProperties AS C ON O.NodeID = C.NodeID
        # WHERE C.SNOW_Product_Name like '%Sonic%fire%' AND NodeDescription like '%SonicWALL%'
        # RDER BY NodeName ''')

        results = {}
        results['results'] = [({'IPAddress': '10.215.16.61', 'NodeID': 1226, 'Classification': 'Medium',
                                'AssetState': 'Post-Production', 'Status': 1, 'Version': ' 6.2.5.4-1n',
                                'NodeName': 'blr12swfwcorp01',
                                'NodeDescription': 'SonicWALL SuperMassive 9400 (SonicOS Enhanced 6.2.5.4-1n)'})]

        # self.log(results)
        val_result = None
        self.log('|{:30.30s}|{:17.17s}|{:8.8s}|{:8.8s}|{:8.8s}|{:11.11}|{:11.11}|{:11.11}|{:11.11}|{:8.8}|{:8.8}|{:19.19}|{:12.12}|'.format(
            'Device Name', 'IP Address', 'Status', 'HA Mode', 'HA State', 'Create RO', 'Create RW', 'Remove RO',
            'Remove RW', 'Add RO', 'Add RW', 'LDAP BindDN Found', 'Validation'))
        for row in results['results']:
            # self.log(row)
            self.log("-" * 180)
            # print("{}".format(row))
            target = row['IPAddress']
            if row['Status'] == 1:  # only devices that are "UP"
                if len([value for value in options.ldap if value in ['all', 'any']]) > 0 or row[
                    'Classification'].lower() in [x.lower() for x in options.ldap]:
                    session = requests.Session()
                    session.mount('https://' + target, sw.DESAdapter())
                    # self.log(target, options.username, options.password)
                    response = sw.do_login(session, options.username, options.password, target, True)
                    # self.log(response)
                    if response:
                        response = sw.get_url(session,
                                              'https://' + target + '/getJsonData.json?_=1566657857&dataSet=alertStatus')
                        resp_json = json.loads(response.text)
                        if 'svrrpNodeState' in resp_json and 'svrrpHaMode' in resp_json:
                            active = (resp_json['svrrpNodeState'].lower() == 'active' or resp_json[
                                'svrrpHaMode'].lower() == 'standalone')
                            # self.log('Firewall HA Mode : ', resp_json['svrrpHaMode'])
                            # self.log('Firewall State   : ', resp_json['svrrpNodeState'].lower())
                            if active:
                                url = 'https://' + target + '/main.cgi'
                                postdata = {
                                    'iStartItem': '1',
                                    'error_page': 'groupObjView.html',
                                    'refresh_page': '',
                                    'userGroupObjId_-1': 'CS_FIREWALL_RW',
                                    'userGroupObjComment_-1': 'Read-Write PAC Group',
                                    'userGroupObjType_-1': '2',
                                    'userGroupObjProperties_-1': '16398',
                                    'userGroupObjPrivMask_-1': '128',
                                    'userGroupObjVpnDestNet_-1': '',
                                    'userGroupObjCfspId_-1': '0',
                                    'userGroupOtpReq_-1': '0',
                                    'userGroupObjLdapLocn_-1': 'emea.dell.com/AdmAccounts/PrivilegedGroups/CS_Firewall_RW'
                                }
                                create_rw_result = 'Skipped'  # send_sw_webcmd(session, url, postdata)
                                # self.log('Create CIS_FIREWALL_RW : ', result)

                                postdata = {'uo_atomToGrp_-3': 'CIS_SFW_RW',
                                            'uo_grpToGrp_-3': 'SonicWALL Administrators'
                                            }
                                del_rw_result = 'Skipped'  # send_sw_webcmd(session, url, postdata)
                                # self.log('Remove CIS_SFW_RW from SonicWALL Administrators : ', result)

                                postdata = {'uo_atomToGrp_0': 'CS_FIREWALL_RW',
                                            'uo_grpToGrp_0': 'SonicWALL Administrators'
                                            }

                                add_rw_result = 'Skipped'  # send_sw_webcmd(session, url, postdata)
                                # self.log('Add CIS_FIREWALL_RO to SonicWALL Administrators : ', result)

                                postdata = {
                                    'iStartItem': '1',
                                    'error_page': 'groupObjView.html',
                                    'refresh_page': '',
                                    'userGroupObjId_-1': 'CS_FIREWALL_RO',
                                    'userGroupObjComment_-1': 'Read-Only PAC Group',
                                    'userGroupObjType_-1': '2',
                                    'userGroupObjProperties_-1': '16398',
                                    'userGroupObjPrivMask_-1': '128',
                                    'userGroupObjVpnDestNet_-1': '',
                                    'userGroupObjCfspId_-1': '0',
                                    'userGroupOtpReq_-1': '0',
                                    'userGroupObjLdapLocn_-1': 'emea.dell.com/AdmAccounts/PrivilegedGroups/CS_Firewall_RO'
                                }
                                create_ro_result = 'Skipped'  # send_sw_webcmd(session, url, postdata)
                                # self.log('Create CIS_FIREWALL_RO :', result)

                                postdata = {'uo_atomToGrp_-3': 'CIS_SFW_RO',
                                            'uo_grpToGrp_-3': 'SonicWALL Read-Only Admins'
                                            }
                                del_ro_result = 'Skipped'  # send_sw_webcmd(session, url, postdata)
                                # self.log('Remove CIS_SFW_RO from SonicWALL Administrators : ', result)

                                postdata = {'uo_atomToGrp_0': 'CS_FIREWALL_RO',
                                            'uo_grpToGrp_0': 'SonicWALL Read-Only Admins'
                                            }

                                add_ro_result = 'Skipped'  # send_sw_webcmd(session, url, postdata)
                                # self.log('Add CIS_FIREWALL_RO to SonicWALL Read-Only Admins : ', result)

                                postdata = {'ldapServerBindPwd': 'newpassword'}
                                # result=send_sw_webcmd(session, url, postdata)
                                # self.log('Change LDAP password : ', result)
                                response = sw.get_url(session, 'https://' + target + '/ldapProps.html')
                                try:
                                    loginname = re.findall(r'var loginName.*', response.text)[0].split('"')[1].lower()
                                    # self.log('Changing Password for Bind DN : ', loginname)
                                    if loginname.lower() in binddn_passwords:
                                        postdata = {'ldapServerBindPwd': binddn_passwords[loginname.lower()]}
                                        result = send_sw_webcmd(session, url, postdata)
                                        # self.log('Change LDAP password : ', result)
                                        # self.log('Changing Password for Bind DN "{}" : {}', format(loginname, result))
                                        bind_result = True
                                    else:
                                        self.log('Unable to change password for Bind DN : ', loginname)
                                        bind_result = False
                                except Exception as e:
                                    try:
                                        loginname = re.findall(r'new LdapSrvr.*', response.text)[0].split('"')[3]
                                        self.log(loginname)
                                        bind_result = True
                                    except:
                                        self.log('Could not get current Bind DN setting')
                                        self.log(e)
                                        # self.log(response.text)
                                        bind_result = False

                                response = sw.get_url(session, 'https://' + target + '/systemToolsView.html')
                                csrf = re.findall(r'csrfToken.*"', response.text)[0].split('value=')[1].split('"')[1]
                                self.log('csrf', csrf)
                                url = 'https://' + target + '/main.cgi'
                                postdata = {'csrfToken': csrf,
                                            'cgiaction': "none",
                                            'ldapCgiAction': "0",
                                            'ldapCgiActnSrvrName': "",
                                            'ldapCgiActnParam': "",
                                            'isLdapPost': "",
                                            'ldapSrvrHostName_-2': "ausdcamer.amer.dell.com",
                                            'ldapSrvrHostName_0': "ausdcamer.amer.dell.com",
                                            'ldapSrvrBindName_0': "newuser3",
                                            'ldapSrvrPort_0': "3269",
                                            'ldapSrvrBindType_0': "1"
                                            }

                                result = send_sw_webcmd(session, url, postdata)
                                self.log(result)

                                sw.do_logout(session, target)
                                val_result = sw.do_login(session, val_username, val_password, target, True)
                                # self.log('Validation check : ', response)
                                sw.do_logout(session, target)
                                if val_result:
                                    self.log('|{:30.30s}|{:17.17s}|{:8.8s}|{:8.8s}|{:8.8s}|{:11.11s}|{:11.11s}|{:11.11s}|{:11.11s}|{:8.8s}|{:8.8s}|{:19.19s}|{:12.12s}|'.format(
                                        row['NodeName'], row['IPAddress'], 'Passed', resp_json['svrrpHaMode'],
                                        resp_json['svrrpNodeState'], str(create_ro_result), str(create_rw_result),
                                        str(del_ro_result), str(del_rw_result), str(add_ro_result), str(add_rw_result),
                                        str(bind_result), str(val_result)))
                                else:
                                    self.log('|{:30.30s}|{:17.17s}|{:8.8s}|{:8.8s}|{:8.8s}|{:11.11s}|{:11.11s}|{:11.11s}|{:11.11s}|{:8.8s}|{:8.8s}|{:19.19s}|{:12.12s}|'.format(
                                        row['NodeName'], row['IPAddress'], 'Failed', resp_json['svrrpHaMode'],
                                        resp_json['svrrpNodeState'], str(create_ro_result), str(create_rw_result),
                                        str(del_ro_result), str(del_rw_result), str(add_ro_result), str(add_rw_result),
                                        str(bind_result), str(val_result)))

                            else:
                                self.log('|{:30.30s}|{:17.17s}|{}|{}|'.format(row['NodeName'], row['IPAddress'], 'Skipped',
                                                                         'Not Active Appliance in HA Pair'))
                        else:
                            self.log('|{:30.30s}|{:17.17s}|{}|{}|'.format(row['NodeName'], row['IPAddress'], 'Skipped',
                                                                     'Unable to determine device state'))

                    else:
                        self.log('|{:30.30s}|{:17.17s}|{}|{}|'.format(row['NodeName'], row['IPAddress'], 'Skipped',
                                                                 'Admin Login Failed'))
                else:
                    self.log('|{:30.30s}|{:17.17s}|{}|{}|'.format(row['NodeName'], row['IPAddress'], 'Skipped',
                                                             'Classification Mismatch'))
            else:
                self.log('|{:30.30s}|{:17.17s}|{}|{}|'.format(row['NodeName'], row['IPAddress'], 'Skipped',
                                                         'Solarwinds Reports Node Down'))

    if options.recheck:  ## not sure what these routines were meant to do.  Perhaps to check LDAP auth and then use admin account to perform DNS and ping checks on LDAP FQDN
        import sonicwall as sw
        import re
        from bs4 import BeautifulSoup as bs

        verify = False
        if not verify:
            from requests.packages.urllib3.exceptions import InsecureRequestWarning

            requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

        val_username = input("  Validation Username : ")
        val_password = input("  Validation Password : ")

        for target in options.recheck:
            url = 'https://' + target + '/main.cgi'
            session = requests.Session()
            session.mount('https://' + target, sw.DESAdapter())

            val_result = sw.do_login(session, val_username, val_password, target, False, 30)
            # self.log('Validation check : ', response)

            if not val_result:
                self.log('{},{}'.format(target, 'User Login Failed'))

            else:
                self.log('{},{}'.format(target, 'User Login Successful'))
                sw.do_logout(session, target)
            # if not val_result:

    if options.gms:  ## clear GMS enabled checkbox
        import sonicwall as sw
        import re
        from bs4 import BeautifulSoup as bs

        # get_username='admin'
        # get_password='admin'
        get_username = options.username
        get_password = options.password
        target = options.gms
        url = 'https://' + target + '/main.cgi'
        session = requests.Session()
        # self.log(url)
        session.mount('https://' + target, sw.DESAdapter())
        login_result = sw.do_login(session, get_username, get_password, target, True,
                                   timeout=options.timeout_sw_webui_login)
        if login_result:
            # print(login_result)
            # response=sw.get_url(session, 'https://' + target + '/systemToolsView.html', timeout=options.timeout_sw_webui)
            # csrf=re.findall(r'csrfToken.*"',response.text)[0].split('value=')[1].split('"')[1]
            # postdata = {    'csrfToken': csrf,
            #                'cbox_useGlobalMgt': '' }
            # postdata = {    'csrfToken': csrf,                         'useGlobalMgt': 'off' }
            # postdata = { 'csrfToken': csrf, 'cgiaction': 'updateSecServInfo' }
            # result=send_sw_webcmd(session, url, postdata, timeout=options.timeout_sw_webui)

            response = session.get('https://{}/systemAdministrationView.html'.format(target), verify=False,
                                   timeout=options.timeout_sw_webui)
            # debug(response.text)
            if response.status_code == 200:
                try:
                    soup = bs(response.text, 'lxml')
                    isGMSEnabled = soup.find('input', attrs={'name': 'useGlobalMgt'}).has_attr('checked')  # isIDPEnabled
                except:
                    isGMSEnabled = None
            else:
                isGMSEnabled = None
            result = isGMSEnabled
            self.log('{},{}'.format(target, result))
            sw.do_logout(session, target)
        else:
            self.log('{},{},{}'.format(target, 'Login Failed', login_result))

    if options.setlogprofile:  ## set log profile for rules on panorama -- too many edits in a short period of time causes issues- palo recommended a 10 sec delay between edits.  wound up doing this via bash using xmlstarlet
        target = options.panoramaip

        commands = []

        for context in options.context:
            changes = {'logs': 0, 'start': 0, 'end': 0, 'comments': 0}
            if options.setlogprofile not in config[context]['logprofiles'] and options.setlogprofile not in \
                    config['shared']['logprofiles']:
                self.log('ERROR! Log Profile {} not available to Device-Group: {}'.format(options.setlogprofile, context))

            else:

                if context != 'shared':
                    # print(context)
                    for policy in config[context]['policies']:
                        # print(config[context]['policies'][policy]['policyLogSetting'])
                        modified = False
                        if config[context]['policies'][policy]['policyLogSetting'] != options.setlogprofile:
                            commands.append(('modify_rule', {'context': context,
                                                             'policyname': config[context]['policies'][policy][
                                                                 'policyName'], 'action': 'log-setting',
                                                             'log-setting': options.setlogprofile}))
                            changes['logs'] += 1
                            modified = True
                        if config[context]['policies'][policy]['policyLogStart'].lower() != 'no':
                            commands.append(('modify_rule', {'context': context,
                                                             'policyname': config[context]['policies'][policy][
                                                                 'policyName'], 'action': 'log-start', 'log-start': 'no'}))
                            changes['start'] += 1
                            modified = True
                        if config[context]['policies'][policy]['policyLogEnd'].lower() != 'yes':
                            commands.append(('modify_rule', {'context': context,
                                                             'policyname': config[context]['policies'][policy][
                                                                 'policyName'], 'action': 'log-end', 'log-end': 'yes'}))
                            changes['end'] += 1
                            modified = True
                        if modified == True:
                            if config[context]['policies'][policy]['policyComment'] == '':
                                commands.append(('modify_rule', {'context': context,
                                                                 'policyname': config[context]['policies'][policy][
                                                                     'policyName'], 'action': 'comment',
                                                                 'comment': config[context]['policies'][policy][
                                                                                'policyComment'] + 'CHG0243187 - Fix Log Settings (Profile/Start-End)'}))
                                changes['comments'] += 1
                            else:
                                commands.append(('modify_rule', {'context': context,
                                                                 'policyname': config[context]['policies'][policy][
                                                                     'policyName'], 'action': 'comment',
                                                                 'comment': config[context]['policies'][policy][
                                                                                'policyComment'] + '\n' + 'CHG0243187 - Fix Log Settings (Profile/Start-End)'}))
                                changes['comments'] += 1

                    self.log('Summary of updates needed for Device Group {}: Log Profiles: {}, Log-Start: {}, Log-End: {}, Comments: {}'.format(
                        context, changes['logs'], changes['start'], changes['end'], changes['comments']))
                # for command in commands:
                #    print(command)
                self.log('Starting API pushes for {} commands'.format(str(len(commands))))
                exec_fw_command(target, 'pano', commands, syntax='api', delay=None, use_session=True)
                # exec_fw_command(target, 'pano', [('modify_rule', { 'context': context, 'policyname': config[context]['policies'][policy], 'action': 'comment', 'comment': config[context]['policies'][policy]['policyComment'] + '\n' + + 'CHGXXXX' })] ,syntax='api')
                # exec_fw_command(target, 'pano', [('modify_rule', { 'context': context, 'policyname': config[context]['policies'][policy], 'action': 'log-start', 'log-start':  'no' })] ,syntax='api')
                # exec_fw_command(target, 'pano', [('modify_rule', { 'context': context, 'policyname': config[context]['policies'][policy], 'action': 'log-end', 'log-end': 'yes' })] ,syntax='api')

    if options.addgroupmember and (options.sonicwallip or options.sonicwall_api_ip):
        retries = 3
        for context in config:
            if context in options.context:
                group_created = False
                api_type = 'api'
                fw_type = config[context]['config']['fw_type']

                if options.sonicwallip:
                    target = options.sonicwallip
                else:
                    target = options.sonicwall_api_ip
                orig_api_enabled = sw_get_api_status(target, options.username, options.password)
                self.log(orig_api_enabled)
                # if not orig_api_enabled:
                sw_enable_api(target, options.username, options.password)

                if fw_type == 'sw65':
                    sw_objects = get_sw_objects(target, options.username, options.password, fw_type)
                # debug(fw_type)
                # debug(sw_objects)
                for mappings in options.addgroupmember:
                    group, member = mappings.split(',')
                    if member in config[context]['addresses']:
                        tries = 0
                        success = False
                        while tries < retries and not success:
                            tries += 1
                            try:
                                self.log('Removing temp_address_object from {}'.format(member))
                                result = exec_fw_command(target, fw_type, [('modify_address',
                                                                            {'action': 'delmembers', 'addressname': member,
                                                                             'members': ['temp_address_object'],
                                                                             'addresstype': '8', 'color': 'black',
                                                                             'context': context})], syntax=api_type,
                                                         delay=0, sw_objects=sw_objects)
                                # self.log(result)
                                if group in config[context]['addresses'] or group_created:
                                    self.log('Adding member object {} to group {} in context {}'.format(member, group, context))
                                    result = exec_fw_command(target, fw_type, [('modify_address', {'action': 'addmembers',
                                                                                                   'addressname': group,
                                                                                                   'members': [member],
                                                                                                   'addresstype': '8',
                                                                                                   'color': 'black',
                                                                                                   'context': context})],
                                                             syntax=api_type, delay=0, sw_objects=sw_objects)
                                    self.log(result)
                                else:
                                    self.log('Adding member object {} to new group {} in context {}'.format(member, group,
                                                                                                       context))
                                    result = exec_fw_command(target, fw_type, [('create_address', {'action': 'addmembers',
                                                                                                   'addressname': group,
                                                                                                   'members': [member],
                                                                                                   'addresstype': '8',
                                                                                                   'color': 'black',
                                                                                                   'context': context})],
                                                             syntax=api_type, delay=0, sw_objects=sw_objects)
                                    # self.log(result)
                                    group_created = result == True
                                success = True
                            except Exception as e:
                                self.log('Exception occured attempting to add address object to group: {}'.format(e))
                    else:
                        self.log('Skipping adding member object {} to group {} in context {} -- Member object not found'.format(
                            member, group, context))
                # if not orig_api_enabled:
                #    sw_disable_api(target, options.username, options.password)

    if options.nexpose:  ## create address objects

        def run_parallel(targets, max_proc=48):

            from multiprocessing import Pool

            pool = Pool(processes=max_proc)
            results = pool.map(bulk_create_addresses, targets)

            return results


        if options.grouptargets:
            results = run_parallel(options.grouptargets)
            for target, new_addresses, existing_addresses, members_added, members_existed in results:
                if new_addresses != 'Exception':
                    self.log('{},{},{},{}'.format(target, 'New Addresses', len(new_addresses), new_addresses))
                    self.log('{},{},{},{}'.format(target, 'Existing Addresses', len(existing_addresses), existing_addresses))
                    self.log('{},{},{},{}'.format(target, 'New Group Members', len(members_added), members_added))
                    self.log('{},{},{},{}'.format(target, 'Existing Group Members', len(members_existed), members_existed))
                else:
                    self.log('{},{},{}'.format(target, 'Exception', new_addresses))

        else:
            self.log('Creating bulk objects without target group targets specified')
            bulk_create_addresses(None, config)

    if options.getconfigs:

        def run_parallel(params, max_proc=48):

            from multiprocessing import Pool

            pool = Pool(processes=max_proc)
            results = pool.map(bulk_get_sw_config, params)
            pool.close()

            return results


        if options.getconfigs:
            # original_logging=options.logging
            results = run_parallel(options.getconfigs)
            # options.logging=original_logging
            for result in results:
                self.log(result)

    if options.nexposesvc:

        def run_parallel(targets, max_proc=48):

            from multiprocessing import Pool

            pool = Pool(processes=max_proc)
            results = pool.map(bulk_create_services, targets)
            pool.close()
            return results


        if options.grouptargets:
            results = run_parallel(options.grouptargets)
            for target, new_services, existing_services, members_added, members_existed in results:
                if new_services != 'Exception':
                    self.log('{},{},{},{}'.format(target, 'New Services', len(new_services), new_services))
                    self.log('{},{},{},{}'.format(target, 'Existing Services', len(existing_services), existing_services))
                    self.log('{},{},{},{}'.format(target, 'New Group Members', len(members_added), members_added))
                    self.log('{},{},{},{}'.format(target, 'Existing Group Members', len(members_existed), members_existed))
                else:
                    self.log('{},{},{}'.format(target, 'Exception', new_services))
        else:
            results = bulk_create_services(None)

    if options.groupmaster:
        # a condition exists where adding addresses to a subgroup may fail:
        # example
        # group1 contains subgroup1 and subgroup2, which contains addresses 1.1.1.1 and 2.2.2.2, respectively.
        # group2 contains subgroup1 and subgroup3, which contains addresses 1.1.1.1 and 3.3.3.3, respectively.

        # issue 1: if a new subgroup is added, to contain the address 3.3.3.3 it will create the subgroup and it will work for group1, but then the subgroup can not be added for group2 since it will overlap
        # issue 2: if the address 2.2.2.2 is the new address to be added, it will not be added to the subgroup when processing group 1.  if other address additions are created so that a subgroup is created, then it can not be added to group2 as it will overlap
        # if there are no other addresses added, the subgroup will be processed when handling group2.  if there are no issues the subgroup will then be created, but only added for group2.
        # this will be an issue if group memberships somehow get out of sync due to inconsistent manual manipulation of the groups. the proper way to handle this will likely to do a check upfront of all the possible overlap issues first

        # will the above be fixed by just reloading the config for each master group? (or adding the config items to the dictionary)

        import re
        import ipaddress
        import sonicwall as sw
        from netaddr import IPSet, IPRange, IPNetwork

        # import time

        # options.grouptargets=['10.215.16.60']
        # options.groupaddresses=['1.1.1.1', '2.2.2.0/32', '1.2.3.0/23', '2.2.2.2/33', '3.3.3.0/2/3', 'a.b.c.d/24', '10.2.3.4/32', '10.2.3.0/24', '1.1.1.0/24']
        # options.groupmaster=['CSIRT_GROUP']
        # options.username='admin'
        # options.password='snowflake'
        # options.groupusemaster=False
        # validate target IPs
        # validate addresses to add

        # get sonicwall config

        # addresses should contain subgroup name, rather than master name, as subgroup will not always be unique
        # address creation should be skipped is the subgroup was already processed.

        for target in options.grouptargets:
            subgroupcreated = False
            if not options.web and (options.username == None or options.password == None):
                options.username, options.password = get_creds()
            tmpconfig = None
            cmds = []
            if target == 'checkpoint':
                fw_type = 'checkpoint'
            else:
                fw_type = get_fw_type(target)
                self.log('!-- Firewall detection : {}'.format(fw_type))
                if fw_type == 'sonicwall':
                    config = get_sonicwall_exp(target)

                    # set up session for config changes
                    session = requests.Session()
                    session.mount('https://' + target, sw.DESAdapter())
                    response = sw.do_login(session, options.username, options.password, target, True)

                context = list(config)[0]

                if response:
                    # address objects ARE CASE SENSITIVE

                    # make sure master group exists
                    # get zone used in first master group object (sonicwall only)
                    # for each address:
                    # if address is already contained within the master group, if so, skip it
                    # determine if address object already exists, if so, use it, else create a new one.
                    # add existing object or new object name to list

                    # determine name of subgroup
                    # create subgroup with members of address object list
                    # add subgroup to master group

                    # make sure none of the groupaddresses are dupes or overlaps
                    addedsubgroups = []
                    for groupmaster in options.groupmaster:  # split groupmaster into master group and subgroup
                        try:
                            groupmaster, subgroupname = groupmaster.split(',')
                        except:
                            subgroupname = None
                        ## should i reload the config for each groupmaster object to get updated objects?

                        if groupmaster in config[context]['addresses']:
                            mastermembers = expand_address(config[context]['addresses'], groupmaster,
                                                           config[context]['addressmappings'])
                            if len(mastermembers) > 0:
                                addresszone = config[context]['addresses'][mastermembers[0]]['addrObjZone']
                                self.log('!-- Using master group {} which includes an address object in zone {}'.format(
                                    groupmaster, addresszone))
                                subgroupindex = 1
                                if subgroupname == None:
                                    subgroupname = groupmaster
                                while subgroupname + '-' + str(subgroupindex) in config[context]['addresses']:
                                    subgroupindex += 1
                                subgroupname = subgroupname + '-' + str(subgroupindex)
                                if options.groupusemaster:
                                    self.log('!-- Using master group name : {}'.format(groupmaster))
                                else:
                                    self.log('!-- Using subgroup name : {}'.format(subgroupname))

                                addresslist = []
                                addipset = IPSet([])
                                for address in options.groupaddresses:
                                    badaddress = False
                                    if len(re.findall('/', address)) == 1:
                                        network, mask = address.split('/')
                                    elif len(re.findall('-', address)) == 1:  # address object is a range
                                        # self.log('range found')
                                        network, mask = address.split('-')
                                    elif len(re.findall('/', address)) == 0:
                                        network = address
                                        mask = '32'
                                    else:
                                        self.log('!-- Skipping {} - Invalid netmask'.format(address))
                                        badaddress = True
                                    if not badaddress:
                                        try:
                                            tmpaddr = ipaddress.IPv4Network(network + '/' + str(mask))
                                            tmpaddr = IPNetwork(network + '/' + str(mask))
                                        except Exception as e:
                                            try:
                                                self.log(network, mask)
                                                tmpaddr = IPRange(network, mask)
                                            except:
                                                self.log('!-- Skipping {} - {}'.format(address, e))
                                                badaddress = True
                                    if not badaddress:
                                        # if len(IPSet([network+'/'+str(mask)]) & config[context]['addresses'][groupmaster]['IPSet'])==0:
                                        if len(IPSet(list(tmpaddr)) & config[context]['addresses'][groupmaster][
                                            'IPSet']) == 0:
                                            # self.log(network)
                                            # if len(IPSet([network+'/'+str(mask)]) & addipset)==0:
                                            if len(IPSet(list(tmpaddr)) & addipset) == 0:
                                                addresslist.append((network, mask))
                                                # addipset.add(network+'/'+str(mask))
                                                # self.log(tmpaddr)
                                                addipset.add(tmpaddr)
                                            else:
                                                self.log('!-- Skipping {} - Overlaps with another new address - Target: {}'.format(
                                                    address, target))
                                        else:
                                            self.log('!-- Skipping {} - Overlaps with existing group member - Target: {}'.format(
                                                address, target))

                                # for network,mask in addresslist:
                                #    print('{}-{}-{}'.format(groupmaster,network,mask))
                                # exit(1)

                                if subgroupname not in addedsubgroups:
                                    for network, mask in addresslist:
                                        if mask == '32':
                                            addresstype = '1'  ## host
                                            ip2 = '255.255.255.255'
                                        elif len(re.findall('.', mask)) > 1:
                                            addresstype = '2'  ## range
                                            ip2 = mask
                                        else:
                                            addresstype = '4'  ## network
                                            ip2 = cidr_to_netmask(mask)
                                        addressname = '{}-{}-{}'.format(subgroupname, network, mask)
                                        index = 1
                                        while addressname in config[context]['addresses']:
                                            addressname = '{}-{}-{}--{}'.format(subgroupname, network, mask, index)
                                        ## create new address object

                                        postdata = {'addrObjId_-1': addressname,
                                                    'addrObjType_-1': addresstype,
                                                    'addrObjZone_-1': addresszone,
                                                    'addrObjProperties_-1': '14',
                                                    'addrObjIp1_-1': network,
                                                    'addrObjIp2_-1': ip2
                                                    }
                                        cmddata = {'cmdtype': 'create_address',
                                                   'target': target,
                                                   'name': addressname,
                                                   'type': addresstype,
                                                   'zone': addresszone,
                                                   'props': 14,
                                                   'ip1': network,
                                                   'ip2': ip2,
                                                   'context': context,
                                                   'fw_type': fw_type,
                                                   'syntax': 'webui'
                                                   }
                                        # self.log(postdata)
                                        url = 'https://' + target + '/main.cgi'
                                        # response = session.post(url, verify=False, data = postdata, headers=get_headers, stream=True, timeout=options.timeout_sw_webui_post)
                                        cmds.append(cmddata)
                                        response = session.post(url, verify=False, data=postdata, stream=True,
                                                                timeout=options.timeout_sw_webui_post)
                                        status = re.findall(r'<span class="message.*', response.text)
                                        if len(status) == 1:
                                            statusmsg = re.sub(r'.*nowrap>(.*?)&nbsp.*', r'\1', status[0])
                                            if 'has been updated' in statusmsg:
                                                self.log('!-- Address object created : {}'.format(addressname))
                                            else:
                                                self.log('!-- Address object creation failed : {} - {}'.format(addressname,
                                                                                                          statusmsg))

                                        ## add object to subgroup
                                        if not subgroupcreated and not options.groupusemaster:
                                            subgroupcreated = True
                                            postdata = {'addrObjId_-1': subgroupname,
                                                        'addrObjType_-1': '8',
                                                        'addrObjZone_-1': '',
                                                        'addrObjProperties_-1': '14',
                                                        'addrObjIp1_-1': '0.0.0.0',
                                                        'addrObjIp2_-1': '0.0.0.0'
                                                        }
                                            cmddata = {'cmdtype': 'create_group',
                                                       'target': target,
                                                       'name': subgroupname,
                                                       'type': '8',
                                                       'zone': '',
                                                       'props': 14,
                                                       'ip1': '0.0.0.0',
                                                       'ip2': '0.0.0.0',
                                                       'context': context,
                                                       'fw_type': fw_type,
                                                       'syntax': 'webui'
                                                       }
                                            cmds.append(cmddata)
                                            response = session.post(url, verify=False, data=postdata, stream=True,
                                                                    timeout=options.timeout_sw_webui_post)
                                            status = re.findall(r'<span class="message.*', response.text)
                                            if len(status) == 1:
                                                statusmsg = re.sub(r'.*nowrap>(.*?)&nbsp.*', r'\1', status[0])
                                            if 'has been updated' in statusmsg:
                                                self.log('!-- Subgroup object created : {}'.format(subgroupname))
                                            else:
                                                self.log('!-- Subgroup object creation failed : {} - {}'.format(subgroupname,
                                                                                                           statusmsg))
                                            ## add subgroup to master group
                                            postdata = {'addro_atomToGrp_0': subgroupname,
                                                        'addro_grpToGrp_0': groupmaster
                                                        }
                                            cmddata = {'cmdtype': 'modify_address',
                                                       'target': target,
                                                       'name': groupmaster,
                                                       'member': [(subgroupname, 'addmember')],
                                                       'context': context,
                                                       'fw_type': fw_type,
                                                       'syntax': 'webui'
                                                       }
                                            url = 'https://' + target + '/main.cgi'
                                            cmds.append(cmddata)
                                            response = session.post(url, verify=False, data=postdata, stream=True,
                                                                    timeout=options.timeout_sw_webui_post)
                                            status = re.findall(r'<span class="message.*', response.text)
                                            if len(status) == 1:
                                                statusmsg = re.sub(r'.*nowrap>(.*?)&nbsp.*', r'\1', status[0])
                                            if 'has been updated' in statusmsg:
                                                self.log('!-- Subgroup {} added to master group {}'.format(subgroupname,
                                                                                                      groupmaster))
                                                addedsubgroups.append(groupmaster)
                                            else:
                                                self.log('!-- Subgroup {} addition to master group {} failed - {}'.format(
                                                    subgroupname, groupmaster, statusmsg))
                                                addedsubgroups.append(subgroupname)

                                        if options.groupusemaster:
                                            postdata = {'addro_atomToGrp_0': addressname,
                                                        'addro_grpToGrp_0': groupmaster
                                                        }
                                            cmddata = {'cmdtype': 'modify_address',
                                                       'target': target,
                                                       'name': groupmaster,
                                                       'member': [(addressname, 'addmember')],
                                                       'context': context,
                                                       'fw_type': fw_type,
                                                       'syntax': 'webui'
                                                       }
                                        else:
                                            postdata = {'addro_atomToGrp_0': addressname,
                                                        'addro_grpToGrp_0': subgroupname
                                                        }
                                            cmddata = {'cmdtype': 'modify_address',
                                                       'target': target,
                                                       'name': subgroupname,
                                                       'member': [(addressname, 'addmember')],
                                                       'context': context,
                                                       'fw_type': fw_type,
                                                       'syntax': 'webui'
                                                       }
                                        cmds.append(cmddata)
                                        response = session.post(url, verify=False, data=postdata, stream=True,
                                                                timeout=options.timeout_sw_webui_post)
                                        status = re.findall(r'<span class="message.*', response.text)
                                        if len(status) == 1:
                                            statusmsg = re.sub(r'.*nowrap>(.*?)&nbsp.*', r'\1', status[0])
                                        if 'has been updated' in statusmsg:
                                            if options.groupusemaster:
                                                self.log('!-- Address {} added to master group {}'.format(addressname,
                                                                                                     groupmaster))
                                            else:
                                                self.log('!-- Address {} added to subgroup {}'.format(addressname, subgroupname))
                                        else:
                                            if options.groupusemaster:
                                                self.log('!-- Address {} addition to master group {} failed - {}'.format(
                                                    addressname, groupmaster, statusmsg))
                                            else:
                                                self.log('!-- Address {} addition to subgroup {} failed - {}'.format(addressname,
                                                                                                                subgroupname,
                                                                                                                statusmsg))
                                else:
                                    self.log('!-- Group {} already created - Skipping - Target: {}'.format(subgroupname, target))
                            else:
                                self.log('!-- Master Group {} has no existing members - zone cannot be determined - Target: {}'.format(
                                    groupmaster, target))
                            # break
                        else:
                            self.log('!-- Master group {} does not exist - Skipping - Target: {}'.format(groupmaster, target))
                    # for cmd in cmds:
                    # self.log(cmd)
                    # exec_fw_command([cmd])
                    else:
                        self.log('!-- Login Failed - Unable to make changes to target : Target: {}'.format(target))
                else:
                    self.log('!-- Unable to load configuration : Target: {}'.format(target))

            # if fw_type=='sonicwall':

    if options.web:
        set_web_tab('')  # close out the last tab elements such as textarea, div and add the download button
        sys.stdout.write('\r\n')
        sys.stdout.write('0\r\n')
        sys.stdout.write('\r\n')

    if options.getidp:  ## routines to get IPS details on sonicwall

        import pandas as pd
        from bs4 import BeautifulSoup
        import sonicwall as sw
        import re

        fw_list = ['10.102.227.203', '10.215.16.60', '1.1.1.1']
        # fw_list= ['10.215.16.60']
        # options.password=
        if not options.web and (options.username == None or options.password == None):
            options.username, options.password = get_creds()
        # self.log(options.grouptargets)
        for fw in options.grouptargets:
            session = requests.Session()
            session.mount('https://' + fw, sw.DESAdapter())
            urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
            response = sw.do_login(session, options.username, options.password, fw, False)
            if response:
                try:
                    response = session.get('https://{}/systemAdministrationView.html'.format(fw), verify=False,
                                           timeout=options.timeout_sw_webui)
                    if response.status_code == 200:
                        soup = BeautifulSoup(response.text, 'lxml')
                        firewallName = soup.find('input', attrs={'name': 'firewallName'}).get('value')  # firewallName
                    else:
                        firewallName = 'Unknown'
                    response = session.get('https://{}/idpSummary.html'.format(fw), verify=False,
                                           timeout=options.timeout_sw_webui)
                    if response.status_code == 200:
                        if re.findall('Upgrade Required', response.text):
                            self.log('{},{},{},{},{},{},{},{},{},{},{},{},{},{},{}'.format('firewallName', 'fw_ip',
                                                                                      'isIDPEnabled', 'db_timestamp',
                                                                                      'lc_timestamp', 'expire_date',
                                                                                      'idpPreventHighPriority',
                                                                                      'idpDetectHighPriority', 'idpLRTHigh',
                                                                                      'idpPreventMediumPriority',
                                                                                      'idpDetectMediumPriority',
                                                                                      'idpLRTMedium',
                                                                                      'idpPreventLowPriority',
                                                                                      'idpDetectLowPriority', 'idpLRTLow'))
                            self.log('{},{},{}'.format(firewallName, fw, 'Device not licensed for IDS/IPS'))
                        else:
                            soup = BeautifulSoup(response.text, 'lxml')
                            # ips_status = soup.find_all('table')[9]
                            # ips_enabled = soup.find_all('table')[12]  ## isIDPEnabled
                            # ips_control = soup.find_all('table')[13] ## listControl

                            tables = [
                                [
                                    [td.get_text(strip=True) for td in tr.find_all('td')]
                                    for tr in table.find_all('tr')
                                ]
                                for table in soup.find_all('table')
                            ]
                            try:
                                isIDPEnabled = soup.find('input', attrs={'name': 'isIDPEnabled'}).has_attr(
                                    'checked')  # isIDPEnabled
                            except:
                                isIDPEnabled = 'N/A'
                            # print(isIDPEnabled)
                            if isIDPEnabled == True:
                                # print(soup.findAll("table", {"class": "swlStatsTableRow"}))
                                try:  ## SonicOS 6.2
                                    db_timestamp = tables[9][1][1]
                                    lc_timestamp = tables[9][2][1]
                                    expire_date = tables[9][3][1]
                                except:  ## SonicOS 6.5
                                    db_timestamp = tables[0][1][1]
                                    lc_timestamp = tables[0][2][1]
                                    expire_date = tables[0][3][1]
                                idpPreventHighPriority = soup.find('input',
                                                                   attrs={'name': 'idpPreventHighPriority'}).has_attr(
                                    'checked')  # idpPreventHighPriority
                                idpDetectHighPriority = soup.find('input',
                                                                  attrs={'name': 'idpDetectHighPriority'}).has_attr(
                                    'checked')  # idpDetectHighPriority
                                idpLRTHigh = soup.find('input', attrs={'name': 'idpLRTHigh'})[
                                    'value']  # idpDetectLowPriority # idpLRTHigh

                                idpPreventMediumPriority = soup.find('input',
                                                                     attrs={'name': 'idpPreventMediumPriority'}).has_attr(
                                    'checked')  # idpPreventMediumPriority
                                idpDetectMediumPriority = soup.find('input',
                                                                    attrs={'name': 'idpDetectMediumPriority'}).has_attr(
                                    'checked')  # idpDetectMediumPriority
                                idpLRTMedium = soup.find('input', attrs={'name': 'idpLRTMedium'})[
                                    'value']  # idpDetectLowPriority # idpLRTMedium

                                idpPreventLowPriority = soup.find('input',
                                                                  attrs={'name': 'idpPreventLowPriority'}).has_attr(
                                    'checked')  # idpPreventLowPriority
                                idpDetectLowPriority = soup.find('input', attrs={'name': 'idpDetectLowPriority'}).has_attr(
                                    'checked')  # idpDetectLowPriority
                                idpLRTLow = soup.find('input', attrs={'name': 'idpLRTLow'})[
                                    'value']  # idpDetectLowPriority # idpLRTLow
                            else:
                                db_timestamp, lc_timestamp, expire_date, idpPreventHighPriority, idpDetectHighPriority, idpLRTHigh, idpPreventMediumPriority, idpDetectMediumPriority, idpLRTMedium, idpPreventLowPriority, idpDetectLowPriority, idpLRTLow = (
                                    'N/A', 'N/A', 'N/A', 'N/A', 'N/A', 'N/A', 'N/A', 'N/A', 'N/A', 'N/A', 'N/A', 'N/A')

                            # db_timestamp=tables[9][1][1]
                            # lc_timestamp=tables[9][2][1]
                            # expire_date=tables[9][3][1]
                            self.log('{},{},{},{},{},{},{},{},{},{},{},{},{},{},{}'.format('firewallName', 'fw_ip',
                                                                                      'isIDPEnabled', 'db_timestamp',
                                                                                      'lc_timestamp', 'expire_date',
                                                                                      'idpPreventHighPriority',
                                                                                      'idpDetectHighPriority', 'idpLRTHigh',
                                                                                      'idpPreventMediumPriority',
                                                                                      'idpDetectMediumPriority',
                                                                                      'idpLRTMedium',
                                                                                      'idpPreventLowPriority',
                                                                                      'idpDetectLowPriority', 'idpLRTLow'))
                            self.log('{},{},{},{},{},{},{},{},{},{},{},{},{},{},{}'.format(firewallName, fw, isIDPEnabled,
                                                                                      db_timestamp, lc_timestamp,
                                                                                      expire_date, idpPreventHighPriority,
                                                                                      idpDetectHighPriority, idpLRTHigh,
                                                                                      idpPreventMediumPriority,
                                                                                      idpDetectMediumPriority, idpLRTMedium,
                                                                                      idpPreventLowPriority,
                                                                                      idpDetectLowPriority, idpLRTLow))
                    else:
                        self.log('{},{},{},{},{},{},{},{},{},{},{},{},{},{},{}'.format('firewallName', 'fw_ip', 'isIDPEnabled',
                                                                                  'db_timestamp', 'lc_timestamp',
                                                                                  'expire_date', 'idpPreventHighPriority',
                                                                                  'idpDetectHighPriority', 'idpLRTHigh',
                                                                                  'idpPreventMediumPriority',
                                                                                  'idpDetectMediumPriority', 'idpLRTMedium',
                                                                                  'idpPreventLowPriority',
                                                                                  'idpDetectLowPriority', 'idpLRTLow'))
                        self.log('{},{},{}'.format(firewallName, fw,
                                              'Could not get IDP configuration table - 200/OK not returned'))
                    # print(tables[12])
                    # for table in soup.find_all('table'):
                    #    print(table)
                except Exception as e:
                    self.log('{},{},{},{},{},{},{},{},{},{},{},{},{},{},{}'.format('firewallName', 'fw_ip', 'isIDPEnabled',
                                                                              'db_timestamp', 'lc_timestamp', 'expire_date',
                                                                              'idpPreventHighPriority',
                                                                              'idpDetectHighPriority', 'idpLRTHigh',
                                                                              'idpPreventMediumPriority',
                                                                              'idpDetectMediumPriority', 'idpLRTMedium',
                                                                              'idpPreventLowPriority',
                                                                              'idpDetectLowPriority', 'idpLRTLow'))
                    self.log('{},{},{},{}'.format(firewallName, fw, 'Could not get IDP configuration table', e))
            else:
                firewallName = 'Unknown'
                self.log('{},{},{},{},{},{},{},{},{},{},{},{},{},{},{}'.format('firewallName', 'fw_ip', 'isIDPEnabled',
                                                                          'db_timestamp', 'lc_timestamp', 'expire_date',
                                                                          'idpPreventHighPriority', 'idpDetectHighPriority',
                                                                          'idpLRTHigh', 'idpPreventMediumPriority',
                                                                          'idpDetectMediumPriority', 'idpLRTMedium',
                                                                          'idpPreventLowPriority', 'idpDetectLowPriority',
                                                                          'idpLRTLow'))
                self.log('{},{},{}'.format(firewallName, fw, 'Login or connection failure'))
            # sw.do_logout(session, fw)
            session.close()

    if options.securityprofile:
        customops.rule_profile_setting = options.securityprofile.lstrip().rstrip()

    if options.logprofile:
        customops.log_forward_profile_name = options.logprofile.lstrip().rstrip()

    ## the following won't really work as expected in a class

    if options.web:
        import time
        #log('finished')
        set_web_tab('') # close out the last tab elements such as textarea, div and add the download button
        log('</html>')
        sys.stdout.write('\r\n')
        sys.stdout.write('0\r\n')
        sys.stdout.write('\r\n')
        sys.stdout.flush()
        time.sleep(2)