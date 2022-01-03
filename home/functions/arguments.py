import argparse

options = argparse.ArgumentParser(description=' Description', epilog='Epilog')
options.add_argument('-i',
                     '--i',
                     help='input SonicWall configuration filename',
                     type=str,
                     metavar='filename',
                     dest='sonicwall')
options.add_argument(
    '-p',
    '--p',
    '--sonicwallip',
    '--ipaddr',
    help='import config from the IP address of SonicWall device',
    type=str,
    metavar='IP Address',
    dest='sonicwallip')
options.add_argument(
    '-pp',
    '--pp',
    '--sonicwall_api_ip',
    '--swapi',
    help='import config via API from the IP address of SonicWall device',
    type=str,
    metavar='IP Address',
    dest='sonicwall_api_ip')
options.add_argument(
    '--gms',
    help='import config from the IP address of SonicWall device',
    type=str,
    metavar='IP Address',
    dest='gms')
options.add_argument(
    '-P',
    '--P',
    '--panoramaip',
    help='import config from the IP address of Panorama server',
    type=str,
    metavar='IP Address',
    dest='panoramaip')
options.add_argument('-I',
                     help='input Panorama configuration filename',
                     type=str,
                     metavar='filename',
                     dest='panorama')
options.add_argument('-o',
                     '--outfile',
                     help='output configuration filename',
                     type=str,
                     metavar='filename',
                     dest='outfile')
options.add_argument(
    '-c',
    '--devicegroup',
    nargs='+',
    help='device-group for search operations (use "any" to search all)',
    metavar='device-group name(s)',
    default='',
    action=file_list(),
    type=str,
    dest='context')
options.add_argument(
    '--policynames',
    nargs='+',
    help=
    'policyname for search (--rulematch) operations and tuples (--tuples) generation ',
    metavar='device-group name(s)',
    default=[''],
    action=file_list(),
    type=str,
    dest='policynames')
options.add_argument(
    '-a',
    nargs='+',
    help='(Overlapping) address object search (specify IP Address)',
    type=str,
    metavar='IPAddr',
    dest='ipaddr')
options.add_argument('-A',
                     nargs='+',
                     help='(Exact) address object search (specify IP Address)',
                     type=str,
                     metavar='IPAddr',
                     dest='exactipaddr')
options.add_argument(
    '-s',
    nargs='+',
    help='service object search (specify service protocol and port ie: tcp/23',
    type=str,
    metavar='Protocol/Port',
    dest='service')
options.add_argument(
    '-S',
    nargs='+',
    help=
    '(Exact) service object search (specify service protocol and port ie: tcp/23',
    type=str,
    metavar='Protocol/Port',
    dest='exactservice')
options.add_argument('-e',
                     nargs='+',
                     help='expand an address object',
                     type=str,
                     action=file_list(),
                     metavar='object name',
                     dest='address')
options.add_argument('-E',
                     nargs='+',
                     help='expand an address object (Verbose)',
                     type=str,
                     action=file_list(),
                     metavar='object name',
                     dest='address_verbose')
options.add_argument('-x',
                     nargs='+',
                     help='expand a service object',
                     type=str,
                     action=file_list(),
                     metavar='object name',
                     dest='exp_service')
options.add_argument('-X',
                     nargs='+',
                     help='expand a service object (Verbose)',
                     type=str,
                     action=file_list(),
                     metavar='object name',
                     dest='service_verbose')
options.add_argument('-z',
                     action='store_false',
                     default=True,
                     help='do not match 0.0.0.0/0 network on IP searches',
                     dest='zero_network')
options.add_argument('-Z',
                     action='store_false',
                     default=True,
                     help='do not match "any" service on rulematch',
                     dest='zero_service')
options.add_argument('-N',
                     action='store_true',
                     default=False,
                     help='interactive mode (NOT IMPLEMENTED)',
                     dest='interactive')
#options.add_argument('-l', default=6, help='set log level', type=int, dest='logging')
options.add_argument('--cp',
                     action='store_true',
                     default=False,
                     help='load checkpoint config',
                     dest='checkpoint')
options.add_argument('--cpapi',
                     type=str,
                     help='load checkpoint config via API',
                     dest='checkpoint_api')
options.add_argument('--checkpointpol',
                     '--cppol',
                     nargs='?',
                     help='specify filename for Checkpoint Security Policies',
                     default='Security_Policy.xml',
                     type=str,
                     metavar='filename',
                     dest='checkpointpol')
options.add_argument('--checkpointobj',
                     '--cpobj',
                     nargs='?',
                     help='specify filename for Checkpoint Network Objects',
                     default='network_objects.xml',
                     type=str,
                     metavar='filename',
                     dest='checkpointobj')
options.add_argument('--checkpointsvc',
                     '--cpsvc',
                     nargs='?',
                     help='specify filename for Checkpoint Service Objects',
                     default='services.xml',
                     type=str,
                     metavar='filename',
                     dest='checkpointsvc')
options.add_argument('--checkpointnat',
                     '--cpnat',
                     nargs='?',
                     help='specify filename for Checkpoint NAT Policy Objects',
                     default='NAT_Policy.xml',
                     type=str,
                     metavar='filename',
                     dest='checkpointnat')
options.add_argument('--checkpointroute',
                     '--cproute',
                     nargs='?',
                     help='specify filename for Checkpoint Routing',
                     default=None,
                     type=str,
                     metavar='filename',
                     dest='checkpointroute')
options.add_argument('--fixzones',
                     nargs='?',
                     help='fix zones for rules for specified device-group',
                     default=None,
                     type=str,
                     metavar='device-group',
                     dest='fixzones')
options.add_argument('--fixzones2',
                     nargs='?',
                     help='fix zones for rules for specified device-group',
                     default=None,
                     type=str,
                     metavar='device-group',
                     dest='fixzones2')
options.add_argument('--fixzones3',
                     nargs='?',
                     help='fix zones for rules for specified device-group',
                     default=None,
                     type=str,
                     metavar='device-group',
                     dest='fixzones3')
options.add_argument(
    '--fwtype',
    nargs='?',
    help=
    'Firewall type for some options.grouptarget routines ("sonicwall", "palo", "pano", "checkpoint"',
    default=None,
    type=str,
    metavar='firewall-type',
    dest='fwtype')
options.add_argument('--checkpointcontext',
                     nargs='?',
                     help='specify context name for Checkpoint config',
                     default='checkpoint',
                     type=str,
                     metavar='string',
                     dest='checkpointcontext')
options.add_argument('--renamecontext',
                     nargs='?',
                     help='specify context name for Checkpoint config',
                     default=None,
                     type=str,
                     metavar='string',
                     dest='renamecontext')
options.add_argument(
    '--includepolicies',
    nargs='+',
    help='whitelist of checkpoint policies to include when loading .xml config',
    default=['all'],
    metavar='list of string',
    dest='includepolicies')
options.add_argument('-t',
                     '--tuples',
                     type=str,
                     metavar='filename',
                     help='generate tuples file',
                     dest='tuplefile')
options.add_argument('-t2',
                     '--tuples2',
                     type=str,
                     nargs='*',
                     help='generate tuples file',
                     dest='tuples2')
options.add_argument('--load',
                     nargs='+',
                     type=str,
                     metavar='filename',
                     help='load config from disk',
                     dest='loadconfig')
options.add_argument('--save',
                     type=str,
                     metavar='filename',
                     help='save config to disk',
                     dest='saveconfig')
options.add_argument('--saveexp',
                     action='store_true',
                     default=False,
                     help='save exported config file to disk',
                     dest='saveexp')
options.add_argument(
    '--cipmatch',
    nargs='+',
    help='perform matching of individual source networks for IP Schema',
    metavar='list of IP networks/hosts',
    type=str,
    dest='cipmatch')
options.add_argument(
    '--cipaudit',
    nargs='+',
    help='perform matching of individual source networks for IP Schema',
    metavar='list of IP networks/hosts',
    type=str,
    dest='cipaudit')
options.add_argument('--cipload',
                     type=str,
                     metavar='filename',
                     help='load change matches from disk',
                     dest='cipload')
options.add_argument('--cipsave',
                     type=str,
                     metavar='filename',
                     help='save change matches to disk',
                     dest='cipsave')
options.add_argument('--cipreviewin',
                     nargs='?',
                     default='',
                     type=str,
                     metavar='filename',
                     help='csv/tab file with ChangeIP changes',
                     dest='cipreviewin')
options.add_argument('--cipsubmit',
                     nargs='?',
                     default='',
                     type=str,
                     metavar='filename',
                     help='show page for ChangeIP Submit',
                     dest='cipsubmit')
options.add_argument('--cipdbedit',
                     action='store_true',
                     default=False,
                     help='generate dbedit commands from ChangeIP matching',
                     dest='cipdbedit')
options.add_argument('--cipswedit',
                     action='store_true',
                     default=False,
                     help='push cipmatch changes directly to sonicwall',
                     dest='cipswedit')
options.add_argument('--rename',
                     action='store_true',
                     default=False,
                     help='rename an address-group object',
                     dest='rename')
options.add_argument('--cipblacklist',
                     nargs='+',
                     help='list of blacklisted policies (do not check)',
                     metavar='Policy Names',
                     default=[],
                     type=str,
                     dest='cipblacklist')
options.add_argument('--cipshowskipped',
                     action='store_true',
                     default=False,
                     help='include skipped matches in results',
                     dest='cipshowskipped')
options.add_argument(
    '--cipskippartial',
    action='store_true',
    default=False,
    help=
    'exclude processing partial matches (added for speed due to st pete change for 152.16.136.0/24 network)',
    dest='cipskippartial')
options.add_argument('--inverseload',
                     type=str,
                     metavar='filename',
                     help='load inverse matches from disk',
                     dest='inverseload')
options.add_argument('--inversesave',
                     type=str,
                     metavar='filename',
                     help='save inverse matches to disk',
                     dest='inversesave')
options.add_argument('--inversecomment',
                     type=str,
                     metavar='filename',
                     default='',
                     help='add comment to inverse match disabled rules',
                     dest='inversecomment')
options.add_argument(
    '--inverseallrules',
    action='store_true',
    default=False,
    help='perform inverse disable/delete for all rules, not just allow rules',
    dest='inverseallrules')
options.add_argument('--policysearch',
                     nargs='+',
                     help='search policies for IP address',
                     metavar='IP Address',
                     type=str,
                     dest='policysearch')
options.add_argument('--rulematch',
                     nargs='+',
                     help='given source,dest,service find matching rules',
                     metavar='source,dest,prot/port',
                     action=file_list(),
                     type=str,
                     dest='rulematch')
options.add_argument('--rulemodify',
                     nargs='?',
                     help='given source,dest,service find matching rules',
                     metavar='source,dest,prot/port',
                     type=str,
                     dest='rulemodify')
options.add_argument(
    '--excludeaddresses',
    nargs='+',
    help='exclude these address objects from rulematch search (case sensitive)',
    metavar='address name',
    action=file_list(),
    default=[],
    type=str,
    dest='excludeaddress')
options.add_argument(
    '--excludesrcnetworks',
    nargs='+',
    help='exclude these source networks from rulematch search',
    metavar='network name',
    action=file_list(),
    default=[],
    type=str,
    dest='excludesrcnetwork')
options.add_argument(
    '--excludedstnetworks',
    nargs='+',
    help='exclude these destination networks from rulematch search',
    metavar='network name',
    action=file_list(),
    default=[],
    type=str,
    dest='excludedstnetwork')
options.add_argument('--batch',
                     nargs='+',
                     help='batch processing of commands',
                     metavar='list of commands or @filename',
                     type=str,
                     dest='batch')  #not yet implemented
options.add_argument('--inversematch',
                     nargs='+',
                     help='perform "inverse" rule matching',
                     metavar='list of IP networks/hosts',
                     type=str,
                     action=file_list(),
                     dest='inversematch')
options.add_argument(
    '--inversesingle',
    action='store_true',
    default=False,
    help=
    'for inverse matching, perform matching on one network at a time rather than as a group',
    dest='inversesingle')
options.add_argument('--vrouter',
                     help='Virtual Router Name (used in .xml output config',
                     type=str,
                     metavar='string',
                     dest='vrouter',
                     default='VRouter')
options.add_argument(
    '--logprofile',
    help='Logprofile name to use for readxlsmigrations and readxls',
    type=str,
    metavar='string',
    dest='logprofile')
options.add_argument('--securityprofile',
                     help='Security profile name to use for migrations',
                     type=str,
                     metavar='string',
                     dest='securityprofile')
options.add_argument('--ruletag',
                     help='Tag to add to created rules',
                     type=str,
                     metavar='string',
                     dest='ruletag')
options.add_argument(
    '--tuplezone',
    '-tz',
    help=
    'limit tuple creation to specified source,destination zones (default is All,All)',
    type=str,
    metavar='string',
    dest='tuplezone',
    default='all,all')
options.add_argument(
    '--device-group',
    help='Device Group/Template Name (used in .xml output config',
    type=str,
    metavar='string',
    dest='devicegroup_name',
    default='Default Device Group')
options.add_argument('--mappings',
                     nargs='+',
                     help='interface mappings',
                     type=str,
                     metavar='filename',
                     default=['@./interfaces.map'],
                     dest='mappings')
options.add_argument('--unused',
                     action='store_true',
                     default=False,
                     help='find unused objects',
                     dest='find_unused')
options.add_argument('--show-unused',
                     action='store_true',
                     default=False,
                     help='show unused objects (will set find used to true)',
                     dest='show_unused')
## consider changing default, and then rename this to keep-unused
options.add_argument('--remove-unused',
                     action='store_true',
                     default=False,
                     help='remove unused objects (will set find used to true)',
                     dest='remove_unused')
options.add_argument('--show-dupes',
                     action='store_true',
                     default=False,
                     help='show duplicate objects',
                     dest='show_dupes')
## consider changing default, and then rename this to keep-dupes
options.add_argument('--remove-dupes',
                     action='store_true',
                     default=False,
                     help='remove duplicate objects',
                     dest='remove_dupes')
options.add_argument('--show-devicegroups',
                     action='store_true',
                     default=False,
                     help='show device groups from Panorama configuration',
                     dest='show_devicegroups')
options.add_argument('--show-templates',
                     action='store_true',
                     default=False,
                     help='show templates from Panorama configuration',
                     dest='show_templates')
options.add_argument('--skip-disabled',
                     action='store_true',
                     default=False,
                     help='do not load disabled rules',
                     dest='skip_disabled')
options.add_argument(
    '--exclude-partial',
    action='store_true',
    default=False,
    help=
    'exclude partial matches from matches (currently implemented in CIP match only)',
    dest='exclude_partial')
options.add_argument('--show-mismatched',
                     action='store_true',
                     default=False,
                     help='show service mismatches',
                     dest='show_mismatch')
options.add_argument('--skip-userid',
                     action='store_false',
                     default=True,
                     help='do not include user_id config in output',
                     dest='userid')
options.add_argument('--dump-config',
                     action='store_true',
                     default=False,
                     help='dump config into an Excel (.xlsx) spreadsheet',
                     dest='dump_config')
options.add_argument('--show-logprofiles',
                     action='store_true',
                     default=False,
                     help='show log profiles for each device-group',
                     dest='show_logprofiles')
options.add_argument('--web',
                     '--Submit',
                     action='store_true',
                     default=False,
                     help='enable "web" mode',
                     dest='web')
options.add_argument(
    '--sccm',
    action='store_true',
    default=False,
    help='Compare "SCCM Servers object in Device group to shared',
    dest='sccm')
options.add_argument('--setlogprofile',
                     type=str,
                     help='change log profile setting',
                     dest='setlogprofile')
options.add_argument(
    '--csv',
    type=str,
    help='enable "csv" mode (only used for rulematch currently)',
    dest='csv')
options.add_argument(
    '--html',
    action='store_true',
    default=False,
    help='enable "html" mode (only used for rulematch currently)',
    dest='html')
options.add_argument('--push',
                     action='store_true',
                     default=False,
                     help='push configuration to panorama',
                     dest='push')
options.add_argument(
    '--inversedisable',
    action='store_true',
    default=False,
    help='enable "generate report to disable rules from inverse match results',
    dest='inversedisable')
options.add_argument(
    '--inversedelete',
    action='store_true',
    default=False,
    help='enable "generate report to delete rules from inverse match results',
    dest='inversedelete')
options.add_argument(
    '--inversestats',
    action='store_true',
    default=False,
    help=
    'show report output only, do not execute commands for inverse matching',
    dest='inversestats')
options.add_argument('--inverseexecute',
                     nargs='?',
                     const='',
                     type=str,
                     help='execute commands for inverse matching',
                     dest='inverseexecute')
options.add_argument('--inversepartial',
                     action='store_true',
                     default=False,
                     help='include partial matches in command generation',
                     dest='inversepartial')
options.add_argument('--inverseaddressdelete',
                     action='store_true',
                     default=False,
                     help='remove address matches from inverse results',
                     dest='inverseaddressdelete')
options.add_argument('--dbedit',
                     nargs='+',
                     type=str,
                     metavar='context',
                     help='create dbedit objects from a particular config',
                     dest='dbedit')
options.add_argument('--pan8',
                     action='store_true',
                     default=False,
                     help='target device for config push is pan8',
                     dest='pan8')
options.add_argument('--username',
                     type=str,
                     help=argparse.SUPPRESS,
                     dest='username')
options.add_argument('--password',
                     type=str,
                     help=argparse.SUPPRESS,
                     dest='password')
options.add_argument('--pushusername',
                     type=str,
                     help=argparse.SUPPRESS,
                     dest='pushusername')
options.add_argument('--pushpassword',
                     type=str,
                     help=argparse.SUPPRESS,
                     dest='pushpassword')
options.add_argument('--pushnotemplate',
                     action='store_true',
                     default=False,
                     help='do not create or push template/template stack',
                     dest='pushnotemplate')
options.add_argument('--getconfigs',
                     nargs='+',
                     type=str,
                     help='run bulk get config routines',
                     action=file_list(),
                     dest='getconfigs')
options.add_argument('--nexpose',
                     '--bulkaddresses',
                     type=str,
                     help='run bulk add routines',
                     dest='nexpose')
options.add_argument('--nexposesvc',
                     '--bulkservices',
                     type=str,
                     help='run bulk add service routines',
                     dest='nexposesvc')
options.add_argument('--nexposerule',
                     '--bulkrules',
                     type=str,
                     nargs='+',
                     help='run bulk add rule routines',
                     action=file_list(),
                     dest='nexposerule')
options.add_argument(
    '--skipzone',
    action='store_true',
    default=False,
    help=
    'do not compute zone for bulk address object creation (for adding objects to group)',
    dest='skipzone')
options.add_argument('--addgroupmember',
                     type=str,
                     nargs='+',
                     help='add address object to group',
                     dest='addgroupmember')
options.add_argument('--matchtypes',
                     type=str,
                     nargs='+',
                     default=['all'],
                     help='what match types to include in rulematch results',
                     dest='matchtypes')
options.add_argument(
    '--devicestoadd',
    type=str,
    metavar='device list',
    help=
    'list of device serial numbers to add to devgroup/template for panorama push',
    dest='devicetoadd')
options.add_argument('--pushfile',
                     type=str,
                     metavar='filename',
                     help='filename to push to panorama',
                     dest='pushfile')
options.add_argument('--puship',
                     type=str,
                     metavar='IP Address',
                     help='IP address of Panorama server for comamnd push',
                     dest='puship')
options.add_argument('--firewall',
                     type=str,
                     metavar='String',
                     help='Firewall type (used for HTML forms)',
                     dest='firewall')
options.add_argument(
    '--expandcheckpoint',
    action='store_true',
    default=False,
    help=
    'When reading Sonicwall configuration, expand "ImportChkpt" group objects into members',
    dest='expandcheckpoint')
options.add_argument('--logging',
                     type=int,
                     default=logging.NOTICE,
                     dest='logging')
options.add_argument('--timeout_sw_webui',
                     type=int,
                     default=30,
                     dest='timeout_sw_webui')
options.add_argument('--timeout_sw_api',
                     type=int,
                     default=30,
                     dest='timeout_sw_api')
options.add_argument('--timeout_sw_webui_post',
                     type=int,
                     default=120,
                     dest='timeout_sw_webui_post')
options.add_argument('--timeout_sw_webui_login',
                     type=int,
                     default=30,
                     dest='timeout_sw_webui_login')
options.add_argument('--timeout_palo_api',
                     type=int,
                     default=60,
                     dest='timeout_palo_api')
options.add_argument('-q',
                     '--quiet',
                     action='store_const',
                     const=logging.NONE,
                     dest='logging')
options.add_argument('-v',
                     help='Verbose (Informational) logging level',
                     action='store_const',
                     const=logging.INFO,
                     dest='logging')
options.add_argument('--debug',
                     help='Debug level logging',
                     action='store_const',
                     const=logging.DEBUG,
                     dest='logging')
options.add_argument('--file',
                     nargs='+',
                     help='test for custom action for filespec',
                     metavar='filename meta',
                     default='',
                     action=file_list(),
                     type=str,
                     dest='filename')
options.add_argument('--ipset',
                     nargs='+',
                     help='test for custom action for filespec',
                     metavar='filename meta',
                     action=file_list('ipset'),
                     type=str,
                     dest='iplist')
options.add_argument('--readxls',
                     help='preliminary work for converting xls to ruleset',
                     metavar='filename meta',
                     type=str,
                     dest='readxls')
options.add_argument(
    '--readxls_notshared',
    help=
    'preliminary work for converting xls to ruleset - putting objects into shared',
    action='store_false',
    default=True,
    dest='readxls_shared')
options.add_argument('--pushobjects',
                     action='store_true',
                     default=False,
                     help='push address and service objects',
                     dest='pushobjects')
options.add_argument('--pushrules',
                     action='store_true',
                     default=False,
                     help='push rules',
                     dest='pushrules')
options.add_argument('--getidp',
                     action='store_true',
                     default=False,
                     help='Get Sonicwall IDP page details',
                     dest='getidp')
options.add_argument('--zonemaps',
                     nargs='+',
                     help='Zone mapping details when reading XML file',
                     metavar='xlszone,fwzone,policynametext',
                     type=str,
                     dest='zonemaps')
options.add_argument(
    '--fixzonemaps',
    nargs='+',
    help='Zone mapping details when fixing converted Expedition zones',
    metavar='interface,oldzone,newzone',
    type=str,
    action=file_list(),
    dest='fixzonemaps')
options.add_argument('--rulelist',
                     nargs='+',
                     help='',
                     metavar='',
                     type=str,
                     action=file_list(),
                     dest='rulelist')
options.add_argument('--migratezones',
                     nargs='+',
                     help='Zone mapping details when migrating SW to Palo',
                     metavar='sw_zone,palo_zone',
                     type=str,
                     action=file_list(),
                     dest='migratezones')
options.add_argument('--nick',
                     type=str,
                     help='update logprofiles',
                     dest='nick')
options.add_argument('--readonly',
                     help='enable readonly for Nexpose address routines',
                     action='store_true',
                     default=False,
                     dest='readonly')
options.add_argument('--testing',
                     help='enable block of code for Testing new routines',
                     action='store_true',
                     default=False,
                     dest='testing')
options.add_argument('--gordon',
                     action='store_true',
                     default=False,
                     help='get list of users',
                     dest='gordon')
options.add_argument('--management',
                     action='store_true',
                     default=False,
                     help='get interface management properties',
                     dest='management')
options.add_argument('--secureid',
                     action='store_true',
                     default=False,
                     help='update all rules with RSA secureid details',
                     dest='secureid')
options.add_argument(
    '--movecheckpoint',
    action='store_true',
    default=False,
    help='Generate dbedit commands to move Checkpoint policy to a new CMA',
    dest='movecheckpoint')
options.add_argument('--emcroute',
                     nargs='+',
                     type=str,
                     help='Update EMC public network routes internally',
                     dest='emcroute')
options.add_argument(
    '--comment',
    type=str,
    default=argparse.SUPPRESS,
    help='Comment for bulk object/rule creation (when supported by target)',
    dest='comment')
options.add_argument('--sw_upload_fw',
                     help='upload SonicWall firmware file',
                     action='store_true',
                     default=False,
                     dest='sw_upload_fw')
options.add_argument('--sw_backup',
                     help='perform "Create Backup" on  SonicWall',
                     action='store_true',
                     default=False,
                     dest='sw_backup')
options.add_argument('--sw_audit',
                     help='audit SonicWall configuration',
                     action='store_true',
                     default=False,
                     dest='sw_audit')
options.add_argument('--sw_reboot',
                     help='reboot SonicWall using uploaded firmware',
                     action='store_true',
                     default=False,
                     dest='sw_reboot')
options.add_argument('--sw_failover',
                     help='Force failover on Sonicwall',
                     action='store_true',
                     default=False,
                     dest='sw_failover')
options.add_argument('--sw_get_tsr',
                     help='upload SonicWall firmware file',
                     action='store_true',
                     default=False,
                     dest='sw_get_tsr')
options.add_argument('--sw_enable_api',
                     help='',
                     action='store_true',
                     default=False,
                     dest='sw_enable_api')
options.add_argument('--sw_revert_api',
                     help='',
                     action='store_true',
                     default=False,
                     dest='sw_revert_api')
options.add_argument('--fixcomments',
                     nargs='+',
                     help='list of address objects that need comment updated',
                     metavar='IP Address',
                     action=file_list(),
                     type=str,
                     dest='fixcomments')
options.add_argument(
    '--grouptargets',
    '--targets',
    nargs='+',
    help='list of Sonicwall IP addresses to make group changes to',
    metavar='IP Address',
    action=file_list(),
    type=str,
    dest='grouptargets')
options.add_argument('--groupaddresses',
                     nargs='+',
                     help='list of IP addresses to add to group',
                     metavar='IP address',
                     action=file_list(),
                     type=str,
                     dest='groupaddresses')
options.add_argument(
    '--groupmaster',
    nargs='+',
    help='list of master group candidate names -- uses first name only',
    metavar='group names',
    action=file_list(),
    type=str,
    dest='groupmaster')
options.add_argument(
    '--groupusemaster',
    action='store_true',
    default=False,
    help='place addresses directly into master group rather than subgroups',
    dest='groupusemaster')
options.add_argument('--groupservices',
                     '--groupsvcs',
                     nargs='+',
                     help='list of services to add to group',
                     metavar='IP address',
                     action=file_list(),
                     type=str,
                     dest='groupservices')
options.add_argument('--testcreate',
                     action='store_true',
                     default=False,
                     help='testing',
                     dest='testcreate')
options.add_argument('--testdelete',
                     action='store_true',
                     default=False,
                     help='testing',
                     dest='testdelete')
options.add_argument('--testmodify',
                     action='store_true',
                     default=False,
                     help='testing',
                     dest='testmodify')
options.add_argument('--dmz',
                     action='store_true',
                     default=False,
                     help='testing',
                     dest='dmz')
options.add_argument('--uuid',
                     type=str,
                     nargs="*",
                     default=None,
                     help='testing',
                     action=file_list(),
                     dest='uuid')
options.add_argument('--ldap', nargs='+', help='testing', dest='ldap')
options.add_argument('--recheck',
                     nargs='+',
                     help='list of IP addresses to log into',
                     metavar='IP Address',
                     action=file_list(),
                     type=str,
                     dest='recheck')
