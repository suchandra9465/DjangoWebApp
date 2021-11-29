import re
import ipaddress
from . import sonicwall
from . import sonicwall_utils
from netaddr import IPSet, IPRange, IPNetwork

class utils:
    def __init__(self,target,options):
        self.target = target
    
    def bulk_create_addresses(target,options,config=None):

        try:
            members_added=[]
            members_existed=[]
            new_addresses=[]
            existing_addresses=[]

            if target==None:
                # params from views
                if options.panoramaip:
                    target=options.panoramaip
                elif options.sonicwallip:
                    target=options.sonicwallip
                elif options.sonicwall_api_ip:
                    target=options.sonicwall_api_ip
                elif options.checkpoint_api:
                    target=options.checkpoint_api
                elif options.checkpoint:
                    target=''
                else:
                    target=''
            else:
                log(target)
                if options.fwtype in ['sw', 'sonicwall']:  ## not really supported as I need to read in routing table
                    config=sonicwall_utils.get_sonicwall_exp(target,options)

                elif options.fwtype in ['sw65']:
                    config={}
                    config['sonicwall']=load_sonicwall_api(target, options.username, options.password)
                    if not options.context:
                        options.context = ['sonicwall']
                    for context in options.context:
                        contexts.append(context)
                elif options.fwtype in ['palo', 'panorama', 'pano']:
                    palo_xml=get_palo_config_https(target, 'config.panorama.temp', options.username, options.password)
                    if palo_xml:
                        config = load_xml('', palo_xml)
                        palo_xml=None
                elif options.fwtype in ['cp', 'checkpoint']:  ## not much advantage for multiprocessing here, can just perform this by loading config files per cma and generating dbedit commands.
                    pass
            ## should probably allow the use of options.grouptargets

            #log(config['sonicwall']['addressmappings'])
        
            comment=options.comment

            nexpose_delay=0
            ## Create Nexpose group

            #if options.nexpose.lower() not in [x.lower() for x in config['shared']['addresses']]:  ## create address group if needed
            #    if not options.readonly:
            #        log('Creating Address Group : {}'.format(options.nexpose))
            #        result=exec_fw_command(target, 'pano', [('create_address', {'addressname': options.nexpose, 'addresstype': '8', 'zone': 'LAN', 'color': 'black', 'comment': comment, 'members': [], 'context': 'shared'})], syntax='api', delay=10)
            #else:
            #    log('Using existing Address Group : {}'.format(options.nexpose))

            ## Create rules with group - this was removed as it is now added as a shared policy
            #if options.context != ['all']:
            #log(options.groupaddresses)

            target_context=None
            for context in options.context:
                log('')
                log('context : ', context)
                target_zone=None
                group_length=len(options.groupaddresses)
                #log(context)
                address_group_members=expand_address(config[context]['addresses'], options.nexpose, config[context]['addressmappings'])
                #if len(address_group_members) >= group_length:
                #    log('{} contains {} members, no action needed (STEP1)'.format(options.nexpose, len(address_group_members)))
                #else:
                #log('{} only contains {} members, creating address objects (STEP1)'.format(options.nexpose, len(address_group_members)))
                #log(config[context]['addresses'])
                if len(config[context]['addresses']) > 1 or context=='shared': # at least one address must exist to continue, otherwise loading config likely failed.
                    debug('addresses > 1')
                    sw_objects={'address_objects': {'ipv4': [], 'ipv6': [], 'fqdn': []}, 'address_groups': {'ipv4': [], 'ipv6': [], 'fqdn': []}, 'service_objects': [], 'service_groups': [] }
                    if context in config:
                        fw_type=config[context]['config']['fw_type']
                        if fw_type in ["sw65", "palo", "pano", "R80", 'paloalto', 'panorama']:
                            api_type='api'
                        elif fw_type == "sonicwall":
                            api_type='webui'
                        elif fw_type == "checkpoint":
                            api_type='cli'
                        if fw_type in ['pano', 'panorama']:
                            fw_type='pano'
                            target_zone=True
                            target_context='shared'
                            if options.nexpose.lower() not in [x.lower() for x in config['shared']['addresses']] and not options.readonly:    ## create address group if needed
                                log('Creating Shared Address Group : {}'.format(options.nexpose))
                                result=exec_fw_command(target, fw_type, [('create_address', {'addressname': options.nexpose, 'addresstype': '8', 'zone': 'LAN', 'color': 'black', 'comment': comment, 'members': [], 'context': target_context})], syntax=api_type, delay=nexpose_delay)
                            elif options.nexpose.lower() in [x.lower() for x in config['shared']['addresses']]:
                                for address in config[context]['addresses']:
                                    if address.lower() == options.nexpose.lower():
                                        options.nexpose=address
                                        break
                                log('!-- Using existing Address Group : {}'.format(options.nexpose))
                        elif  fw_type not in ['pano', 'panorama']:
                            target_context=context
                            if fw_type in ['sonicwall', 'sw65']:
                                #log(options.groupaddresses[0].split(',')[0])
                                if not options.skipzone:
                                    for address in options.groupaddresses:
                                        if len(address.split('%'))==2:
                                            target_zone=get_zone(target_context, address.split(',')[0].split('%')[1], config)
                                        else:
                                            target_zone=get_zone(target_context, address.split(',')[0], config)
                                        if target_zone!=None:
                                            #log('target_zone', target_zone, address)
                                            break
                                    if target_zone==None:
                                        #log(options.groupaddresses)
                                        #log(options.groupaddresses[0].split(',')[0])
                                        try:
                                            log('Trying to determine zone for {}'.format(options.groupaddresses[0].split(',')[0]))
                                            target_zone=get_zones2(target_context, options.groupaddresses[0].split(',')[0], config)[0]
                                        except:
                                            target_zone=None
                                    
                                    log('!-- Zone for newly created objects : {}'.format(target_zone))
                                else:
                                    log('!-- Skipping zone detection for adding address objects to group')
                                    target_zone=True
                                log('!-- Building lists for address and service objects')
                                orig_api=True
                                #orig_api=sw_get_api_status(target, options.username, options.password)
                                #sw_enable_api(target, options.username, options.password)
                                sw_objects=get_sw_objects(target, options.username, options.password, fw_type)
                            else:
                                #log('Zone for newly created objects : {}'.format(target_zone))
                                target_zone='LAN'
                                orig_api=None
                            
                            #if options.nexpose.lower() not in [x.lower() for x in config[context]['addresses']] and not options.readonly:
                                #log('!-- Original API status {}'.format(orig_api))
                                #if api_type=='api' and orig_api==False:  ## only enable if needed -- enabling API will log you out of box
                                #    sw_enable_api(target, options.username, options.password) 
                                #log('!-- Creating Temp Address Object for Sonicwalls ')
                                #result=exec_fw_command(target, fw_type, [('create_address', {'addressname': 'temp_address_object', 'ip1': '1.1.1.1', 'ip2' : '255.255.255.255', 'addresstype': '1', 'zone': target_zone, 'color': 'black', 'comment': 'DELETE_ME', 'context': target_context})], syntax=api_type, delay=nexpose_delay)
                                #log('!-- Creating Address Group : {}'.format(options.nexpose))
                                #result=exec_fw_command(target, fw_type, [('create_address', {'addressname': options.nexpose, 'addresstype': '8', 'zone': target_zone, 'color': 'black', 'comment': comment, 'members': ['temp_address_object'], 'context': target_context})], syntax=api_type, delay=nexpose_delay)
                                #log(result)
                            #elif options.nexpose.lower() in [x.lower() for x in config[context]['addresses']]:
                            if options.nexpose.lower() in [x.lower() for x in config[context]['addressmappings']]:
                                for address in config[context]['addresses']:
                                    if address.lower() == options.nexpose.lower():
                                        options.nexpose=address
                                        break
                                log('!-- Using existing Address Group : {}'.format(options.nexpose))                 
                            

                            #result=exec_fw_command(target, fw_type, [('create_rule', {'rulename': 'test_rule', 'policyname': context, 'policynum': '1', 'polaction': '1', 'srczones': [target_zone], 'dstzones': ['WAN'], 'sources': ['test_host'], 'dests': ['test_group'], 'services': ['any'], 'comment': 'testing', 'context': context})], syntax='api')
                            #result=exec_fw_command(target, fw_type, [('create_rule', {'rulename': 'NEXPOSE', 'policyname': context, 'policynum': '1', 'polaction': '2', 'srczones': [target_zone], 'dstzones': ['any'], 'sources': [options.nexpose], 'dests': ['any'], 'services': ['any'], 'applications': ['any'], 'comment': comment, 'disabled': 'True', 'context': context})], syntax='api', delay=10)
                            #result=exec_fw_command(target, 'pano', [('modify_rule', {'action': 'disable', 'comment': 'Modified Comment', 'rulename': 'NEXPOSE', 'policyname': context, 'policynum': '1', 'polaction': '1', 'srczones': ['LAN'], 'dstzones': ['WAN'], 'sources': ['test_host'], 'dests': ['test_group'], 'services': ['any'], 'context': context})], syntax='api')
            #if len(address_group_members) >= group_length:
            #    log('{} contains {} members, no action needed (STEP2)'.format(options.nexpose, len(address_group_members)))
            #else:
            #target_zone='WAN'
            #log(target_zone, target_context)

            members_added=[]
            members_existed=[]
            new_addresses=[]
            existing_addresses=[]      
            log(target_zone)
            log(target_context)
            if target_context:
                if target_zone and (len(config[target_context]['addresses']) > 1 or context== 'shared' ):

                    addresses_to_add=[] # list of sets containing (network, mask, address_name)
                    address_cmds=[]
                    group_members=[]

                    for address_to_add in options.groupaddresses:  ## build addresses_to_add
                        fqdn=None
                        if address_to_add in config[target_context]['addresses']:
                            group_members.append(address_to_add)
                            log('Using existing object name with exact name match {}'.format(address_to_add))
                            existing_addresses.append(address_to_add)
                        elif len(address_to_add.split(',')) == 2:
                            
                            address_obj, address_name=address_to_add.split(',')
                            if len(address_obj.split('/'))==2:
                                network, mask=address_obj.split('/')
                            elif len(address_obj.split('%'))==2:
                                fqdn, fqdn_ip=address_obj.split('%')
                            elif len(address_obj.split('-'))==2:
                                range_start, range_end=address_obj.split('-')
                                network, mask = (None, None)
                            else: 
                                network, mask=(address_obj, '32')
                            if fqdn!=None:
                                addresses_to_add.append((fqdn, fqdn_ip, address_name, 'fqdn'))
                                #target_zone=get_zone(target_context, fqdn_ip, config)
                            else:
                                try: 
                                    tmpaddr=IPNetwork(network+'/'+str(mask))
                                    addresses_to_add.append((network, mask, address_name, 'network'))
                                except:
                                    try:
                                        tmpaddr=IPRange(range_start, range_end)
                                        addresses_to_add.append((range_start, range_end, address_name, 'range'))
                                    except:
                                        #pass
                                        log('!-- Skipping entry {} - Invalid format'.format(address_to_add))
                        
                        else:
                            log('!-- Skipping entry {} - Invalid format - Expected network/mask,address_name'.format(address_to_add))

                    ## for sonicwalls, if we are adding objects to a group, I need to add routines to ensure addresses being added do not overlap!

                    #for address_to_add in addresses_to_add: ## now perform action on each address object to add
                    matches={}
                    
                    #for addr in addresslist: log(addr)
                    #log ('-'*100)
                    #for first, address_name in groupaddresses: log(address_name)

                    ###result=exec_fw_command(fwip, fw, [('create_address', {'addressname': 'test_fqdn', 'domain': 'www.deleteme.com', 'ttl': '120', 'addresstype': 'fqdn', 'zone': 'LAN', 'color': 'black' })], syntax=syntax)
                    
                    for network, mask, address_name, address_type in addresses_to_add: ## build a list of existing address objects that match each object that needs to be created
                        if address_type=='network':
                            network_mask='{}/{}'.format(network, mask)
                            fqdn_name=address_name
                            try:
                                host_name=address_name.split('.')[0]
                            except:
                                host_name=address_name
                            matches[network_mask]={'address_ip': None, 'fqdn': None, 'hostname': None, 'other': None }
                            #log('new address : ', address_name)
                            for config_address in config[target_context]['addresses']:  ## build a list of existing address objects that match the object we want to add
                                if config[target_context]['addresses'][config_address]['IPv4Networks'] == [ipaddress.IPv4Network(network_mask)]: # or ( config[target_context]['addresses'][config_address]['addrObjIp1'] == network and config[target_context]['addresses'][config_address]['addrObjIp2']==cidr_to_netmask(mask)):
                                    #log(config[target_context]['addresses'][address])
                                    if config_address not in matches[network_mask]:
                                        if re.findall(r'{}.*{}'.format(host_name, network), config_address.lower(), flags=re.IGNORECASE):
                                            matches[network_mask]['address_ip']=config_address
                                            existing_addresses.append(config_address)
                                        elif config_address.lower() == fqdn_name.lower():
                                            matches[network_mask]['fqdn']=config_address
                                            existing_addresses.append(config_address)
                                        elif config_address.lower() == host_name.lower():
                                            if not matches[network_mask]['hostname']:
                                                matches[network_mask]['hostname']=config_address 
                                                existing_addresses.append(config_address)
                                        else:
                                            if not matches[network_mask]['other']:
                                                matches[network_mask]['other']=config_address
                                                existing_addresses.append(config_address)


                            #if len(matches[network_mask]) == 0: ## no address object exists with same definition - create new address object and add it to group
                            #result=exec_fw_command(target, fw_type, [('create_address', {'addressname': new_address_name, 'ip1': network, 'ip2' : cidr_to_netmask(mask), 'addresstype': '1', 'zone': target_zone, 'color': 'black', 'comment': 'NEXPOSE_SCANNERS', 'context': target_context})], syntax='cli')
                            #result=exec_fw_command(target, fw_type, [('modify_address', {'action': 'addmembers', 'addressname': options.nexpose, 'members': [new_address_name], 'comment': 'NEXPOSE_GROUP', 'addresstype': '8', 'zone': target_zone, 'color': 'black', 'context': target_context})], syntax='cli')
                            #else: # figure out what address object to use and add it to group
                            #address_name
                            new_address_name=address_name
                            if len(address_name.split('.')) > 0:
                                new_address_name=address_name.split('.')[0]
                            if mask!='32':
                                new_address_name='{}-{}_{}'.format(new_address_name, network, mask)
                            else:
                                new_address_name='{}-{}'.format(new_address_name, network)
                            if matches[network_mask]['address_ip']:
                                log('Using existing object name with address_ip match {} instead of requested name {}'.format(matches[network_mask]['address_ip'], address_name))
                                group_members.append(matches[network_mask]['address_ip'])
                            elif matches[network_mask]['fqdn']:
                                log('Using existing object name with fqdn match {} instead of requested name {}'.format(matches[network_mask]['fqdn'], address_name))
                                group_members.append(matches[network_mask]['fqdn'])
                            elif matches[network_mask]['hostname']:
                                log('Using existing object name with hostname match {} instead of requested name {}'.format(matches[network_mask]['hostname'], address_name))
                                group_members.append(matches[network_mask]['hostname'])
                            elif matches[network_mask]['other']:
                                log('Using existing object name with first match {} instead of requested name {}'.format(matches[network_mask]['other'], address_name))
                                group_members.append(matches[network_mask]['other'])
                            else: ## no matches found
                                log('Creating new address object {} defined as {}'.format(new_address_name, network_mask))
                                new_addresses.append(new_address_name)
                                group_members.append(new_address_name)
                                if mask=='32':
                                    address_cmds.append(('create_address', {'addressname': new_address_name, 'ip1': network, 'ip2' : cidr_to_netmask(mask), 'addresstype': '1', 'zone': target_zone, 'color': 'black', 'comment': comment, 'context': target_context}))
                                else:
                                    address_cmds.append(('create_address', {'addressname': new_address_name, 'ip1': network, 'ip2' : cidr_to_netmask(mask), 'addresstype': '4', 'zone': target_zone, 'color': 'black', 'comment': comment, 'context': target_context}))
                        elif address_type=='range':
                            new_address_name=address_name
                            #for range_start, range_end, address_name, address_type in addresses_to_add: ## build a list of existing address objects that match each object that needs to be created
                            address_cmds.append(('create_address', {'addressname': new_address_name, 'ip1': network, 'ip2' : mask, 'addresstype': '2', 'zone': target_zone, 'color': 'black', 'comment': comment, 'context': target_context}))
                            group_members.append(new_address_name)
                        elif address_type=='fqdn':  #[('create_address', {'addressname': 'test_fqdn', 'domain': 'www.deleteme.com', 'ttl': '120', 'addresstype': 'fqdn', 'zone': 'LAN', 'color': 'black' })]
                            #log('Creating fqdn object {}'.format(address_name))
                            #log(config[target_context]['addressesfqdn'])
                            #for x in config[target_context]['addressesfqdn']:
                            #    log(x)
                            #    pass
                            #    log(config[target_context]['addressesfqdn'][x])
                            #if address_name in config[target_context]['addresses'] or address_name in config[target_context]['addressesV6']:# or address_name in config[target_context]['addressesfqdn']:
                            #    existing_addresses.append(address_name)
                            #    log('Using existing fqdn object with name {}'.format(address_name))

                            ## Sonicwall 6.5.4.8 has a problem where sometimes the JSON returned for FQDN objects is mixed-up.  an FQDN match will only happen if both the Name of the object and the
                            ## FQDN definition of the object are the same.  This is not ideal, as it should only match on FQDN definition.  Our use of FQDNs is limited, so no major concerns here. 

                            if network in [config[target_context]['addressesfqdn'][x]['addrObjFqdn'] for x in config[target_context]['addressesfqdn']] and address_name in [config[target_context]['addressesfqdn'][y]['addrObjFqdnId'] for y in config[target_context]['addressesfqdn']]:
                                for y in config[target_context]['addressesfqdn']:
                                    log('{} -- {} -- {} -- {}'.format(network, config[target_context]['addressesfqdn'][y]['addrObjFqdn'], address_name, config[target_context]['addressesfqdn'][y]['addrObjFqdnId']))
                                    if network in config[target_context]['addressesfqdn'][y]['addrObjFqdn'] and address_name == config[target_context]['addressesfqdn'][y]['addrObjFqdnId']:
                                        group_members.append(config[target_context]['addressesfqdn'][y]['addrObjFqdnId'])
                                        existing_addresses.append(config[target_context]['addressesfqdn'][y]['addrObjFqdnId'])
                                        log('Using existing fqdn object {} with name {}'.format(y, config[target_context]['addressesfqdn'][y]['addrObjFqdnId']))
                                        break
                                #existing_addresses.append(address_name)
                                #group_members.append(new_address_name)
                                
                            else:
                                log('Creating new fqdn object {}'.format(address_name))
                                new_address_name=address_name
                                address_cmds.append(('create_address', {'addressname': new_address_name, 'domain': network, 'addresstype': 'fqdn', 'zone': target_zone, 'color': 'black', 'comment': comment, 'context': target_context}))
                                group_members.append(new_address_name)
                    if not options.readonly:
                        if address_cmds != []:
                            #log(target, fw_type)
                            result=exec_fw_command(target, fw_type, address_cmds, syntax=api_type, delay=nexpose_delay, sw_objects=sw_objects)
                            log('Creating Address objects', result)
                            
                        else:
                            log('No new addresses need to be created')
                        members_added=[]
                        members_existed=[]
                        group_created=False
                        for sublist in [group_members[i:i + 50] for i in range(0, len(group_members), 50)]: ## only add a max of 50 group members at a time (limit is 100) -- should likely move this to the create/modify address group routines instead
                            result=False
                            if fw_type in ['sonicwall', 'sw65']:
                                sw_objects=get_sw_objects(target, options.username, options.password, fw_type)
                            for member in [x for x in sublist]: # cant use sublist and then change it in the loop.
                                if options.nexpose in config[target_context]['addressmappings']:
                                    if member in config[target_context]['addressmappings'][options.nexpose]:
                                        sublist.remove(member)
                                        members_existed.append(member)
                                        log('Removing {} from sublist'.format(member))

                            if options.nexpose.lower()!='none':
                                #log('sublist', sublist)
                                tries=0
                                while sublist != [] and result != True and tries<len(sublist):
                                    tries += 1
                                    log('subgroup members : ', sublist)
                                    if options.nexpose.lower() in [x.lower() for x in config[target_context]['addresses']] or options.nexpose.lower() in [x.lower() for x in config[target_context]['addressesV6']] or group_created:
                                        result=exec_fw_command(target, fw_type, [('modify_address', {'action': 'addmembers', 'addressname': options.nexpose, 'addresstype': '8', 'zone': target_zone, 'color': 'black', 'comment': comment, 'members': sublist, 'context': target_context})], syntax=api_type, delay=nexpose_delay, sw_objects=sw_objects)
                                        log('Adding members to existing group :', result)
                                    else:
                                        result=exec_fw_command(target, fw_type, [('create_address', {'addressname': options.nexpose, 'addresstype': '8', 'zone': target_zone, 'color': 'black', 'comment': comment, 'members': sublist, 'context': target_context})], syntax=api_type, delay=nexpose_delay, sw_objects=sw_objects)
                                        log('Creating group and adding members :', result)
                                        if result==True:
                                            group_created=True
                                    
                                    if result != True:
                                        bad_object=''
                                        if fw_type=='sw65':
                                            try:
                                                bad_object=result[1].split(' ')[5]
                                                sublist.remove(bad_object)
                                                log('Removing {} from group members'.format(bad_object))
                                                log('Group members {}'.format(sublist))
                                            except:
                                                log('Removing {} from group failed'.format(bad_object))
                                        else:
                                            #log(result)
                                            result=True
                                    else:
                                        for x in sublist:
                                            members_added.append(x) 

                        if members_added != []:
                            log('The following group members were successfully added : ', members_added)
                    #    if not orig_api:
                    #        sw_disable_api(target, options.username, options.password)
                else:
                    log('!-- Unable to determine Address object zone - skipping')        
            return (target, new_addresses, existing_addresses, members_added, members_existed)
        except Exception as e:
            #log(e)
            return (target, 'Exception', e, '', '')
