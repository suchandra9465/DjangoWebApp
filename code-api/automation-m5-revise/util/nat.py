import urllib
from urllib.parse import unquote

from logger import log, debug
from helper import sc
from zones import get_zones


def create_nat(nat_policies, context, zone_map, interface_map, interfaces, builtin_map):

    # currently only handles source NAT (and bidirectionals)
    # Interface objects do not appear to be in the output xml file, some built in types may not be converted
    # Object names in groups not expanded as expected
    #

    # nat_props = [ 'natPolicyOrigSrc', 'natPolicyOrigDst', 'natPolicyOrigSvc', 'natPolicyTransSrc', 'natPolicyTransDst', 'natPolicyTransSvc', 'natPolicySrcIface', 'natPolicyDstIface', 'natPolicyEnabled', 'natPolicyComment', 'natPolicyProperties', 'natPolicyName' ]

    ## if source if a "default"/built-in address GROUP, the code below does not handle this properly.
    ## change orig/trans src/dest to lists

    policynum = 1
    intnums = {}
    added_policies = []
    for interface in interfaces:
        intnums[interfaces[interface]['iface_ifnum']] = interface
    log('            <nat>')
    log('              <rules>')

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
                    debug(nat_policies[policy]['natPolicyDstIface'])
                    debug(interface_map)

            if nat_policies[policy]['natPolicyOrigSrc'][0] == '':
                orig_source = ['any']
            else:
                if config[context]['addresses'][nat_policies[policy]['natPolicyOrigSrc'][0]][
                    'addrObjProperties'] != '14':
                    orig_source = ["BUILTIN_" + sc(nat_policies[policy]['natPolicyOrigSrc'][0])]  ## placeholder
                else:
                    orig_source = [nat_policies[policy]['natPolicyOrigSrc'][0]]

            if nat_policies[policy]['natPolicyTransSrc'][0] != '':
                if config[context]['addresses'][nat_policies[policy]['natPolicyTransSrc'][0]][
                    'addrObjProperties'] != '14':
                    '''
                    trans_source=config[context]['addresses'][nat_policies[policy]['natPolicyTransSrc'][0]]['addrObjIp1']+'/'+ str(netmask_to_cidr(config[context]['addresses'][nat_policies[policy]['natPolicyTransSrc'][0]]['addrObjIp2']))
                    trans_source='NAT_TransSrc_{}'.format(int(policy+1))
                    '''
                    trans_source = "BUILTIN_" + sc(nat_policies[policy]['natPolicyTransSrc'][0])  ## placeholder
                else:
                    trans_source = nat_policies[policy]['natPolicyTransSrc'][0]

            if nat_policies[policy]['natPolicyOrigDst'][0] == '':
                orig_dest = ['any']
            else:
                if config[context]['addresses'][nat_policies[policy]['natPolicyOrigDst'][0]]['addrObjProperties'] != '14':
                    '''orig_dest=[config[context]['addresses'][nat_policies[policy]['natPolicyOrigDst'][0]]['addrObjIp1']+'/'+ str(netmask_to_cidr(config[context]['addresses'][nat_policies[policy]['natPolicyOrigDst'][0]]['addrObjIp2']))]
                    orig_dest=['NAT_OrigDst_{}'.format(int(policy+1))]
                    '''
                    orig_dest = ["BUILTIN_" + sc(nat_policies[policy]['natPolicyOrigDst'][0])]  ## placeholder
                else:
                    orig_dest = [nat_policies[policy]['natPolicyOrigDst'][0]]
            # log(orig_dest)
            # log(zone_map)
            # log(context)
            # log(config[context]['addresses'][orig_dest[0]]['addrObjType'])
            # log(config[context]['addresses'][orig_dest[0]])
            # log(config[context]['addresses'][orig_dest[0]]['IPSet'])
            if dst_zones == ['any']:
                # dst_zones=zone_map[get_zones(context, str(config[context]['addresses'][orig_dest[0]]['IPSet'].iter_cidrs()[0][0])).lower()]
                tmp_dst_zones = get_zones(context, orig_dest[0])
                dst_zones = []
                for zone in tmp_dst_zones:
                    if zone in zone_map:
                        dst_zones.append(zone_map[zone])
                    else:
                        dst_zones.append(zone)

            # if src_zones==['any']:
            #    #src_zones=zone_map[get_zones(context, str(config[context]['addresses'][orig_source[0]]['IPSet'].iter_cidrs()[0][0])).lower()]
            #    src_zones=get_zones(context, orig_source[0])
            # log('DSTZONE: ', dst_zones)
            if nat_policies[policy]['natPolicyTransDst'][0] != '':
                if config[context]['addresses'][nat_policies[policy]['natPolicyTransDst'][0]][
                    'addrObjProperties'] != '14':
                    '''trans_dest=config[context]['addresses'][nat_policies[policy]['natPolicyTransDst'][0]]['addrObjIp1']+'/'+ str(netmask_to_cidr(config[context]['addresses'][nat_policies[policy]['natPolicyTransDst'][0]]['addrObjIp2']))
                    trans_dest='NAT_TransDst_{}'.format(int(policy+1))
                    '''
                    trans_dest = "BUILTIN_" + sc(nat_policies[policy]['natPolicyTransDst'][0])  ## placeholder
                else:
                    trans_dest = nat_policies[policy]['natPolicyTransDst'][0]

            # log('"{}" "{}" "{}"'.format('translated', nat_policies[policy]['natPolicyTransSrc'][0], trans_source))
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
                    nat_policies[tmp_policy]['natPolicyTransDst'], nat_policies[tmp_policy]['natPolicyOrigDst'],
                    nat_policies[tmp_policy]['natPolicyOrigSrc'], nat_policies[tmp_policy]['natPolicyTransSrc'],
                    nat_policies[tmp_policy]['natPolicyOrigSvc'], nat_policies[tmp_policy]['natPolicyTransSvc']):
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
                        log('                  <entry name="Imported NAT Policy {}-{}">'.format(policynum, dst_zone))

                        if nat_policies[policy]['natPolicyTransSrc'][0] != '':
                            log('                    <source-translation>')
                            log('                      <static-ip>')
                            log('                       <translated-address>{}</translated-address>'.format(
                                sc(trans_source)))
                            log('                      <bi-directional>{}</bi-directional>'.format(bidirectional))
                            log('                     </static-ip>')
                            log('                   </source-translation>')
                        if nat_policies[policy]['natPolicyTransDst'][0] != '':
                            log('                    <destination-translation>')
                            log('                       <translated-address>{}</translated-address>'.format(
                                sc(trans_dest)))
                            log('                   </destination-translation>')
                        log('                    <target>')
                        log('                      <negate>no</negate>')
                        log('                    </target>')
                        log('                    <to>')
                        log('                      <member>{}</member>'.format(urllib.parse.unquote(dst_zone)))
                        log('                    </to>')
                        log('                    <from>')
                        log('                      <member>{}</member>'.format(urllib.parse.unquote(src_zone)))
                        log('                    </from>')
                        log('                    <source>')
                        for source in orig_source:
                            log('                      <member>{}</member>'.format(sc(source)))
                        log('                    </source>')
                        log('                    <destination>')
                        for dest in orig_dest:
                            log('                      <member>{}</member>'.format(sc(dest)))
                        log('                    </destination>')
                        log('                    <service>{}</service>'.format(urllib.parse.unquote(orig_svc)))
                        log('                    <nat-type>ipv4</nat-type>')
                        if nat_policies[policy]['natPolicyEnabled'] == '0':
                            log('                    <disabled>yes</disabled>')
                        # log(policynum, nat_policies[policy]['natPolicyProperties'], nat_policies[policy]['natPolicyEnabled'])
                        log('                    <description>{}</description>'.format(
                            urllib.parse.unquote(nat_policies[policy]['natPolicyComment'])))
                        log('                    <to-interface>{}</to-interface>'.format(dst_int))

                        log('                  </entry>')
                added_policies.append((nat_policies[policy]['natPolicyOrigSrc'],
                                       nat_policies[policy]['natPolicyTransSrc'],
                                       nat_policies[policy]['natPolicyOrigDst'],
                                       nat_policies[policy]['natPolicyTransDst'],
                                       nat_policies[policy]['natPolicyOrigSvc'],
                                       nat_policies[policy]['natPolicyTransSvc']))
        policynum += 1

        # log('                </entry>')
    log('              </rules>')
    log('            </nat>')

    return
