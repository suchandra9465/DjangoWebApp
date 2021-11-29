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


def get_sw_config_https(host, outfile, username='admin', password='admin'):

    log("!-- Retrieving SonicWall configuration file from host : " + host)
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
            log("!-- Error retrieving configuration file")
            return False
    except:
        return False
    return sw_config.text
      
