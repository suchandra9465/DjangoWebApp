from . import utils
from . import rulesearch_utils

class services:
    config={}
    def __init__(self, config) -> None:
        self.config = config
        
    
    # todo: not sure how to create config .. so considering it as parameter?
    # consider input as dict 
    
    def service_nexpose(self,options):  ## create address objects 

        def run_parallel(targets, max_proc=48):
        
            from multiprocessing import Pool

            pool = Pool(processes=max_proc)
            results=pool.map(utils.bulk_create_addresses, targets)
            
            return results
    
        if options.grouptargets:
            results=run_parallel(options.grouptargets)
            for target, new_addresses, existing_addresses, members_added, members_existed in results:
                if new_addresses!='Exception':
                    # check for better way 
                    log('{},{},{},{}'.format(target, 'New Addresses', len(new_addresses), new_addresses))
                    log('{},{},{},{}'.format(target, 'Existing Addresses', len(existing_addresses), existing_addresses))
                    log('{},{},{},{}'.format(target, 'New Group Members', len(members_added), members_added))
                    log('{},{},{},{}'.format(target, 'Existing Group Members', len(members_existed), members_existed))
                else:
                    log('{},{},{}'.format(target, 'Exception', new_addresses))

        else:
            log(options.grouptargets)
            log('Creating bulk objects without target group targets specified')
            utils.bulk_create_addresses(None, self.config,self.params)

    # todo: contexts 
    def service_ruleSearch(self,options):
        rulesearch_utils.find_matching_rules2(config, config['shared'], options.rulematch, contexts, options.rulemodify)
        
    # dunp config
    
    # sonicwall 14620