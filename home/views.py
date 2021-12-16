from django.shortcuts import render,redirect
from django.contrib import messages,auth,admin
from django.contrib.auth.decorators import login_required
from .models import large
from .models import StatusLog
from django.utils import timezone
from home.functions.services import services
from home.admin import StatusLogAdmin
import logging
db_logger = logging.getLogger('db')


# Create your views here.
@login_required
def dashboard(request):
    context = {}
    form_data = large.objects.all().order_by('-id')[:5]
    bulkaddress_no = large.objects.filter(jobType='bulkaddress').count()
    dumpConfig_no = large.objects.filter(jobType='dumpConfig').count()
    migrations_no = large.objects.filter(jobType='migrations').count()
    ruleSearch_no = large.objects.filter(jobType='ruleSearch').count()
    
    context['form_data'] = form_data
    context['bulkaddress_no'] = bulkaddress_no
    context['dumpConfig_no'] = dumpConfig_no
    context['migrations_no'] = migrations_no
    context['ruleSearch_no'] = ruleSearch_no
    
    return render(request, 'home/dashboard.html',context)

@login_required
def history(request):
    
    
    context = {}
    form_data = large.objects.all().order_by('-id')
    context['form_data'] = form_data
    
    
    return render(request, 'home/history.html', context)

#function to store the logs in database

def saveLog(request,jobid,ip,logdata):
    
    data_entry = StatusLog(jobid=jobid,ip=ip,log=logdata)
    data_entry.save()
    
    return render(request, 'home/pipeline.html')

@login_required
def bulkaddress(request):
    options = {} 
    if request.method == 'POST':
        target_ip = request.POST.get('target_ip')
        username = request.POST.get('username')
        password = request.POST.get('password')
        group_name = request.POST.get('address_group_name')
        firewallType = request.POST.get('firewall_type')
        comment = request.POST.get('comment')
        context = request.POST.get('context')
        addressObject = request.POST.get('about')
        readOnly = request.POST.get('readonly')
        if readOnly == 'on':
            readOnly = True
        else:
            readOnly = False
                     
        messages.success(request, 'Job has launched successfully',extra_tags='alert')
        # result = "/opt/scripts/git/m65/m5.py --nexpose DeleteMe --groupadd {group} --fwtype sw65 --grouptargets 10.0.8.237 --username {user} --password {pwd} --comment 'Test'".format(group=group_name, user=username,pwd=password)
        options['target_ip'] = target_ip
        options['username'] = username
        options['password'] = password
        options['group_name'] = group_name
        options['firewallType'] = firewallType
        options['comment'] = comment
        options['context'] = context
        options['addressObject'] = addressObject
        options['readOnly'] = readOnly
        # result = services()
        # print(result.service_nexpose(options))
        # print(result)
        
        # db_logger.warning('warning message')
        
        data_entry = large(createdBy=request.user.username,createdAt=timezone.now(),jobType="bulkaddress",username=username,password=password,targetID=target_ip,firewallType=firewallType,group_name=group_name,comment=comment,context=context,addressObject=addressObject,readOnly=readOnly)
        data_entry.save()
        
        # send_ip = StatusLogAdmin(admin.ModelAdmin)
        # send_ip.ip_format(target_ip)
        
        # db_logger.info('info message')
        
        
        return redirect('bulkaddress')
    
    return render(request, 'home/bulkaddress_form.html')

@login_required
def migrations(request):
    options = {} 
    if request.method == 'POST':
        username = request.POST.get('username')
        password = request.POST.get('password')
        group_address = request.POST.get('device_group_template')
        target_ip = request.POST.get('target_ip')
        loggingProfileName = request.POST.get('logging_profile_name')
        securityProfileName = request.POST.get('security_profile_name')
        interfaceMapping = request.POST.get('interface_mappings')
        zoneMapping = request.POST.get('zone_mapping')
        removeDupes = request.POST.get('remove_dupes')
        if removeDupes == 'on':
            removeDupes = True
        else:
            removeDupes = False
        removeUnused = request.POST.get('remove_unused')
        if removeUnused == 'on':
            removeUnused = True
        else:
            removeUnused = False
        checkPointExpansion = request.POST.get('checkpoint')
        if checkPointExpansion == 'on':
            checkPointExpansion = True
        else:
            checkPointExpansion = False
        print(zoneMapping,interfaceMapping,removeDupes,removeUnused,checkPointExpansion)
        messages.success(request, 'Job has launched successfully',extra_tags='alert')
        result = "/opy/pavan.py --grouptar {group} -nexpose AGILE_GROUP --nexposeaddr  'file.csv' --iwtype sw --username {user} --password {pwd}".format(group=group_address, user=username,pwd=password)
        print(result)
        
        options['target_ip'] = target_ip
        options['username'] = username
        options['password'] = password
        options['group_address'] = group_address
        options['securityProfileName'] = securityProfileName
        options['loggingProfileName'] = loggingProfileName
        options['interfaceMapping'] = interfaceMapping
        options['zoneMapping'] = zoneMapping
        options['removeDupes'] = removeDupes
        options['removeUnused'] = removeUnused
        options['checkPointExpansion'] = checkPointExpansion
        
        # result = services.service_nexpose(options)
        # print(result)
        
        data_entry = large(createdBy=request.user.username,createdAt=timezone.now(),jobType="migrations",username=username,password=password,targetID=target_ip,loggingProfileName=loggingProfileName,securityProfileName=securityProfileName,interfaceMapping=interfaceMapping,zoneMapping=zoneMapping,removeDupes=removeDupes,removeUnused=removeUnused,checkPointExpansion=checkPointExpansion)
        data_entry.save()
        
        return redirect('migrations')
    
    return render(request, 'home/migration_form.html')

@login_required
def dumpConfig(request):
    options = {} 
    if request.method == 'POST':
        #getting the values from dumpConfig Form
        username = request.POST.get('username')
        password = request.POST.get('password')
        target_ip = request.POST.get('target_ip')
        debug_enable = request.POST.get('enableCheck')
        if debug_enable == 'on':
            debug_enable = True
        else:
            debug_enable = False
        print(username,password,target_ip,debug_enable)
        
        messages.success(request, 'Job has launched successfully',extra_tags='alert')
        result = "/opt/scripts/git/m65/m5.py --nexpose DeleteMe --groupadd {group} --fwtype sw65 --grouptargets 10.0.8.237 --username {user} --password {pwd} --comment 'Test'".format(group=target_ip, user=username,pwd=password)
        print(result)
        
        options['target_ip'] = target_ip
        options['username'] = username
        options['password'] = password
        options['debug_enable'] = debug_enable
        
        # result = services.dump_config(options)
        # print(result)
        
        data_entry = large(createdBy=request.user.username,createdAt=timezone.now(),jobType="dumpConfig",username=username,password=password,targetID=target_ip,enableDebugOutput=debug_enable)
        data_entry.save()
        
        return redirect('dumpconfig')
    
    return render(request, 'home/dumpConfig_form.html')

@login_required
def ruleSearch(request):
    options = {}
    if request.method == 'POST':
        rule_match_pattern = request.POST.get('rule_match_pattern')
        target_ip = request.POST.get('target_ip')
        username = request.POST.get('username')
        password = request.POST.get('password')
        enableDebugOutput = request.POST.get('readonly')
        if enableDebugOutput == 'on':
            enableDebugOutput = True
        else:
            enableDebugOutput = False
        doNotMatchAnyAddress = request.POST.get('remove_unused')
        if doNotMatchAnyAddress == 'on':
            doNotMatchAnyAddress = True
        else:
            doNotMatchAnyAddress = False
        doNotMatchAnyService = request.POST.get('checkpoint')
        if doNotMatchAnyService == 'on':
            doNotMatchAnyService = True
        else:
            doNotMatchAnyService = False
            
            
        messages.success(request, 'Job has launched successfully',extra_tags='alert')
        result = "/opt/scripts/git/m65/m5.py -p 1.2.3.4 or -P 5.6.7.8 –username {user} –password {pwd} –rulematch {rule}".format(pwd=password, user=username,rule=rule_match_pattern)
        print(result)
        
        options['target_ip'] = target_ip
        options['username'] = username
        options['password'] = password
        options['rule_match_pattern'] = rule_match_pattern
        options['enableDebugOutput'] = enableDebugOutput
        options['doNotMatchAnyAddress'] = doNotMatchAnyAddress
        options['doNotMatchAnyService'] = doNotMatchAnyService
        
        # result = services.service_ruleSearch(options)
        # print(result)
        
        data_entry = large(createdBy=request.user.username,createdAt=timezone.now(),jobType="ruleSearch",username=username,password=password,targetID=target_ip,enableDebugOutput=enableDebugOutput,doNotMatchAnyAddress=doNotMatchAnyAddress,doNotMatchAnyService=doNotMatchAnyService  )
        data_entry.save()
        
        return redirect('rulesearch')
    
    return render(request, 'home/ruleSearch_form.html')