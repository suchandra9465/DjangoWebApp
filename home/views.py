from django.shortcuts import render,redirect
from django.contrib import messages,auth
from django.contrib.auth.decorators import login_required

# Create your views here.
@login_required
def dashboard(request):
    if request.method == 'POST':
        username = request.POST.get('username')
        password = request.POST.get('password')
        group_address = request.POST.get('address_group_name')
        messages.success(request, 'Job has launched successfully',extra_tags='alert')
        result = "/opt/scripts/git/m65/m5.py --nexpose DeleteMe --groupadd {group} --fwtype sw65 --grouptargets 10.0.8.237 --username {user} --password {pwd} --comment 'Test'".format(group=group_address, user=username,pwd=password)
        print(result)
        return redirect('dashboard')
    
    return render(request, 'home/dashboard.html')

@login_required
def migrations(request):
    if request.method == 'POST':
        username = request.POST.get('username')
        password = request.POST.get('password')
        group_address = request.POST.get('address_group_name')
        messages.success(request, 'Job has launched successfully',extra_tags='alert')
        result = "/opy/pavan.py --grouptar {group} -nexpose AGILE_GROUP --nexposeaddr  'file.csv' --iwtype sw --username {user} --password {pwd}".format(group=group_address, user=username,pwd=password)
        print(result)
        return redirect('dashboard')
    
    return render(request, 'home/migration_form.html')

@login_required
def dumpConfig(request):
    if request.method == 'POST':
        username = request.POST.get('username')
        password = request.POST.get('password')
        group_address = request.POST.get('address_group_name')
        messages.success(request, 'Job has launched successfully',extra_tags='alert')
        result = "/opt/scripts/git/m65/m5.py --nexpose DeleteMe --groupadd {group} --fwtype sw65 --grouptargets 10.0.8.237 --username {user} --password {pwd} --comment 'Test'".format(group=group_address, user=username,pwd=password)
        print(result)
         
    
    return render(request, 'home/dumpConfig_form.html')

@login_required
def ruleSearch(request):
    if request.method == 'POST':
        username = request.POST.get('username')
        password = request.POST.get('password')
        rule_match_pattern = request.POST.get('rule_match_pattern')
        messages.success(request, 'Job has launched successfully',extra_tags='alert')
        result = "/opt/scripts/git/m65/m5.py -p 1.2.3.4 or -P 5.6.7.8 –username {user} –password {pwd} –rulematch {rule}".format(pwd=password, user=username,rule=rule_match_pattern)
        print(result)
        return redirect('dashboard')
    
    return render(request, 'home/ruleSearch_form.html')