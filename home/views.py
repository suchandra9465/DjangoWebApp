from django.shortcuts import render, redirect
from django.contrib import messages, auth, admin
from django.contrib.auth.decorators import login_required
from .models import JobLog, Large
from django.utils import timezone
from home.functions.services import Services
import logging
import sys
from django.http.response import HttpResponse
from django.http import JsonResponse
import math


# Create your views here.
@login_required
def dashboard(request):
    context = {}
    form_data = Large.objects.all().order_by('-id')[:5]
    bulkaddress_no = Large.objects.filter(jobType='bulkaddress').count()
    dumpConfig_no = Large.objects.filter(jobType='dumpConfig').count()
    migrations_no = Large.objects.filter(jobType='migrations').count()
    ruleSearch_no = Large.objects.filter(jobType='ruleSearch').count()

    context['form_data'] = form_data
    context['bulkaddress_no'] = bulkaddress_no
    context['dumpConfig_no'] = dumpConfig_no
    context['migrations_no'] = migrations_no
    context['ruleSearch_no'] = ruleSearch_no

    return render(request, 'home/dashboard.html', context)


@login_required
def history(request):
    context = {}
    form_data = Large.objects.all().order_by('-id')
    context['form_data'] = form_data

    return render(request, 'home/history.html', context)


# function to store the logs in database
def pipeline_logs(request):
    job_id = request.GET.get('job_id')
    log_id = request.GET.get('logId')
    logs = JobLog.objects.filter(id=log_id).all()
    response_data = "No Logs Available"
    if logs:
        response_data = logs.values()[0]['log']

    return HttpResponse(response_data)


def pipeline(request):
    context = {}
    job_data = Large.objects.all().order_by('id')[:4]

    jobs = []
    total_cols = 6
    for job in job_data.values():
        jobLogs = JobLog.objects.filter(jobid_id=job['id']).all()

        temp = {'jobDetails': job, 'totalJobs': jobLogs.count(), 'jobs': jobLogs.values(),
                'colSpanVal': math.ceil(total_cols / jobLogs.count())};
        jobs.append(temp);

    context['jobsList'] = jobs;
    return render(request, 'home/pipeline.html', context);


@login_required
def bulk_address(request):
    options = {}
    if request.method == 'POST':

        options['target_ip'] = request.POST.get('target_ip')
        options['username'] = request.POST.get('username')
        options['password'] = request.POST.get('password')
        options['group_name'] = request.POST.get('address_group_name')
        options['firewallType'] = request.POST.get('firewall_type')
        options['comment'] = request.POST.get('comment')
        options['context'] = request.POST.get('context')
        options['addressObject'] = request.POST.get('about')
        options['readOnly'] = True if request.POST.get('readonly') == 'on' else False

        status = "InProgress"
        data_entry = Large(createdBy=request.user.username,
                           createdAt=timezone.now(),
                           jobType="bulkaddress",
                           username=options['username'],
                           password=options['password'],
                           targetID=options['target_ip'],
                           firewallType=options['firewallType'],
                           group_name=options['group_name'],
                           comment=options['comment'],
                           context=options['context'],
                           addressObject=options['addressObject'],
                           readOnly=options['readOnly'],
                           status=status)
        data_entry.save()

        obj = Large.objects.latest('id')
        result = Services.service_nexpose(options)

        # Todo : Write it to the log.
        # for ip in target_ip.split(','):
        #     job_entry = jobLog(jobid=obj, ip=ip, status=status)
        #     job_entry.save()

        return redirect('dashboard')

    return render(request, 'home/bulkaddress_form.html')


@login_required
def migrations(request):
    options = {}
    if request.method == 'POST':

        options['username'] = request.POST.get('username')
        options['password'] = request.POST.get('password')
        options['target_ip'] = request.POST.get('target_ip')
        options['group_address'] = request.POST.get('device_group_template')
        options['securityProfileName'] = request.POST.get('security_profile_name')
        options['loggingProfileName'] = request.POST.get('logging_profile_name')
        options['interfaceMapping'] = request.POST.get('interface_mappings')
        options['zoneMapping'] = request.POST.get('zone_mapping')
        options['removeDupes'] = True if request.POST.get('remove_dupes') == 'on' else False
        options['removeUnused'] = True if request.POST.get('remove_unused') == 'on' else False
        options['checkPointExpansion'] = True if request.POST.get('checkpoint') == 'on' else False

        messages.success(request, 'Job has launched successfully', extra_tags='alert')
        result = Services.service_nexpose(options)

        data_entry = Large(createdBy=request.user.username,
                           createdAt=timezone.now(),
                           jobType="migrations",
                           username=options['username'],
                           password=options['password'],
                           targetID=options['target_ip'],
                           loggingProfileName=options['loggingProfileName'],
                           securityProfileName=options['securityProfileName'],
                           interfaceMapping=options['interfaceMapping'],
                           zoneMapping=options['zoneMapping'],
                           removeDupes=options['removeDupes'],
                           removeUnused=options['removeUnused'],
                           checkPointExpansion=options['checkPointExpansion'])
        data_entry.save()

        return redirect('dashboard')

    return render(request, 'home/migration_form.html')


@login_required
def dump_config(request):
    options = {}
    if request.method == 'POST':

        options['username'] = request.POST.get('username')
        options['password'] = request.POST.get('password')
        options['target_ip'] = request.POST.get('target_ip')
        options['debug_enable'] = True if request.POST.get('enableCheck') == 'on' else False

        messages.success(request, 'Job has launched successfully', extra_tags='alert')

        # result = Services.dump_config(options)
        # print(result)

        data_entry = Large(createdBy=request.user.username, createdAt=timezone.now(), jobType="dumpConfig",
                           username=options['username'], password=options['password'], targetID=options['target_ip'],
                           enableDebugOutput=options['debug_enable'])
        data_entry.save()

        return redirect('dashboard')
    return render(request, 'home/dumpConfig_form.html')


@login_required
def rule_search(request):
    options = {}
    if request.method == 'POST':
        options['rule_match_pattern'] = request.POST.get('rule_match_pattern')
        options['target_ip'] = request.POST.get('target_ip')
        options['username'] = request.POST.get('username')
        options['password'] = request.POST.get('password')

        options['enableDebugOutput'] = True if request.POST.get('readonly') == 'on' else False
        options['doNotMatchAnyAddress'] = True if request.POST.get('remove_unused') == 'on' else False
        options['doNotMatchAnyService'] = True if request.POST.get('checkpoint') == 'on' else False

        messages.success(request, 'Job has launched successfully', extra_tags='alert')

        data_entry = Large(createdBy=request.user.username, createdAt=timezone.now(), jobType="ruleSearch",
                           username=options['username'], password=options['password'], targetID=options['target_ip'],
                           enableDebugOutput=options['enableDebugOutput'], doNotMatchAnyAddress=options['doNotMatchAnyAddress'],
                           doNotMatchAnyService=options['doNotMatchAnyService'])
        data_entry.save()

        return redirect('dashboard')

    return render(request, 'home/ruleSearch_form.html')
