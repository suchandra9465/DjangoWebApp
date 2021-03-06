from django.db import models
from django.contrib.auth import get_user_model

# Create your models here.

# JobId  - (Primary Key)
# CreatedAt (Time) 
# CreatedBy ( userId - forigen Key)
# JobType ( 4 different JobType {migration, rule, dump, bulk)
# JobBlob (json or dist)
# status 
# completedAt
User = get_user_model()

class large(models.Model):
    createdBy = models.CharField(max_length=50)
    createdAt = models.DateTimeField(auto_now_add=True)
    jobType = models.CharField(max_length=100)
    username = models.CharField(max_length=50)
    password = models.CharField(max_length=50)
    targetID = models.CharField(max_length=50)
    firewallType = models.CharField(max_length=50,null=True)
    group_name = models.CharField(max_length=50,null=True)
    comment = models.CharField(max_length=200,null=True)
    context = models.CharField(max_length=300,null=True)
    addressObject = models.CharField(max_length=50,null=True)
    readOnly = models.BooleanField(default=False)
    loggingProfileName = models.CharField(max_length=50,null=True)
    securityProfileName = models.CharField(max_length=50,null=True)
    interfaceMapping = models.CharField(max_length=50,null=True)
    zoneMapping = models.CharField(max_length=50,null=True)
    removeDupes = models.BooleanField(default=False)
    removeUnused = models.BooleanField(default=False)
    checkPointExpansion = models.BooleanField(default=False)
    ruleMatchPattern = models.CharField(max_length=100,null=True)
    enableDebugOutput = models.BooleanField(default=False)
    doNotMatchAnyAddress = models.BooleanField(default=False)
    doNotMatchAnyService = models.BooleanField(default=False)
    status = models.CharField(max_length=10)