from django.db import models
from django.contrib.auth import get_user_model
import logging
# from six import python_2_unicode_compatible
from django.utils.translation import gettext_lazy as _

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
    
class jobLog(models.Model):
    jobid = models.ForeignKey(large, on_delete=models.CASCADE)
    ip = models.CharField(max_length=200)
    log  = models.TextField(null=True)


# LOG_LEVELS = (
#     (logging.NOTSET, _('NotSet')),
#     (logging.INFO, _('Info')),
#     (logging.WARNING, _('Warning')),
#     (logging.DEBUG, _('Debug')),
#     (logging.ERROR, _('Error')),
#     (logging.FATAL, _('Fatal')),
# )


# @python_2_unicode_compatible
# class StatusLog(models.Model):
#     logger_name = models.CharField(max_length=100)
#     level = models.PositiveSmallIntegerField(choices=LOG_LEVELS, default=logging.ERROR, db_index=True)
#     msg = models.TextField()
#     trace = models.TextField(blank=True, null=True)
#     ip = models.CharField(max_length=200, null=True)
#     # create_datetime = models.DateTimeField(auto_now_add=True, verbose_name='Created at')

#     def __str__(self):
#         return self.msg

#     class Meta:
#         # ordering = ('-create_datetime',)
#         verbose_name_plural = verbose_name = 'Logging'