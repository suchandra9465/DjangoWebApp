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
    createdBy = models.ForeignKey(User,on_delete=models.CASCADE,related_name='jobCreatedBy')
    createdAt = models.DateTimeField(auto_now_add=True)
    jobType = models.CharField(max_length=100)
    jobBlob = models.JSONField()
    status = models.CharField(max_length=10)