from django.urls import path, include
from . import views

urlpatterns = [
    path('', views.dashboard, name="dashboard"),
    path('history/', views.history, name="history"),
    path('bulkaddress/', views.bulk_address, name="bulkaddress"),
    path('migrations/', views.migrations, name="migrations"),
    path('rulesearch/', views.rule_search, name="rulesearch"),
    path('dumpconfig/', views.dump_config, name="dumpconfig"),
    path('pipeline/', views.pipeline, name="pipeline"),
    path('joblogs/getLogs', views.pipeline_logs, name="pipelineLogs")
]
