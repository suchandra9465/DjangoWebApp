from django.urls import path, include
from . import views

urlpatterns = [
    path('', views.dashboard, name="dashboard"),
    path('history/', views.history, name="history"),
    path('bulkaddress/', views.bulkaddress, name="bulkaddress"),
    path('migrations/',views.migrations,name="migrations"),
    path('rulesearch/',views.ruleSearch,name="rulesearch"),
    path('dumpconfig/',views.dumpConfig,name="dumpconfig"),
    path('pipeline/',views.pipeLine, name="pipeline"),
    path('joblogs/getLogs',views.pipelineLogs, name="pipelineLogs")
]