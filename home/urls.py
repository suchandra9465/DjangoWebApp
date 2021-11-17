from django.urls import path, include
from . import views

urlpatterns = [
    path('', views.dashboard, name="dashboard"),
    path('history', views.history, name="history"),
    path('bulkaddress/', views.bulkaddress, name="bulkaddress"),
    path('migrations/',views.migrations,name="migrations"),
    path('rulesearch/',views.ruleSearch,name="rulesearch"),
    path('dumpconfig',views.dumpConfig,name="dumpconfig")
]