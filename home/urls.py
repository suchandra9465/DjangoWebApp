from django.urls import path, include
from . import views

urlpatterns = [
    path('dashboard/', views.dashboard, name="dashboard"),
    path('migrations/',views.migrations,name="migrations"),
    path('rulesearch/',views.ruleSearch,name="rulesearch"),
    path('dumpconfig',views.dumpConfig,name="dumpconfig")
]