from django.urls import path, include
from . import views
from django.contrib.auth.decorators import login_required

urlpatterns = [
    path('register/', views.register,name="register"),
    path('login/', views.login, name="login"),
    path('logout/',views.logoutUser, name="logout"), 
]