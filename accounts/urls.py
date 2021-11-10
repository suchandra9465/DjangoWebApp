from django.urls import path, include
from . import views

urlpatterns = [
    path('dashboard/', views.dashboard, name="dashboard"),
    path('register/', views.register,name="register"),
    path('login/', views.login, name="login"),
    path('logout/',views.logoutUser, name="logout")
]