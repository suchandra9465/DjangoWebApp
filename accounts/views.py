
from django.shortcuts import render, redirect
from django.http import HttpResponse

from django.contrib.auth import authenticate,login as auth_login, logout
from django.contrib import messages,auth
from django.contrib.auth.models import User
from django.utils.decorators import method_decorator
from django.contrib.auth.decorators import login_required

# Create your views here.

def register(request):
    if request.method == "POST":
        if request.POST['password1'] == request.POST['password2']:
            try:
                User.objects.get(username = request.POST['username'])
                return render (request,'accounts/signup.html', {'error':'Username is already taken!'})
            except User.DoesNotExist:
                user = User.objects.create_user(request.POST['username'],password=request.POST['password1'])
                auth.login(request,user)
                # messages.success(request, "Registration successful." )
                return redirect('login')
        else:
            # messages.error(request, "Unsuccessful registration. Invalid information.")
            return render (request,'accounts/signup.html', {'error':'Password does not match!'})
    else:
        return render(request,'accounts/signup.html')

def login(request):
    
    if request.method == "POST":
        username = request.POST.get('username')
        password = request.POST.get('password')
        
        user = authenticate(request , username=username, password=password)
        
        if user is not None:
            auth_login(request, user)
            return redirect('dashboard')
    context = {}
    return render(request ,'accounts/login.html', context)

def logoutUser(request):
    logout(request)
    return redirect('login')
    # return redirect('dashboard')
    