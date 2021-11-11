
from django.shortcuts import render, redirect
from django.http import HttpResponse
from django.contrib.auth.forms import UserCreationForm

from django.contrib.auth import authenticate,login as auth_login, logout
from django.contrib import messages,auth
from django.contrib.auth.models import User

# Create your views here.
def dashboard(request):
    if request.method == 'POST':
        username = request.POST.get('username')
        password = request.POST.get('password')
        group_address = request.POST.get('address_group_name')
        messages.success(request, 'Job has launched successfully',extra_tags='alert')
        result = "/opy/pavan.py --grouptar {group} -nexpose AGILE_GROUP --nexposeaddr  'file.csv' --iwtype sw --username {user} --password {pwd}".format(group=group_address, user=username,pwd=password)
        print(result)
        return redirect('dashboard')
    
    return render(request, 'accounts/dashboard.html')

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
    