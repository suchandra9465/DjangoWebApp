from django.shortcuts import render, redirect
from django.http import HttpResponse
from django.contrib.auth.forms import UserCreationForm

from django.contrib.auth import authenticate,login as auth_login, logout

# Create your views here.
def home(request):
    if request.method == 'POST':
        username = request.POST.get('username')
        password = request.POST.get('password')
        group_address = request.POST.get('address_group_name')
        
        result = "/opy/pavan.py --grouptar {group} -nexpose AGILE_GROUP --nexposeaddr  'file.csv' --iwtype sw --username {user} --password {pwd}".format(group=group_address, user=username,pwd=password)
        print(result)
        return redirect('home')
    
    return render(request, 'accounts/home.html')

def register(request):
    form = UserCreationForm()
    print('checking')
    if request.method == 'POST':
        form = UserCreationForm(request.POST)
        if form.is_valid():
            print('valid')
            form.save()
            return redirect('login')
            
    context = {'form':form}
    return render(request,'accounts/register.html',context)

def login(request):
    
    if request.method == "POST":
        username = request.POST.get('username')
        password = request.POST.get('password')
        
        user = authenticate(request , username=username, password=password)
        
        if user is not None:
            auth_login(request, user)
            return redirect('home')
    context = {}
    return render(request ,'accounts/login.html', context)

def logoutUser(request):
    logout(request)
    return redirect('login')