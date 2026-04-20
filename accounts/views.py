from django.shortcuts import render, redirect
from django.contrib.auth import login, logout, authenticate
from django.contrib.auth.forms import UserCreationForm, AuthenticationForm


def register(request):  #register new users
    if request.method == 'POST':
        form = UserCreationForm(request.POST)
        if form.is_valid(): # checks that passwords match, username isn't taken, etc.
            user = form.save()
            login(request, user)
            return redirect('dashboard') #returns to dashboard
    else:
        form = UserCreationForm()
    return render(request, 'accounts/register.html', {'form': form}) #First visit to the page renders a blank form and Failed submission renders the same form with errors attached


def login_view(request):    #basic login
    if request.method == 'POST':
        form = AuthenticationForm(data=request.POST)
        if form.is_valid():
            user = form.get_user()
            login(request, user)
            return redirect('dashboard')
    else:
        form = AuthenticationForm()
    return render(request, 'accounts/login.html', {'form': form})


def logout_view(request): #basic logout
    logout(request)
    return redirect('login')