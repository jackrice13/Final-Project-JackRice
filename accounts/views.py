from django.shortcuts import render, redirect
from django.contrib.auth import login, logout, authenticate, update_session_auth_hash
from django.contrib.auth.forms import UserCreationForm, AuthenticationForm, PasswordChangeForm
from django.contrib.auth.decorators import login_required
from django.contrib import messages
from core.models import Vendor
from .forms import UserUpdateForm, VendorSelectionForm

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


@login_required
def vendor_selection(request): #vendor selector for user profile
    profile = request.user.userprofile
    all_vendors = Vendor.objects.all()

    if request.method == 'POST':
        selected_vendors = request.POST.getlist('vendors')
        profile.vendors.set(selected_vendors)
        return redirect('dashboard')

    return render(request, 'accounts/vendor_selection.html', {
        'all_vendors': all_vendors,
        'user_vendors': profile.vendors.all()
    })
@login_required
def profile(request):
    profile = request.user.userprofile
    all_vendors = Vendor.objects.all()

    # Initialize all three forms
    user_form = UserUpdateForm(instance=request.user)
    password_form = PasswordChangeForm(request.user)
    vendor_form = VendorSelectionForm(
        vendor_queryset=all_vendors,
        initial={'vendors': profile.vendors.values_list('id', flat=True)}
    )

    if request.method == 'POST':
        action = request.POST.get('action')

        # Handle email update
        if action == 'update_email':
            user_form = UserUpdateForm(request.POST, instance=request.user)
            if user_form.is_valid():
                user_form.save()
                messages.success(request, 'Email updated successfully.')
                return redirect('profile')

        # Handle password change
        elif action == 'change_password':
            password_form = PasswordChangeForm(request.user, request.POST)
            if password_form.is_valid():
                user = password_form.save()
                update_session_auth_hash(request, user)
                messages.success(request, 'Password changed successfully.')
                return redirect('profile')
            else:
                messages.error(request, 'Please correct the errors below.')

        # Handle vendor selection
        elif action == 'save_vendors':
            vendor_form = VendorSelectionForm(
                request.POST,
                vendor_queryset=all_vendors
            )
            if vendor_form.is_valid():
                selected = vendor_form.cleaned_data['vendors']
                profile.vendors.set(selected)
                messages.success(request, 'Vendor preferences saved.')
                return redirect('profile')

    context = {
        'user_form': user_form,
        'password_form': password_form,
        'vendor_form': vendor_form,
        'all_vendors': all_vendors,
        'user_vendors': profile.vendors.all(),
        'joined_date': request.user.date_joined,
    }
    return render(request, 'accounts/profile.html', context)