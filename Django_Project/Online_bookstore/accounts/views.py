from django.shortcuts import render, redirect, get_object_or_404
from django.contrib import messages
from django.contrib.auth.models import User
from django.contrib.auth import authenticate, login, logout
from django.contrib.auth.decorators import login_required

from django.contrib.auth.password_validation import validate_password
from django.core.exceptions import ValidationError

from .models import UserProfile
from .forms import UserProfileForm, AppUserForm
from django.contrib.auth import get_user_model
from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response

import requests

User = get_user_model()  # Use your custom us

@api_view(['GET'])
@permission_classes([IsAuthenticated])
def protected_view(request):
    user = request.user
    return Response({
        'message': f'Hello, {user.name}!',
        'email': user.email
    })



@login_required
def call_flask_api(request):
    access_token = request.session.get('access_token')
    refresh_token = request.session.get('refresh_token')

    if not access_token:
        return render(request, 'error.html', {'message': 'Access token not found. Please log in again.'})

    headers = {'Authorization': f'Bearer {access_token}'}
    flask_base = 'http://127.0.0.1:5000/api'

    def fetch_data(endpoint):
        try:
            return requests.get(f"{flask_base}/{endpoint}", headers=headers)
        except requests.exceptions.ConnectionError:
            return None

    # Fetch multiple endpoints
    data = {}
    endpoints = ['data', 'sections', 'books']
    for endpoint in endpoints:
        response = fetch_data(endpoint)
        if response and response.status_code == 200:
            data[endpoint] = response.json()
        elif response and response.status_code == 401 and refresh_token:
            refresh_response = requests.post('http://127.0.0.1:8000/accounts/api/token/refresh/', json={
                'refresh': refresh_token
            })

            if refresh_response.status_code == 200:
                new_tokens = refresh_response.json()
                request.session['access_token'] = new_tokens['access']
                headers['Authorization'] = f'Bearer {new_tokens["access"]}'

                retry_response = requests.get(f"{flask_base}/{endpoint}", headers=headers)
                if retry_response.status_code == 200:
                    data[endpoint] = retry_response.json()
                else:
                    data[endpoint] = {'error': f'Failed to fetch {endpoint} after retry'}
            else:
                return render(request, 'error.html', {'message': 'Token refresh failed. Please log in again.'})
        else:
            data[endpoint] = {'error': f'Failed to fetch {endpoint}'}

    return render(request, 'accounts/flask_data.html', {'data': data})


    

def register_view(request):
    if request.method == 'POST':
        name = request.POST.get('name')
        email = request.POST.get('email')
        phone = request.POST.get('phone')
        address = request.POST.get('address')
        gender = request.POST.get('gender')
        password = request.POST.get('password')
        cpassword = request.POST.get('cpassword')


        if password != cpassword:
            messages.error(request, 'Passwords do not match')
        elif User.objects.filter(email=email).exists():
            messages.error(request, 'Email already registered')
        else:
            try:
                validate_password(password)
                User.objects.create_user(
                    email=email,
                    name=name,
                    phone=phone,
                    address=address,
                    gender=gender,
                    password=password
                )
                messages.success(request, 'Registration successful! You can now login.')
                return redirect('login')
            except ValidationError as e:
                for error in e:
                    messages.error(request, error)
    return render(request, 'accounts/register.html')



def login_view(request):
    if request.method == 'POST':
        email = request.POST.get('email')
        password = request.POST.get('password')
        selected_role = request.POST.get('role')

        user = authenticate(request, email=email, password=password)
        if user:
            if (selected_role == 'admin' and user.is_superuser) or (selected_role == 'user' and not user.is_superuser):
                login(request, user)

                # ✅ Fetch JWT token from Django's own API
                try:
                    jwt_response = requests.post('http://127.0.0.1:8000/accounts/api/token/', json={
                        'email': email,
                        'password': password
                    })

                    if jwt_response.status_code == 200:
                        tokens = jwt_response.json()
                        request.session['access_token'] = tokens['access']
                        request.session['refresh_token'] = tokens['refresh']
                    else:
                        messages.warning(request, 'Logged in, but failed to fetch access token.')

                except requests.exceptions.RequestException as e:
                    messages.warning(request, f"Logged in, but couldn't connect to token endpoint: {e}")

                return redirect('dashboard')
            else:
                messages.error(request, "Invalid credentials: Role mismatch")
        else:
            messages.error(request, 'Invalid email or password')
    return render(request, 'accounts/login.html')




@login_required
def logout_view(request):
    logout(request)
    return redirect('book_list')



@login_required
def view_profile(request):
    profile, created = UserProfile.objects.get_or_create(user=request.user)
    return render(request, 'accounts/user_profile.html', {
        'profile': profile,
    })


@login_required
def edit_profile(request):
    user = request.user
    profile = request.user.userprofile

    if request.method == 'POST':
        user_form = AppUserForm(request.POST, instance=user)
        profile_form = UserProfileForm(request.POST, request.FILES, instance=profile)

        if user_form.is_valid() and profile_form.is_valid():
            user_form.save()
            profile_form.save()
            return redirect('view_profile')
    else:
        user_form = AppUserForm(instance=user)
        profile_form = UserProfileForm(instance=profile)

    return render(request, 'accounts/edit_profile.html', {
        'user_form': user_form,
        'profile_form': profile_form
    })