from django import forms
from .models import AppUser, UserProfile

# -------------------------------
# AppUser Form (Editable fields)
# -------------------------------
class AppUserForm(forms.ModelForm):
    class Meta:
        model = AppUser
        fields = ['name', 'email', 'phone', 'address', 'gender']
        widgets = {
            'name': forms.TextInput(attrs={'class': 'form-control'}),
            'email': forms.EmailInput(attrs={'class': 'form-control'}),
            'phone': forms.TextInput(attrs={'class': 'form-control'}),
            'address': forms.Textarea(attrs={'class': 'form-control', 'rows': 2}),
            'gender': forms.Select(attrs={'class': 'form-select'}),
        }

# -------------------------------
# UserProfile Form (Extra fields)
# -------------------------------
class UserProfileForm(forms.ModelForm):
    class Meta:
        model = UserProfile
        fields = ['profile_picture', 'bio', 'birth_date']
        widgets = {
            'bio': forms.Textarea(attrs={'class': 'form-control', 'rows': 3}),
            'birth_date': forms.DateInput(attrs={'class': 'form-control', 'type': 'date'}),
            'profile_picture': forms.FileInput(attrs={'class': 'form-control'}),
        }
