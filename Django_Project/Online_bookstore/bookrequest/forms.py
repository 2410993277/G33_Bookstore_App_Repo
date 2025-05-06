# bookrequest/forms.py
from django import forms
from .models import BookRequest

class BookRequestForm(forms.ModelForm):
    class Meta:
        model = BookRequest
        fields = ['name', 'author', 'category', 'description']
