from django import forms
from .models import Review, ClientReview

class ReviewForm(forms.ModelForm):
    class Meta:
        model = Review
        fields = ['rating', 'comment']


class ContactForm(forms.Form):
    name = forms.CharField(max_length=100, widget=forms.TextInput(attrs={
        'class': 'form-control',
        'placeholder': 'Enter your Name',
        'required': 'required'
    }))
    email = forms.EmailField(widget=forms.EmailInput(attrs={
        'class': 'form-control',
        'placeholder': 'Enter your Email',
        'required': 'required'
    }))
    message = forms.CharField(widget=forms.Textarea(attrs={
        'class': 'form-control',
        'placeholder': 'Enter your Message',
        'rows': 4,
        'required': 'required'
    }))



class ClientReviewForm(forms.ModelForm):
    class Meta:
        model = ClientReview
        fields = ['name', 'image', 'review', 'rating']
        widgets = {
            'name': forms.TextInput(attrs={
                'class': 'form-control shadow-sm rounded-3',
                'placeholder': 'Your Name',
            }),
            'image': forms.ClearableFileInput(attrs={
                'class': 'form-control shadow-sm rounded-3',
            }),
            'review': forms.Textarea(attrs={
                'class': 'form-control shadow-sm rounded-3',
                'placeholder': 'Write your review here...',
                'rows': 4,
                'style': 'resize: none;',
            }),
            'rating': forms.NumberInput(attrs={
                'class': 'form-control shadow-sm rounded-3',
                'min': 1,
                'max': 5,
                'placeholder': 'Rate us (1 to 5)',
            }),
        }
        labels = {
            'image': 'Upload your photo (optional)',
            'review': 'Your Review',
        }