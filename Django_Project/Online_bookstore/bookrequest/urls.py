from django.urls import path
from . import views

urlpatterns = [
    path('request/', views.request_book, name='request_book'),
    path('request-success/', views.book_request_success, name='book_request_success'),
    path('my-requests/', views.view_book_requests, name='view_book_requests'),
    path('admin/approve/<int:request_id>/', views.approve_book_request, name='approve_book_request'),
    path('admin/decline/<int:request_id>/', views.decline_book_request, name='decline_book_request'),
]
