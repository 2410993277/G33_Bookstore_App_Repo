from django.urls import path
from . import views

urlpatterns = [
    # 📚 Book listing and detail
    path('', views.book_list, name='book_list'),
    path('dashboard/', views.dashboard_view, name='dashboard'),
    
    path('book/<int:book_id>/', views.book_detail, name='book_detail'),
    path('book/<int:book_id>/review/', views.add_review, name='add_review'),

    # 🛒 Cart functionality
    path('cart/', views.view_cart, name='view_cart'),
    path('cart/add/<int:book_id>/', views.add_to_cart, name='add_to_cart'),
    path('cart/remove/<int:book_id>/', views.remove_from_cart, name='remove_from_cart'),
    path('cart/increase/<int:book_id>/', views.increase_quantity, name='increase_quantity'),
    path('cart/decrease/<int:book_id>/', views.decrease_quantity, name='decrease_quantity'),
    path('cart/clear/', views.clear_cart, name='clear_cart'),

    
    path('about/', views.aboutus, name='aboutus'),
    

    path('shipping/', views.shipping_view, name='shipping'),
    path('checkout/', views.checkout_view, name='checkout'),
    path('place_order/', views.place_order, name='place_order'),
    path('proceed-to-checkout/', views.proceed_to_checkout, name='proceed_to_checkout'),
    path('track-order/', views.order_tracking_view, name='track_order'),




    path('contact/', views.contact_view, name='contact'),
    path('client-review/', views.client_review, name='client_review'),

    
    path('search/', views.search_results, name='search_results'),
    path('section/<int:section_id>/', views.section_detail, name='section_detail'),
    path('order_success/<int:order_id>/', views.order_success, name='order_success'),

    path('wishlist/', views.view_wishlist, name='view_wishlist'),
    path('wishlist/add/<int:book_id>/', views.add_to_wishlist, name='add_to_wishlist'),
    path('wishlist/remove/<int:book_id>/', views.remove_from_wishlist, name='remove_from_wishlist'),


]
