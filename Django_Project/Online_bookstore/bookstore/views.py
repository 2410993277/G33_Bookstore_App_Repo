from django.shortcuts import render, redirect, get_object_or_404
from django.contrib.auth.decorators import login_required
from django.contrib import messages
from django.utils import timezone
from django.db.models import Q
from django.db import transaction
from django.views.decorators.cache import never_cache
from django.http import HttpResponse

from .models import Book, Order, Review, OrderItem, ClientReview, Section, CartItem, Wishlist
from .forms import ReviewForm, ContactForm, ClientReviewForm
import requests

# -------------------- Home & Book Views --------------------

from django.shortcuts import render
from django.http import HttpResponse
import requests

def book_list(request):
    query = request.GET.get('q', '')
    section_id = request.GET.get('section')

    access_token = request.session.get('access_token')  # JWT token
    headers = {'Authorization': f'Bearer {access_token}'} if access_token else {}

    try:
        books_response = requests.get('http://127.0.0.1:5000/api/books', headers=headers)
        reviews_response = requests.get('http://127.0.0.1:5000/api/client_review', headers=headers)
        sections_response = requests.get('http://127.0.0.1:5000/api/sections', headers=headers)

        if books_response.status_code == 200 and reviews_response.status_code == 200 and sections_response.status_code == 200:
            books = books_response.json()
            reviews = reviews_response.json()
            sections = sections_response.json()

            for review in reviews:
                review['stars'] = range(int(review.get('rating', 0)))

            if query:
                books = [book for book in books if query.lower() in book['title'].lower()]
            if section_id:
                books = [book for book in books if str(book.get('section_id')) == str(section_id)]

            return render(request, 'bookstore/index.html', {
                'books': books,
                'reviews': reviews,
                'sections': sections,  # pass to template
                'query': query,
                'selected_section': section_id,
            })

        else:
            return HttpResponse("<h2>Failed to fetch books, reviews, or sections from Flask API</h2>")

    except Exception as e:
        return HttpResponse(f"<h2>Failed to connect to Flask API:</h2><pre>{e}</pre>")



@never_cache
@login_required
def dashboard_view(request):
    return render(request, 'bookstore/dashboard.html')



def book_detail(request, book_id):
    access_token = request.session.get('access_token')
    headers = {'Authorization': f'Bearer {access_token}'} if access_token else {}

    try:
        response = requests.get(f'http://127.0.0.1:5000/api/books/{book_id}', headers=headers)
        if response.status_code == 200:
            book = response.json()
            in_wishlist = False

            if request.user.is_authenticated:
                in_wishlist = Wishlist.objects.filter(user=request.user, book_id=book_id).exists()

            reviews = Review.objects.filter(book_id=book_id)


            return render(request, 'bookstore/book_detail.html', {
                'book': book,  # This is a dict now
                'reviews': reviews,
                'in_wishlist': in_wishlist,
            })
        else:
            return render(request, 'error.html', {'message': 'Book not found in Flask API'})
    except Exception as e:
        return render(request, 'error.html', {'message': f'Error fetching book: {e}'})



# -------------------- Cart Functionality --------------------

@login_required
def add_to_cart(request, book_id):
    book = get_object_or_404(Book, pk=book_id)
    cart_item, created = CartItem.objects.get_or_create(user=request.user, book=book)
    if not created:
        cart_item.quantity += 1
        cart_item.save()
    messages.success(request, f"✅ '{book.title}' added to your cart.")
    return redirect('book_detail', book_id=book.id)



@login_required
def view_cart(request):
    cart_items = CartItem.objects.filter(user=request.user)
    total = sum(item.subtotal for item in cart_items)

    return render(request, 'bookstore/cart.html', {
        'cart_items': cart_items,
        'total': total
    })


@login_required
def increase_quantity(request, book_id):
    item = get_object_or_404(CartItem, user=request.user, book_id=book_id)
    item.quantity += 1
    item.save()
    return redirect('view_cart')

@login_required
def decrease_quantity(request, book_id):
    item = get_object_or_404(CartItem, user=request.user, book_id=book_id)
    if item.quantity > 1:
        item.quantity -= 1
        item.save()
    else:
        item.delete()
    return redirect('view_cart')



@login_required
def clear_cart(request):
    CartItem.objects.filter(user=request.user).delete()
    messages.info(request, "Your cart has been cleared.")
    return redirect('view_cart')



@login_required
def remove_from_cart(request, book_id):
    cart_item = get_object_or_404(CartItem, user=request.user, book_id=book_id)
    cart_item.delete()
    return redirect('view_cart')


# -------------------- Review System --------------------


@login_required
def add_review(request, book_id):
    book = get_object_or_404(Book, id=book_id)
    form = ReviewForm(request.POST or None)

    # Check if the user has already reviewed this book
    existing_review = Review.objects.filter(book=book, user=request.user).first()

    if request.method == 'POST':
        if existing_review:
            messages.success(request, "You've already submitted a review for this book.")
            return redirect('book_detail', book_id=book.id)

        if form.is_valid():
            review = form.save(commit=False)
            review.book = book
            review.user = request.user
            review.save()
            messages.success(request, "Thank you! Your review has been added.")
            return redirect('book_detail', book_id=book.id)

    return render(request, 'bookstore/add_review.html', {
        'form': form,
        'book': book
    })



# -------------------- Static Pages --------------------

@login_required
def aboutus(request):
    return render(request, 'bookstore/aboutus.html')



@login_required
def contact_view(request):
    if request.method == 'POST':
        form = ContactForm(request.POST)
        if form.is_valid():
            data = {
                'name': form.cleaned_data['name'],
                'email': form.cleaned_data['email'],
                'message': form.cleaned_data['message']
            }
            try:
                response = requests.post('http://localhost:5000/api/contact', json=data)
                if response.status_code == 201:
                    messages.success(request, "Your message has been sent!")
                    return render(request, 'bookstore/contact.html', {
                        'form': ContactForm(),
                        'success': True
                    })
                else:
                    messages.error(request, "Failed to send message to the server.")
            except requests.exceptions.RequestException:
                messages.error(request, "Failed to connect to the contact service.")
    else:
        form = ContactForm()
    
    return render(request, 'bookstore/contact.html', {'form': form})


# -------------------- Order & Checkout --------------------

@login_required
def shipping_view(request):
    if request.method == 'POST':
        request.session['shipping_data'] = {
            'name': request.POST.get('name', ''),
            'phone': request.POST.get('phone', ''),
            'email': request.POST.get('email', ''),
            'address': request.POST.get('address', ''),
            'locality': request.POST.get('locality', ''),
            'city': request.POST.get('city', ''),
            'state': request.POST.get('state', ''),
            'pincode': request.POST.get('pincode', '')
        }
        return redirect('checkout')
    return render(request, 'bookstore/shipping.html')


@login_required
def proceed_to_checkout(request):
    if request.session.get('shipping_data'):
        return redirect('checkout')
    return redirect('shipping')




@login_required
def checkout_view(request):
    cart_items = CartItem.objects.filter(user=request.user)
    total_price = sum(item.subtotal for item in cart_items)

    shipping_data = request.session.get('shipping_data')
    if not shipping_data:
        messages.error(request, "Shipping information is missing.")
        return redirect('shipping_form')

    return render(request, 'bookstore/checkout.html', {
        'cart_items': cart_items,
        'total_price': total_price,
        'shipping_data': shipping_data,
    })



@login_required
def place_order(request):
    if request.method == 'POST':
        payment_method = request.POST.get('payment_method')
        if not payment_method:
            messages.error(request, "Please select a payment method.")
            return redirect('proceed_to_checkout')

        cart_items = CartItem.objects.filter(user=request.user)
        if not cart_items.exists():
            messages.error(request, "Your cart is empty.")
            return redirect('view_cart')

        shipping_data = request.session.get('shipping_data')
        if not shipping_data:
            messages.error(request, "Shipping data not found.")
            return redirect('shipping_form')

        total = sum(item.subtotal for item in cart_items)

        try:
            with transaction.atomic():
                order = Order.objects.create(
                    user=request.user,
                    name=shipping_data['name'],
                    phone=shipping_data['phone'],
                    email=shipping_data['email'],
                    address=shipping_data['address'],
                    locality=shipping_data['locality'],
                    city=shipping_data['city'],
                    state=shipping_data['state'],
                    pincode=shipping_data['pincode'],
                    payment_method=payment_method,
                    total_price=total,
                )

                for item in cart_items:
                    OrderItem.objects.create(
                        order=order,
                        book=item.book,
                        quantity=item.quantity,
                        price=item.book.price,
                    )

                cart_items.delete()
                request.session.pop('shipping_data', None)
                messages.success(request, f"Order #{order.id} placed successfully!")
                return redirect('order_success', order_id=order.id)

        except Exception as e:
            messages.error(request, "An error occurred while placing your order. Please try again.")
            return redirect('checkout')

    return redirect('view_cart')




@login_required
def order_success(request, order_id):
    try:
        order = Order.objects.get(id=order_id, user=request.user)
    except Order.DoesNotExist:
        messages.error(request, "Order not found.")
        return redirect('book_list')

    return render(request, 'bookstore/order_success.html', {
        'order_id': order.id,
        'name': order.name,
        'total_price': order.total_price
    })




# -------------------- Order Tracking --------------------

@login_required
def order_tracking_view(request):
    orders = Order.objects.filter(user=request.user).order_by('-ordered_date')
    return render(request, 'bookstore/order_tracking.html', {'orders': orders})


# -------------------- Client Review --------------------
def client_review(request):
    if request.method == 'POST':
        form = ClientReviewForm(request.POST, request.FILES)
        if form.is_valid():
            data = {
                'name': form.cleaned_data['name'],
                'review': form.cleaned_data['review'],
                'rating': form.cleaned_data['rating'],
            }

            files = {
                'image': request.FILES['image']
            } if 'image' in request.FILES else {}

            try:
                response = requests.post(
                    'http://127.0.0.1:5000/api/client_review',
                    data=data,
                    files=files
                )

                if response.status_code == 201:
                    messages.success(request, 'Your review has been submitted successfully!')
                    return redirect('book_list')

                # Try to parse JSON error if possible
                try:
                    error_msg = response.json().get('error', 'Could not submit review')
                except ValueError:
                    error_msg = response.text or 'Unknown error occurred'

                return render(request, 'bookstore/client_review.html', {
                    'form': form,
                    'error': f"Error: {error_msg}"
                })

            except Exception as e:
                return render(request, 'bookstore/client_review.html', {
                    'form': form,
                    'error': f"Request failed: {e}"
                })

    else:
        form = ClientReviewForm()

    return render(request, 'bookstore/client_review.html', {'form': form})

# -------------------- Search & Section --------------------

def search_results(request):
    query = request.GET.get('q')
    results = Book.objects.filter(title__icontains=query)
    return render(request, 'bookstore/search_results.html', {'results': results, 'query': query})


def section_detail(request, section_id):
    access_token = request.session.get('access_token')
    headers = {'Authorization': f'Bearer {access_token}'} if access_token else {}

    section = {}
    books = []

    try:
        # Get section details from Flask
        sec_response = requests.get(
            f'http://127.0.0.1:5000/api/sections/{section_id}',
            headers=headers
        )
        if sec_response.status_code == 200:
            section = sec_response.json()

        # Get books in this section from Flask
        books_response = requests.get(
            f'http://127.0.0.1:5000/api/sections/{section_id}/books',
            headers=headers
        )
        if books_response.status_code == 200:
            books = books_response.json()

    except Exception as e:
        print("Error fetching section or books:", e)

    return render(request, 'bookstore/section.html', {
        'section': section,
        'books': books,
    })

@login_required
def add_to_wishlist(request, book_id):
    book = Book.objects.get(id=book_id)
    wishlist_item, created = Wishlist.objects.get_or_create(user=request.user, book=book)
    if created:
        messages.success(request, f'"{book.title}" added to your wishlist.')
    else:
        messages.info(request, f'"{book.title}" is already in your wishlist.')
    return redirect('book_detail', book_id=book.id)

@login_required
def view_wishlist(request):
    wishlist_items = Wishlist.objects.filter(user=request.user)
    return render(request, 'bookstore/wishlist.html', {'wishlist_items': wishlist_items})



@login_required
def remove_from_wishlist(request, book_id):
    Wishlist.objects.filter(user=request.user, book_id=book_id).delete()
    messages.success(request, "Book removed from your wishlist!")
    return redirect('view_wishlist')