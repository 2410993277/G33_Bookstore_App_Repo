from django.shortcuts import render, redirect
from .models import BookRequest
from .forms import BookRequestForm
from django.contrib.auth.decorators import login_required
from django.contrib import messages

# Handle the book request form submission
@login_required
def request_book(request):
    if request.method == 'POST':
        form = BookRequestForm(request.POST)
        if form.is_valid():
            # Save the book request and set its status as Pending by default
            book_request = form.save(commit=False)
            book_request.user = request.user  # Automatically set the logged-in user
            book_request.save()
            messages.success(request, "Your book request has been submitted successfully!")
            return redirect('book_request_success')  # Redirect to success page
    else:
        form = BookRequestForm()  # For GET request, show the form

    return render(request, 'bookrequest/request_book.html', {'form': form})


# Success page after the request is submitted
@login_required
def book_request_success(request):
    return render(request, 'bookrequest/request_success.html')


# View for a logged-in user to see their previous book requests
@login_required
def view_book_requests(request):
    # Get all book requests made by the logged-in user, ordered by requested date
    user_requests = BookRequest.objects.filter(user=request.user).order_by('-requested_on')
    return render(request, 'bookrequest/book_request.html', {'requests': user_requests})


# Admin view for managing book requests
# This view is not needed as you're handling it via admin.py, but just in case you need it
@login_required
def manage_book_requests(request):
    # Get all book requests made by users
    all_requests = BookRequest.objects.all().order_by('-requested_on')
    return render(request, 'bookrequest/manage_book_requests.html', {'requests': all_requests})


# Admin action to approve a book request (done via the admin panel, but added here for completeness)
@login_required
def approve_book_request(request, request_id):
    book_request = BookRequest.objects.get(id=request_id)
    if book_request.status == BookRequest.PENDING:
        book_request.status = BookRequest.APPROVED
        book_request.save()
        messages.success(request, f"Request for '{book_request.name}' has been approved.")
    else:
        messages.error(request, "This request is not in Pending status.")
    return redirect('manage_book_requests')


# Admin action to decline a book request (done via the admin panel, but added here for completeness)
@login_required
def decline_book_request(request, request_id):
    book_request = BookRequest.objects.get(id=request_id)
    if book_request.status == BookRequest.PENDING:
        book_request.status = BookRequest.DECLINED
        book_request.save()
        messages.success(request, f"Request for '{book_request.name}' has been declined.")
    else:
        messages.error(request, "This request is not in Pending status.")
    return redirect('manage_book_requests')
