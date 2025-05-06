from django.db import models
from django.conf import settings
from django.utils import timezone



class Section(models.Model):
    name = models.CharField(max_length=100)
    description = models.TextField(blank=True)
    banner = models.ImageField(upload_to='section_banners/', blank=True)  # Ensure MEDIA settings configured

    def __str__(self):
        return self.name



class Book(models.Model):
    title = models.CharField(max_length=200)
    author = models.CharField(max_length=100)
    description = models.TextField()
    price = models.DecimalField(max_digits=6, decimal_places=2)
    section = models.ForeignKey(Section, on_delete=models.CASCADE, related_name='books', null=True, blank=True)
    cover_image = models.ImageField(upload_to='book_covers/', blank=True, null=True)
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return self.title


class Review(models.Model):
    book = models.ForeignKey('Book', on_delete=models.CASCADE, related_name='reviews')
    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE)
    rating = models.IntegerField(choices=[(i, i) for i in range(1, 6)])
    comment = models.TextField()
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        unique_together = ('book', 'user')  # This enforces one review per user per book

    def __str__(self):
        return f"{self.user.username} - {self.book.title} ({self.rating}⭐)"



class CartItem(models.Model):
    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE)
    book = models.ForeignKey(Book, on_delete=models.CASCADE)
    quantity = models.PositiveIntegerField(default=1)

    @property
    def subtotal(self):
        return self.book.price * self.quantity

    def __str__(self):
        return f"{self.book.title} x {self.quantity}"
    
    

# ✅ New Order model: one per checkout
class Order(models.Model):
    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, null=True, blank=True)
    total_price = models.DecimalField(max_digits=10, decimal_places=2, default=0.0)

    PAYMENT_STATUS_CHOICES = [
        ('pending', 'Pending'),
        ('completed', 'Completed'),
        ('failed', 'Failed'),
    ]
    ORDER_STATUS_CHOICES = [
        ('processing', 'Processing'),
        ('shipped', 'Shipped'),
        ('out_for_delivery', 'Out for Delivery'),
        ('delivered', 'Delivered'),
        ('cancelled', 'Cancelled'),
    ]


    # Shipping details
    name = models.CharField(max_length=100, default='Customer')
    phone = models.CharField(max_length=15, default='0000000000')
    email = models.EmailField(default='noemail@example.com')
    address = models.TextField(default='No address provided')
    locality = models.CharField(max_length=100, default='Unknown')
    city = models.CharField(max_length=100, default='Unknown City')
    state = models.CharField(max_length=100, default='Unknown State')
    pincode = models.CharField(max_length=10, default='000000')
    payment_method = models.CharField(max_length=20, choices=[
    ('card', 'Card'),
    ('upi', 'UPI'),
    ('cod', 'Cash on Delivery')
    ],  default='Unknown')
    payment_status = models.CharField(max_length=20, choices=PAYMENT_STATUS_CHOICES, default='pending')
    order_status = models.CharField(max_length=20, choices=ORDER_STATUS_CHOICES, default='processing')


    ordered_date = models.DateTimeField(default=timezone.now)

    def __str__(self):
        return f"Order #{self.id} by {self.user.name if self.user else 'Guest'}"
    

# ✅ OrderItem: each book in the order
class OrderItem(models.Model):
    order = models.ForeignKey(Order, on_delete=models.CASCADE, related_name='items')
    book = models.ForeignKey(Book, on_delete=models.CASCADE)
    quantity = models.PositiveIntegerField()
    price = models.DecimalField(max_digits=8, decimal_places=2)  # unit price

    @property
    def subtotal(self):
        return self.price * self.quantity

    def __str__(self):
        return f"{self.book.title} x {self.quantity} (Order #{self.order.id})"




class ClientReview(models.Model):
    name = models.CharField(max_length=100, default="")
    image = models.ImageField(upload_to='client_reviews/', blank=True, null=True)
    review = models.TextField()
    rating = models.PositiveIntegerField(default=5)
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return self.name
    


class Wishlist(models.Model):
    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name='wishlist')
    book = models.ForeignKey(Book, on_delete=models.CASCADE)
    added_date = models.DateTimeField(auto_now_add=True)

    class Meta:
        unique_together = ('user', 'book')  # Prevent duplicate entries

    def __str__(self):
        return f"{self.user.username} - {self.book.title}"
