from django.contrib import admin
from .models import Book, CartItem, Review, Section, ClientReview, Order, OrderItem


@admin.register(Book)
class BookAdmin(admin.ModelAdmin):
    list_display = ('title', 'author', 'price', 'section', 'created_at')
    search_fields = ('title', 'author')
    list_filter = ()


@admin.register(CartItem)
class CartItemAdmin(admin.ModelAdmin):
    list_display = ['user', 'book', 'quantity']


@admin.register(Section)
class SectionAdmin(admin.ModelAdmin):
    list_display = ('name', 'description')
    search_fields = ('name',)



@admin.register(Review)
class ReviewAdmin(admin.ModelAdmin):
    list_display = ('book', 'user', 'rating', 'created_at')
    search_fields = ('book__title', 'user__username', 'comment')
    list_filter = ('rating',)


@admin.register(ClientReview)
class ClientReviewAdmin(admin.ModelAdmin):
    list_display = ['name', 'review', 'rating', 'created_at']
    ordering = ['-created_at']    



# Inline order items within Order admin
class OrderItemInline(admin.TabularInline):
    model = OrderItem
    readonly_fields = ['book', 'quantity', 'price', 'subtotal']
    extra = 0
    can_delete = False


# Custom admin for Order
@admin.register(Order)
class OrderAdmin(admin.ModelAdmin):
    list_display = [
        'id', 'user', 'total_price', 'payment_method',
        'payment_status', 'order_status', 'ordered_date'
    ]
    list_filter = ['payment_status', 'order_status', 'ordered_date']
    search_fields = ['id', 'user__username', 'email', 'phone']
    list_editable = ['payment_status', 'order_status']
    inlines = [OrderItemInline]

    actions = ['mark_as_shipped', 'mark_as_delivered']

    @admin.action(description="Mark selected orders as Shipped")
    def mark_as_shipped(self, request, queryset):
        queryset.update(order_status='shipped')

    @admin.action(description="Mark selected orders as Delivered")
    def mark_as_delivered(self, request, queryset):
        queryset.update(order_status='delivered')

# Simple registration of other models
@admin.register(OrderItem)
class OrderItemAdmin(admin.ModelAdmin):
    list_display = ['order', 'book', 'quantity', 'price', 'subtotal']
