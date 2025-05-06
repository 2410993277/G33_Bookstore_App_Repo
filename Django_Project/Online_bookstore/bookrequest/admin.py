from django.contrib import admin
from .models import BookRequest

class BookRequestAdmin(admin.ModelAdmin):
    list_display = ['get_user_name', 'name', 'author', 'category', 'status', 'requested_on']
    list_editable = ['status']
    list_filter = ['status', 'category', 'requested_on']
    search_fields = ['name', 'author', 'user__name', 'user__email']  # You can search by the user's name or email as well
    actions = ['approve_requests', 'decline_requests']

    def get_user_name(self, obj):
        return obj.user.name if obj.user else "No user"
    get_user_name.short_description = 'User Name'  # The column header for admin

    @admin.action(description="Approve selected requests")
    def approve_requests(self, request, queryset):
        updated = queryset.update(status=BookRequest.APPROVED)
        self.message_user(request, f'{updated} requests approved successfully.')

    @admin.action(description="Decline selected requests")
    def decline_requests(self, request, queryset):
        updated = queryset.update(status=BookRequest.DECLINED)
        self.message_user(request, f'{updated} requests declined successfully.')

# Register the admin class for BookRequest
admin.site.register(BookRequest, BookRequestAdmin)
