from django.contrib import admin
from .models import UserProfile, VulnerabilityStatus


class UserProfileAdmin(admin.ModelAdmin):
    # columns shown in the list view
    list_display = ['user', 'get_email', 'get_vendor_list', 'get_vendor_count']

    # searchable fields
    search_fields = ['user__username', 'user__email']

    # filter sidebar
    list_filter = ['vendors']

    # allows editing vendors directly on the list page
    filter_horizontal = ['vendors']

    def get_email(self, obj):
        # pulls email from the related User object
        return obj.user.email
    get_email.short_description = 'Email'

    def get_vendor_count(self, obj):
        # counts how many vendors this user tracks
        return obj.vendors.count()
    get_vendor_count.short_description = 'Vendor Count'

    def get_vendor_list(self, obj):
        # returns a comma separated list of vendor names
        return ', '.join([v.name for v in obj.vendors.all()])
    get_vendor_list.short_description = 'Tracked Vendors'


class VulnerabilityStatusAdmin(admin.ModelAdmin):
    # columns shown in the list view
    list_display = [
        'get_username',
        'get_cve_id',
        'status',
        'get_severity',
        'updated_at'
    ]

    # filter sidebar - filter by status or severity
    list_filter = ['status', 'vulnerability__severity']

    # search by username or CVE ID
    search_fields = [
        'profile__user__username',
        'vulnerability__cve_id'
    ]

    # default sort - most recently updated first
    ordering = ['-updated_at']

    def get_username(self, obj):
        # pulls username from the related UserProfile → User chain
        return obj.profile.user.username
    get_username.short_description = 'Username'

    def get_cve_id(self, obj):
        # pulls CVE ID from the related Vulnerability
        return obj.vulnerability.cve_id
    get_cve_id.short_description = 'CVE ID'

    def get_severity(self, obj):
        # pulls severity from the related Vulnerability
        return obj.vulnerability.severity
    get_severity.short_description = 'Severity'


admin.site.register(UserProfile, UserProfileAdmin)
admin.site.register(VulnerabilityStatus, VulnerabilityStatusAdmin)