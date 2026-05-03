from django.contrib import admin
from .models import Vendor, Software, Vulnerability


class SoftwareInline(admin.TabularInline):
    # shows software entries directly inside the vendor admin page
    model = Software
    extra = 0  # don't show empty extra rows
    fields = ['name', 'version', 'end_of_life_date']


class VendorAdmin(admin.ModelAdmin):
    list_display = ['name', 'slug', 'get_software_count']
    search_fields = ['name', 'slug']

    # shows software inline when editing a vendor
    inlines = [SoftwareInline]

    def get_software_count(self, obj):
        return obj.software_set.count()
    get_software_count.short_description = 'Software Count'


class SoftwareAdmin(admin.ModelAdmin):
    list_display = ['name', 'vendor', 'version', 'end_of_life_date']
    list_filter = ['vendor']
    search_fields = ['name', 'vendor__name']
    ordering = ['vendor__name', 'name']


class VulnerabilityAdmin(admin.ModelAdmin):
    list_display = [
        'cve_id',
        'severity',
        'cvss_score',
        'in_cisa_kev',
        'published_date',
        'get_software_count'
    ]

    # filter sidebar
    list_filter = ['severity', 'in_cisa_kev']

    # search by CVE ID or description
    search_fields = ['cve_id', 'description']

    # default sort - highest CVSS first
    ordering = ['-cvss_score']

    # allows editing software links directly on the edit page
    filter_horizontal = ['software']

    def get_software_count(self, obj):
        return obj.software.count()
    get_software_count.short_description = 'Affected Software'


admin.site.register(Vendor, VendorAdmin)
admin.site.register(Software, SoftwareAdmin)
admin.site.register(Vulnerability, VulnerabilityAdmin)