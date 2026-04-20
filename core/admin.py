from django.contrib import admin
from .models import Vendor, Software, Vulnerability

admin.site.register(Vendor)
admin.site.register(Software)
admin.site.register(Vulnerability)