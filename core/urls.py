from django.urls import path
from . import views

urlpatterns = [
    path('', views.dashboard, name='dashboard'),
    path('vulnerability/<str:cve_id>/', views.vulnerability_detail, name='vulnerability_detail'),
    path('vulnerability/<str:cve_id>/status/', views.update_status, name='update_status'),
    path('aging-report/', views.aging_report, name='aging_report'),
]