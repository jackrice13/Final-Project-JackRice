from django.shortcuts import render, get_object_or_404, redirect
from django.contrib.auth.decorators import login_required
from django.core.paginator import Paginator
from core.models import Vulnerability, Vendor
from accounts.models import VulnerabilityStatus

@login_required
def dashboard(request):
    profile = request.user.userprofile
    user_vendors = profile.vendors.all()

    # Base queryset filtered by user's vendors
    vulnerabilities = Vulnerability.objects.filter(
        software__vendor__in=user_vendors
    ).distinct()

    # Get filter values from the URL
    severity_filter = request.GET.get('severity', '')
    vendor_filter = request.GET.get('vendor', '')
    kev_filter = request.GET.get('kev', '')

    # Apply filters
    if severity_filter:
        vulnerabilities = vulnerabilities.filter(severity=severity_filter)

    if vendor_filter:
        vulnerabilities = vulnerabilities.filter(
            software__vendor__id=vendor_filter
        ).distinct()

    if kev_filter == 'true':
        vulnerabilities = vulnerabilities.filter(in_cisa_kev=True)

    # Always sort by CVSS score highest first
    vulnerabilities = vulnerabilities.order_by('-cvss_score')

    # Pagination - 25 per page
    paginator = Paginator(vulnerabilities, 25)
    page_number = request.GET.get('page')
    page_obj = paginator.get_page(page_number)

    # Stats always based on full unfiltered queryset
    all_vulns = Vulnerability.objects.filter(
        software__vendor__in=user_vendors
    ).distinct()

    # Get user's remediation stats
    user_statuses = VulnerabilityStatus.objects.filter(profile=profile)

    context = {
        'page_obj': page_obj,
        'total_count': all_vulns.count(),
        'critical_count': all_vulns.filter(severity='CRITICAL').count(),
        'high_count': all_vulns.filter(severity='HIGH').count(),
        'kev_count': all_vulns.filter(in_cisa_kev=True).count(),
        'remediated_count': user_statuses.filter(status='REMEDIATED').count(),
        'na_count': user_statuses.filter(status='NA').count(),
        'user_vendors': user_vendors,
        'severity_filter': severity_filter,
        'vendor_filter': vendor_filter,
        'kev_filter': kev_filter,
        'severity_choices': ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'UNKNOWN'],
    }

    return render(request, 'core/dashboard.html', context)

@login_required
def vulnerability_detail(request, cve_id):
    vuln = get_object_or_404(Vulnerability, cve_id=cve_id)

    # Get user's status for this vulnerability if it exists
    user_status = None
    try:
        from accounts.models import VulnerabilityStatus
        user_status = VulnerabilityStatus.objects.get(
            profile=request.user.userprofile,
            vulnerability=vuln
        )
    except:
        pass

    context = {
        'vuln': vuln,
        'user_status': user_status,
        'software_list': vuln.software.all().select_related('vendor'),
    }
    return render(request, 'core/vulnerability_detail.html', context)

@login_required
def update_status(request, cve_id):
    if request.method == 'POST':
        vuln = get_object_or_404(Vulnerability, cve_id=cve_id)
        status = request.POST.get('status')

        VulnerabilityStatus.objects.update_or_create(
            profile=request.user.userprofile,
            vulnerability=vuln,
            defaults={'status': status}
        )

    return redirect('vulnerability_detail', cve_id=cve_id)