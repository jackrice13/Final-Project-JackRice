from django.shortcuts import render, get_object_or_404, redirect
from django.contrib.auth.decorators import login_required
from django.core.paginator import Paginator
from core.models import Vulnerability, Vendor
from accounts.models import VulnerabilityStatus


def calculate_risk_score(vuln):
    score = vuln.cvss_score or 0 # sets a default fault to prevent crash if no CVSS

    # Base score = CVSS score(0 - 10)
    # KEV bonus = +3 if actively exploited
    # EOL bonus = +2 if any software is pastend of life Max possible = 15

    # actively exploited vulnerabilities are higher priority
    if vuln.in_cisa_kev:
        score += 3 #adds + to  CVSS if found in KEV

    # if any affected software is past end of life, risk is higher
    today = date.today() #sets today as date
    for software in vuln.software.all():
        if software.end_of_life_date and software.end_of_life_date < today: #checks if software is EOL by todays date
            score += 2
            break  # only add the bonus once even if multiple EOL software

    return round(score, 1) #rounds to nearest one to prevent display issues

def get_sort_params(request, default='-cvss_score'): #helper function that reads and parses the sort parameter from the URL
    sort = request.GET.get('sort', default)
    # if sort starts with - it's descending, strip it to get the field name
    if sort.startswith('-'):
        current_field = sort[1:]
        direction = 'desc'
    else:
        current_field = sort
        direction = 'asc'
    return sort, current_field, direction


# def get_next_sort(current_sort, field): #switche to java script, no longer used
#     # if already sorting by this field, reverse direction
#     # otherwise sort descending by default
#     if current_sort == f'-{field}':
#         return field
#     return f'-{field}'

@login_required
def dashboard(request):
    profile = request.user.userprofile #connect user to profile
    user_vendors = profile.vendors.all() #gets vendors user is tracking

    # core of filter by user's vendors
    vulnerabilities = Vulnerability.objects.filter(
        software__vendor__in=user_vendors #only include users vendors
    ).distinct() #prevents dups

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

    # Get sort parameters
    sort, current_field, direction = get_sort_params(request, '-cvss_score')

    # Apply database level sorting for fields that exist on the model
    db_sort_fields = {
        'cvss_score': 'cvss_score',
        'published_date': 'published_date',
        'severity': 'severity',
    }

    if current_field in db_sort_fields:
        if direction == 'desc':
            vulnerabilities = vulnerabilities.order_by(
                f'-{db_sort_fields[current_field]}'
            )
        else:
            vulnerabilities = vulnerabilities.order_by(
                db_sort_fields[current_field]
            )
    else:
        # default sort
        vulnerabilities = vulnerabilities.order_by('-cvss_score')

    # Sets pages and options,
    paginator = Paginator(vulnerabilities, 25) #25 per page
    page_number = request.GET.get('page') #reads page number
    page_obj = paginator.get_page(page_number) #returns correct page

    # Calculate risk scores for current page only
    vuln_data = []
    for vuln in page_obj:
        vuln_data.append({
            'vuln': vuln,
            'risk_score': calculate_risk_score(vuln),
        })

    # Sort by risk score in Python if selected
    # (can't do this at DB level since it's calculated)
    if current_field == 'risk_score':
        vuln_data.sort(
            key=lambda x: x['risk_score'], # a lambda is an anonymous one line function. This one takes a dictionary x and returns its risk_score value. Python's sort() uses this to know what value to compare when sorting.
            reverse=(direction == 'desc')
        )

    # Stats always based on full unfiltered queryset
    all_vulns = Vulnerability.objects.filter(
        software__vendor__in=user_vendors
    ).distinct()

    # Get user's remediation stats
    user_statuses = VulnerabilityStatus.objects.filter(profile=profile)

    context = { #dictionary of everything passed to the template
        'page_obj': page_obj,
        'vuln_data': vuln_data,
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
        'current_sort': sort,
        'current_field': current_field,
        'direction': direction,
    }

    return render(request, 'core/dashboard.html', context)

@login_required
def vulnerability_detail(request, cve_id): #comes from the URL — defined in urls.py. from /vulnerability/CVE-2024-1234/ passes 'CVE-2024-1234' as cve_id
    vuln = get_object_or_404(Vulnerability, cve_id=cve_id) #looks up the vulnerability by CVE ID. If it doesn't exist pop 404

    # Get user's status for this vulnerability if it exists
    user_status = None
    try: #find the user's status for this CVE or presents error
        user_status = VulnerabilityStatus.objects.get(
            profile=request.user.userprofile,
            vulnerability=vuln
        )
    except VulnerabilityStatus.DoesNotExist:
        pass

    context = {
        'vuln': vuln,
        'user_status': user_status,
        'software_list': vuln.software.all().select_related('vendor'),
        'risk_score': calculate_risk_score(vuln),
    }
    return render(request, 'core/vulnerability_detail.html', context)

@login_required #Remediate / Not Applicable / Reset buttons
def update_status(request, cve_id):
    if request.method == 'POST': #processes if form was submitted
        vuln = get_object_or_404(Vulnerability, cve_id=cve_id)
        status = request.POST.get('status') #reads which button was clicked. Each button has name="status" and a different value attribute

        VulnerabilityStatus.objects.update_or_create( #updates or creates to prevent duplciates
            profile=request.user.userprofile,
            vulnerability=vuln,
            defaults={'status': status}
        )

    return redirect('vulnerability_detail', cve_id=cve_id) #returns user back to details page

from datetime import date

@login_required
def aging_report(request):
    profile = request.user.userprofile
    user_vendors = profile.vendors.all()
    today = date.today()

    sla_map = { #Builds a lookup dictionary from the user's SLA settings
        'CRITICAL': profile.sla_critical,
        'HIGH': profile.sla_high,
        'MEDIUM': profile.sla_medium,
        'LOW': profile.sla_low,
        'UNKNOWN': profile.sla_low,
    }

    open_vulns = Vulnerability.objects.filter( #only the user's vendors, same as dashboard
        software__vendor__in=user_vendors,
    ).distinct().exclude( #removes anything the user has already marked as remediated or N/A
        vulnerabilitystatus__profile=profile,
        vulnerabilitystatus__status__in=['REMEDIATED', 'NA']
    ).filter( #removes CVEs with no published date
        published_date__isnull=False
    ).order_by('published_date') #removes CVEs with no published date since we can't calculate age witho

    # Build vuln data with calculated fields
    vuln_data = []
    overdue_count = 0
    within_sla_count = 0

    for vuln in open_vulns:
        age_days = (today - vuln.published_date).days #subtraction finds age
        sla_target = sla_map.get(vuln.severity, profile.sla_low) #looks up the SLA target for this severity. profile.sla_low is failsafe
        days_remaining = sla_target - age_days #positive means time left, negative means overdue
        is_overdue = age_days > sla_target # True/False comparison

        if is_overdue: # Counter for stats at top of page
            overdue_count += 1
        else:
            within_sla_count += 1

        vuln_data.append({
            'vuln': vuln,
            'age_days': age_days,
            'sla_target': sla_target,
            'days_remaining': days_remaining,
            'is_overdue': is_overdue,
            'days_overdue': age_days - sla_target,
            'risk_score': calculate_risk_score(vuln),
        })

    # Get sort parameters
    sort, current_field, direction = get_sort_params(request, '-age_days')

    # Sort vuln_data list in Python since all fields are calculated
    sort_key_map = {
        'cvss_score': lambda x: x['vuln'].cvss_score or 0,
        'risk_score': lambda x: x['risk_score'],
        'published_date': lambda x: x['vuln'].published_date,
        'age_days': lambda x: x['age_days'],
        'severity': lambda x: x['vuln'].severity,
    }

    if current_field in sort_key_map:
        vuln_data.sort(
            key=sort_key_map[current_field],
            reverse=(direction == 'desc')
        )

    # Pagination
    paginator = Paginator(vuln_data, 25)
    page_number = request.GET.get('page')
    page_obj = paginator.get_page(page_number)

    context = {
        'page_obj': page_obj,
        'overdue_count': overdue_count,
        'within_sla_count': within_sla_count,
        'total_open': len(vuln_data),
        'sla_map': sla_map,
        'profile': profile,
        'current_sort': sort,
        'current_field': current_field,
        'direction': direction,
    }

    return render(request, 'core/aging_report.html', context)