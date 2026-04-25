from django.core.management.base import BaseCommand
from core.models import Vulnerability
import requests


class Command(BaseCommand):
    help = 'Fetches CISA Known Exploited Vulnerabilities and enriches local CVE data'

    def handle(self, *args, **kwargs):
        self.stdout.write('Starting CISA KEV fetch...') #output

        url = 'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json' #api endpoint

        response = requests.get(url) #collect response

        if response.status_code != 200:
            self.stdout.write(self.style.ERROR(f'API error: {response.status_code}')) #outputs error if it not 200
            return

        data = response.json() #API output set to data
        kev_list = data.get('vulnerabilities', [])

        self.stdout.write(f'Downloaded {len(kev_list)} KEV entries...')

        updated = 0
        not_found = 0

        for entry in kev_list:
            cve_id = entry.get('cveID', '')

            try:
                vuln = Vulnerability.objects.get(cve_id=cve_id)
                vuln.in_cisa_kev = True
                vuln.save()
                updated += 1
            except Vulnerability.DoesNotExist:
                not_found += 1

        self.stdout.write(self.style.SUCCESS(
            f'Done! Marked {updated} CVEs as actively exploited. '
            f'{not_found} KEV entries not in local database.'
        ))