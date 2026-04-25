from django.core.management.base import BaseCommand
from core.models import Vulnerability, Vendor, Software
import requests
from datetime import datetime, timedelta


# Mapping of MSRC product name keywords to simple names
PRODUCT_MAP = {
    'windows 11': 'Windows 11',
    'windows 10': 'Windows 10',
    'windows server 2022': 'Windows Server 2022',
    'windows server 2019': 'Windows Server 2019',
    'windows server 2016': 'Windows Server 2016',
    'office': 'Microsoft Office',
    'excel': 'Microsoft Excel',
    'word': 'Microsoft Word',
    'outlook': 'Microsoft Outlook',
    'sharepoint': 'Microsoft SharePoint',
    'exchange': 'Microsoft Exchange',
    'azure': 'Azure',
    'visual studio': 'Visual Studio',
    '.net': '.NET',
    'edge': 'Microsoft Edge',
    'defender': 'Microsoft Defender',
}


def simplify_product_name(product_name): #scans output for keywords from above.
    """Takes a verbose MSRC product name and returns a simplified version."""
    product_lower = product_name.lower()
    for keyword, simple_name in PRODUCT_MAP.items():
        if keyword in product_lower:
            return simple_name
    return None  # return None if we don't recognize the product


class Command(BaseCommand):
    help = 'Fetches Microsoft Security Response Center CVE data'

    def add_arguments(self, parser): #sets argument for allowing limited searches by no of months
        parser.add_argument(
            '--months',
            type=int,
            default=3,
            help='Number of months back to fetch'
        )

    def handle(self, *args, **kwargs):
        self.stdout.write('Starting MSRC fetch...') #output

        months = kwargs['months'] #reads months

        # Get or create the Microsoft vendor, should keep from creating duplicates
        vendor, created = Vendor.objects.get_or_create(
            slug='microsoft', #looks for mcirosoft
            defaults={'name': 'Microsoft'}
        )
        if created: #creates MS vendor if its missing
            self.stdout.write('Created Microsoft vendor.')
        else:
            self.stdout.write('Microsoft vendor already exists.')

        base_url = 'https://api.msrc.microsoft.com/cvrf/v2.0'
        headers = {'Accept': 'application/json'}

        # MSRC API serves data one month at a time, so this builds a list of month strings to request.
        months_to_fetch = []
        for i in range(months):
            date = datetime.now() - timedelta(days=30 * i) #subtracts 30 days from i, for each month specified
            months_to_fetch.append(date.strftime('%Y-%b')) #formats the date as YYYY-MM

        total_linked = 0
        total_not_found = 0

        for month in months_to_fetch: # builds URL for API fetch
            self.stdout.write(f'Fetching MSRC data for {month}...')

            url = f'{base_url}/cvrf/{month}' #formatting of the URL
            response = requests.get(url, headers=headers)

            if response.status_code != 200: #if other than 200, show error
                self.stdout.write(f'No data for {month}, skipping...')
                continue

            data = response.json() # Response collector

            # Get the list of affected products for this month
            product_tree = data.get('ProductTree', {})
            full_product_names = product_tree.get('FullProductName', [])

            # Build a lookup dict of product ID to simple name
            product_lookup = {}
            for product in full_product_names:
                product_id = product.get('ProductID')
                product_name = product.get('Value', '')
                simple_name = simplify_product_name(product_name)
                if simple_name:
                    product_lookup[product_id] = simple_name

            # Process each CVE in this month
            vulnerabilities = data.get('Vulnerability', [])

            for item in vulnerabilities:
                cve_id = item.get('CVE', '')

                if not cve_id:
                    continue

                # Find matching CVE in our database
                try:
                    vuln = Vulnerability.objects.get(cve_id=cve_id)
                except Vulnerability.DoesNotExist:
                    total_not_found += 1
                    continue

                # Get affected product IDs for this CVE
                affected_products = set()
                for threat in item.get('Threats', []):
                    product_id = threat.get('ProductID', '')

                    # MSRC sometimes returns ProductID as a list, handle both cases
                    if isinstance(product_id, list):
                        for pid in product_id:
                            if pid in product_lookup:
                                affected_products.add(product_lookup[pid])
                    else:
                        if product_id in product_lookup:
                            affected_products.add(product_lookup[product_id])

                # Create software entries and link to vulnerability
                for simple_name in affected_products:
                    software, _ = Software.objects.get_or_create(
                        name=simple_name,
                        vendor=vendor,
                    )
                    vuln.software.add(software)

                total_linked += 1

        self.stdout.write(self.style.SUCCESS(
            f'Done! Linked {total_linked} CVEs to Microsoft software. '
            f'{total_not_found} CVEs not in local database.'
        ))