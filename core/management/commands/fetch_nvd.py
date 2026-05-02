from django.core.management.base import BaseCommand
from core.models import Vulnerability, Vendor, Software
import requests
import os
from datetime import datetime, timedelta


# Maps NVD CPE vendor strings to clean display names
# CPE strings use lowercase no-space vendor names, this converts them to readable names
#vendor map filters vendors for only the list we care about
VENDOR_MAP = {
    'microsoft': 'Microsoft',
    'canonical': 'Canonical',
    'redhat': 'Red Hat',
    'debian': 'Debian',
    'apache': 'Apache',
    'google': 'Google',
    'apple': 'Apple',
    'oracle': 'Oracle',
    'linux': 'Linux',
    'ubuntu': 'Canonical',
    'fedoraproject': 'Fedora',
    'suse': 'SUSE',
    'nvidia': 'NVIDIA',
    'adobe': 'Adobe',
    'cisco': 'Cisco',
    'mozilla': 'Mozilla',
}


class Command(BaseCommand):
    help = 'Fetches vulnerabilities from the NVD API'

    def add_arguments(self, parser):  # adds the ability to limit the number of days to check
        parser.add_argument(
            '--days',
            type=int,
            default=30,
            help='Number of days back to fetch vulnerabilities for'
        )

    def handle(self, *args, **kwargs):
        self.stdout.write('Starting NVD fetch...')

        days = kwargs['days'] #reads --days from above
        api_key = os.getenv('NVD_API_KEY') # gets apikey from .env
        headers = {'apiKey': api_key} if api_key else {} #made api optional for easier portability
        base_url = 'https://services.nvd.nist.gov/rest/json/cves/2.0' # API endpoint

        end_date = datetime.now() #sets today as end_date
        start_date = end_date - timedelta(days=days) #subtracts days from above to get last X number of days data

        params = {
            'resultsPerPage': 100,
            'startIndex': 0,
            'pubStartDate': start_date.strftime('%Y-%m-%dT%H:%M:%S.000'),
            'pubEndDate': end_date.strftime('%Y-%m-%dT%H:%M:%S.000'),
        } #passes data filters to NVD API, Added to URL, basically passes start day and end day to the vuln data request

        total_fetched = 0 #vuln counters for output
        total_linked = 0 #tracks how many CVEs get linked to software via CPE data

        while True: #loops until break
            self.stdout.write(f'Fetching records starting at index {params["startIndex"]}...')

            response = requests.get(base_url, headers=headers, params=params)

            if response.status_code != 200: # if any failure occurs present error
                self.stdout.write(self.style.ERROR(f'API error: {response.status_code}'))
                break

            data = response.json() #api response

            vulnerabilities = data.get('vulnerabilities', []) #Extracts the Vuln data from the API response

            if not vulnerabilities: #Stops if vulnerabilities is empty
                break

            for item in vulnerabilities:
                cve = item.get('cve', {}) #pulls CVE from vulnerabilities
                cve_id = cve.get('id', '') #pulls id from vulnerabilities

                # Get description
                descriptions = cve.get('descriptions', []) #pulls descriptions from vulnerabilities
                description = next(
                    (d['value'] for d in descriptions if d['lang'] == 'en'), #looks for english language description
                    'No description available'  #returns if nothing is found in description
                )

                # Get CVSS score and severity
                cvss_score = None
                severity = 'UNKNOWN'
                metrics = cve.get('metrics', {}) #pulls metrics from vulnerabilities

                if 'cvssMetricV31' in metrics: #checks for and extracts v3.1 first
                    cvss_data = metrics['cvssMetricV31'][0]['cvssData']
                    cvss_score = cvss_data.get('baseScore')
                    severity = cvss_data.get('baseSeverity', 'UNKNOWN')
                elif 'cvssMetricV2' in metrics: #falls back and extracts 2.0 if v3.1 not available
                    cvss_data = metrics['cvssMetricV2'][0]['cvssData']
                    cvss_score = cvss_data.get('baseScore')

                # Get published date - gets the published date from API payload
                published_str = cve.get('published', '')
                published_date = None # Sets none as default and error check
                if published_str: #checks if published_str empty and converts to python format for storage
                    published_date = datetime.strptime(
                        published_str[:10], '%Y-%m-%d' #gets first 10 chars and stores as year,month,day
                    ).date()

                # Saves or updates vulnerability to db, update_or_create keeps from making duplicates
                vuln, created = Vulnerability.objects.update_or_create(
                    cve_id=cve_id,
                    defaults={
                        'description': description,
                        'cvss_score': cvss_score,
                        'severity': severity,
                        'published_date': published_date,
                    }
                )

                #attempt to extract vendor data from NVD
                #NVD formats this data weird in "configurations"
                # CPE strings look like: cpe:2.3:o:canonical:ubuntu_linux:20.04:...
                #                                        ↑vendor  ↑product    ↑version
                configurations = cve.get('configurations', []) #pulls the configurations list out of the CVE data
                affected_software = set() # use a set to avoid processing duplicates

                for config in configurations:  #Three loops because the data is three levels deep.
                    for node in config.get('nodes', []):
                        for cpe_match in node.get('cpeMatch', []):

                            # only process CPEs marked as vulnerable
                            #Each CPE match has a vulnerable flag, True or False
                            if not cpe_match.get('vulnerable', False): # skip any CPE where vulnerable is False
                                continue

                            cpe_string = cpe_match.get('criteria', '')
                            parts = cpe_string.split(':') # splits cpe string into parts by colon
                                                            #'cpe', '2.3', 'o', 'canonical', 'ubuntu_linux', '20.04', ...]
                            if len(parts) < 5: # skips strings with less than 5 parts
                                continue

                            vendor_slug = parts[3]  # Tags Part 3 as Vendor
                            product_name = parts[4]  # Tags Part 4 as Product

                            # only process vendors we recognize in our VENDOR_MAP
                            # this keeps the database clean and avoids thousands of unknown vendors
                            if vendor_slug not in VENDOR_MAP: #checks for vendors in map above, only  to keep DB smaller.
                                continue

                            # converts underscores to spaces and title case the product name
                            clean_product = product_name.replace('_', ' ').title()
                            affected_software.add((vendor_slug, clean_product))

                # create vendor and software records and link them to the vulnerability
                for vendor_slug, clean_product in affected_software:
                    vendor, _ = Vendor.objects.get_or_create(
                        slug=vendor_slug,
                        defaults={'name': VENDOR_MAP[vendor_slug]} # uses clean name from VENDOR_MAP
                    )
                    software, _ = Software.objects.get_or_create(
                        name=clean_product,
                        vendor=vendor,
                    )
                    vuln.software.add(software) # adds to junction table
                    total_linked += 1 #increments our counter

                total_fetched += 1  # increments our counter

            # back to while loop level
            self.stdout.write(f'Processed {total_fetched} vulnerabilities, {total_linked} software links so far...')

            total_results = data.get('totalResults', 0)
            params['startIndex'] += 100

            if params['startIndex'] >= total_results:
                break

        self.stdout.write(self.style.SUCCESS(
            f'Done! Fetched {total_fetched} vulnerabilities with {total_linked} software links.'
        ))