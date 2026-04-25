from django.core.management.base import BaseCommand
from core.models import Vulnerability
import requests
import os
from datetime import datetime, timedelta


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
        headers = {'apiKey': api_key} #builds API call headers
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

        while True: #loops until break
            self.stdout.write(f'Fetching records starting at index {params["startIndex"]}...')

            response = requests.get(base_url, headers=headers, params=params)

            if response.status_code != 200: # if any failure occurs present error
                self.stdout.write(self.style.ERROR(f'API error: {response.status_code}'))
                break

            data = response.json() #api response
            # # DEBUG - let's see what the API is actually returning
            # self.stdout.write(f'Status code: {response.status_code}')
            # self.stdout.write(f'Total results: {data.get("totalResults", "KEY NOT FOUND")}')
            # self.stdout.write(f'Results in this batch: {len(data.get("vulnerabilities", []))}')
            # break  # stop after one request for now

            vulnerabilities = data.get('vulnerabilities', []) #Extracts the Vuln data from the API response

            if not vulnerabilities: #Stops if vulnerabilities is empty
                break

            for item in vulnerabilities:
                cve = item.get('cve', {}) #pulls CVE from vulnerabilities
                cve_id = cve.get('id', '') #pulls id from vulnerabilities

                # Get description
                descriptions = cve.get('descriptions', []) #pulls descriptions from vulnerabilities
                description = next(
                    (d['value'] for d in descriptions if d['lang'] == 'en'), #looks for english langage description
                    'No description available'  #returns if nothing is found in description
                )

                # Get CVSS score and severity
                cvss_score = None
                severity = 'UNKNOWN'
                metrics = cve.get('metrics', {}) #pulls descriptions from vulnerabilities

                if 'cvssMetricV31' in metrics: #checks for and extracts v3.1 first
                    cvss_data = metrics['cvssMetricV31'][0]['cvssData']
                    cvss_score = cvss_data.get('baseScore')
                    severity = cvss_data.get('baseSeverity', 'UNKNOWN')
                elif 'cvssMetricV2' in metrics: #falls back and extracts 2.0 if v3.1 available
                    cvss_data = metrics['cvssMetricV2'][0]['cvssData']
                    cvss_score = cvss_data.get('baseScore')

                # Get published date #gets the published date from API payload
                published_str = cve.get('published', '')
                published_date = None # Sets none as default and error check
                if published_str: #checks if published_str empty and converts to python format for storage
                    published_date = datetime.strptime(
                        published_str[:10], '%Y-%m-%d' #gets first 10 chars and stores as year,month,day
                    ).date()

                # Saves or updates vulnerability to db, update or create should keep from making duplicates
                Vulnerability.objects.update_or_create(
                    cve_id=cve_id,
                    defaults={
                        'description': description,
                        'cvss_score': cvss_score,
                        'severity': severity,
                        'published_date': published_date,
                    }
                )

                total_fetched += 1  # ← this is inside the for loop

            # ← back to while loop level (4 spaces indent)
            self.stdout.write(f'Processed {total_fetched} vulnerabilities so far...')

            total_results = data.get('totalResults', 0)
            params['startIndex'] += 100

            if params['startIndex'] >= total_results:
                break

        self.stdout.write(self.style.SUCCESS(f'Done! Fetched {total_fetched} vulnerabilities.'))