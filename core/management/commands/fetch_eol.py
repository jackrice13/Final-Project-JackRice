from django.core.management.base import BaseCommand
from core.models import Software, Vendor
import requests
from datetime import datetime

#this command mostly is just used to populate software and vendor tables

# Maps endoflife.date product names to what we have in our database
PRODUCT_MAP = { # key and value to setup tuple of name and vendor
    'windows': ('Windows', 'microsoft'),
    'windows-server': ('Windows Server', 'microsoft'),
    'msexchange': ('Microsoft Exchange', 'microsoft'),
    'office': ('Microsoft Office', 'microsoft'),
    'sharepoint': ('Microsoft SharePoint', 'microsoft'),
    'visual-studio': ('Visual Studio', 'microsoft'),
    'windows-embedded': ('Windows Embedded', 'microsoft'),
    'dotnet': ('.NET', 'microsoft'),
    'mssqlserver': ('Microsoft SQL Server', 'microsoft'),
    'powershell': ('PowerShell', 'microsoft'),
}


class Command(BaseCommand):

    def handle(self, *args, **kwargs):
        self.stdout.write('Starting endoflife.date fetch...') #term output

        base_url = 'https://endoflife.date/api' #API endpoint
        updated = 0 #update counter
        not_found = 0 #fail counter

        for product_slug, value in PRODUCT_MAP.items(): #builds url from software name and vendor, tuple unpacking?=<(
            software_name = value[0]
            vendor_slug = value[1]

            self.stdout.write(f'Fetching EOL data for {software_name}...') #term output

            url = f'{base_url}/{product_slug}.json' #url builder
            response = requests.get(url)

            if response.status_code != 200: #error handling, if response is other than 200
                self.stdout.write(self.style.WARNING( #term output
                    f'No data found for {product_slug}, skipping...'
                ))
                continue

            cycles = response.json()

            # Find the vendor
            try:
                vendor = Vendor.objects.get(slug=vendor_slug) #Looks up the vendor by slug
            except Vendor.DoesNotExist:
                self.stdout.write(self.style.WARNING(
                    f'Vendor {vendor_slug} not in database, skipping...' #term output if not found
                ))
                continue

            for cycle in cycles: #The endoflife.date API returns a list of cycles for specific version or release.
                cycle_name = cycle.get('cycle', '')
                eol_value = cycle.get('eol')

                # #eol field from the API can be three different things, Date, True or False
                eol_date = None #default to None before checking
                if isinstance(eol_value, str): #eol field from the API can be three different things, Date, True or False
                    try:
                        eol_date = datetime.strptime( #only try to parse if it's actually a string. If it's True or False,skip
                            eol_value, '%Y-%m-%d' #builds python date object
                        ).date()
                    except ValueError: #if the date string is in an unexpected format throw ValueError
                        pass

                # Build a specific software name for this cycle
                # e.g. 'Windows 10 22H2', 'Windows 11 23H2'
                cycle_software_name = f'{software_name} {cycle_name}'

                software, created = Software.objects.get_or_create(
                    name=cycle_software_name,
                    vendor=vendor,
                )

                if eol_date: #only saves and counts if we actually have a date. Records where EOL is True or False get a Software entry created but no date saved.
                    software.end_of_life_date = eol_date
                    software.save()
                    updated += 1
                    self.stdout.write(
                        f'  {cycle_software_name} → EOL: {eol_date}'
                    )

        self.stdout.write(self.style.SUCCESS(
            f'Done! Updated {updated} software entries with EOL dates.' #term output
        ))