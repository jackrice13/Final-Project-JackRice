from django.core.management.base import BaseCommand
from django.core.management import call_command
from django.contrib.auth.models import User
from core.models import Vendor, Vulnerability, Software
from accounts.models import UserProfile


class Command(BaseCommand):
    help = 'Sets up the project with demo data and fetches API data'

    def handle(self, *args, **kwargs):
        self.stdout.write('Setting up VulnTracker...')
        self.stdout.write('=' * 50)

        # Step 1 - Load fixtures (vendors + demo user)
        self.stdout.write('\nStep 1: Loading fixture data...')
        call_command('loaddata', 'seed_data.json')
        self.stdout.write(self.style.SUCCESS('Fixtures loaded.'))

        # Step 2 - Create superuser if it doesn't exist
        # superuser has full access to the admin panel at /admin/
        self.stdout.write('\nStep 2: Creating superuser...')
        if not User.objects.filter(username='admin').exists():
            User.objects.create_superuser(
                username='admin',
                password='Admin1234!',
                email='admin@vulntracker.com'
            )
            self.stdout.write(self.style.SUCCESS('Superuser created.'))
        else:
            self.stdout.write('Superuser already exists, skipping.')

        # Step 3 - Make sure demo user has a profile and vendor assigned
        # fixtures bypass Django signals so we create the profile manually
        # signals only fire on model saves not fixture loads
        self.stdout.write('\nStep 3: Configuring demo user profile...')
        try:
            demo_user = User.objects.get(username='demo')
            profile, created = UserProfile.objects.get_or_create(
                user=demo_user
            )
            # assign Microsoft to demo user so dashboard has data on first login
            microsoft = Vendor.objects.get(slug='microsoft')
            profile.vendors.add(microsoft)
            self.stdout.write(self.style.SUCCESS('Demo user profile configured.'))
        except User.DoesNotExist:
            self.stdout.write(self.style.WARNING(
                'Demo user not found - check seed_data.json.'
            ))
        except Vendor.DoesNotExist:
            self.stdout.write(self.style.WARNING(
                'Microsoft vendor not found - check seed_data.json.'
            ))

        # Step 4 - Fetch NVD vulnerability data
        # pulls last 30 days of CVEs from NIST National Vulnerability Database
        # no API key required - will run slower without one due to rate limiting
        self.stdout.write('\nStep 4: Fetching NVD data (last 30 days)...')
        self.stdout.write('This may take several minutes...')
        try:
            call_command('fetch_nvd', days=30)
            self.stdout.write(self.style.SUCCESS('NVD fetch complete.'))
        except Exception as e:
            self.stdout.write(self.style.ERROR(f'NVD fetch failed: {e}'))
            self.stdout.write('If this keeps failing try adding an NVD API key to your .env file.')
            self.stdout.write('Get a free key at https://nvd.nist.gov/developers/request-an-api-key')

        # Step 5 - Fetch CISA KEV data
        # enriches CVEs with actively exploited flags
        self.stdout.write('\nStep 5: Fetching CISA KEV data...')
        try:
            call_command('fetch_kev')
            self.stdout.write(self.style.SUCCESS('CISA KEV fetch complete.'))
        except Exception as e:
            self.stdout.write(self.style.ERROR(f'CISA KEV fetch failed: {e}'))

        # Step 6 - Fetch Microsoft MSRC data
        # links CVEs to Microsoft products and software
        self.stdout.write('\nStep 6: Fetching Microsoft MSRC data (last 3 months)...')
        try:
            call_command('fetch_msrc', months=3)
            self.stdout.write(self.style.SUCCESS('MSRC fetch complete.'))
        except Exception as e:
            self.stdout.write(self.style.ERROR(f'MSRC fetch failed: {e}'))

        # Step 7 - Fetch end of life dates
        # adds EOL dates to software entries
        self.stdout.write('\nStep 7: Fetching end of life dates...')
        try:
            call_command('fetch_eol')
            self.stdout.write(self.style.SUCCESS('EOL fetch complete.'))
        except Exception as e:
            self.stdout.write(self.style.ERROR(f'EOL fetch failed: {e}'))

        # Step 8 - Print summary
        self.stdout.write('\n' + '=' * 50)
        self.stdout.write(self.style.SUCCESS('Setup complete!'))
        self.stdout.write('=' * 50)
        self.stdout.write(f'\nDatabase summary:')
        self.stdout.write(f'  Vendors:         {Vendor.objects.count()}')
        self.stdout.write(f'  Software:        {Software.objects.count()}')
        self.stdout.write(f'  Vulnerabilities: {Vulnerability.objects.count()}')
        self.stdout.write(f'\nAdmin login (full access including /admin/):')
        self.stdout.write(f'  Username: admin')
        self.stdout.write(f'  Password: Admin1234!')
        self.stdout.write(f'\nDemo login (regular user):')
        self.stdout.write(f'  Username: demo')
        self.stdout.write(f'  Password: Demo1234!')
        self.stdout.write(f'\nRun the server:')
        self.stdout.write(f'  python manage.py runserver')
        self.stdout.write('=' * 50)