from django.core.management.base import BaseCommand
from django.core.management import call_command
from django.contrib.auth.models import User
from core.models import Vendor
from accounts.models import UserProfile


class Command(BaseCommand):
    help = 'Sets up the project with demo data and fetches API data'

    def handle(self, *args, **kwargs):
        self.stdout.write('Setting up VulnTracker...')

        # Step 1 - Load fixtures (vendors + demo user)
        self.stdout.write('Loading fixture data...')
        call_command('loaddata', 'seed_data.json')

        # Step 2 - Make sure demo user has a profile
        # signals handle this for new users but fixtures bypass signals
        try:
            demo_user = User.objects.get(username='demo')
            profile, created = UserProfile.objects.get_or_create(
                user=demo_user
            )
            # assign Microsoft vendor to demo user
            microsoft = Vendor.objects.get(slug='microsoft')
            profile.vendors.add(microsoft)
            self.stdout.write('Demo user profile configured.')
        except User.DoesNotExist:
            self.stdout.write(self.style.WARNING('Demo user not found.'))

        # Step 3 - Fetch API data
        self.stdout.write('Fetching NVD data (30 days)...')
        call_command('fetch_nvd', days=30)

        self.stdout.write('Fetching CISA KEV data...')
        call_command('fetch_kev')

        self.stdout.write('Fetching Microsoft MSRC data...')
        call_command('fetch_msrc', months=3)

        self.stdout.write('Fetching end of life dates...')
        call_command('fetch_eol')

        # Step 4 - Summary
        from core.models import Vulnerability, Software
        self.stdout.write(self.style.SUCCESS(
            f'\nSetup complete!'
            f'\n  Vendors:         {Vendor.objects.count()}'
            f'\n  Software:        {Software.objects.count()}'
            f'\n  Vulnerabilities: {Vulnerability.objects.count()}'
            f'\n\nDemo login:'
            f'\n  Username: demo'
            f'\n  Password: Demo1234!'
        ))