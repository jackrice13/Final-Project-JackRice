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
                password='Password01!',
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
        self.stdout.write('\nStep 4: Fetching NVD data (last 30 days)...')
        self.stdout.write('Thi