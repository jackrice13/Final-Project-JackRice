### INF601 - Advanced Programming in Python
### Jack Rice
### Final-Project-JackRice
 
 
# Project Title
 
### VulnTracker

A user-curated vulnerability and software update tracking dashboard for endpoint engineers and software asset managers. 
## Description
 
VulnTracker is a Django-based web application that aggregates vulnerability and software update data from multiple public security APIs into a single, personalized dashboard. Rather than digging through massive amounts of security data that may not apply to their environment, users can create an account, select the software vendors they care about, and receive a filtered view of relevant CVEs sorted by criticality. 
## Getting Started
 
### Dependencies
 
django
requests
python-dotenv
 
### Installing
## Quick Setup (Recommended)

Run Requirements.txt
```
pip install -r requirements.txt
```
Run Migrations
```
python manage.py migrate
```
After installing dependencies and running migrations, seed the entire 
database:

```
python manage.py setup_project
```

This will load vendor data, create a demo user account, and fetch 
vulnerability data from all configured APIs.

**Demo login credentials:**
- Username: `demo`
- Password: `Demo1234!`

### Optional: NVD API Key
An NVD API key is not required but recommended for faster data fetching.
Without a key there is a limit to the API requests run against this API.
Get a free key at https://nvd.nist.gov/developers/request-an-api-key

If you have a key add it to your .env file:
```
NVD_API_KEY=your-key-here
```

## Manual Setup (If setup_project Fails)

If the automated setup script fails, you can run each step manually in order.

### 1. Apply Database Migrations
```bash
python manage.py migrate
```

### 2. Create a Superuser Account
```bash
python manage.py createsuperuser
```

### 3. Load Vendor Fixture Data
```bash
python manage.py loaddata seed_data.json
```

### 4. Fetch NVD Vulnerability Data
```bash
python manage.py fetch_nvd --days 30
```
> This step may take several minutes depending on connection speed.
> An NVD API key is optional but will speed up this step significantly.

### 5. Fetch CISA KEV Actively Exploited Flags
```bash
python manage.py fetch_kev
```

### 6. Fetch Microsoft MSRC Product Data
```bash
python manage.py fetch_msrc --months 3
```

### 7. Fetch Software End of Life Dates
```bash
python manage.py fetch_eol
```

### 8. Start the Development Server
```bash
python manage.py runserver
```

### 9. Create a Demo User (Optional)
Visit `http://127.0.0.1:8000/accounts/register/` and register a new 
account. After logging in, visit **My Profile** and select **Microsoft** 
as a tracked vendor to populate your dashboard with data.

---

> **Note:** All fetch commands (steps 4-7) require an active internet 
> connection. If any command fails it can be safely re-run without 
> creating duplicate database entries.

### Executing program
 
Start the development server:
```
python manage.py runserver
```
Open your browser and navigate to:
```
http://127.0.0.1:8000
 ```
## Logins
**SuperUser login credentials:**
- Username: 'admin'
- Password: 'Password01!'

**Demo login credentials:**
- Username: `demo`
- Password: `Demo1234!`

## Authors
 
Jack Rice
 
## Version History
* 0.1
    * Initial Release

## Acknowledgments

* [NVD API Documentation](https://nvd.nist.gov/developers/vulnerabilities)
* [CISA Known Exploited Vulnerabilities Catalog](https://www.cisa.gov/known-exploited-vulnerabilities-catalog)
* [Microsoft Security Response Center API](https://api.msrc.microsoft.com/cvrf/v2.0)
* [endoflife.date API](https://endoflife.date/docs/api)
* [Django ](https://docs.djangoproject.com/)
* [Bootstrap 5](https://getbootstrap.com/)
