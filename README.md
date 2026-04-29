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
 
* How/where to download your program
* Any modifications needed to be made to files/folders
 
### Executing program
 
Start the development server:
```
python manage.py runserver
```
Open your browser and navigate to:
```
http://127.0.0.1:8000
 ```
## Help
 
Any advise for common problems or issues.
```
command to run if program contains helper info
```
 
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
* [Django Documentation](https://docs.djangoproject.com/)
* [Bootstrap 5](https://getbootstrap.com/)
