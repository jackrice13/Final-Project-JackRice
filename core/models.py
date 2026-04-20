from django.db import models

class Vendor(models.Model):
    name = models.CharField(max_length=100)
    slug = models.SlugField(unique=True)  #used to build URLs

    def __str__(self):
        return self.name


class Software(models.Model):
    vendor = models.ForeignKey(Vendor, on_delete=models.CASCADE) #ties software to one Vender, on_delete removed software if vendor is deleted
    name = models.CharField(max_length=200)
    version = models.CharField(max_length=50, blank=True) #not required in form
    end_of_life_date = models.DateField(null=True, blank=True) #not required in DB or form

    def __str__(self):
        return f"{self.vendor.name} - {self.name}" #Builds Vendor+Software name in f-string


class Vulnerability(models.Model):

    SEVERITY_CHOICES = [
        ('CRITICAL', 'Critical'),
        ('HIGH', 'High'),
        ('MEDIUM', 'Medium'),
        ('LOW', 'Low'),
        ('UNKNOWN', 'Unknown'),
    ]

    cve_id = models.CharField(max_length=20, unique=True)  # e.g. CVE-2024-1234
    description = models.TextField()
    severity = models.CharField(max_length=10, choices=SEVERITY_CHOICES, default='UNKNOWN') #uses severity_choices above
    cvss_score = models.FloatField(null=True, blank=True)  # 0.0 - 10.0
    in_cisa_kev = models.BooleanField(default=False)  # actively exploited flag
    published_date = models.DateField(null=True, blank=True)
    software = models.ManyToManyField(Software, blank=True) #one vulnerability can affect many software packages, and one software package can have many vulnerabilities

    def __str__(self):
        return self.cve_id