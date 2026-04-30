from django.db import models
from django.contrib.auth.models import User
from core.models import Vendor

STATUS_CHOICES = [
    ('OPEN', 'Open'),
    ('REMEDIATED', 'Remediated'),
    ('NA', 'Not Applicable'),
]


class UserProfile(models.Model): #adds extension to built in auth_user
    user = models.OneToOneField(User, on_delete=models.CASCADE) # Creates accounts_userprofile, binds user to user_ID, allows
    vendors = models.ManyToManyField(Vendor, blank=True) # Creates accounts_userprofile_vendors, many to many allows use to track multiple vendors


    def __str__(self):
        return f"{self.user.username}'s profile"


class VulnerabilityStatus(models.Model): # allows users to set a status of a vulnerability (hide those that do not apply)
    profile = models.ForeignKey(UserProfile, on_delete=models.CASCADE)
    vulnerability = models.ForeignKey('core.Vulnerability', on_delete=models.CASCADE)
    status = models.CharField(max_length=15, choices=STATUS_CHOICES, default='OPEN')
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        constraints = [
            models.UniqueConstraint(
                fields=['profile', 'vulnerability'],
                name='unique_user_and_vulnerability_status'
            )  #user can only have one status record per vulnerability
        ]

    def __str__(self):
        return f"{self.profile.user.username} - {self.vulnerability.cve_id} - {self.status}"