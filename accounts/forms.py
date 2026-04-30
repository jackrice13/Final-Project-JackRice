from django import forms
from django.contrib.auth.models import User
from accounts.models import UserProfile
#from django.contrib.auth.forms import PasswordChangeForm


class UserUpdateForm(forms.ModelForm):
    email = forms.EmailField(required=False)

    class Meta:
        model = User
        fields = ['email']


class VendorSelectionForm(forms.Form):
    vendors = forms.MultipleChoiceField( #allows user to pick multiple
        required=False, # no selection required
        widget=forms.CheckboxSelectMultiple # uses checkboxes instead of dropdown
    )

    def __init__(self, *args, vendor_queryset=None, **kwargs):
        super().__init__(*args, **kwargs)
        if vendor_queryset is not None:
            self.fields['vendors'].choices = [
                (v.id, v.name) for v in vendor_queryset
            ]

class SLASettingsForm(forms.ModelForm): #form for user to adjust SLA time limits
    class Meta:
        model = UserProfile
        fields = ['sla_critical', 'sla_high', 'sla_medium', 'sla_low']
        labels = {
            'sla_critical': 'Critical (days)',
            'sla_high': 'High (days)',
            'sla_medium': 'Medium (days)',
            'sla_low': 'Low (days)',
        }
        widgets = {
            'sla_critical': forms.NumberInput(attrs={'class': 'form-control', 'min': 1}),
            'sla_high': forms.NumberInput(attrs={'class': 'form-control', 'min': 1}),
            'sla_medium': forms.NumberInput(attrs={'class': 'form-control', 'min': 1}),
            'sla_low': forms.NumberInput(attrs={'class': 'form-control', 'min': 1}),
        }
