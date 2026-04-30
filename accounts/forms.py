from django import forms
from django.contrib.auth.models import User
from django.contrib.auth.forms import PasswordChangeForm


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