from django.contrib import admin
from django.contrib.auth.admin import UserAdmin as BaseUserAdmin
from .models import User, Organization
from django import forms
from django.contrib.auth.forms import ReadOnlyPasswordHashField
from django.core.exceptions import ValidationError
from .email_utils import send_verification_email
from django.core.validators import validate_email as django_validate_email


@admin.register(Organization)
class OrganizationAdmin(admin.ModelAdmin):
    list_display = ['name', 'subscription_tier', 'is_active', 'get_user_count', 'max_users', 'created_at']
    list_filter = ['subscription_tier', 'is_active', 'created_at']
    search_fields = ['name']
    readonly_fields = ['created_at', 'get_user_count']
    
    fieldsets = (
        ('Organization Details', {
            'fields': ('name', 'is_active')
        }),
        ('Subscription', {
            'fields': ('subscription_tier', 'max_users')
        }),
        ('Statistics', {
            'fields': ('created_at', 'get_user_count'),
            'classes': ('collapse',)
        }),
    )
    
    def get_user_count(self, obj):
        return obj.get_user_count()
    get_user_count.short_description = 'Active Users'


class UserCreationForm(forms.ModelForm):
    first_name = forms.CharField(
        label='First Name',
        max_length=150,
        required=True,
        help_text='Required. User\'s first name.'
    )
    password1 = forms.CharField(label='Password', widget=forms.PasswordInput)
    password2 = forms.CharField(label='Password confirmation', widget=forms.PasswordInput)

    class Meta:
        model = User
        fields = ('email', 'first_name', 'last_name', 'role', 'organization')

    def clean_email(self):
        email = self.cleaned_data.get('email')
        
        try:
            django_validate_email(email)
        except ValidationError:
            raise forms.ValidationError("Enter a valid email address")
        
        if '@' in email:
            domain = email.split('@')[1]
            if '.' not in domain:
                raise forms.ValidationError("Email domain appears invalid")
        
        return email

    def clean_first_name(self):
        first_name = self.cleaned_data.get('first_name')
        if not first_name or not first_name.strip():
            raise forms.ValidationError("First name is required")
        return first_name.strip()

    def clean_password2(self):
        p1 = self.cleaned_data.get("password1")
        p2 = self.cleaned_data.get("password2")
        if p1 and p2 and p1 != p2:
            raise forms.ValidationError("Passwords don't match")
        return p2
    
    def clean(self):
        cleaned_data = super().clean()
        role = cleaned_data.get('role')
        organization = cleaned_data.get('organization')
        
        if role == 'org_admin' and organization:
            if not organization.can_add_user():
                raise forms.ValidationError(
                    f"Cannot add user. Organization '{organization.name}' has reached "
                    f"its maximum user limit of {organization.max_users}. "
                    f"Current users: {organization.get_user_count()}"
                )
        
        return cleaned_data

    def save(self, commit=True):
        user = super().save(commit=False)
        user.set_password(self.cleaned_data["password1"])
        user.first_name = self.cleaned_data.get('first_name', '')
        user.last_name = self.cleaned_data.get('last_name', '')
        return user

class UserChangeForm(forms.ModelForm):
    password = ReadOnlyPasswordHashField()

    class Meta:
        model = User
        fields = ('email', 'password', 'is_active', 'is_staff', 'is_superuser')

@admin.register(User)
class UserAdmin(BaseUserAdmin):
    form = UserChangeForm
    add_form = UserCreationForm

    list_display = ('email', 'role', 'organization', 'first_name', 'last_name', 'is_verified', 'is_active', 'date_joined')
    list_filter = ('role', 'organization', 'is_verified', 'is_active', 'is_staff')
    ordering = ('-date_joined',)
    search_fields = ('email', 'first_name', 'last_name')
    readonly_fields = ('date_joined', 'is_verified', 'verification_code', 'code_expires_at')

    fieldsets = (
        (None, {'fields': ('email', 'password')}),
        ('Personal info', {'fields': ('first_name', 'last_name')}),
        ('Multi-Tenant', {'fields': ('role', 'organization')}),
        ('Status', {'fields': ('is_active', 'is_verified', 'date_joined')}),
        ('Permissions', {'fields': ('is_staff', 'is_superuser'), 'classes': ('collapse',)}),
        ('Email Verification', {'fields': ('verification_code', 'code_expires_at'), 'classes': ('collapse',)}),
    )

    add_fieldsets = (
        (None, {
            'classes': ('wide',),
            'fields': ('email', 'first_name', 'last_name', 'role', 'organization', 'password1', 'password2'),
            'description': 'First name is required. Verification email will be sent automatically. '
                         'Platform Owners must have no organization. Org Admins must have an organization.'
        }),
    )

    def save_model(self, request, obj, form, change):
        from django.contrib import messages
        
        if not change:
            if not obj.is_superuser:
                import random
                from django.utils import timezone
                verification_code = str(random.randint(100000, 999999))
                obj.verification_code = verification_code
                obj.code_expires_at = timezone.now() + timezone.timedelta(minutes=5)
                
                obj.save()
                
                from .email_utils import send_verification_email
                email_sent = send_verification_email(obj)
                
                obj._email_already_sent = True
                
                if email_sent:
                    messages.success(
                        request,
                        f"User created successfully. Verification email sent to {obj.email}"
                    )
                else:
                    messages.success(
                        request,
                        f"User created successfully. Please check {obj.email} for the verification email."
                    )
            else:
                super().save_model(request, obj, form, change)
        else:
            super().save_model(request, obj, form, change)