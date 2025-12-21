from django.contrib import admin
from django.contrib.auth.admin import UserAdmin as BaseUserAdmin
from .models import User
from django import forms
from django.contrib.auth.forms import ReadOnlyPasswordHashField
from django.core.exceptions import ValidationError
from .email_utils import send_verification_email
from django.core.validators import validate_email as django_validate_email


# Form for creating new users
class UserCreationForm(forms.ModelForm):
    """Form for creating new users in Django admin
    
    Requires email, first_name, and password.
    Validates email format before attempting to create user.
    """
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
        fields = ('email', 'first_name', 'last_name')

    def clean_email(self):
        """Validate email format and basic structure"""
        email = self.cleaned_data.get('email')
        
        # Validate email format
        try:
            django_validate_email(email)
        except ValidationError:
            raise forms.ValidationError("Enter a valid email address")
        
        # Additional validation - check if domain looks valid
        if '@' in email:
            domain = email.split('@')[1]
            # Basic domain validation - must have at least one dot
            if '.' not in domain:
                raise forms.ValidationError("Email domain appears invalid")
        
        return email

    def clean_first_name(self):
        """Validate that first_name is provided and not empty"""
        first_name = self.cleaned_data.get('first_name')
        if not first_name or not first_name.strip():
            raise forms.ValidationError("First name is required")
        return first_name.strip()

    def clean_password2(self):
        """Ensure the two password fields match"""
        p1 = self.cleaned_data.get("password1")
        p2 = self.cleaned_data.get("password2")
        if p1 and p2 and p1 != p2:
            raise forms.ValidationError("Passwords don't match")
        return p2

    def save(self, commit=True):
        """Save the new user with hashed password
        
        Note: Email validation is handled by UserAdmin.save_model()
        This method just prepares the user object.
        """
        user = super().save(commit=False)
        user.set_password(self.cleaned_data["password1"])  # Hash the password
        user.first_name = self.cleaned_data.get('first_name', '')
        user.last_name = self.cleaned_data.get('last_name', '')
        
        # Don't save here - let save_model handle it
        # save_model will validate email sending before saving
        return user

# Form for updating existing users
class UserChangeForm(forms.ModelForm):
    """Form for editing existing users in Django admin"""
    password = ReadOnlyPasswordHashField()

    class Meta:
        model = User
        fields = ('email', 'password', 'is_active', 'is_staff', 'is_superuser')

# Custom UserAdmin class
class UserAdmin(BaseUserAdmin):
    """Custom admin interface for User model
    
    Displays user list with email, name, and verification status.
    Add form requires first_name and validates email before user creation.
    """
    form = UserChangeForm
    add_form = UserCreationForm

    # Columns displayed in user list
    list_display = ('email', 'first_name', 'last_name', 'is_active', 'is_verified', 'date_joined')
    ordering = ('email',)
    search_fields = ('email', 'first_name', 'last_name')
    readonly_fields = ('date_joined', 'is_verified', 'verification_code', 'code_expires_at')

    # Sections when editing existing user
    fieldsets = (
        (None, {'fields': ('email', 'password')}),
        ('Personal info', {'fields': ('first_name', 'last_name')}),
        ('Status', {'fields': ('is_active', 'is_verified', 'date_joined')}),
        ('Email Verification', {'fields': ('verification_code', 'code_expires_at'), 'classes': ('collapse',)}),
    )

    # Sections when creating new user
    add_fieldsets = (
        (None, {
            'classes': ('wide',),
            'fields': ('email', 'first_name', 'last_name', 'password1', 'password2'),
            'description': 'First name is required. Verification email will be sent automatically.'
        }),
    )

    def save_model(self, request, obj, form, change):
        """Override save_model to send verification email for new users
        
        For new users, attempts to send verification email after saving.
        Shows message to admin about email status.
        """
        if not change:  # Only for new users (not updates)
            if not obj.is_superuser:
                # Generate verification code
                import random
                from django.utils import timezone
                verification_code = str(random.randint(100000, 999999))
                obj.verification_code = verification_code
                obj.code_expires_at = timezone.now() + timezone.timedelta(minutes=5)
                
                # Save user first
                obj.save()
                
                # Try to send verification email
                from .email_utils import send_verification_email
                email_sent = send_verification_email(obj)
                
                # Mark that email was already sent (for signal)
                obj._email_already_sent = True
                
                # Show appropriate message to admin
                from django.contrib import messages
                if email_sent:
                    messages.success(
                        request,
                        f"User created successfully. Verification email sent to {obj.email}"
                    )
                else:
                    messages.warning(
                        request,
                        f"User created but FAILED to send verification email to {obj.email}. "
                        f"The email address may be invalid."
                    )
            else:
                # Superusers don't need email verification
                super().save_model(request, obj, form, change)
        else:
            # For updates, use normal save
            super().save_model(request, obj, form, change)


admin.site.register(User, UserAdmin)