

from django.contrib.auth.models import AbstractUser, BaseUserManager
from django.db import models
from django.utils import timezone
from django.core.exceptions import ValidationError


class Organization(models.Model):
    """
    Represents a customer organization in ThreatEye.
    Organizations have subscription tiers that control max users and features.
    Multi-tenant: each organization is isolated from others.
    """
    
    # Subscription tier options - controls features and user limits
    TIER_NOT_SUBSCRIBED = 'not_subscribed'
    TIER_BASIC = 'basic'
    TIER_PROFESSIONAL = 'professional'
    
    SUBSCRIPTION_TIERS = [
        (TIER_NOT_SUBSCRIBED, 'Not Subscribed'),
        (TIER_BASIC, 'Basic plan'),
        (TIER_PROFESSIONAL, 'Professional plan'),
    ]
    
    name = models.CharField(
        max_length=255,
        unique=True,
        help_text="Organization name (must be unique)"
    )
    created_at = models.DateTimeField(
        auto_now_add=True,
        help_text="Organization creation timestamp"
    )
    is_active = models.BooleanField(
        default=False,
        help_text="Whether organization subscription is active"
    )
    subscription_tier = models.CharField(
        max_length=20,
        choices=SUBSCRIPTION_TIERS,
        default=TIER_NOT_SUBSCRIBED,
        help_text="Current subscription tier"
    )
    max_users = models.IntegerField(
        default=1,
        help_text="Maximum number of users allowed in this organization"
    )
    
    class Meta:
        ordering = ['name']
        verbose_name = 'Organization'
        verbose_name_plural = 'Organizations'
    
    def __str__(self):
        return self.name
    
    def get_user_count(self):
        return self.users.filter(is_active=True).count()
    
    def can_add_user(self):
        return self.get_user_count() < self.max_users
    
    def save(self, *args, **kwargs):
        # Keep Organization state consistent with subscription tier.
        if self.subscription_tier == self.TIER_NOT_SUBSCRIBED:
            self.max_users = 1
            self.is_active = False
        elif self.subscription_tier == self.TIER_BASIC:
            self.max_users = 5
            self.is_active = True
        elif self.subscription_tier == self.TIER_PROFESSIONAL:
            self.max_users = 20
            self.is_active = True
        
        super().save(*args, **kwargs)


class UserManager(BaseUserManager):
    """
    Custom user manager for Django authentication using email instead of username.
    """
    
    def create_user(self, email, password=None, **extra_fields):
        # Create regular user account
        if not email:
            raise ValueError("Email is required")

        email = self.normalize_email(email)
        user = self.model(email=email, **extra_fields)
        user.set_password(password)
        user.save(using=self._db)
        return user

    def create_superuser(self, email, password=None, **extra_fields):
        # Create admin/superuser account
        extra_fields.setdefault('is_staff', True)
        extra_fields.setdefault('is_superuser', True)
        extra_fields.setdefault('is_active', True)
        extra_fields.setdefault('is_verified', True)
        extra_fields.setdefault('role', 'platform_owner')  # Set platform_owner as default for superusers

        if extra_fields.get('is_staff') is not True:
            raise ValueError('Superuser must have is_staff=True')
        if extra_fields.get('is_superuser') is not True:
            raise ValueError('Superuser must have is_superuser=True')

        return self.create_user(email, password, **extra_fields)


class User(AbstractUser):
    """
    Custom user model for ThreatEye.
    Uses email as username. Has roles (Platform Owner vs Organization Admin).
    Email verification required before account is active.
    """
    
    # User role options in the system
    PLATFORM_OWNER = 'platform_owner'
    ORG_ADMIN = 'org_admin'
    
    ROLE_CHOICES = [
        (PLATFORM_OWNER, 'Platform Owner'),
        (ORG_ADMIN, 'Organization Admin'),
    ]
    
    # Remove default Django username field - we use email instead
    username = None
    
    # Email is the unique identifier for login
    email = models.EmailField(unique=True, help_text="User's email address for authentication")
    
    # User's role - Platform Owner (system admin) or Org Admin (organization manager)
    role = models.CharField(
        max_length=20,
        choices=ROLE_CHOICES,
        default=ORG_ADMIN,
        help_text="User's role in the system"
    )
    
    # Organization this user belongs to (null if Platform Owner)
    organization = models.ForeignKey(
        Organization,
        on_delete=models.CASCADE,
        related_name='users',
        null=True,
        blank=True,
        help_text="Organization this user belongs to (null for Platform Owners)"
    )
    
    is_verified = models.BooleanField(
        default=False,
        help_text="Whether the user's email has been verified"
    )
    verification_code = models.CharField(
        max_length=6,
        blank=True,
        null=True,
        help_text="6-digit verification code sent to user's email"
    )
    code_expires_at = models.DateTimeField(
        blank=True,
        null=True,
        help_text="Expiration timestamp for verification code (5 minutes from generation)"
    )

    USERNAME_FIELD = 'email'
    REQUIRED_FIELDS = []

    objects = UserManager()

    def __str__(self):
        return self.email
    
    def generate_verification_code(self):
        import random
        
        self.verification_code = str(random.randint(100000, 999999))
        self.code_expires_at = timezone.now() + timezone.timedelta(minutes=5)
        self.save()
        return self.verification_code
    
    def verify_code(self, code):
        if self.verification_code != code:
            return False
        if timezone.now() > self.code_expires_at:
            return False
        return True
    
    def is_platform_owner(self):
        return self.role == self.PLATFORM_OWNER
    
    def is_org_admin(self):
        return self.role == self.ORG_ADMIN
    
    def has_organization_access(self, organization):
        if self.is_platform_owner():
            return True
        return self.organization == organization
    
    def clean(self):
        super().clean()
        
        if self.role == self.PLATFORM_OWNER and self.organization is not None:
            raise ValidationError({
                'organization': 'Platform Owners cannot belong to an organization.'
            })
        
        if self.role == self.ORG_ADMIN and self.organization is None:
            raise ValidationError({
                'organization': 'Organization Admins must belong to an organization.'
            })
    
    def save(self, *args, **kwargs):
        # Skip validation for superusers to allow flexible creation
        if not (self.is_superuser and self.is_staff):
            self.clean()
        super().save(*args, **kwargs)
