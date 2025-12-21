"""Authentication Models

This module defines the custom User model with email-based authentication
and email verification functionality for the ThreatEye system.
"""

from django.contrib.auth.models import AbstractUser, BaseUserManager
from django.db import models
from django.utils import timezone


class UserManager(BaseUserManager):
    """Custom User Manager for email-based authentication
    
    Handles creation of regular users and superusers with email as the primary identifier.
    """
    
    def create_user(self, email, password=None, **extra_fields):
        """Create and save a regular user with email and password
        
        Args:
            email (str): User's email address (required)
            password (str): User's password (will be hashed)
            **extra_fields: Additional user model fields
            
        Returns:
            User: Created user instance
            
        Raises:
            ValueError: If email is not provided
        """
        if not email:
            raise ValueError("Email is required")

        # Normalize email (lowercase domain, etc.)
        email = self.normalize_email(email)
        user = self.model(email=email, **extra_fields)
        
        # Hash password using PBKDF2 (260,000 iterations)
        user.set_password(password)
        user.save(using=self._db)
        return user

    def create_superuser(self, email, password=None, **extra_fields):
        """Create and save a superuser with elevated permissions
        
        Superusers are automatically verified and don't need email verification.
        
        Args:
            email (str): Superuser's email address (required)
            password (str): Superuser's password (will be hashed)
            **extra_fields: Additional user model fields
            
        Returns:
            User: Created superuser instance
            
        Raises:
            ValueError: If is_staff or is_superuser is not True
        """
        # Set default superuser flags
        extra_fields.setdefault('is_staff', True)
        extra_fields.setdefault('is_superuser', True)
        extra_fields.setdefault('is_active', True)
        extra_fields.setdefault('is_verified', True)  # Superusers bypass email verification

        # Validate required flags
        if extra_fields.get('is_staff') is not True:
            raise ValueError('Superuser must have is_staff=True')
        if extra_fields.get('is_superuser') is not True:
            raise ValueError('Superuser must have is_superuser=True')

        return self.create_user(email, password, **extra_fields)


class User(AbstractUser):
    """Custom User model with email-based authentication and verification
    
    Replaces default Django User model to use email instead of username.
    Includes email verification system with 6-digit codes that expire after 5 minutes.
    
    Attributes:
        email (str): User's email address (unique, used for authentication)
        is_verified (bool): Whether user's email has been verified
        verification_code (str): 6-digit code sent to user's email
        code_expires_at (datetime): When the verification code expires
    """
    
    # Remove username field (use email instead)
    username = None
    
    # Primary authentication field
    email = models.EmailField(unique=True, help_text="User's email address for authentication")
    
    # Email verification fields
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

    # Configure email as the username field for authentication
    USERNAME_FIELD = 'email'
    REQUIRED_FIELDS = []  # No additional required fields for createsuperuser

    # Use custom manager
    objects = UserManager()

    def __str__(self):
        """String representation of user (email address)"""
        return self.email
    
    def generate_verification_code(self):
        """Generate a new 6-digit verification code
        
        Creates a random 6-digit code and sets expiry time to 5 minutes from now.
        Automatically saves the user instance.
        
        Returns:
            str: The generated 6-digit verification code
            
        Example:
            >>> user.generate_verification_code()
            '123456'
        """
        import random
        
        # Generate random 6-digit code
        self.verification_code = str(random.randint(100000, 999999))
        
        # Set expiry to 5 minutes from now
        self.code_expires_at = timezone.now() + timezone.timedelta(minutes=5)
        
        # Save to database
        self.save()
        return self.verification_code
    
    def verify_code(self, code):
        """Verify if the provided code matches and is not expired
        
        Args:
            code (str): The verification code to check
            
        Returns:
            bool: True if code is valid and not expired, False otherwise
            
        Example:
            >>> user.verify_code('123456')
            True  # If code matches and hasn't expired
        """
        # Check if code matches
        if self.verification_code != code:
            return False
        
        # Check if code has expired
        if timezone.now() > self.code_expires_at:
            return False
        
        return True
