#!/usr/bin/env python
import os
import django

os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'ThreatEye.settings')
django.setup()

from authentication.models import User
from authentication.email_utils import send_verification_email

# Get or create test user
try:
    user = User.objects.get(email='sharkdk0@gmail.com')
    print(f"Found user: {user.email}")
except User.DoesNotExist:
    print("User not found!")
    exit(1)

# Send verification email
print(f"Sending verification email to {user.email}...")
result = send_verification_email(user)

if result:
    print(f"✓ Email sent successfully!")
    print(f"Verification code: {user.verification_code}")
    print(f"Expires at: {user.code_expires_at}")
else:
    print("✗ Failed to send email")
