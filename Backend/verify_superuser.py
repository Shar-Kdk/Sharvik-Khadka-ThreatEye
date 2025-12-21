#!/usr/bin/env python
import os
import django

os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'ThreatEye.settings')
django.setup()

from authentication.models import User

# Update superuser to verified
try:
    user = User.objects.get(email='sharvikhadka@gmail.com')
    if user.is_superuser:
        user.is_verified = True
        user.verification_code = None
        user.code_expires_at = None
        user.save()
        print(f"✓ Superuser {user.email} marked as verified")
        print(f"  - is_verified: {user.is_verified}")
        print(f"  - verification_code: {user.verification_code}")
    else:
        print(f"User {user.email} is not a superuser")
except User.DoesNotExist:
    print("Superuser not found!")
