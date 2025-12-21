#!/usr/bin/env python
import os
import django

os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'ThreatEye.settings')
django.setup()

from authentication.models import User

# Delete the invalid user
try:
    user = User.objects.get(email='dadad@dad.com')
    user.delete()
    print(f"✓ Deleted user: {user.email}")
except User.DoesNotExist:
    print("User not found")
