#!/usr/bin/env python
import os
import django

os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'ThreatEye.settings')
django.setup()

from authentication.models import User

# Auto-verify all existing superusers
superusers = User.objects.filter(is_superuser=True, is_verified=False)
count = superusers.count()

if count > 0:
    for user in superusers:
        user.is_verified = True
        user.verification_code = None
        user.code_expires_at = None
        user.save()
        print(f"✓ Verified superuser: {user.email}")
    print(f"\n✓ Total {count} superuser(s) verified")
else:
    print("✓ All superusers are already verified")
