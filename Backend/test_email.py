#!/usr/bin/env python
import os
import django

os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'ThreatEye.settings')
django.setup()

from django.core.mail import send_mail
from django.conf import settings

print(f"EMAIL_HOST: {settings.EMAIL_HOST}")
print(f"EMAIL_PORT: {settings.EMAIL_PORT}")
print(f"EMAIL_HOST_USER: {settings.EMAIL_HOST_USER}")
print(f"EMAIL_HOST_PASSWORD: {'*' * 10}... (hidden)")
print()

try:
    result = send_mail(
        'Test Email from ThreatEye',
        'This is a test email to verify Gmail SMTP is working.',
        settings.DEFAULT_FROM_EMAIL,
        ['sharkdk0@gmail.com'],
        fail_silently=False,
    )
    print(f'✓ Email sent successfully! Result: {result}')
except Exception as e:
    print(f'✗ Error sending email: {str(e)}')
    import traceback
    traceback.print_exc()
