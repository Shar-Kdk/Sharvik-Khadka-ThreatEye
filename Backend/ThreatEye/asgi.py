"""ASGI config for ThreatEye project."""

import os
import django

os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'ThreatEye.settings')

# Initialize Django first
django.setup()

from django.core.asgi import get_asgi_application

application = get_asgi_application()
