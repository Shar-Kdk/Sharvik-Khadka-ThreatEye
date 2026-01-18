from django.urls import path

from .views import live_alerts

urlpatterns = [
    path('live/', live_alerts, name='live_alerts'),
]
