import requests
import json
from django.shortcuts import redirect
from django.urls import reverse
from django.conf import settings
from django.utils import timezone
from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework import status
from .models import Subscription, SubscriptionPlan

@api_view(['GET'])
@permission_classes([IsAuthenticated])
def get_plans(request):
    plans = SubscriptionPlan.objects.all().values('id', 'display_name', 'max_users', 'email_alerts_enabled', 'price')
    return Response(list(plans))


@api_view(['POST'])
@permission_classes([IsAuthenticated])
def initiate_payment(request):
    try:
        # data is already parsed in request.data for DRF views
        plan_id = request.data.get('plan_id')

        # User has a ForeignKey to Organization named 'organization'
        org = request.user.organization

        if not org:
            return Response({'error': 'User does not belong to any organization. Please contact support or create an organization.'}, status=status.HTTP_403_FORBIDDEN)

        try:
            plan = SubscriptionPlan.objects.get(id=plan_id)
        except SubscriptionPlan.DoesNotExist:
             return Response({'error': 'Plan not found'}, status=status.HTTP_404_NOT_FOUND)

        sub, created = Subscription.objects.get_or_create(
            organization=org,
            defaults={'plan': plan, 'status': 'pending'}
        )
        if not created:
            sub.plan = plan
            sub.status = 'pending'
            sub.save()

        amount = int(plan.price * 100) # Khalti expects paisa
        return_url = request.build_absolute_uri(reverse('payment_callback'))
        purchase_order_id = f"Sub-{sub.id}"

        payload = {
            "return_url": return_url,
            "website_url": request.build_absolute_uri('/'),
            "amount": amount,
            "purchase_order_id": purchase_order_id,
            "purchase_order_name": plan.display_name,
            "customer_info": {
                "name": request.user.get_full_name() or request.user.username,
                "email": request.user.email,
                "phone": "9800000001"
            }
        }

        headers = {
            "Authorization": f"Key {settings.KHALTI_SECRET_KEY}",
            "Content-Type": "application/json",
        }

        response = requests.post(
            f"{settings.KHALTI_API_URL}epayment/initiate/",
            json=payload,
            headers=headers,
            timeout=10
        )

        if response.status_code == 200:
            res = response.json()
            sub.khalti_pidx = res.get('pidx')
            sub.save()
            return Response({'payment_url': res['payment_url']})
        else:
            return Response({'error': 'Payment initiation failed', 'details': response.text}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

    except Exception as e:
        return Response({'error': str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


# Callback is usually a standard view because it's hit by the browser/Khalti, not via AJAX with Auth header usually. 
# Khalti redirects the user browser to this URL.
# So this one should remain a standard Django view or handle no-auth.
def payment_callback(request):
    pidx = request.GET.get('pidx')
    status = request.GET.get('status')
    frontend_url = getattr(settings, 'FRONTEND_URL', 'http://localhost:5173')

    if status == "Completed" and pidx:
        try:
            payload = {"pidx": pidx}
            headers = {"Authorization": f"Key {settings.KHALTI_SECRET_KEY}"}

            verify_res = requests.post(
                f"{settings.KHALTI_API_URL}epayment/lookup/",
                json=payload,
                headers=headers,
                timeout=10
            )

            if verify_res.status_code == 200:
                data = verify_res.json()
                if data.get('status') == "Completed":
                    sub = Subscription.objects.filter(khalti_pidx=pidx).first()
                    if sub:
                        sub.status = 'active'
                        sub.start_date = timezone.now()
                        sub.khalti_transaction_id = data.get('transaction_id')
                        sub.save()
                        return redirect(f'{frontend_url}/subscription/success?txn={sub.khalti_transaction_id}')

        except Exception as e:
            return redirect(f'{frontend_url}/subscription/failed?error={str(e)}')

    return redirect(f'{frontend_url}/subscription/failed')


@api_view(['GET'])
@permission_classes([IsAuthenticated])
def subscription_status(request):
    # Platform Owners, Superusers, and ID=1 always have full access (Admin/Dev)
    if request.user.role == 'platform_owner' or request.user.is_superuser or request.user.id == 1:
        return Response({
            'status': 'active',
            'plan': 'Platform Administrator',
            'max_users': 9999,
            'email_alerts_enabled': True,
            'start_date': timezone.now().isoformat(),
            'end_date': None,  # Never expires
        })

    org = getattr(request.user, 'organization', None)
    if not org:
         org = request.user.organization_set.first()
         
    if not org:
        return Response({'error': 'Organization not found'}, status=status.HTTP_403_FORBIDDEN)

    sub = Subscription.objects.filter(organization=org).first()
    if sub:
        return Response({
            'status': sub.status,
            'plan': sub.plan.display_name if sub.plan else None,
            'max_users': sub.plan.max_users if sub.plan else None,
            'email_alerts': sub.plan.email_alerts_enabled if sub.plan else False,
            'start_date': sub.start_date.isoformat() if sub.start_date else None,
            'end_date': sub.end_date.isoformat() if sub.end_date else None,
        })
    return Response({'status': 'none'})