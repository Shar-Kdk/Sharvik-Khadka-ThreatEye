import stripe
from django.conf import settings
from django.utils import timezone
from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework import status
from .models import Subscription, SubscriptionPlan
from authentication.models import Organization, User

stripe.api_key = settings.STRIPE_SECRET_KEY


def _downgrade_organization_if_unsubscribed(org):
    """Keep organization fields consistent when no active subscription exists."""
    if not org:
        return

    if (
        org.subscription_tier != Organization.TIER_NOT_SUBSCRIBED
        or org.is_active
        or org.max_users != 1
    ):
        org.subscription_tier = Organization.TIER_NOT_SUBSCRIBED
        org.is_active = False
        org.max_users = 1
        org.save(update_fields=['subscription_tier', 'is_active', 'max_users'])


def _sync_expired_subscriptions(org=None):
    """Expire overdue subscriptions and reflect the result on organization state."""
    now = timezone.now()
    active_subs = Subscription.objects.filter(status='active', end_date__isnull=False, end_date__lte=now)
    if org:
        active_subs = active_subs.filter(organization=org)

    for sub in active_subs.select_related('organization'):
        sub.status = 'expired'
        sub.save(update_fields=['status', 'updated_at'])
        _downgrade_organization_if_unsubscribed(sub.organization)

    if org and not Subscription.objects.filter(organization=org, status='active').exists():
        _downgrade_organization_if_unsubscribed(org)

@api_view(['GET'])
@permission_classes([IsAuthenticated])
def get_plans(request):
    plans = SubscriptionPlan.objects.all().values('id', 'display_name', 'max_users', 'email_alerts_enabled', 'price')
    return Response(list(plans))

@api_view(['POST'])
@permission_classes([IsAuthenticated])
def initiate_payment(request):
    """Create Stripe PaymentIntent and pending subscription."""
    try:
        plan_id = request.data.get('plan_id')
        user = request.user
        org = user.organization
        if not org:
            return Response({'error': 'User does not belong to any organization.'}, status=status.HTTP_403_FORBIDDEN)

        try:
            plan = SubscriptionPlan.objects.get(id=plan_id)
        except SubscriptionPlan.DoesNotExist:
            return Response({'error': 'Plan not found'}, status=status.HTTP_404_NOT_FOUND)

        amount = int(plan.price * 100)
        
        # Create the PaymentIntent
        try:
            intent = stripe.PaymentIntent.create(
                amount=amount,
                currency='usd',
                metadata={
                    'org_id': org.id,
                    'plan_id': plan.id,
                    'user_email': user.email
                }
            )
        except stripe.error.StripeError as e:
            return Response({'error': f"Stripe Error: {str(e)}"}, status=status.HTTP_400_BAD_REQUEST)
        
        # Create/Update pending subscription
        sub, created = Subscription.objects.get_or_create(
            organization=org,
            defaults={
                'plan': plan,
                'status': 'pending',
                'stripe_payment_intent_id': intent.id
            }
        )
        
        # If subscription exists, update plan and payment intent
        if not created:
            sub.plan = plan
            sub.status = 'pending'
            sub.stripe_payment_intent_id = intent.id
            sub.save()

        return Response({
            'clientSecret': intent.client_secret,
            'publishableKey': settings.STRIPE_PUBLISHABLE_KEY,
            'subscriptionId': sub.id
        })

    except Exception as e:
        return Response({'error': str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

@api_view(['POST'])
@permission_classes([IsAuthenticated])
def verify_payment(request):
    """
    Final check after frontend confirms payment.
    """
    payment_intent_id = request.data.get('payment_intent_id')
    try:
        intent = stripe.PaymentIntent.retrieve(payment_intent_id)
        if intent.status == 'succeeded':
            sub = Subscription.objects.get(stripe_payment_intent_id=payment_intent_id)
            sub.status = 'active'
            sub.start_date = timezone.now()
            # Set end date to 1 month from now for demo
            sub.end_date = timezone.now() + timezone.timedelta(days=30)
            sub.save()

            # Sync Organization tier and capacity
            org = sub.organization
            if org:
                # Map plan display name to organization tier constants
                plan_name_lower = sub.plan.display_name.lower()
                if 'basic' in plan_name_lower:
                    org.subscription_tier = 'basic'
                elif 'professional' in plan_name_lower:
                    org.subscription_tier = 'professional'
                elif 'enterprise' in plan_name_lower:
                    org.subscription_tier = 'professional' # Map enterprise to professional for now or add to choices
                
                org.is_active = True
                org.save() # This also updates max_users via Organization.save()

            return Response({'status': 'success', 'plan': sub.plan.display_name})
        else:
            return Response({'status': 'failed', 'stripe_status': intent.status})
    except Exception as e:
        return Response({'error': str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

@api_view(['GET'])
@permission_classes([IsAuthenticated])
def subscription_status(request):
    if request.user.role == 'platform_owner' or request.user.is_superuser:
        return Response({
            'status': 'active',
            'plan': 'Platform Administrator',
            'max_users': 9999,
            'email_alerts': True,
            'start_date': timezone.now().isoformat(),
            'end_date': None,
        })

    org = getattr(request.user, 'organization', None)
    if not org:
        return Response({'status': 'none', 'error': 'No organization linked'})

    _sync_expired_subscriptions(org=org)

    # Get active subscription, with fallback to most recent subscription
    sub = (
        Subscription.objects.filter(organization=org, status='active')
        .order_by('-created_at')
        .first()
    ) or (
        Subscription.objects.filter(organization=org)
        .order_by('-created_at')
        .first()
    )
    
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

@api_view(['GET'])
@permission_classes([IsAuthenticated])
def get_platform_stats(request):
    if request.user.role != 'platform_owner':
        return Response({'error': 'Unauthorized'}, status=status.HTTP_403_FORBIDDEN)

    _sync_expired_subscriptions()
    
    total_users = User.objects.count()
    total_orgs = Organization.objects.count()
    active_orgs = Organization.objects.filter(is_active=True).count()
    
    # Calculate plan distribution
    plans = SubscriptionPlan.objects.all()
    plan_distribution = []
    for plan in plans:
        count = Subscription.objects.filter(plan=plan, status='active').count()
        plan_distribution.append({
            'name': plan.display_name,
            'count': count
        })
    
    # Add Not Subscribed count
    not_subscribed_count = Organization.objects.filter(is_active=False).count()
    if not_subscribed_count > 0:
        plan_distribution.append({
            'name': 'Not Subscribed',
            'count': not_subscribed_count
        })

    # Detailed org list
    orgs = Organization.objects.all()
    org_list = []
    for org in orgs:
        # Prioritize active subscription
        sub = Subscription.objects.filter(organization=org, status='active').order_by('-created_at').first()
        if not sub:
            sub = Subscription.objects.filter(organization=org).order_by('-created_at').first()
        org_list.append({
            'id': org.id,
            'name': org.name,
            'plan': sub.plan.display_name if sub and sub.plan else 'No License',
            'users': org.users.count(),
            'status': sub.status if sub else 'none',
            'renewal': sub.end_date if sub else 'N/A'
        })

    return Response({
        'total_users': total_users,
        'total_organizations': total_orgs,
        'active_organizations': active_orgs,
        'plan_distribution': plan_distribution,
        'organizations': org_list
    })

@api_view(['GET'])
@permission_classes([IsAuthenticated])
def get_subscription_history(request):
    """
    Returns all subscription records for the user's organization.
    """
    org = getattr(request.user, 'organization', None)
    if not org:
        return Response({'error': 'No organization linked'}, status=status.HTTP_403_FORBIDDEN)

    _sync_expired_subscriptions(org=org)
    
    subscriptions = Subscription.objects.filter(organization=org).order_by('-created_at')
    
    history = []
    for sub in subscriptions:
        history.append({
            'id': sub.id,
            'plan_name': sub.plan.display_name if sub.plan else 'Unknown',
            'status': sub.status,
            'amount': float(sub.plan.price) if sub.plan else 0,
            'start_date': sub.start_date.isoformat() if sub.start_date else None,
            'end_date': sub.end_date.isoformat() if sub.end_date else None,
            'created_at': sub.created_at.isoformat(),
        })
    
    return Response(history)
