"""
Subscription Views - Reworked following React-Django-Stripe-Backend pattern.

Flow:
1. GET  /subscriptions/plans/                → List available plans
2. POST /subscriptions/create-payment-intent/ → Create Stripe PaymentIntent (saves Payment as pending)
3. POST /subscriptions/verify-payment/        → Verify intent succeeded, activate org subscription
4. GET  /subscriptions/status/                → Check current subscription status
5. GET  /subscriptions/payment-history/       → List user's payment history
"""

import stripe
import logging
from datetime import timedelta
from django.conf import settings
from django.utils import timezone
from rest_framework.views import APIView
from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import IsAuthenticated
from rest_framework.generics import ListAPIView
from rest_framework.response import Response
from rest_framework import status
from .models import Payment, SubscriptionPlan
from .serializers import PaymentSerializer, SubscriptionPlanSerializer

logger = logging.getLogger(__name__)

# Initialize Stripe
stripe.api_key = settings.STRIPE_SECRET_KEY


def resolve_plan_tier(plan):
    """Resolve a subscription plan into the canonical org tier."""
    return plan.get_tier_key()


def get_latest_completed_org_payment(org):
    """Return the latest completed payment for an organization."""
    if not org:
        return None
    return (
        Payment.objects.filter(
            organization=org,
            status='completed',
            plan__isnull=False,
        )
        .order_by('-created_at')
        .first()
    )


# ===== 1. LIST PLANS =====

@api_view(['GET'])
@permission_classes([IsAuthenticated])
def get_plans(request):
    """
    GET /subscriptions/plans/
    Returns all available subscription plans.
    """
    try:
        plans = SubscriptionPlan.objects.all()
        serializer = SubscriptionPlanSerializer(plans, many=True)
        return Response(serializer.data, status=status.HTTP_200_OK)
    except Exception as e:
        logger.error(f"Error fetching plans: {str(e)}")
        return Response(
            {'error': 'Failed to fetch plans'},
            status=status.HTTP_500_INTERNAL_SERVER_ERROR
        )


# ===== 2. CREATE PAYMENT INTENT (Following reference pattern) =====

class CreatePaymentIntentView(APIView):
    """
    POST /subscriptions/create-payment-intent/
    Request body: { plan_id }

    Following React-Django-Stripe-Backend pattern:
    1. Validate inputs
    2. Create Stripe PaymentIntent
    3. Save Payment record (pending)
    4. Return clientSecret + publishableKey to frontend
    """
    permission_classes = [IsAuthenticated]

    def post(self, request):
        try:
            plan_id = request.data.get('plan_id')
            user_email = request.user.email

            # --- Validate plan_id ---
            if not plan_id:
                return Response(
                    {'error': 'plan_id is required'},
                    status=status.HTTP_400_BAD_REQUEST
                )

            try:
                plan_id = int(plan_id)
            except (ValueError, TypeError):
                return Response(
                    {'error': 'Invalid plan_id format'},
                    status=status.HTTP_400_BAD_REQUEST
                )

            # --- Fetch plan ---
            try:
                plan = SubscriptionPlan.objects.get(id=plan_id)
            except SubscriptionPlan.DoesNotExist:
                available = list(SubscriptionPlan.objects.values_list('id', 'display_name'))
                return Response(
                    {'error': f'Plan not found. Available plans: {available}'},
                    status=status.HTTP_404_NOT_FOUND
                )

            # --- Check if org already has this plan ---
            org = getattr(request.user, 'organization', None)
            if org and org.is_active:
                selected_tier = resolve_plan_tier(plan)
                latest_org_payment = get_latest_completed_org_payment(org)
                if latest_org_payment and latest_org_payment.plan:
                    current_tier = resolve_plan_tier(latest_org_payment.plan)
                else:
                    current_tier = org.subscription_tier

                if selected_tier == current_tier:
                    current_tier_label = 'Basic plan' if current_tier == 'basic' else 'Professional plan'
                    return Response(
                        {'error': f'Your organization is already on the {current_tier_label}.'},
                        status=status.HTTP_400_BAD_REQUEST
                    )

            # --- Prepare amount (convert dollars to cents) ---
            amount = int(plan.price * 100)
            currency = 'usd'

            if amount <= 0:
                return Response(
                    {'error': 'Invalid plan price'},
                    status=status.HTTP_400_BAD_REQUEST
                )

            # --- Create Stripe PaymentIntent ---
            stripe.api_key = settings.STRIPE_SECRET_KEY
            intent = stripe.PaymentIntent.create(
                amount=amount,
                currency=currency,
                metadata={
                    'plan_id': plan.id,
                    'plan_name': plan.get_tier_label(),
                    'user_email': user_email,
                }
            )

            # --- Save Payment record to DB (following reference pattern) ---
            payment_data = {
                'amount': plan.price,
                'currency': currency,
                'stripe_payment_id': intent['id'],
                'user_email': user_email,
                'plan': plan.id,
                'organization': (
                    request.user.organization.id
                    if hasattr(request.user, 'organization') and request.user.organization
                    else None
                ),
                'status': 'pending',
            }

            serializer = PaymentSerializer(data=payment_data)
            if serializer.is_valid():
                serializer.save()

                # Return clientSecret for Stripe.js to confirm payment on frontend
                return Response({
                    'clientSecret': intent['client_secret'],
                    'publishableKey': settings.STRIPE_PUBLISHABLE_KEY,
                    'payment': serializer.data,
                    'planName': plan.get_tier_label(),
                    'planId': plan.id,
                }, status=status.HTTP_201_CREATED)

            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

        except stripe.error.StripeError as e:
            logger.error(f"Stripe error: {str(e)}")
            return Response({'error': str(e)}, status=status.HTTP_400_BAD_REQUEST)
        except Exception as e:
            logger.error(f"Error creating PaymentIntent: {str(e)}", exc_info=True)
            return Response(
                {'error': 'Failed to create payment intent'},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )


# ===== 3. VERIFY PAYMENT & ACTIVATE SUBSCRIPTION =====

class VerifyPaymentView(APIView):
    """
    POST /subscriptions/verify-payment/
    Request body: { payment_intent_id }

    Verifies that Stripe payment succeeded.
    On success: marks Payment as completed AND activates the organization subscription.
    """
    permission_classes = [IsAuthenticated]

    def post(self, request):
        try:
            payment_intent_id = request.data.get('payment_intent_id')

            if not payment_intent_id:
                return Response(
                    {'error': 'payment_intent_id is required'},
                    status=status.HTTP_400_BAD_REQUEST
                )

            # --- Retrieve PaymentIntent from Stripe ---
            stripe.api_key = settings.STRIPE_SECRET_KEY
            intent = stripe.PaymentIntent.retrieve(payment_intent_id)

            if intent.status == 'succeeded':
                # --- Update Payment record ---
                try:
                    payment = Payment.objects.get(stripe_payment_id=payment_intent_id)
                    payment.status = 'completed'
                    payment.save()
                    logger.info(f"Payment {payment.id} completed for {payment.user_email}")

                    # --- ACTIVATE ORGANIZATION SUBSCRIPTION ---
                    if payment.plan and payment.organization:
                        org = payment.organization
                        plan = payment.plan

                        # Map plan to subscription tier using plan capacity instead of raw display name
                        org.subscription_tier = resolve_plan_tier(plan)

                        # Organization.save() auto-sets is_active=True and max_users
                        org.save()
                        logger.info(
                            f"Organization '{org.name}' activated: "
                            f"tier={org.subscription_tier}, max_users={org.max_users}"
                        )

                except Payment.DoesNotExist:
                    logger.warning(f"Payment record not found for intent: {payment_intent_id}")

                return Response({
                    'status': 'success',
                    'paymentStatus': intent.status,
                    'paymentId': payment.id if 'payment' in dir() else None,
                }, status=status.HTTP_200_OK)

            else:
                return Response({
                    'status': 'pending',
                    'paymentStatus': intent.status,
                    'message': 'Payment has not succeeded yet',
                }, status=status.HTTP_400_BAD_REQUEST)

        except stripe.error.StripeError as e:
            logger.error(f"Stripe error verifying payment: {str(e)}")
            return Response({'error': str(e)}, status=status.HTTP_400_BAD_REQUEST)
        except Exception as e:
            logger.error(f"Error verifying payment: {str(e)}", exc_info=True)
            return Response(
                {'error': 'Payment verification failed'},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )


# ===== 4. PAYMENT LIST (admin) =====

class PaymentListView(ListAPIView):
    """
    GET /subscriptions/payments/
    Admin: all payments. Regular user: own payments only.
    """
    permission_classes = [IsAuthenticated]
    serializer_class = PaymentSerializer

    def get_queryset(self):
        if self.request.user.is_staff:
            return Payment.objects.all().order_by('-created_at')
        return Payment.objects.filter(
            user_email=self.request.user.email
        ).order_by('-created_at')


# ===== 5. PAYMENT HISTORY =====

@api_view(['GET'])
@permission_classes([IsAuthenticated])
def get_payment_history(request):
    """
    GET /subscriptions/payment-history/
    Returns the last 20 payments for the authenticated user.
    """
    try:
        payments = Payment.objects.filter(
            user_email=request.user.email
        ).order_by('-created_at')[:20]
        serializer = PaymentSerializer(payments, many=True)
        return Response(serializer.data, status=status.HTTP_200_OK)
    except Exception as e:
        logger.error(f"Error fetching payment history: {str(e)}")
        return Response(
            {'error': 'Failed to fetch payment history'},
            status=status.HTTP_500_INTERNAL_SERVER_ERROR
        )


# ===== 6. SUBSCRIPTION STATUS =====

@api_view(['GET'])
@permission_classes([IsAuthenticated])
def subscription_status(request):
    """
    GET /subscriptions/status/
    Returns the user's current subscription status based on their organization
    and most recent completed payment.
    """
    try:
        user = request.user
        org = getattr(user, 'organization', None)

        # Get most recent completed payment for the organization first.
        # This keeps plan status consistent across all users in the same org.
        latest_payment = None
        if org:
            latest_payment = get_latest_completed_org_payment(org)

        # Fallback for users without organization-scoped payments.
        if latest_payment is None:
            latest_payment = Payment.objects.filter(
                user_email=user.email,
                status='completed'
            ).order_by('-created_at').first()

        if org and org.is_active and latest_payment and latest_payment.plan:
            plan = latest_payment.plan
            status_text = 'active'
        else:
            status_text = 'inactive'
            plan = None

        # Derive start/end dates from payment date (30-day billing cycle)
        start_date = latest_payment.created_at if latest_payment else None
        end_date = (latest_payment.created_at + timedelta(days=30)) if latest_payment else None

        return Response({
            'status': status_text,
            'plan': plan.get_tier_label() if plan else None,
            'plan_display_name': plan.display_name if plan else None,
            'plan_id': plan.id if plan else None,
            'max_users': plan.max_users if plan else 1,
            'email_alerts': plan.email_alerts_enabled if plan else False,
            'last_payment': latest_payment.created_at.isoformat() if latest_payment else None,
            'start_date': start_date.isoformat() if start_date else None,
            'end_date': end_date.isoformat() if end_date else None,
            'organization': org.name if org else None,
        }, status=status.HTTP_200_OK)

    except Exception as e:
        logger.error(f"Error fetching subscription status: {str(e)}")
        return Response(
            {'error': 'Failed to fetch subscription status'},
            status=status.HTTP_500_INTERNAL_SERVER_ERROR
        )
