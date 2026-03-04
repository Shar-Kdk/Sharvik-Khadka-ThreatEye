import React, { useState } from 'react';
import { useStripe, useElements, CardNumberElement, CardExpiryElement, CardCvcElement } from '@stripe/react-stripe-js';

/**
 * StripePaymentForm component - Credit card payment form
 * Takes card details and confirms payment with Stripe
 * Used for subscription plan purchases
 */
const StripePaymentForm = ({ clientSecret, onPaymentSuccess, amount }) => {
    const stripe = useStripe();
    const elements = useElements();
    const [cardHolder, setCardHolder] = useState('');
    const [error, setError] = useState(null);
    const [processing, setProcessing] = useState(false);

    const handleSubmit = async (event) => {
        event.preventDefault();
        if (!stripe || !elements) return;

        setProcessing(true);
        const cardNumberElement = elements.getElement(CardNumberElement);

        const { error, paymentIntent } = await stripe.confirmCardPayment(clientSecret, {
            payment_method: {
                card: cardNumberElement,
                billing_details: {
                    name: cardHolder,
                },
            },
        });

        if (error) {
            setError(error.message);
            setProcessing(false);
        } else {
            console.log('[PaymentIntent]', paymentIntent);
            onPaymentSuccess(paymentIntent.id);
        }
    };

    const elementOptions = {
        style: {
            base: {
                fontSize: '16px',
                color: '#111827',
                '::placeholder': {
                    color: '#9ca3af',
                },
                backgroundColor: 'transparent',
            },
            invalid: {
                color: '#dc2626',
            },
        },
    };

    return (
        <div className="space-y-6">
            <form onSubmit={handleSubmit} className="space-y-6">
                {/* Card Holder */}
                <div>
                    <label className="block text-gray-300 mb-2">Card Holder</label>
                    <input
                        type="text"
                        autoComplete="off"
                        value={cardHolder}
                        onChange={(e) => setCardHolder(e.target.value)}
                        placeholder="John Doe"
                        className="w-full px-4 py-2 bg-white text-gray-900 border border-gray-300 rounded focus:outline-none focus:ring-2 focus:ring-blue-500"
                        required
                    />
                </div>

                {/* Card Number */}
                <div>
                    <label className="block text-gray-300 mb-2">Credit Card Number</label>
                    <div className="px-4 py-2 bg-white border border-gray-300 rounded focus-within:ring-2 focus-within:ring-blue-500">
                        <CardNumberElement options={elementOptions} />
                    </div>
                </div>

                {/* Expiry and CVC */}
                <div className="grid grid-cols-2 gap-4">
                    <div>
                        <label className="block text-gray-300 mb-2">Expiration Date</label>
                        <div className="px-4 py-2 bg-white border border-gray-300 rounded focus-within:ring-2 focus-within:ring-blue-500">
                            <CardExpiryElement options={elementOptions} />
                        </div>
                    </div>
                    <div>
                        <label className="block text-gray-300 mb-2">CVV</label>
                        <div className="px-4 py-2 bg-white border border-gray-300 rounded focus-within:ring-2 focus-within:ring-blue-500">
                            <CardCvcElement options={elementOptions} />
                        </div>
                    </div>
                </div>

                {error && (
                    <div className="bg-red-500 text-white p-3 rounded text-center">
                        {error}
                    </div>
                )}

                <button
                    type="submit"
                    disabled={!stripe || processing}
                    className="w-full bg-blue-600 hover:bg-blue-700 disabled:bg-gray-600 disabled:text-gray-400 text-white font-bold py-2 px-4 rounded focus:outline-none focus:ring-2 focus:ring-blue-500 transition-colors"
                >
                    {processing ? "Securing Transaction..." : `Pay $${amount}`}
                </button>
            </form>
        </div>
    );
};

export default StripePaymentForm;
