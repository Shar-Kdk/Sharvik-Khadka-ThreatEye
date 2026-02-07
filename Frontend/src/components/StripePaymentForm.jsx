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
                color: '#ffffff',
                '::placeholder': {
                    color: '#6b7280',
                },
                backgroundColor: 'transparent',
            },
            invalid: {
                color: '#ef4444',
            },
        },
    };

    return (
        <div className="space-y-8">
            <form onSubmit={handleSubmit} className="space-y-8">
                <div className="space-y-6">
                    {/* Card Holder */}
                    <div>
                        <label className="block text-xs font-bold text-blue-500 mb-2">Card Holder</label>
                        <input
                            type="text"
                            value={cardHolder}
                            onChange={(e) => setCardHolder(e.target.value)}
                            placeholder="John Doe"
                            className="w-full bg-transparent border-b border-[#30363d] py-3 text-white placeholder-gray-600 focus:outline-none focus:border-blue-500 transition-colors"
                            required
                        />
                    </div>

                    {/* Card Number */}
                    <div>
                        <label className="block text-xs font-bold text-blue-500 mb-2">Credit Card Number</label>
                        <div className="border-b border-[#30363d] py-3 focus-within:border-blue-500 transition-colors">
                            <CardNumberElement options={elementOptions} />
                        </div>
                    </div>

                    {/* Expiry and CVC */}
                    <div className="grid grid-cols-2 gap-6">
                        <div>
                            <label className="block text-xs font-bold text-blue-500 mb-2">Expiration Date</label>
                            <div className="border-b border-[#30363d] py-3 focus-within:border-blue-500 transition-colors">
                                <CardExpiryElement options={elementOptions} />
                            </div>
                        </div>
                        <div>
                            <label className="block text-xs font-bold text-blue-500 mb-2">CVV</label>
                            <div className="border-b border-[#30363d] py-3 focus-within:border-blue-500 transition-colors">
                                <CardCvcElement options={elementOptions} />
                            </div>
                        </div>
                    </div>
                </div>

                {error && (
                    <div className="text-red-500 text-xs text-center font-medium animate-pulse">
                        {error}
                    </div>
                )}

                <button
                    type="submit"
                    disabled={!stripe || processing}
                    className="w-full bg-blue-600 hover:bg-blue-500 disabled:bg-gray-800 disabled:text-gray-600 text-white font-black py-4 rounded-xl transition-all shadow-lg hover:shadow-blue-500/20 uppercase tracking-widest text-sm"
                >
                    {processing ? "Securing Transaction..." : `Pay $${amount}`}
                </button>
            </form>
        </div>
    );
};

export default StripePaymentForm;
