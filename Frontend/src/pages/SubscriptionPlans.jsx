import React, { useState, useEffect } from 'react';
import { loadStripe } from '@stripe/stripe-js';
import { Elements } from '@stripe/react-stripe-js';
import StripePaymentForm from '../components/StripePaymentForm';
import { useNavigate } from 'react-router-dom';

const SubscriptionPlans = ({ token }) => {
    const [plans, setPlans] = useState([]);
    const [loading, setLoading] = useState(true);
    const [error, setError] = useState('');
    const [selectError, setSelectError] = useState('');
    const [selectedPlan, setSelectedPlan] = useState(null);
    const [clientSecret, setClientSecret] = useState('');
    const [stripePromise, setStripePromise] = useState(null);
    const API_BASE_URL = import.meta.env.VITE_API_URL || 'http://localhost:8000';
    const navigate = useNavigate();

    useEffect(() => {
        fetchPlans();
    }, []);

    const fetchPlans = async () => {
        const controller = new AbortController();
        const timeoutId = setTimeout(() => controller.abort(), 8000);

        try {
            setError('');
            const headers = token ? { 'Authorization': `Bearer ${token}` } : {};
            const response = await fetch(`${API_BASE_URL}/subscriptions/plans/`, {
                headers,
                signal: controller.signal,
            });

            if (!response.ok) {
                const text = await response.text();
                throw new Error(text || `Failed to fetch plans (${response.status})`);
            }

            if (response.ok) {
                const data = await response.json();
                setPlans(data);
            }
        } catch (error) {
            console.error('Error fetching plans:', error);
            if (error.name === 'AbortError') {
                setError('Request timed out while loading plans. Please retry.');
            } else {
                setError('Unable to load plans right now. Please retry.');
            }
        } finally {
            clearTimeout(timeoutId);
            setLoading(false);
        }
    };

    const handlePlanSelect = async (plan) => {
        setSelectError('');
        try {
            if (!token) {
                setSelectError("Please login to subscribe");
                return;
            }

            const controller = new AbortController();
            const timeoutId = setTimeout(() => controller.abort(), 20000);
            setLoading(true);

            const response = await fetch(`${API_BASE_URL}/subscriptions/initiate/`, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'Authorization': `Bearer ${token}`
                },
                body: JSON.stringify({ plan_id: plan.id }),
                signal: controller.signal,
            });

            clearTimeout(timeoutId);
            const data = await response.json();

            if (response.ok) {
                setStripePromise(loadStripe(data.publishableKey));
                setClientSecret(data.clientSecret);
                setSelectedPlan(plan);
            } else {
                const errorMessage = data.error || data.detail || 'Failed to initiate payment';
                setSelectError(errorMessage);
            }
        } catch (error) {
            console.error('Error initiating payment:', error);
            if (error.name === 'AbortError') {
                setSelectError('Payment initiation timed out. Please try again.');
            } else {
                setSelectError('Failed to contact payment server. Please check your connection and try again.');
            }
        } finally {
            setLoading(false);
        }
    };

    const handlePaymentSuccess = async (paymentIntentId) => {
        try {
            setLoading(true);
            const response = await fetch(`${API_BASE_URL}/subscriptions/verify/`, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'Authorization': `Bearer ${token}`
                },
                body: JSON.stringify({ payment_intent_id: paymentIntentId })
            });

            if (response.ok) {
                navigate('/subscription/success');
            } else {
                navigate('/subscription/failed');
            }
        } catch (error) {
            console.error('Verification failed:', error);
            navigate('/subscription/failed');
        }
    };

    if (loading && !selectedPlan) {
        return (
            <div className="min-h-screen bg-[#010409] text-gray-400 flex items-center justify-center">
                <p>Loading plans...</p>
            </div>
        );
    }

    return (
        <div className="min-h-screen bg-[#010409] text-gray-200 p-6">
            <div className="max-w-4xl mx-auto">
                <div className="flex justify-between items-center mb-12">
                    <h1 className="text-2xl font-bold text-white">ThreatEye Subscription</h1>
                    <button
                        onClick={() => navigate('/dashboard')}
                        className="text-sm text-gray-400 hover:text-white"
                    >
                        Back to Dashboard
                    </button>
                </div>

                {!selectedPlan ? (
                    <>
                        {error && (
                            <div className="bg-red-900/30 border border-red-500/40 text-red-200 rounded-md p-4 mb-6 flex items-center justify-between gap-3">
                                <span>{error}</span>
                                <button
                                    onClick={() => {
                                        setLoading(true);
                                        fetchPlans();
                                    }}
                                    className="px-3 py-1.5 rounded-md bg-red-600 hover:bg-red-500 text-white text-sm"
                                >
                                    Retry
                                </button>
                            </div>
                        )}

                        {selectError && (
                            <div className="bg-red-900/30 border border-red-500/40 text-red-200 rounded-md p-4 mb-6">
                                <p className="font-semibold mb-2">Unable to select plan</p>
                                <p className="text-sm mb-3">{selectError}</p>
                                <button
                                    onClick={() => setSelectError('')}
                                    className="px-3 py-1.5 rounded-md bg-red-600 hover:bg-red-500 text-white text-sm"
                                >
                                    Dismiss
                                </button>
                            </div>
                        )}

                        {plans.length === 0 ? (
                            <div className="text-center py-12">
                                <p className="text-gray-400 mb-4">No subscription plans available at the moment.</p>
                                <button
                                    onClick={() => navigate('/dashboard')}
                                    className="text-blue-500 hover:text-blue-400"
                                >
                                    Return to Dashboard
                                </button>
                            </div>
                        ) : (
                            <div className="grid grid-cols-1 md:grid-cols-2 gap-8">
                                {plans.map((plan) => (
                                    <div key={plan.id} className="bg-[#0d1117] border border-[#30363d] rounded-lg p-8 flex flex-col">
                                        <h2 className="text-xl font-bold text-white mb-2">{plan.display_name}</h2>
                                        <p className="text-3xl font-bold text-white mb-6">${plan.price}<span className="text-sm text-gray-500 font-normal"> / mo</span></p>

                                        <ul className="space-y-4 mb-8 flex-grow">
                                            <li className="flex items-center text-sm text-gray-300">
                                                <span className="text-blue-500 mr-2">✓</span> {plan.max_users} Users
                                            </li>
                                            <li className="flex items-center text-sm text-gray-300">
                                                <span className="text-blue-500 mr-2">✓</span> {plan.email_alerts_enabled ? "Email Alerts" : "Dashboard Only"}
                                            </li>
                                        </ul>

                                        <button
                                            onClick={() => handlePlanSelect(plan)}
                                            className="w-full bg-blue-600 hover:bg-blue-500 text-white font-bold py-3 rounded-md transition-colors"
                                        >
                                            Select Plan
                                        </button>
                                    </div>
                                ))}
                            </div>
                        )}
                    </>
                ) : (
                    <div className="max-w-md mx-auto">
                        <button
                            onClick={() => setSelectedPlan(null)}
                            className="text-sm text-gray-500 hover:text-white mb-6"
                        >
                            &larr; Different Plan
                        </button>

                        <div className="bg-[#0d1117] border border-[#30363d] rounded-lg p-8">
                            <h2 className="text-xl font-bold text-white mb-1">Payment Details</h2>
                            <p className="text-sm text-gray-400 mb-8">Subscribing to {selectedPlan.display_name}</p>

                            {stripePromise && clientSecret && (
                                <Elements stripe={stripePromise} options={{ clientSecret }}>
                                    <StripePaymentForm
                                        clientSecret={clientSecret}
                                        onPaymentSuccess={handlePaymentSuccess}
                                        planName={selectedPlan.display_name}
                                        amount={selectedPlan.price}
                                    />
                                </Elements>
                            )}
                        </div>
                    </div>
                )}
            </div>
        </div>
    );
};

export default SubscriptionPlans;