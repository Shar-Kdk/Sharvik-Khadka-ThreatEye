import React, { useState, useEffect } from 'react';

const SubscriptionPlans = () => {
    const [plans, setPlans] = useState([]);
    const [loading, setLoading] = useState(true);
    const API_BASE_URL = import.meta.env.VITE_API_URL || 'http://localhost:8000';

    useEffect(() => {
        fetchPlans();
    }, []);

    const getToken = () => {
        // Assuming token is stored in localStorage or you can pass it via props/context
        // Based on App.jsx, the token state is at top level, but for now we'll check localStorage
        // If your app handles token storage differently (e.g. only in state), we might need to adjust App.jsx
        return localStorage.getItem('token');
    };

    const fetchPlans = async () => {
        try {
            const token = getToken();
            const headers = token ? { 'Authorization': `Bearer ${token}` } : {};

            const response = await fetch(`${API_BASE_URL}/subscriptions/plans/`, {
                headers: headers
            });

            if (response.ok) {
                const data = await response.json();
                setPlans(data);
            } else {
                console.error('Failed to fetch plans');
            }
        } catch (error) {
            console.error('Error fetching plans:', error);
        } finally {
            setLoading(false);
        }
    };

    const handleSubscribe = async (planId) => {
        try {
            const token = getToken();
            if (!token) {
                alert("Please login to subscribe");
                return;
            }

            const response = await fetch(`${API_BASE_URL}/subscriptions/initiate/`, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'Authorization': `Bearer ${token}`
                },
                body: JSON.stringify({ plan_id: planId })
            });

            const data = await response.json();

            if (response.ok && data.payment_url) {
                window.location.href = data.payment_url;
            } else {
                console.error("Payment Error:", data);
                alert(`Payment Failed: ${data.error}\n\nDetails: ${data.details || 'Check console for more info'}`);
            }
        } catch (error) {
            console.error('Error initiating payment:', error);
            alert('Payment initiation failed. Network error?');
        }
    };

    if (loading) return (
        <div className="min-h-screen bg-gray-900 text-white flex items-center justify-center">
            <p className="text-xl">Loading plans...</p>
        </div>
    );

    return (
        <div className="min-h-screen bg-gray-900 text-white font-sans">
            {/* Navbar */}
            <nav className="bg-gray-800 p-4 mb-8 border-b border-gray-700">
                <div className="container mx-auto flex justify-between items-center">
                    <h1 className="text-xl font-bold">ThreatEye Subscriptions</h1>
                    <a href="/dashboard" className="text-gray-300 hover:text-white transition-colors text-sm">
                        &larr; Back to Dashboard
                    </a>
                </div>
            </nav>

            <div className="container mx-auto px-4 pb-12">
                <div className="text-center mb-10">
                    <h1 className="text-3xl font-bold mb-4">Subscription Plans</h1>
                    <p className="text-gray-400 max-w-xl mx-auto">
                        Choose the plan that suits your security needs.
                    </p>
                </div>

                <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-2 gap-6 max-w-4xl mx-auto">
                    {plans.map((plan) => (
                        <div key={plan.id} className="bg-gray-800 border border-gray-700 rounded-lg p-6 flex flex-col">
                            <h2 className="text-2xl font-bold mb-2">{plan.display_name}</h2>
                            <div className="mb-6">
                                <span className="text-4xl font-bold text-white">Rs. {plan.price}</span>
                                <span className="text-gray-500 ml-1">/ month</span>
                            </div>

                            <div className="flex-grow mb-8 text-gray-300 space-y-3">
                                <p className="flex items-center">
                                    <span className="text-blue-500 mr-2">•</span>
                                    {plan.max_users} Users Allowed
                                </p>
                                <p className="flex items-center">
                                    <span className={plan.email_alerts_enabled ? "text-blue-500 mr-2" : "text-gray-500 mr-2"}>•</span>
                                    {plan.email_alerts_enabled ? "Email Alerts Included" : "No Email Alerts"}
                                </p>
                                <p className="flex items-center">
                                    <span className="text-blue-500 mr-2">•</span>
                                    Standard Support
                                </p>
                            </div>

                            <button
                                className="w-full bg-blue-600 hover:bg-blue-700 text-white font-semibold py-3 px-4 rounded transition-colors duration-200"
                                onClick={() => handleSubscribe(plan.id)}
                            >
                                Subscribe Monthly
                            </button>
                        </div>
                    ))}
                </div>
            </div>
        </div>
    );
};

export default SubscriptionPlans;