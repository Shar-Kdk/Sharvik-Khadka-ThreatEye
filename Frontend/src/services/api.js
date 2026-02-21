/**
 * API service - All backend API calls for ThreatEye frontend
 * Handles authentication, alerts, subscriptions, and statistics
 */

const BASE_URL = (import.meta.env.VITE_API_URL || 'http://localhost:8000').replace(/\/$/, '');
const API_URL = `${BASE_URL}/api`;

function extractErrorMessage(data) {
  // Extract error from API response
  if (data.email?.[0]) return data.email[0];
  if (data.password?.[0]) return data.password[0];
  if (data.non_field_errors?.[0]) return data.non_field_errors[0];
  return 'An error occurred';
}

// Login with email and password, returns user data and JWT token
export const login = async (email, password) => {
  const response = await fetch(`${API_URL}/auth/login/`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
    },
    body: JSON.stringify({ email, password }),
  });

  const data = await response.json();

  if (!response.ok) {
    throw new Error(extractErrorMessage(data) || 'Login failed');
  }

  return data;
};

// Get currently logged-in user's profile
export const getProfile = async (token) => {
  const response = await fetch(`${API_URL}/auth/profile/`, {
    headers: {
      'Authorization': `Bearer ${token}`,
    },
  });

  if (!response.ok) {
    throw new Error('Failed to fetch profile');
  }

  return response.json();
};

// ===== SUBSCRIPTION API (Following React-Django-Stripe-Backend pattern) =====

// Get available subscription plans
export const getSubscriptionPlans = async (token) => {
  const response = await fetch(`${BASE_URL}/subscriptions/plans/`, {
    headers: token ? { 'Authorization': `Bearer ${token}` } : {},
  });

  if (!response.ok) {
    throw new Error('Failed to fetch plans');
  }

  return response.json();
};

// Create a Stripe PaymentIntent for a selected plan
// Returns: { clientSecret, publishableKey, payment, planName, planId }
export const createPaymentIntent = async (token, planId) => {
  const response = await fetch(`${BASE_URL}/subscriptions/create-payment-intent/`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'Authorization': `Bearer ${token}`,
    },
    body: JSON.stringify({ plan_id: planId }),
  });

  const data = await response.json();

  if (!response.ok) {
    throw new Error(data.error || 'Failed to create payment intent');
  }

  return data;
};

// Verify a Stripe PaymentIntent succeeded and activate subscription
export const verifyPayment = async (token, paymentIntentId) => {
  const response = await fetch(`${BASE_URL}/subscriptions/verify-payment/`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'Authorization': `Bearer ${token}`,
    },
    body: JSON.stringify({ payment_intent_id: paymentIntentId }),
  });

  const data = await response.json();

  if (!response.ok) {
    throw new Error(data.error || 'Payment verification failed');
  }

  return data;
};

// Get subscription status for the current user
export const getSubscriptionStatus = async (token) => {
  const response = await fetch(`${BASE_URL}/subscriptions/status/`, {
    headers: {
      'Authorization': `Bearer ${token}`,
    },
  });

  if (!response.ok) {
    throw new Error('Failed to fetch subscription status');
  }

  return response.json();
};

// Get user's payment history (last 20 payments)
export const getPaymentHistory = async (token) => {
  const response = await fetch(`${BASE_URL}/subscriptions/payment-history/`, {
    headers: {
      'Authorization': `Bearer ${token}`,
    },
  });

  if (!response.ok) {
    throw new Error('Failed to fetch payment history');
  }

  return response.json();
};

// ===== ALERTS & ANALYTICS API =====

// Get real-time security alerts from Snort IDS
export const getLiveAlerts = async (token, limit = 100, signal) => {
  const response = await fetch(`${BASE_URL}/api/alerts/live/?limit=${limit}`, {
    signal,
    headers: {
      'Authorization': `Bearer ${token}`,
    },
  });

  if (!response.ok) {
    throw new Error('Failed to fetch live alerts');
  }

  return response.json();
};

// Get count of alerts by threat level (safe, medium, high) for chart
export const getThreatLevelDistribution = async (token, signal) => {
  const response = await fetch(`${API_URL}/threat-level-distribution/`, {
    signal,
    headers: {
      Authorization: `Bearer ${token}`,
    },
  });

  if (!response.ok) {
    throw new Error('Failed to fetch threat level distribution');
  }

  return response.json();
};

// Get distinct SIDs, source IPs, and destination IPs for filter dropdowns
export const getFilterOptions = async (token) => {
  const response = await fetch(`${BASE_URL}/api/alerts/filter-options/`, {
    headers: {
      'Authorization': `Bearer ${token}`,
    },
  });

  if (!response.ok) {
    throw new Error('Failed to fetch filter options');
  }

  return response.json();
};

// Get top 5 most common attack types
export const getTopAttacks = async (token, signal) => {
  const response = await fetch(`${API_URL}/top-attacks/`, {
    signal,
    headers: {
      Authorization: `Bearer ${token}`,
    },
  });

  if (!response.ok) {
    throw new Error('Failed to fetch top attacks');
  }

  return response.json();
};

// Get alerts grouped by time for timeline chart
export const getAlertsTimeline = async (token, signal) => {
  const response = await fetch(`${API_URL}/alerts-timeline/`, {
    signal,
    headers: {
      Authorization: `Bearer ${token}`,
    },
  });

  if (!response.ok) {
    throw new Error('Failed to fetch alerts timeline');
  }

  return response.json();
};

// Get network protocol distribution (TCP, UDP, ICMP usage percentages)
export const getProtocolStatistics = async (token, signal) => {
  const response = await fetch(`${API_URL}/protocol-statistics/`, {
    signal,
    headers: {
      Authorization: `Bearer ${token}`,
    },
  });

  if (!response.ok) {
    throw new Error('Failed to fetch protocol statistics');
  }

  return response.json();
};

// Get top 5 most suspicious source IPs by alert frequency
export const getTopSuspiciousIPs = async (token, signal) => {
  const response = await fetch(`${API_URL}/top-suspicious-ips/`, {
    signal,
    headers: {
      Authorization: `Bearer ${token}`,
    },
  });

  if (!response.ok) {
    throw new Error('Failed to fetch suspicious IPs');
  }

  return response.json();
};

// Get dashboard summary with all key metrics
export const getDashboardSummary = async (token, signal) => {
  const response = await fetch(`${API_URL}/alerts/dashboard-summary/`, {
    signal,
    headers: {
      Authorization: `Bearer ${token}`,
    },
  });

  if (!response.ok) {
    throw new Error('Failed to fetch dashboard summary');
  }

  return response.json();
};
