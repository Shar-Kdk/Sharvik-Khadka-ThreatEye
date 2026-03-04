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
export const getLiveAlerts = async (token, limit = 100, signal, filters = {}, offset = 0) => {
  const params = new URLSearchParams({ limit, offset });
  
  if (filters.threat_level) params.append('threat_level', filters.threat_level);
  if (filters.protocol) params.append('protocol', filters.protocol);
  if (filters.sid) params.append('sid', filters.sid);
  if (filters.src_ip) params.append('src_ip', filters.src_ip);
  if (filters.dest_ip) params.append('dest_ip', filters.dest_ip);
  if (filters.date_from) params.append('date_from', filters.date_from);
  if (filters.date_to) params.append('date_to', filters.date_to);
  if (filters.search) params.append('search', filters.search);
  
  const response = await fetch(`${BASE_URL}/api/alerts/live/?${params.toString()}`, {
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

// ===== EXPORT API =====

// Helper function to build query string from filters
function buildFilterQueryString(filters = {}) {
  const params = new URLSearchParams();
  
  if (filters.threat_level) params.append('threat_level', filters.threat_level);
  if (filters.protocol) params.append('protocol', filters.protocol);
  if (filters.sid) params.append('sid', filters.sid);
  if (filters.src_ip) params.append('src_ip', filters.src_ip);
  if (filters.dest_ip) params.append('dest_ip', filters.dest_ip);
  if (filters.date_from) params.append('date_from', filters.date_from);
  if (filters.date_to) params.append('date_to', filters.date_to);
  if (filters.search) params.append('search', filters.search);
  if (filters.limit) params.append('limit', filters.limit);
  
  return params.toString();
}

function buildPdfExportFilename(filters = {}) {
  const normalize = (value) => {
    const trimmed = String(value || '').trim();
    if (!trimmed) return 'all-dates';
    return trimmed.includes('T') ? trimmed.split('T', 1)[0] : trimmed;
  };

  return `alert log ${normalize(filters.date_from)} - ${normalize(filters.date_to)}.pdf`;
}

// Export alerts as PDF (max 10k rows)
export const exportAlertsPDF = async (token, filters = {}) => {
  try {
    const queryString = buildFilterQueryString({ ...filters, limit: 10000 });
    const url = `${BASE_URL}/api/alerts/export/pdf/?${queryString}`;
    
    console.log('[exportAlertsPDF] URL:', url);
    
    const response = await fetch(url, {
      headers: {
        'Authorization': `Bearer ${token}`,
      },
    });

    if (!response.ok) {
      const errorText = await response.text();
      console.error('[exportAlertsPDF] Error response:', response.status, errorText);
      throw new Error(`PDF export failed: ${response.status} ${errorText.substring(0, 100)}`);
    }

    // Get filename from content-disposition header if available
    const contentDisposition = response.headers.get('content-disposition');
    let filename = buildPdfExportFilename(filters);
    if (contentDisposition) {
      const match = contentDisposition.match(/filename="?([^";\n]+)"?/);
      if (match) filename = match[1];
    }

    console.log('[exportAlertsPDF] Filename:', filename);

    // Download the file
    const blob = await response.blob();
    console.log('[exportAlertsPDF] Blob size:', blob.size, 'bytes');
    
    const downloadUrl = window.URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.href = downloadUrl;
    link.download = filename;
    document.body.appendChild(link);
    
    // Trigger download
    setTimeout(() => {
      link.click();
      document.body.removeChild(link);
      window.URL.revokeObjectURL(downloadUrl);
      console.log('[exportAlertsPDF] Download triggered');
    }, 100);
  } catch (error) {
    console.error('[exportAlertsPDF] Exception:', error);
    throw error;
  }
};
