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

// Get user's past subscription history (list of previous plans)
export const getSubscriptionHistory = async (token) => {
  const response = await fetch(`${BASE_URL}/subscriptions/history/`, {
    headers: {
      'Authorization': `Bearer ${token}`,
    },
  });

  if (!response.ok) {
    throw new Error('Failed to fetch subscription history');
  }

  return response.json();
};

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

// Get alerts grouped by time for timeline chart (shows attack frequency over time)
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

