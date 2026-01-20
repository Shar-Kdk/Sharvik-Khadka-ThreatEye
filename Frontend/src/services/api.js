const BASE_URL = (import.meta.env.VITE_API_URL || 'http://localhost:8000').replace(/\/$/, '');
const API_URL = `${BASE_URL}/api`;

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
    throw new Error(data.email?.[0] || data.password?.[0] || data.non_field_errors?.[0] || 'Login failed');
  }

  return data;
};

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

