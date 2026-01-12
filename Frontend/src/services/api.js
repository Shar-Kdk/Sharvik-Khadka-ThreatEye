const API_URL = `${import.meta.env.VITE_API_URL}/api`;

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
