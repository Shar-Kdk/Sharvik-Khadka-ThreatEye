import { useState } from 'react';
import { BrowserRouter as Router, Routes, Route, Navigate } from 'react-router-dom';
import Login from './components/Login';
import Dashboard from './components/Dashboard';
import EmailVerification from './components/EmailVerification';
import SubscriptionPlans from './pages/SubscriptionPlans';
import SubscriptionSuccess from './pages/SubscriptionSuccess';
import SubscriptionFailed from './pages/SubscriptionFailed';

function App() {
  const [user, setUser] = useState(() => {
    const saved = localStorage.getItem('user');
    return saved ? JSON.parse(saved) : null;
  });
  const [token, setToken] = useState(() => localStorage.getItem('token'));
  const [showVerification, setShowVerification] = useState(false);

  const handleLoginSuccess = (data) => {
    setUser(data.user);
    setToken(data.token);
    localStorage.setItem('user', JSON.stringify(data.user));
    localStorage.setItem('token', data.token);

    // Show verification screen if user is not verified
    if (!data.user.is_verified) {
      setShowVerification(true);
    }
  };

  const handleVerified = () => {
    // Update user's verification status
    const updatedUser = { ...user, is_verified: true };
    setUser(updatedUser);
    localStorage.setItem('user', JSON.stringify(updatedUser));
    setShowVerification(false);
  };

  const handleBackToLogin = () => {
    setUser(null);
    setToken(null);
    localStorage.removeItem('user');
    localStorage.removeItem('token');
    setShowVerification(false);
  };

  const handleLogout = () => {
    setUser(null);
    setToken(null);
    localStorage.removeItem('user');
    localStorage.removeItem('token');
    setShowVerification(false);
  };

  return (
    <Router>
      <Routes>
        {/* Public Routes */}
        <Route
          path="/login"
          element={!user ? <Login onLoginSuccess={handleLoginSuccess} /> : <Navigate to="/dashboard" />}
        />

        {/* Verification Route */}
        <Route
          path="/verify-email"
          element={user && showVerification ? (
            <EmailVerification
              email={user.email}
              onVerified={handleVerified}
              onBack={handleBackToLogin}
            />
          ) : <Navigate to="/login" />}
        />

        {/* Subscription Routes */}
        <Route
          path="/subscriptions/plans"
          element={user ? <SubscriptionPlans /> : <Navigate to="/login" />}
        />
        <Route
          path="/subscription/success"
          element={user ? <SubscriptionSuccess /> : <Navigate to="/login" />}
        />
        <Route
          path="/subscription/failed"
          element={user ? <SubscriptionFailed /> : <Navigate to="/login" />}
        />

        {/* Dashboard Route */}
        <Route
          path="/dashboard"
          element={user && !showVerification ? (
            <Dashboard user={user} onLogout={handleLogout} />
          ) : <Navigate to="/login" />}
        />

        {/* Default Route */}
        <Route path="/" element={<Navigate to={user ? "/dashboard" : "/login"} />} />
      </Routes>
    </Router>
  );
}

export default App;