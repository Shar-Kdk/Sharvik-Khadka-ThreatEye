import { useState } from 'react';
import { BrowserRouter as Router, Routes, Route, Navigate } from 'react-router-dom';
import Login from './components/Login';
import Dashboard from './components/Dashboard';
import EmailVerification from './components/EmailVerification';
import SubscriptionPlans from './pages/SubscriptionPlans';
import SubscriptionSuccess from './pages/SubscriptionSuccess';
import SubscriptionFailed from './pages/SubscriptionFailed';

function App() {
  const [user, setUser] = useState(null);
  const [token, setToken] = useState(null);
  const [showVerification, setShowVerification] = useState(false);

  /**
   * Clear all auth state
   */
  const clearAuthState = () => {
    setUser(null);
    setToken(null);
    setShowVerification(false);
  };

  const handleLoginSuccess = (data) => {
    setUser(data.user);
    setToken(data.token);
    setShowVerification(!data.user.is_verified);
  };

  const handleVerified = (data) => {
    setUser(data.user);
    setToken(data.token);
    setShowVerification(false);
  };

  const handleBackToLogin = clearAuthState;
  const handleLogout = clearAuthState;

  return (
    <Router>
      <Routes>
        {/* Public Routes */}
        <Route
          path="/login"
          element={<Login onLoginSuccess={handleLoginSuccess} />}
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
          ) : <Navigate to={user ? "/dashboard" : "/login"} />}
        />

        {/* Subscription Routes */}
        <Route
          path="/subscriptions/plans"
          element={user ? <SubscriptionPlans token={token} /> : <Navigate to="/login" />}
        />
        <Route
          path="/subscription/success"
          element={user ? <SubscriptionSuccess /> : <Navigate to="/login" />}
        />
        <Route
          path="/subscription/failed"
          element={user ? <SubscriptionFailed /> : <Navigate to="/login" />}
        />

        {/* Dashboard Route (Nested) */}
        <Route
          path="/dashboard/*"
          element={user && !showVerification ? (
            <Dashboard user={user} token={token} onLogout={handleLogout} />
          ) : <Navigate to="/login" />}
        />

        {/* Default Route */}
        <Route path="/" element={<Navigate to={user ? "/dashboard" : "/login"} />} />
      </Routes>
    </Router>
  );
}

export default App;