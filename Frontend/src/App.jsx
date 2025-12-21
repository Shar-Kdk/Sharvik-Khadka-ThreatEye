import { useState } from 'react';
import Login from './components/Login';
import Dashboard from './components/Dashboard';
import EmailVerification from './components/EmailVerification';

function App() {
  const [user, setUser] = useState(null);
  const [token, setToken] = useState(null);
  const [showVerification, setShowVerification] = useState(false);

  const handleLoginSuccess = (data) => {
    setUser(data.user);
    setToken(data.token);
    
    // Show verification screen if user is not verified
    if (!data.user.is_verified) {
      setShowVerification(true);
    }
  };

  const handleVerified = () => {
    // Update user's verification status
    setUser({ ...user, is_verified: true });
    setShowVerification(false);
  };

  const handleBackToLogin = () => {
    setUser(null);
    setToken(null);
    setShowVerification(false);
  };

  const handleLogout = () => {
    setUser(null);
    setToken(null);
    setShowVerification(false);
  };

  return (
    <div className="w-full h-full">
      {!user ? (
        <Login onLoginSuccess={handleLoginSuccess} />
      ) : showVerification ? (
        <EmailVerification 
          email={user.email} 
          onVerified={handleVerified}
          onBack={handleBackToLogin}
        />
      ) : (
        <Dashboard user={user} onLogout={handleLogout} />
      )}
    </div>
  );
}

export default App;