import { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';

function EmailVerification({ email, onVerified, onBack }) {
  const [code, setCode] = useState('');
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(false);
  const [message, setMessage] = useState('');
  const navigate = useNavigate();


  // Auto-hide error messages after 5 seconds
  useEffect(() => {
    if (error) {
      const timer = setTimeout(() => setError(''), 5000);
      return () => clearTimeout(timer);
    }
  }, [error]);

  // Auto-hide success messages after 5 seconds (except verification success)
  useEffect(() => {
    if (message && !message.includes('Redirecting')) {
      const timer = setTimeout(() => setMessage(''), 5000);
      return () => clearTimeout(timer);
    }
  }, [message]);

  const API_BASE_URL = import.meta.env.VITE_API_URL || 'http://127.0.0.1:8000';

  const handleVerify = async (e) => {
    e.preventDefault();
    setError('');
    setLoading(true);

    try {
      const response = await fetch(`${API_BASE_URL}/api/auth/verify-email/`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({ email, code }),
      });

      const data = await response.json();

      if (response.ok) {
        setMessage('Email verified successfully! Redirecting...');
        setTimeout(() => {
            onVerified(data);
            navigate('/dashboard');
        }, 1500);
      } else {
        setError(data.error || 'Verification failed. Please check your code.');
      }
    } catch (err) {
      console.error('Email verification error:', err);
      setError('Network error. Please try again.');
    } finally {
      setLoading(false);
    }
  };

  const [resendTimer, setResendTimer] = useState(0);

  useEffect(() => {
    let timer;
    if (resendTimer > 0) {
      timer = setInterval(() => {
        setResendTimer((prev) => prev - 1);
      }, 1000);
    }
    return () => clearInterval(timer);
  }, [resendTimer]);

  const handleResend = async () => {
    if (resendTimer > 0) return;

    setError('');
    setMessage('');
    setLoading(true);

    try {
      const response = await fetch(`${API_BASE_URL}/api/auth/resend-verification/`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({ email }),
      });

      const data = await response.json();

      if (response.ok) {
        setMessage('Verification code resent! Check your email.');
        setResendTimer(60); // Set 60 second cooldown
      } else {
        setError(data.error || 'Failed to resend code.');
      }
    } catch (err) {
      console.error('Resend verification error:', err);
      setError('Network error. Please try again.');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="min-h-screen flex items-center justify-center bg-gray-900">
      <div className="bg-gray-800 p-8 rounded-lg shadow-lg w-96">
        <h2 className="text-2xl font-bold text-white mb-6 text-center">Verify Your Email</h2>

        <p className="text-gray-300 text-sm mb-6 text-center">
          We sent a 6-digit verification code to<br />
          <span className="font-semibold text-white">{email}</span>
        </p>

        {error && (
          <div className="bg-red-500 text-white p-3 rounded mb-4 text-sm">
            {error}
          </div>
        )}

        {message && (
          <div className="bg-green-500 text-white p-3 rounded mb-4 text-sm">
            {message}
          </div>
        )}

        <form onSubmit={handleVerify}>
          <div className="mb-6">
            <label className="block text-gray-300 text-sm font-bold mb-2">
              Verification Code
            </label>
            <input
              type="text"
              maxLength="6"
              value={code}
              onChange={(e) => setCode(e.target.value.replace(/\D/g, ''))}
              className="w-full px-4 py-2 bg-gray-700 border border-gray-600 rounded text-white text-center text-2xl tracking-widest focus:outline-none focus:border-blue-500"
              placeholder="000000"
              required
              autoFocus
            />
          </div>

          <button
            type="submit"
            disabled={loading || code.length !== 6}
            className="w-full bg-blue-600 text-white py-2 rounded hover:bg-blue-700 disabled:bg-gray-600 disabled:cursor-not-allowed transition duration-200 font-semibold"
          >
            {loading ? 'Verifying...' : 'Verify Email'}
          </button>
        </form>

        <div className="mt-4 text-center">
          <button
            onClick={handleResend}
            disabled={loading || resendTimer > 0}
            className="text-blue-400 hover:text-blue-300 text-sm disabled:text-gray-500 transition-colors"
          >
            {resendTimer > 0 ? `Resend Code in ${resendTimer}s` : 'Resend Code'}
          </button>
        </div>

        <div className="mt-4 text-center">
          <button
            onClick={onBack}
            className="text-gray-400 hover:text-gray-300 text-sm"
          >
            ← Back to Login
          </button>
        </div>
      </div>
    </div>
  );
}

export default EmailVerification;
