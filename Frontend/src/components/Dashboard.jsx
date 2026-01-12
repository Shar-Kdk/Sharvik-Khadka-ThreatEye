import { useState, useEffect } from 'react';
import { Link } from 'react-router-dom';
import LiveTrafficTable from './traffic/LiveTrafficTable';
import TrafficCharts from './traffic/TrafficCharts';

function Dashboard({ user, onLogout }) {
  const [subscription, setSubscription] = useState(null);
  const [loading, setLoading] = useState(true);
  const [isCapturing, setIsCapturing] = useState(false);
  const API_BASE_URL = import.meta.env.VITE_API_URL || 'http://localhost:8000';

  useEffect(() => {
    const checkSubscription = async () => {
      try {
        const token = localStorage.getItem('token');
        if (!token) return;

        const response = await fetch(`${API_BASE_URL}/subscriptions/status/`, {
          headers: {
            'Authorization': `Bearer ${token}`
          }
        });

        if (response.ok) {
          const data = await response.json();
          setSubscription(data);
        } else {
          console.error("Failed to fetch subscription status");
          setSubscription({ status: 'error' });
        }
      } catch (error) {
        console.error("Error checking subscription:", error);
        setSubscription({ status: 'error' });
      } finally {
        setLoading(false);
      }
    };

    checkSubscription();
  }, []);

  if (loading) {
    return (
      <div className="min-h-screen bg-gray-900 text-white flex items-center justify-center">
        <p className="text-xl animate-pulse">Checking subscription status...</p>
      </div>
    );
  }

  // Access Control Logic
  const hasActiveSubscription = subscription?.status === 'active';

  if (!hasActiveSubscription) {
    return (
      <div className="min-h-screen bg-gray-900 text-white flex flex-col items-center justify-center p-4">
        <div className="max-w-md w-full bg-gray-800 border-2 border-red-500/50 rounded-xl p-8 text-center shadow-2xl relative overflow-hidden">
          <div className="bg-red-500/10 w-24 h-24 rounded-full flex items-center justify-center mx-auto mb-6">
            <svg className="w-12 h-12 text-red-500" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M12 15v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2zm10-10V7a4 4 0 00-8 0v4h8z" />
            </svg>
          </div>

          <h1 className="text-3xl font-bold mb-2">Access Restricted</h1>
          <p className="text-gray-400 mb-8">
            This dashboard is protected. You need an <strong>active subscription</strong> to view network traffic and threat data.
          </p>

          <div className="bg-gray-700/50 rounded-lg p-4 mb-8 text-left text-sm">
            <div className="flex justify-between mb-2">
              <span className="text-gray-400">Current Status:</span>
              <span className="font-mono text-yellow-400 uppercase">{subscription?.status || 'Unknown'}</span>
            </div>
            <div className="flex justify-between">
              <span className="text-gray-400">Required:</span>
              <span className="font-mono text-green-400 uppercase">ACTIVE</span>
            </div>
          </div>

          <div className="space-y-3">
            <Link
              to="/subscriptions/plans"
              className="block w-full bg-blue-600 hover:bg-blue-700 text-white font-bold py-3 px-4 rounded-lg transition-colors"
            >
              View Subscription Plans
            </Link>
            <button
              onClick={onLogout}
              className="block w-full bg-gray-700 hover:bg-gray-600 text-gray-300 font-semibold py-3 px-4 rounded-lg transition-colors"
            >
              Logout
            </button>
          </div>
        </div>
      </div>
    );
  }

  return (
    <div className="min-h-screen bg-gray-900 text-white font-sans">
      <nav className="bg-gray-800 p-4 shadow-lg border-b border-gray-700 sticky top-0 z-50">
        <div className="container mx-auto flex justify-between items-center">
          <div className="flex items-center space-x-6">
            <h1 className="text-2xl font-bold tracking-wide">ThreatEye Dashboard</h1>
            <span className="bg-green-500/10 text-green-400 text-[10px] px-2 py-0.5 rounded border border-green-500/20 font-mono font-bold">
              ACTIVE LICENSE
            </span>
          </div>
          <div className="flex items-center space-x-4">
            <button
              onClick={() => setIsCapturing(!isCapturing)}
              className={`flex items-center space-x-2 px-4 py-2 rounded-lg text-sm font-bold transition-all ${isCapturing
                ? 'bg-red-500/10 text-red-500 border border-red-500/20 shadow-[0_0_15px_rgba(239,68,68,0.1)]'
                : 'bg-green-500/10 text-green-500 border border-green-500/20 hover:bg-green-500/20'
                }`}
            >
              <span className={`w-2 h-2 rounded-full ${isCapturing ? 'bg-red-500 animate-pulse' : 'bg-green-500'}`}></span>
              <span>{isCapturing ? 'Stop Capture' : 'Start Capture'}</span>
            </button>
            <button
              onClick={onLogout}
              className="bg-gray-700 hover:bg-gray-600 text-white px-4 py-2 rounded-lg text-sm font-semibold transition-colors"
            >
              Logout
            </button>
          </div>
        </div>
      </nav>

      <div className="container mx-auto p-6 space-y-6">
        {/* Welcome & Stats Row */}
        <div className="flex flex-col lg:flex-row gap-6">
          <div className="flex-grow bg-gray-800 p-6 rounded-xl border border-gray-700 shadow-xl flex justify-between items-center">
            <div>
              <h2 className="text-2xl font-bold mb-1">Welcome, {user.first_name || 'Admin'}!</h2>
              <p className="text-gray-400 text-sm">{user.email}</p>
            </div>
            <div className="text-right border-l border-gray-700 pl-6 hidden md:block">
              <p className="text-[10px] text-gray-500 uppercase tracking-widest mb-1">Account Type</p>
              <p className="text-white font-bold text-sm">{subscription?.plan || 'Platform Admin'}</p>
            </div>
          </div>

          <div className="grid grid-cols-2 gap-4">
            <div className="bg-gray-800 p-4 px-8 rounded-xl border border-gray-700 shadow-xl text-center">
              <p className="text-[10px] text-gray-500 uppercase tracking-widest mb-1 font-bold">Packets</p>
              <p className="text-2xl font-black text-blue-400 font-mono">3</p>
            </div>
            <div className="bg-gray-800 p-4 px-8 rounded-xl border border-gray-700 shadow-xl text-center">
              <p className="text-[10px] text-gray-500 uppercase tracking-widest mb-1 font-bold">Threats</p>
              <p className="text-2xl font-black text-red-500 font-mono">1</p>
            </div>
          </div>
        </div>

        {/* Primary Visualization (US009, US010) */}
        <TrafficCharts />

        {/* Live Data (US006, US008) */}
        <LiveTrafficTable />
      </div>
    </div>
  );
}

export default Dashboard;
