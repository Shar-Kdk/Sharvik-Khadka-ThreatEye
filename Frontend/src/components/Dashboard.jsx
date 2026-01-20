import { useState, useEffect } from 'react';
import { Routes, Route, Link, useLocation } from 'react-router-dom';
import Sidebar from './Sidebar';
import Overview from '../pages/dashboard/Overview';
import AdminOverview from '../pages/dashboard/AdminOverview';
import OrganizationsList from '../pages/dashboard/OrganizationsList';
import SubscriptionDetails from '../pages/dashboard/SubscriptionDetails';
import SubscriptionHistory from '../pages/dashboard/SubscriptionHistory';
import LiveTraffic from '../pages/dashboard/LiveTraffic';

function Dashboard({ user, token, onLogout }) {
  const [subscription, setSubscription] = useState(null);
  const [loading, setLoading] = useState(true);
  const API_BASE_URL = import.meta.env.VITE_API_URL || 'http://localhost:8000';
  const location = useLocation();

  // Detect if user is the Platform Owner using the user object role
  const isPlatformOwner = user?.role === 'platform_owner';

  useEffect(() => {
    const checkSubscription = async () => {
      try {
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
  }, [token]);

  if (loading) {
    return (
      <div className="min-h-screen bg-[#010409] text-gray-400 flex items-center justify-center">
        <p className="animate-pulse font-medium">Authenticating Environment...</p>
      </div>
    );
  }

  const hasActiveSubscription = isPlatformOwner || subscription?.status === 'active';
  const isSubscriptionPath = location.pathname === '/dashboard/subscription';

  if (!hasActiveSubscription && !isSubscriptionPath) {
    return (
      <div className="min-h-screen bg-[#010409] flex items-center justify-center p-6 text-center">
        <div className="max-w-sm w-full bg-[#0d1117] border border-[#30363d] rounded-xl p-10 shadow-xl">
          <h1 className="text-2xl font-bold text-white mb-3">Subscription Required</h1>
          <p className="text-gray-400 mb-8 text-sm leading-relaxed">Please activate a subscription plan to access the network monitoring dashboard.</p>
          <div className="space-y-4">
            <Link
              to="/subscriptions/plans"
              className="block w-full bg-blue-600 hover:bg-blue-500 text-white font-bold py-3.5 rounded-lg transition-all shadow-md shadow-blue-900/40 uppercase tracking-widest text-xs"
            >
              Explore Plans & Pricing
            </Link>
            <button
              onClick={onLogout}
              className="block w-full text-gray-400 hover:text-white font-semibold text-xs transition-colors py-2 uppercase tracking-widest"
            >
              Logout
            </button>
          </div>
        </div>
      </div>
    );
  }

  return (
    <div className="min-h-screen bg-[#010409] text-gray-200 flex">
      {/* Sidebar Navigation (Conditional) */}
      <Sidebar onLogout={onLogout} isPlatformOwner={isPlatformOwner} />

      {/* Main Content Area */}
      <main className="flex-grow p-10 overflow-auto">
        <div className="max-w-6xl mx-auto">
          <div className="mb-10">
            <h1 className="text-2xl font-bold text-white tracking-tight capitalize">
              {location.pathname === '/dashboard' ? (isPlatformOwner ? 'Platform Overview' : 'General Overview') :
                location.pathname === '/dashboard/organizations' ? 'Organizations' :
                    location.pathname === '/dashboard/subscription' ? 'Plan Management' :
                    location.pathname === '/dashboard/subscription/history' ? 'Subscription History' :
                    location.pathname === '/dashboard/live-traffic' ? 'Live Traffic' :
                    'Overview'}
            </h1>
          </div>

          <Routes>
            {/* Platform Owner Routes */}
            {isPlatformOwner ? (
              <>
                <Route path="/" element={<AdminOverview token={token} />} />
                <Route path="/organizations" element={<OrganizationsList token={token} />} />
                <Route path="/live-traffic" element={<LiveTraffic token={token} />} />
              </>
            ) : (
              /* Regular User Routes */
              <>
                <Route path="/" element={<Overview user={user} subscription={subscription} token={token} />} />
                 <Route path="/subscription" element={<SubscriptionDetails subscription={subscription} token={token} />} />
                 <Route path="/subscription/history" element={<SubscriptionHistory token={token} />} />
                 <Route path="/live-traffic" element={<LiveTraffic token={token} />} />
              </>
            )}
          </Routes>
        </div>
      </main>
    </div>
  );
}

export default Dashboard;
