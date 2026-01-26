import { useState, useEffect, useRef } from 'react';
import { Routes, Route, Link, useLocation } from 'react-router-dom';
import Sidebar from './Sidebar';
import Overview from '../pages/dashboard/Overview';
import AdminOverview from '../pages/dashboard/AdminOverview';
import OrganizationsList from '../pages/dashboard/OrganizationsList';
import SubscriptionDetails from '../pages/dashboard/SubscriptionDetails';
import SubscriptionHistory from '../pages/dashboard/SubscriptionHistory';
import LiveTraffic from '../pages/dashboard/LiveTraffic';

/**
 * Dashboard component - Main application layout after login
 * Checks subscription status, shows different views for Platform Owner vs Org Admin
 * Routes to different dashboard pages: Overview, Live Traffic, Subscription Management
 */
function Dashboard({ user, token, onLogout }) {
  // Track subscription status and loading state
  const [subscription, setSubscription] = useState(null);
  const [loading, setLoading] = useState(true);
  // Profile dropdown menu visibility
  const [showProfileMenu, setShowProfileMenu] = useState(false);
  const profileMenuRef = useRef(null);
  const API_BASE_URL = import.meta.env.VITE_API_URL || 'http://localhost:8000';
  const location = useLocation();

  // Check if user is a Platform Owner (system admin) vs Organization Admin
  const isPlatformOwner = user?.role === 'platform_owner';

  const getPageTitle = () => {
    // Map routes to page titles
    const pathToTitle = {
      '/dashboard': isPlatformOwner ? 'Platform Overview' : 'General Overview',
      '/dashboard/organizations': 'Organizations',
      '/dashboard/subscription': 'Plan Management',
      '/dashboard/subscription/history': 'Subscription History',
      '/dashboard/live-traffic': 'Live Traffic',
    };
    
    return pathToTitle[location.pathname] || 'Overview';
  };

  const getUserDisplayName = () => {
    // Get user's full name or fallback to email username
    if (user?.first_name && user?.last_name) {
      return `${user.first_name} ${user.last_name}`;
    }
    if (user?.first_name) {
      return user.first_name;
    }
    return user?.email?.split('@')[0] || 'User';
  };

  useEffect(() => {
    // Fetch user's subscription status from backend
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

  // Close profile menu when clicking outside
  useEffect(() => {
    // Close profile menu when clicking outside of it
    const handleClickOutside = (event) => {
      if (profileMenuRef.current && !profileMenuRef.current.contains(event.target)) {
        setShowProfileMenu(false);
      }
    };

    if (showProfileMenu) {
      document.addEventListener('mousedown', handleClickOutside);
      return () => document.removeEventListener('mousedown', handleClickOutside);
    }
  }, [showProfileMenu]);

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
          <div className="mb-10 flex items-center justify-between">
            <h1 className="text-2xl font-bold text-white tracking-tight capitalize">
              {getPageTitle()}
            </h1>

            {/* Profile Button */}
            <div className="relative" ref={profileMenuRef}>
              <button
                onClick={() => setShowProfileMenu(!showProfileMenu)}
                className="flex items-center space-x-2 px-4 py-2 rounded-lg bg-[#1f2937] hover:bg-[#2d3748] text-white border border-[#30363d] transition-colors"
              >
                <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M16 7a4 4 0 11-8 0 4 4 0 018 0zM12 14a7 7 0 00-7 7h14a7 7 0 00-7-7z" />
                </svg>
                <span className="text-sm font-medium hidden sm:inline">
                  {getUserDisplayName()}
                </span>
              </button>

              {/* Profile Dropdown Menu */}
              {showProfileMenu && (
                <div className="absolute right-0 mt-2 w-56 bg-[#0d1117] border border-[#30363d] rounded-lg shadow-xl z-50">
                  <div className="px-4 py-3 border-b border-[#30363d]">
                    <p className="text-sm font-medium text-white truncate">{user?.email}</p>
                    <p className="text-xs text-gray-400 mt-1 truncate">
                      {user?.organization?.name || 'Organization'}
                    </p>
                    <div className="mt-2 flex items-center space-x-1">
                      <span className="text-xs text-gray-500">Role:</span>
                      <span className="text-xs font-semibold text-blue-400 capitalize">
                        {user?.role?.replace('_', ' ') || 'Member'}
                      </span>
                    </div>
                  </div>
                  <button
                    onClick={onLogout}
                    className="w-full text-left px-4 py-2.5 text-sm text-red-400 hover:bg-[#161b22] hover:text-red-300 transition-colors flex items-center space-x-2"
                  >
                    <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                      <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M17 16l4-4m0 0l-4-4m4 4H7m6 4v1a3 3 0 01-3 3H6a3 3 0 01-3-3V7a3 3 0 013-3h4a3 3 0 013 3v1" />
                    </svg>
                    <span>Logout</span>
                  </button>
                </div>
              )}
            </div>
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
