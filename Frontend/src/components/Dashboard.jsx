import { useState, useEffect, useRef } from 'react';
import { Routes, Route, Link, useLocation } from 'react-router-dom';
import Sidebar from './Sidebar';
import Overview from '../pages/dashboard/Overview';
import AdminOverview from '../pages/dashboard/AdminOverview';
import OrganizationsList from '../pages/dashboard/OrganizationsList';
import SubscriptionDetails from '../pages/dashboard/SubscriptionDetails';
import SubscriptionHistory from '../pages/dashboard/SubscriptionHistory';
import LiveTraffic from '../pages/dashboard/LiveTraffic';
import { getLiveAlerts, getSubscriptionStatus } from '../services/api';

const BASE_URL = (import.meta.env.VITE_API_URL || 'http://localhost:8000').replace(/\/$/, '');

const MAX_NOTIFICATION_ITEMS = 20;

const NOTIFICATION_THREAT_STYLES = {
  medium: 'bg-yellow-500/20 text-yellow-300 border border-yellow-400/30',
  high: 'bg-red-500/20 text-red-300 border border-red-400/30',
};

function normalizeThreatLevel(value) {
  return String(value || '').toLowerCase();
}

function isSevereThreatAlert(alert) {
  const threatLevel = normalizeThreatLevel(alert?.threat_level);
  return threatLevel === 'medium' || threatLevel === 'high';
}

function formatTimestamp(value) {
  try {
    return new Date(value).toLocaleString();
  } catch {
    return value;
  }
}

/**
 * Dashboard component - Main application layout after login
 * Checks subscription status, shows different views for Platform Owner vs Org Admin
 * Routes to different dashboard pages: Overview, Live Traffic, Subscription Management
 */
function Dashboard({ user, token, onLogout }) {
  // Track subscription status and loading state
  const [subscription, setSubscription] = useState(null);
  const [loading, setLoading] = useState(true);
  const [unreadAlertCount, setUnreadAlertCount] = useState(0);
  const [showNotificationsMenu, setShowNotificationsMenu] = useState(false);
  const [notificationAlerts, setNotificationAlerts] = useState([]);
  const [notificationError, setNotificationError] = useState('');
  const [isNotificationLoading, setIsNotificationLoading] = useState(false);
  // Profile dropdown menu visibility
  const [showProfileMenu, setShowProfileMenu] = useState(false);
  const notificationsMenuRef = useRef(null);
  const profileMenuRef = useRef(null);
  const seenAlertIdsRef = useRef(new Set());
  const hasInitializedNotificationsRef = useRef(false);
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

        const data = await getSubscriptionStatus(token);
        setSubscription(data);
      } catch (error) {
        console.error("Error checking subscription:", error);
        setSubscription({ status: 'error' });
      } finally {
        setLoading(false);
      }
    };

    checkSubscription();
  }, [token]);

  useEffect(() => {
    if (!token) {
      return;
    }

    let active = true;
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), 8000);

    const warmNotifications = async () => {
      try {
        const payload = await getLiveAlerts(token, 500, controller.signal);
        if (!active) {
          return;
        }

        const results = payload.results || [];
        const severeAlerts = results.filter(isSevereThreatAlert).slice(0, MAX_NOTIFICATION_ITEMS);

        severeAlerts.forEach((alert) => {
          if (alert?.id !== null && alert?.id !== undefined) {
            seenAlertIdsRef.current.add(alert.id);
          }
        });

        setNotificationAlerts((prev) => {
          const next = [...severeAlerts, ...prev];
          const deduped = [];
          const seen = new Set();

          for (const item of next) {
            const id = item?.id;
            if (id === null || id === undefined || seen.has(id)) {
              continue;
            }
            seen.add(id);
            deduped.push(item);
            if (deduped.length >= MAX_NOTIFICATION_ITEMS) {
              break;
            }
          }

          return deduped;
        });

        setUnreadAlertCount((prev) => Math.max(prev, severeAlerts.length));
      } catch {
        // Silent warm-up; WS + manual refresh will keep notifications updated.
      } finally {
        clearTimeout(timeoutId);
        controller.abort();
      }
    };

    warmNotifications();

    return () => {
      active = false;
      clearTimeout(timeoutId);
      controller.abort();
    };
  }, [token]);

  useEffect(() => {
    if (location.pathname === '/dashboard/live-traffic') {
      setShowNotificationsMenu(false);
    }
  }, [location.pathname]);

  useEffect(() => {
    if (showNotificationsMenu) {
      setUnreadAlertCount(0);
    }
  }, [showNotificationsMenu]);

  useEffect(() => {
    if (!token) {
      return;
    }

    if (!showNotificationsMenu) {
      return;
    }

    let active = true;
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), 8000);

    const loadSevereAlerts = async () => {
      setIsNotificationLoading(true);
      setNotificationError('');

      try {
        const payload = await getLiveAlerts(token, 500, controller.signal);
        if (!active) {
          return;
        }

        const results = payload.results || [];
        const severeAlerts = results.filter(isSevereThreatAlert).slice(0, MAX_NOTIFICATION_ITEMS);

        severeAlerts.forEach((alert) => {
          if (alert?.id !== null && alert?.id !== undefined) {
            seenAlertIdsRef.current.add(alert.id);
          }
        });

        setNotificationAlerts(severeAlerts);
      } catch (err) {
        if (!active) {
          return;
        }

        if (err?.name === 'AbortError') {
          setNotificationError('Notification refresh timed out.');
        } else {
          setNotificationError(err.message || 'Failed to load notifications');
        }
      } finally {
        clearTimeout(timeoutId);
        if (active) {
          setIsNotificationLoading(false);
        }
      }
    };

    loadSevereAlerts();

    return () => {
      active = false;
      clearTimeout(timeoutId);
      controller.abort();
    };
  }, [showNotificationsMenu, token]);

  // Close menus when clicking outside
  useEffect(() => {
    const handleClickOutside = (event) => {
      const clickedProfile = profileMenuRef.current && profileMenuRef.current.contains(event.target);
      const clickedNotifications = notificationsMenuRef.current && notificationsMenuRef.current.contains(event.target);

      if (clickedProfile || clickedNotifications) {
        return;
      }

      setShowProfileMenu(false);
      setShowNotificationsMenu(false);
    };

    if (showProfileMenu || showNotificationsMenu) {
      document.addEventListener('mousedown', handleClickOutside);
      return () => document.removeEventListener('mousedown', handleClickOutside);
    }
  }, [showProfileMenu, showNotificationsMenu]);

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
      <Sidebar isPlatformOwner={isPlatformOwner} />

      {/* Main Content Area */}
      <main className="flex-grow p-10 overflow-auto">
        <div className="max-w-6xl mx-auto">
          <div className="mb-10 flex items-center justify-between">
            <h1 className="text-2xl font-bold text-white tracking-tight capitalize">
              {getPageTitle()}
            </h1>

            <div className="flex items-center gap-3">
              <div className="relative" ref={notificationsMenuRef}>
                <button
                  type="button"
                  aria-label="Notifications"
                  title="Notifications"
                  onClick={() => {
                    setShowProfileMenu(false);
                    setShowNotificationsMenu((prev) => !prev);
                  }}
                  className="relative flex items-center justify-center w-10 h-10 rounded-lg bg-[#1f2937] hover:bg-[#2d3748] text-white border border-[#30363d] transition-colors"
                >
                  <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path
                      strokeLinecap="round"
                      strokeLinejoin="round"
                      strokeWidth="2"
                      d="M15 17h5l-1.405-1.405A2.032 2.032 0 0118 14.158V11a6.002 6.002 0 00-4-5.659V5a2 2 0 10-4 0v.341C7.67 6.165 6 8.388 6 11v3.159c0 .538-.214 1.055-.595 1.436L4 17h5m6 0v1a3 3 0 11-6 0v-1m6 0H9"
                    />
                  </svg>
                  {unreadAlertCount > 0 && (
                    <span className="absolute -top-1 -right-1 min-w-[18px] h-[18px] px-1 rounded-full bg-red-500 text-white text-[11px] font-bold flex items-center justify-center">
                      {unreadAlertCount > 99 ? '99+' : unreadAlertCount}
                    </span>
                  )}
                </button>

                {showNotificationsMenu && (
                  <div className="absolute right-0 mt-2 w-80 bg-[#0d1117] border border-[#30363d] rounded-lg shadow-xl z-50 overflow-hidden">
                    {notificationError && (
                      <div className="px-4 py-3 bg-red-500/10 border-b border-red-500/20 text-sm text-red-300">
                        {notificationError}
                      </div>
                    )}

                    {isNotificationLoading ? (
                      <div className="px-4 py-6 text-sm text-gray-400">Loading notifications...</div>
                    ) : (
                      <div className="max-h-80 overflow-y-auto no-scrollbar">
                        {notificationAlerts.length === 0 ? (
                          <div className="px-4 py-6 text-sm text-gray-400">No medium/high threat alerts yet.</div>
                        ) : (
                          notificationAlerts.map((alert) => {
                            const threatLevel = normalizeThreatLevel(alert?.threat_level);
                            const threatStyle = NOTIFICATION_THREAT_STYLES[threatLevel] || NOTIFICATION_THREAT_STYLES.medium;

                            return (
                              <div key={alert.id} className="px-4 py-3 border-b border-[#161b22] last:border-b-0">
                                <div className="flex items-start justify-between gap-3">
                                  <div className="min-w-0">
                                    <p className="text-sm text-white font-medium truncate">{alert.message || 'Alert'}</p>
                                    <p className="text-xs text-gray-500 mt-1">{formatTimestamp(alert.timestamp)}</p>
                                  </div>
                                  <span className={`shrink-0 inline-block px-2 py-1 rounded text-[11px] font-semibold uppercase ${threatStyle}`}>
                                    {threatLevel || 'medium'}
                                  </span>
                                </div>
                              </div>
                            );
                          })
                        )}
                      </div>
                    )}
                  </div>
                )}
              </div>

              {/* Profile Button */}
              <div className="relative" ref={profileMenuRef}>
                <button
                  onClick={() => {
                    setShowNotificationsMenu(false);
                    setShowProfileMenu((prev) => !prev);
                  }}
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
                <Route path="/" element={<Overview user={user} token={token} />} />
                 <Route path="/subscription" element={<SubscriptionDetails subscription={subscription} />} />
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
