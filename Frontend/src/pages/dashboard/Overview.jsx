import { useState, useEffect } from 'react';
import { getProtocolStatistics, getThreatLevelDistribution, getTopSuspiciousIPs } from '../../services/api';

/**
 * Overview page - Dashboard showing alert statistics
 * Displays: protocol distribution, threat levels, recent alerts
 * Auto-refreshes every 8 seconds to show real-time data
 * Can also show minimal profile icon mode (showOnlyIcon=true)
 */
const Overview = ({ user, subscription, token, showOnlyIcon = false }) => {
    const [showProfilePopup, setShowProfilePopup] = useState(false);
    // Track protocol statistics (TCP, UDP, ICMP counts)
    const [protocolStats, setProtocolStats] = useState([]);
    const [protocolLoading, setProtocolLoading] = useState(false);
    // Track threat level counts (safe, medium, high)
    const [threatStats, setThreatStats] = useState({});
    const [threatLoading, setThreatLoading] = useState(false);
    // Track suspicious IPs (top attacking source IPs)
    const [suspiciousIPs, setSuspiciousIPs] = useState([]);
    const [suspiciousIPsLoading, setSuspiciousIPsLoading] = useState(false);

    // Fetch protocol statistics every 8 seconds (auto-refresh)
    useEffect(() => {
        if (!token || showOnlyIcon) return;
        
        let isActive = true;
        let interval = null;
        
        // Fetch protocol stats from API
        const fetchProtocolStats = async () => {
            if (!isActive) return;
            setProtocolLoading(true);
            try {
                const stats = await getProtocolStatistics(token);
                if (isActive) {
                    setProtocolStats(stats.results || []);
                }
            } catch (error) {
                if (isActive) {
                    console.error('Failed to fetch protocol statistics:', error);
                }
            } finally {
                if (isActive) {
                    setProtocolLoading(false);
                }
            }
        };

        fetchProtocolStats();
        interval = setInterval(fetchProtocolStats, 8000);
        
        return () => {
            isActive = false;
            if (interval) clearInterval(interval);
        };
    }, [token, showOnlyIcon]);

    useEffect(() => {
        if (!token || showOnlyIcon) return;
        
        let isActive = true;
        let interval = null;
        
        const fetchThreatStats = async () => {
            if (!isActive) return;
            setThreatLoading(true);
            try {
                const data = await getThreatLevelDistribution(token);
                if (!isActive) return;
                
                const counts = { safe: 0, medium: 0, high: 0 };
                (data.results || []).forEach(item => {
                    const level = item.threat_level?.toLowerCase().trim() || '';
                    if (level === 'safe') {
                        counts.safe = item.count;
                    } else if (level === 'medium') {
                        counts.medium = item.count;
                    } else if (level === 'high') {
                        counts.high = item.count;
                    }
                });
                
                if (isActive) {
                    setThreatStats(counts);
                }
            } catch (error) {
                if (isActive) {
                    console.error('Failed to fetch threat statistics:', error);
                }
            } finally {
                if (isActive) {
                    setThreatLoading(false);
                }
            }
        };

        fetchThreatStats();
        interval = setInterval(fetchThreatStats, 8000);
        
        return () => {
            isActive = false;
            if (interval) clearInterval(interval);
        };
    }, [token, showOnlyIcon]);

    useEffect(() => {
        if (!token || showOnlyIcon) return;
        
        let isActive = true;
        let interval = null;
        
        const fetchSuspiciousIPs = async () => {
            if (!isActive) return;
            setSuspiciousIPsLoading(true);
            try {
                const data = await getTopSuspiciousIPs(token);
                if (isActive) {
                    setSuspiciousIPs(data.results || []);
                }
            } catch (error) {
                if (isActive) {
                    console.error('Failed to fetch suspicious IPs:', error);
                }
            } finally {
                if (isActive) {
                    setSuspiciousIPsLoading(false);
                }
            }
        };

        fetchSuspiciousIPs();
        interval = setInterval(fetchSuspiciousIPs, 8000);
        
        return () => {
            isActive = false;
            if (interval) clearInterval(interval);
        };
    }, [token, showOnlyIcon]);

    if (showOnlyIcon) {
        return (
            <div className="relative">
                <button
                    onClick={() => setShowProfilePopup(!showProfilePopup)}
                    className="w-12 h-12 rounded-full bg-blue-600 flex items-center justify-center hover:bg-blue-700 cursor-pointer border border-blue-500"
                >
                    <span className="text-white font-bold text-lg">
                        {user.first_name?.charAt(0).toUpperCase() || 'U'}
                    </span>
                </button>

                {showProfilePopup && (
                    <div className="absolute top-16 right-0 bg-[#0d1117] border border-[#30363d] rounded-lg p-6 shadow-2xl z-50 w-80">
                        <div className="flex justify-end mb-4">
                            <button
                                onClick={() => setShowProfilePopup(false)}
                                className="text-gray-400 hover:text-white"
                            >
                                ✕
                            </button>
                        </div>
                        <div className="space-y-4">
                            <div>
                                <p className="text-gray-500 text-xs uppercase font-bold mb-1">Name</p>
                                <p className="text-white">{user.first_name} {user.last_name}</p>
                            </div>
                            <div>
                                <p className="text-gray-500 text-xs uppercase font-bold mb-1">Email</p>
                                <p className="text-white text-sm">{user.email}</p>
                            </div>
                            <div>
                                <p className="text-gray-500 text-xs uppercase font-bold mb-1">Organization</p>
                                <p className="text-white">{user.organization?.name || 'Academic Project'}</p>
                            </div>
                            <div>
                                <p className="text-gray-500 text-xs uppercase font-bold mb-1">Role</p>
                                <p className="text-white">{user.role === 'org_admin' ? 'Organization Admin' : user.role}</p>
                            </div>
                        </div>
                    </div>
                )}
            </div>
        );
    }

    return (
        <div className="space-y-6">
            <div className="bg-[#0d1117] border border-[#30363d] rounded-xl p-6">
                <h2 className="text-white text-lg font-bold mb-4">Packet Classification</h2>
                <p className="text-sm text-gray-400 mb-4">Traffic categorization based on Snort alert priority</p>
                {threatLoading ? (
                    <div className="text-gray-400 text-sm">Loading...</div>
                ) : (
                    <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
                        {[
                            { label: 'Safe', key: 'safe' },
                            { label: 'Medium', key: 'medium' },
                            { label: 'High', key: 'high' }
                        ].map(({ label, key }) => {
                            const count = threatStats[key] || 0;
                            const total = Object.values(threatStats).reduce((a, b) => a + b, 0) || 1;
                            const percentage = Math.round((count / total) * 100);
                            
                            return (
                                <div key={key} className="bg-[#161b22] border border-[#30363d] rounded-lg p-4">
                                    <div className="text-sm text-gray-400 mb-2">{label}</div>
                                    <div className="text-2xl font-bold text-white mb-1">{count.toLocaleString()}</div>
                                    <div className="text-xs text-gray-400 opacity-80">{percentage}% of traffic</div>
                                    <div className="mt-3 bg-black/30 rounded h-2 overflow-hidden">
                                        <div 
                                            className="h-full bg-gray-500" 
                                            style={{ width: `${percentage}%` }}
                                        />
                                    </div>
                                </div>
                            );
                        })}
                    </div>
                )}
            </div>

            <div className="bg-[#0d1117] border border-[#30363d] rounded-xl p-6">
                <h2 className="text-white text-lg font-bold mb-4">Protocol Statistics</h2>
                <p className="text-sm text-gray-400 mb-4">Distribution of network protocols in captured traffic</p>
                {protocolLoading ? (
                    <div className="text-gray-400 text-sm">Loading...</div>
                ) : (
                    <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
                        {protocolStats.length > 0 ? (
                            protocolStats.map((stat) => {
                                const total = protocolStats.reduce((sum, s) => sum + s.count, 0) || 1;
                                const percentage = Math.round((stat.count / total) * 100);
                                
                                return (
                                    <div key={stat.protocol} className="bg-[#161b22] border border-[#30363d] rounded-lg p-4">
                                        <div className="text-sm text-gray-400 mb-2">{stat.protocol}</div>
                                        <div className="text-2xl font-bold text-white mb-1">{stat.count.toLocaleString()}</div>
                                        <div className="text-xs text-gray-400 opacity-80">{percentage}% of traffic</div>
                                        <div className="mt-3 bg-black/30 rounded h-2 overflow-hidden">
                                            <div 
                                                className="h-full bg-gray-500" 
                                                style={{ width: `${percentage}%` }}
                                            />
                                        </div>
                                    </div>
                                );
                            })
                        ) : (
                            <div className="text-gray-400 text-sm col-span-3">No protocol data available</div>
                        )}
                    </div>
                )}
            </div>

            <div className="bg-[#0d1117] border border-[#30363d] rounded-xl p-6">
                <h2 className="text-white text-lg font-bold mb-4">Top Suspicious IPs</h2>
                <p className="text-sm text-gray-400 mb-4">Most active source IPs generating alerts</p>
                {suspiciousIPsLoading ? (
                    <div className="text-gray-400 text-sm">Loading...</div>
                ) : (
                    <div className="overflow-x-auto">
                        <table className="w-full text-sm">
                            <thead className="bg-[#161b22] border-b border-[#30363d]">
                                <tr>
                                    <th className="text-left px-4 py-3 text-gray-400 font-semibold">IP Address</th>
                                    <th className="text-left px-4 py-3 text-gray-400 font-semibold">Alert Count</th>
                                    <th className="text-left px-4 py-3 text-gray-400 font-semibold">Last Seen</th>
                                </tr>
                            </thead>
                            <tbody>
                                {suspiciousIPs.length > 0 ? (
                                    suspiciousIPs.map((ip, idx) => {
                                        const lastSeen = new Date(ip.last_seen);
                                        const now = new Date();
                                        const diffMinutes = Math.floor((now - lastSeen) / 60000);
                                        let timeStr = '';
                                        if (diffMinutes < 1) timeStr = 'Just now';
                                        else if (diffMinutes < 60) timeStr = `${diffMinutes}m ago`;
                                        else if (diffMinutes < 1440) timeStr = `${Math.floor(diffMinutes / 60)}h ago`;
                                        else timeStr = `${Math.floor(diffMinutes / 1440)}d ago`;

                                        return (
                                            <tr key={idx} className="border-b border-[#222a35] hover:bg-[#161b22]">
                                                <td className="px-4 py-3">
                                                    <span className="font-mono text-blue-400">{ip.src_ip}</span>
                                                </td>
                                                <td className="px-4 py-3">
                                                    <span className="inline-block bg-red-500/20 text-red-300 px-3 py-1 rounded font-bold">
                                                        {ip.alert_count}
                                                    </span>
                                                </td>
                                                <td className="px-4 py-3 text-gray-400 text-xs">{timeStr}</td>
                                            </tr>
                                        );
                                    })
                                ) : (
                                    <tr>
                                        <td colSpan={3} className="px-4 py-8 text-center text-gray-400 text-sm">
                                            No suspicious IPs tracked yet
                                        </td>
                                    </tr>
                                )}
                            </tbody>
                        </table>
                    </div>
                )}
            </div>
        </div>
    );
};

export default Overview;
