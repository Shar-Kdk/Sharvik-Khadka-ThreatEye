import { useState, useEffect } from 'react';
import { getProtocolStatistics, getLiveAlerts } from '../../services/api';

const Overview = ({ user, subscription, token, showOnlyIcon = false }) => {
    const [showProfilePopup, setShowProfilePopup] = useState(false);
    const [protocolStats, setProtocolStats] = useState([]);
    const [protocolLoading, setProtocolLoading] = useState(false);
    const [threatStats, setThreatStats] = useState({});
    const [threatLoading, setThreatLoading] = useState(false);

    useEffect(() => {
        if (!token || showOnlyIcon) return;
        
        let isActive = true;
        let interval = null;
        
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
                const alerts = await getLiveAlerts(token, 500);
                if (!isActive) return;
                
                const results = alerts.results || [];
                
                const counts = { safe: 0, medium: 0, high: 0 };
                results.forEach(alert => {
                    const level = alert.threat_level?.toLowerCase().trim() || '';
                    if (level === 'safe') {
                        counts.safe++;
                    } else if (level === 'medium') {
                        counts.medium++;
                    } else if (level === 'high') {
                        counts.high++;
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
            {/* US009: Packet Classification */}
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

            {/* US010: Protocol Statistics */}
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
        </div>
    );
};

export default Overview;
