import { useState, useEffect } from 'react';
import IdsAnalyticsSection from '../../components/dashboard/IdsAnalyticsSection';

const AdminOverview = ({ token, latestWsAlert, wsClearSignal }) => {
    const [stats, setStats] = useState(null);
    const [loading, setLoading] = useState(true);
    const API_BASE_URL = import.meta.env.VITE_API_URL || 'http://localhost:8000';

    useEffect(() => {
        const fetchStats = async () => {
            try {
                const response = await fetch(`${API_BASE_URL}/subscriptions/platform-stats/`, {
                    headers: { 'Authorization': `Bearer ${token}` }
                });
                if (response.ok) {
                    const data = await response.json();
                    setStats(data);
                }
            } catch (error) {
                console.error("Error fetching admin stats:", error);
            } finally {
                setLoading(false);
            }
        };
        fetchStats();
    }, [token, API_BASE_URL]);

    if (loading) return <div className="text-gray-500 animate-pulse font-medium">Syncing Platform Metrics...</div>;
    if (!stats) return <div className="text-red-500 font-medium">Failed to load platform metrics.</div>;

    const cards = [
        { label: 'Total Users', value: stats.total_users, color: 'text-blue-500' },
        { label: 'Total Organizations', value: stats.total_organizations, color: 'text-purple-500' },
        { label: 'Active Subscriptions', value: stats.active_organizations, color: 'text-green-500' }
    ];

    return (
        <div className="space-y-8">
            <div className="bg-[#0d1117] p-8 rounded-xl border border-[#30363d]">
                <h2 className="text-xl font-bold text-white tracking-tight">Platform Performance</h2>
                <p className="text-gray-400 text-sm mt-1">Live metrics fetched from the production database.</p>
            </div>

            <IdsAnalyticsSection token={token} latestWsAlert={latestWsAlert} wsClearSignal={wsClearSignal} />

            <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                {cards.map((stat) => (
                    <div key={stat.label} className="bg-[#0d1117] p-8 rounded-xl border border-[#30363d]">
                        <p className="text-[10px] text-gray-500 uppercase tracking-widest font-bold mb-1">{stat.label}</p>
                        <p className="text-3xl font-black text-white">{stat.value}</p>
                    </div>
                ))}
            </div>

            <div className="grid grid-cols-1 gap-8">
                <div className="bg-[#0d1117] p-8 rounded-xl border border-[#30363d]">
                    <h3 className="text-sm font-bold text-gray-200 uppercase tracking-widest mb-6">Subscription Distribution</h3>
                    <div className="space-y-4">
                        {stats.plan_distribution?.map(plan => (
                            <div key={plan.name}>
                                <div className="flex justify-between text-xs mb-2">
                                    <span className="text-gray-400">{plan.name}</span>
                                    <span className="text-white font-bold">{plan.count} Organizations</span>
                                </div>
                                <div className="w-full bg-[#161b22] h-1.5 rounded-full overflow-hidden border border-[#30363d]">
                                    <div className="bg-blue-600 h-full" style={{ width: `${(plan.count / stats.total_organizations) * 100}%` }}></div>
                                </div>
                            </div>
                        ))}
                    </div>
                </div>
            </div>
        </div>
    );
};

export default AdminOverview;
