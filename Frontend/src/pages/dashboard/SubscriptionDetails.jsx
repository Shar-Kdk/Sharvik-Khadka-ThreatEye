import React from 'react';
import { Link } from 'react-router-dom';

const SubscriptionDetails = ({ subscription }) => {
    const formatDate = (dateString) => {
        if (!dateString) return 'Infinite';
        return new Date(dateString).toLocaleDateString('en-US', {
            year: 'numeric',
            month: 'long',
            day: 'numeric',
            hour: '2-digit',
            minute: '2-digit'
        });
    };

    return (
        <div className="space-y-6">
            {!subscription || subscription.status === 'none' ? (
                <div className="bg-[#0d1117] border border-[#30363d] rounded-lg p-8 text-center">
                    <h2 className="text-xl font-bold text-white mb-2">No Active Subscription</h2>
                    <p className="text-gray-400 mb-6 text-sm">You currently don't have an active plan. Subscribe to gain full access.</p>
                    <Link
                        to="/subscriptions/plans"
                        className="inline-block bg-blue-600 hover:bg-blue-500 text-white font-bold py-2 px-6 rounded-md transition-colors text-sm"
                    >
                        View Plans
                    </Link>
                </div>
            ) : (
                <div className="bg-[#0d1117] border border-[#30363d] rounded-lg overflow-hidden">
                    <div className="p-6 border-b border-[#30363d] flex justify-between items-center bg-[#161b22]/50">
                        <h2 className="text-lg font-bold text-white">Current Subscription</h2>
                        <span className={`px-3 py-1 rounded-full text-[10px] font-black uppercase tracking-widest border ${subscription.status === 'active'
                                ? 'bg-green-500/10 text-green-500 border-green-500/20'
                                : 'bg-yellow-500/10 text-yellow-500 border-yellow-500/20'
                            }`}>
                            {subscription.status}
                        </span>
                    </div>

                    <div className="p-6 grid grid-cols-1 md:grid-cols-2 gap-8">
                        <div className="space-y-4">
                            <div>
                                <p className="text-[10px] text-gray-500 uppercase font-black tracking-widest mb-1">Plan Tier</p>
                                <p className="text-xl font-bold text-white uppercase tracking-tight">{subscription.plan}</p>
                            </div>
                            <div>
                                <p className="text-[10px] text-gray-500 uppercase font-black tracking-widest mb-1">Node Capacity</p>
                                <p className="text-white font-medium">{subscription.max_users} Concurrent Nodes</p>
                            </div>
                            <div>
                                <p className="text-[10px] text-gray-500 uppercase font-black tracking-widest mb-1">Features</p>
                                <p className="text-white font-medium">
                                    {subscription.email_alerts ? "Real-time Email Alerts Included" : "Standard Dashboard Monitoring"}
                                </p>
                            </div>
                        </div>

                        <div className="space-y-4">
                            <div className="p-4 bg-[#161b22] rounded-lg border border-[#30363d]">
                                <div className="mb-4">
                                    <p className="text-[10px] text-gray-400 uppercase font-black tracking-widest mb-1">Activated On</p>
                                    <p className="text-sm font-mono text-blue-400">{formatDate(subscription.start_date)}</p>
                                </div>
                                <div>
                                    <p className="text-[10px] text-gray-400 uppercase font-black tracking-widest mb-1">Renews/Expires On</p>
                                    <p className="text-sm font-mono text-green-400">{formatDate(subscription.end_date)}</p>
                                </div>
                            </div>
                        </div>
                    </div>

                    <div className="p-6 bg-[#010409] border-t border-[#30363d] flex justify-end">
                        <Link
                            to="/subscriptions/plans"
                            className="text-xs font-bold text-blue-500 hover:text-blue-400 uppercase tracking-widest"
                        >
                            Upgrade or Change Plan &rarr;
                        </Link>
                    </div>
                </div>
            )}

            {/* Link to Subscription History Page */}
            <div className="flex justify-center">
                <Link
                    to="/dashboard/subscription/history"
                    className="text-xs font-bold text-gray-500 hover:text-white uppercase tracking-widest bg-[#0d1117] border border-[#30363d] px-6 py-2 rounded-full transition-all hover:border-gray-500"
                >
                    View Subscription History
                </Link>
            </div>

            <div className="p-4 bg-blue-500/5 border border-blue-500/10 rounded-lg">
                <p className="text-xs text-blue-400 text-center">
                    Invoice history and billing management are available via the Stripe Customer Portal.
                </p>
            </div>
        </div>
    );
};

export default SubscriptionDetails;
