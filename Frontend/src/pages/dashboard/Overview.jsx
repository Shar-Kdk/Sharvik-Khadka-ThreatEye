import React from 'react';

const Overview = ({ user, subscription }) => {
    const formatDate = (dateString) => {
        if (!dateString) return 'Infinite';
        return new Date(dateString).toLocaleDateString('en-US', {
            year: 'numeric',
            month: 'long',
            day: 'numeric'
        });
    };

    return (
        <div className="space-y-8">
            {/* Header Row */}
            <div className="grid grid-cols-1 gap-6">
                <div className="bg-[#0d1117] p-8 rounded-xl border border-[#30363d] shadow-sm relative overflow-hidden">
                    <h3 className="text-sm font-bold text-gray-400 uppercase tracking-widest mb-6 border-b border-blue-500/30 pb-2 inline-block">Account Profile</h3>
                    <div className="grid grid-cols-2 md:grid-cols-4 gap-x-8 gap-y-4">
                        <div className="space-y-4">
                            <div>
                                <p className="text-[10px] text-gray-500 uppercase font-black tracking-tighter">First Name</p>
                                <p className="text-white font-bold">{user.first_name || 'Admin'}</p>
                            </div>
                        </div>
                        <div className="space-y-4">
                            <div>
                                <p className="text-[10px] text-gray-500 uppercase font-black tracking-tighter">Email Address</p>
                                <p className="text-white font-bold text-sm truncate">{user.email}</p>
                            </div>
                        </div>
                        <div className="space-y-4">
                            <div>
                                <p className="text-[10px] text-gray-500 uppercase font-black tracking-tighter">Organization</p>
                                <p className="text-white font-bold">{user.organization?.name || 'Academic Project'}</p>
                            </div>
                        </div>
                        <div className="space-y-4">
                            <div>
                                <p className="text-[10px] text-gray-500 uppercase font-black tracking-tighter font-black tracking-tighter">Account Role</p>
                                <span className="text-[10px] bg-blue-500/10 text-blue-400 px-2 py-0.5 rounded border border-blue-400/20 font-black uppercase inline-block mt-1">
                                    {user.role === 'org_admin' ? 'Organization Admin' : user.role}
                                </span>
                            </div>
                        </div>
                    </div>
                </div>
            </div>

            {/* Subscription Detail Section */}
            <div className="bg-[#0d1117] p-8 rounded-xl border border-[#30363d] shadow-sm">
                <div className="flex justify-between items-center mb-8">
                    <div>
                        <h3 className="text-lg font-bold text-white tracking-tight">Active Subscription</h3>
                    </div>
                    <span className={`px-4 py-1 rounded-full text-[10px] font-black uppercase tracking-[0.2em] shadow-sm border ${subscription?.status === 'active' ? 'bg-green-500/10 text-green-500 border-green-500/20' : 'bg-red-500/10 text-red-500 border-red-500/20'
                        }`}>
                        {subscription?.status || 'No License'}
                    </span>
                </div>

                <div className="grid grid-cols-1 md:grid-cols-4 gap-8">
                    <div className="space-y-1">
                        <p className="text-[10px] text-gray-500 uppercase font-bold tracking-widest leading-none">Current Plan</p>
                        <p className="text-xl font-black text-white uppercase tracking-tighter">{subscription?.plan || 'Platform Admin'}</p>
                    </div>
                    <div className="space-y-1">
                        <p className="text-[10px] text-gray-500 uppercase font-bold tracking-widest leading-none">Billing Cycle</p>
                        <p className="text-white font-bold">Monthly</p>
                    </div>
                    <div className="space-y-1">
                        <p className="text-[10px] text-gray-500 uppercase font-bold tracking-widest leading-none">Max Sessions/Users</p>
                        <p className="text-white font-bold">{subscription?.max_users || 'Unrestricted'}</p>
                    </div>
                    <div className="space-y-1">
                        <p className="text-[10px] text-gray-500 uppercase font-bold tracking-widest leading-none">Access Expiry</p>
                        <p className="text-white font-bold text-blue-400">
                            {subscription?.end_date ? formatDate(subscription.end_date) : 'Infinite Access'}
                        </p>
                    </div>
                </div>
            </div>

        </div>
    );
};

export default Overview;
