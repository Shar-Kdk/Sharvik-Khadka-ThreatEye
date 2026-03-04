import React, { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import { getPaymentHistory } from '../../services/api';
import Pagination from '../../components/common/Pagination';

const SubscriptionHistory = ({ token }) => {
    const [history, setHistory] = useState([]);
    const [loading, setLoading] = useState(true);
    const [itemsPerPage, setItemsPerPage] = useState(5);
    const [currentPage, setCurrentPage] = useState(1);
    const navigate = useNavigate();

    const formatAmount = (amount) => {
        const numericAmount = Number(amount);
        if (!Number.isFinite(numericAmount)) return '$0.00';
        return `$${numericAmount.toFixed(2)}`;
    };

    useEffect(() => {
        const fetchHistory = async () => {
            try {
                const data = await getPaymentHistory(token);
                setHistory(data);
            } catch (error) {
                console.error("Error fetching history:", error);
            } finally {
                setLoading(false);
            }
        };

        if (token) fetchHistory();
    }, [token]);

    // Pagination Logic
    const lastItemIndex = currentPage * itemsPerPage;
    const firstItemIndex = lastItemIndex - itemsPerPage;
    const currentItems = history.slice(firstItemIndex, lastItemIndex);

    if (loading) {
        return (
            <div className="min-h-screen bg-[#010409] text-gray-400 flex items-center justify-center">
                <p className="animate-pulse">Loading subscription history...</p>
            </div>
        );
    }

    return (
        <div className="space-y-6">
            <div className="flex justify-between items-center mb-6">
                <div>
                    <h2 className="text-xl font-bold text-white uppercase tracking-tight">Subscription History</h2>
                    <p className="text-xs text-gray-500 mt-1">View all your past and current plan activities.</p>
                </div>
                <button
                    onClick={() => navigate('/dashboard/subscription')}
                    className="text-xs font-bold text-gray-400 hover:text-white uppercase tracking-widest bg-[#0d1117] border border-[#30363d] px-4 py-2 rounded-lg transition-all"
                >
                    &larr; Back to Plan
                </button>
            </div>

            <div className="bg-[#0d1117] border border-[#30363d] rounded-lg overflow-hidden shadow-2xl">
                {history.length === 0 ? (
                    <div className="p-20 text-center">
                        <div className="w-16 h-16 bg-[#161b22] rounded-full flex items-center justify-center mx-auto mb-4 border border-[#30363d]">
                            <span className="text-2xl">📄</span>
                        </div>
                        <p className="text-gray-400 text-sm">No subscription history found for your organization.</p>
                        <button
                          onClick={() => navigate('/subscriptions/plans')}
                          className="mt-4 text-blue-500 text-xs font-bold uppercase tracking-widest hover:underline"
                        >
                          Explore Plans
                        </button>
                    </div>
                ) : (
                    <>
                        <div className="overflow-x-auto">
                            <table className="w-full text-left text-sm text-gray-400">
                                <thead className="bg-[#161b22] text-[10px] uppercase text-gray-500 font-black tracking-[0.2em] border-b border-[#30363d]">
                                    <tr>
                                        <th className="px-8 py-5">Date</th>
                                        <th className="px-8 py-5">Plan Tier</th>
                                        <th className="px-8 py-5">Amount</th>
                                        <th className="px-8 py-5">Status</th>
                                        <th className="px-8 py-5">Active Period</th>
                                    </tr>
                                </thead>
                                <tbody className="divide-y divide-[#30363d]">
                                    {currentItems.map((item) => (
                                        <tr key={item.id} className="hover:bg-[#161b22]/50 transition-colors group">
                                            <td className="px-8 py-6 font-mono text-xs text-gray-300">
                                                {new Date(item.created_at).toLocaleDateString('en-US', {
                                                    year: 'numeric',
                                                    month: 'short',
                                                    day: 'numeric'
                                                })}
                                            </td>
                                            <td className="px-8 py-6">
                                                <div className="flex flex-col">
                                                    <span className="text-white font-bold tracking-tight uppercase">{item.plan_name}</span>
                                                    <span className="text-[10px] text-gray-500 mt-0.5">Monthly Billing</span>
                                                </div>
                                            </td>
                                            <td className="px-8 py-6">
                                                <span className="text-gray-200 font-medium">{formatAmount(item.amount)}</span>
                                            </td>
                                            <td className="px-8 py-6">
                                                <span className={`px-3 py-1 rounded-full text-[9px] font-black uppercase tracking-widest border ${
                                                    item.status === 'active' || item.status === 'completed' ? 'bg-green-500/10 text-green-500 border-green-500/20' :
                                                    item.status === 'pending' ? 'bg-yellow-500/10 text-yellow-500 border-yellow-500/20' :
                                                    'bg-red-500/10 text-red-500 border-red-500/20'
                                                }`}>
                                                    {item.status}
                                                </span>
                                            </td>
                                            <td className="px-8 py-6 text-gray-500 text-xs tabular-nums">
                                                {item.start_date ? new Date(item.start_date).toLocaleDateString() : 'N/A'} 
                                                <span className="mx-2 opacity-50">&rarr;</span>
                                                {item.end_date ? new Date(item.end_date).toLocaleDateString() : 'N/A'}
                                            </td>
                                        </tr>
                                    ))}
                                </tbody>
                            </table>
                        </div>

                        <Pagination
                            totalItems={history.length}
                            itemsPerPage={itemsPerPage}
                            currentPage={currentPage}
                            onPageChange={setCurrentPage}
                            onItemsPerPageChange={(newVal) => {
                                setItemsPerPage(newVal);
                                setCurrentPage(1);
                            }}
                        />
                    </>
                )}
            </div>

            <div className="p-6 bg-blue-500/5 border border-blue-500/10 rounded-xl">
                <div className="flex items-start space-x-4">
                    <div className="text-blue-500 mt-1">
                        <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M13 16h-1v-4h-1m1-4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z" />
                        </svg>
                    </div>
                    <div>
                        <h4 className="text-sm font-bold text-blue-400">Billing Information</h4>
                        <p className="text-xs text-blue-400/70 mt-1 leading-relaxed">
                            Detailed invoice history, tax documents, and payment method management are handled securely through the Stripe Customer Portal. 
                            Contact support if you need assistance with specific billing records.
                        </p>
                    </div>
                </div>
            </div>
        </div>
    );
};

export default SubscriptionHistory;
