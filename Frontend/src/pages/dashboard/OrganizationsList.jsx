import { useState, useEffect } from 'react';
import Pagination from '../../components/common/Pagination';

const OrganizationsList = ({ token }) => {
    const [orgs, setOrgs] = useState([]);
    const [loading, setLoading] = useState(true);
    const [itemsPerPage, setItemsPerPage] = useState(5);
    const [currentPage, setCurrentPage] = useState(1);
    const API_BASE_URL = import.meta.env.VITE_API_URL || 'http://localhost:8000';

    useEffect(() => {
        const fetchOrgs = async () => {
            try {
                const response = await fetch(`${API_BASE_URL}/subscriptions/platform-stats/`, {
                    headers: { 'Authorization': `Bearer ${token}` }
                });
                if (response.ok) {
                    const data = await response.json();
                    setOrgs(data.organizations || []);
                }
            } catch (error) {
                console.error("Error fetching organizations:", error);
            } finally {
                setLoading(false);
            }
        };
        fetchOrgs();
    }, [token]);

    // Pagination Logic
    const lastItemIndex = currentPage * itemsPerPage;
    const firstItemIndex = lastItemIndex - itemsPerPage;
    const currentItems = orgs.slice(firstItemIndex, lastItemIndex);

    if (loading) return <div className="text-gray-500 animate-pulse font-medium p-8">Loading Subscriber Directory...</div>;

    return (
        <div className="bg-[#0d1117] rounded-xl border border-[#30363d] overflow-hidden shadow-xl">
            <div className="p-6 border-b border-[#30363d] flex justify-between items-center bg-[#161b22]/50">
                <h3 className="font-bold text-gray-200 text-sm uppercase tracking-widest">Subscriber Organizations</h3>
                <span className="text-[10px] bg-blue-500/10 text-blue-400 px-3 py-1 rounded-full border border-blue-400/20 font-bold uppercase tracking-widest">
                    {orgs.length} Total
                </span>
            </div>
            <div className="overflow-x-auto">
                <table className="w-full text-left text-sm">
                    <thead className="bg-[#161b22] text-gray-400">
                        <tr>
                            <th className="p-4 font-bold uppercase text-[10px] tracking-widest border-b border-[#30363d]">Organization Name</th>
                            <th className="p-4 font-bold uppercase text-[10px] tracking-widest border-b border-[#30363d]">Tier</th>
                            <th className="p-4 font-bold uppercase text-[10px] tracking-widest border-b border-[#30363d] text-center">Users</th>
                            <th className="p-4 font-bold uppercase text-[10px] tracking-widest border-b border-[#30363d]">Status</th>
                            <th className="p-4 font-bold uppercase text-[10px] tracking-widest border-b border-[#30363d] text-right">Renewal Date</th>
                        </tr>
                    </thead>
                    <tbody className="text-gray-300">
                        {currentItems.length > 0 ? currentItems.map((org) => (
                            <tr key={org.id} className="hover:bg-[#161b22] transition-colors">
                                <td className="p-4 border-b border-[#30363d] font-bold text-white tracking-tight">{org.name}</td>
                                <td className="p-4 border-b border-[#30363d]">
                                    <span className={`text-[10px] px-2 py-0.5 rounded font-black uppercase tracking-tighter ${org.plan.toLowerCase().includes('enterprise') ? 'border border-purple-500/30 text-purple-400 bg-purple-500/10' :
                                        org.plan.toLowerCase().includes('professional') ? 'border border-blue-500/30 text-blue-400 bg-blue-500/10' :
                                            'border border-gray-500/30 text-gray-400 bg-gray-500/10'
                                        }`}>
                                        {org.plan}
                                    </span>
                                </td>
                                <td className="p-4 border-b border-[#30363d] text-center font-mono text-xs">{org.users}</td>
                                <td className="p-4 border-b border-[#30363d]">
                                    <span className={`text-[9px] font-bold uppercase ${org.status === 'active' ? 'text-green-500' : 'text-red-500'}`}>
                                        {org.status}
                                    </span>
                                </td>
                                <td className="p-4 border-b border-[#30363d] text-right font-mono text-xs text-gray-500">
                                    {org.renewal !== 'N/A' ? new Date(org.renewal).toLocaleDateString() : 'N/A'}
                                </td>
                            </tr>
                        )) : (
                            <tr>
                                <td colSpan="5" className="p-12 text-center text-gray-500 italic">No organizations found in the system.</td>
                            </tr>
                        )}
                    </tbody>
                </table>
            </div>
            
            <Pagination
                totalItems={orgs.length}
                itemsPerPage={itemsPerPage}
                currentPage={currentPage}
                onPageChange={setCurrentPage}
                onItemsPerPageChange={(newVal) => {
                    setItemsPerPage(newVal);
                    setCurrentPage(1);
                }}
            />
        </div>
    );
};

export default OrganizationsList;
