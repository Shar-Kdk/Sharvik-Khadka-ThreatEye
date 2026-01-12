import { useState, useEffect } from 'react';

const TrafficCharts = () => {
    const [stats, setStats] = useState({
        TCP: 1,
        UDP: 1,
        ICMP: 1,
        Other: 0
    });

    // Real-time statistical logic will go here
    useEffect(() => {
        // Future integration with backend API
    }, []);

    const total = stats.TCP + stats.UDP + stats.ICMP + stats.Other || 1;

    return (
        <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
            {/* Protocol Distribution */}
            <div className="bg-gray-800 p-6 rounded-xl border border-gray-700 shadow-lg">
                <h3 className="text-lg font-semibold text-gray-200 mb-6">Protocol Distribution</h3>
                <div className="space-y-4">
                    {Object.entries(stats).map(([proto, value]) => (
                        <div key={proto}>
                            <div className="flex justify-between text-xs mb-1">
                                <span className="text-gray-400 font-medium">{proto}</span>
                                <span className="text-gray-300">{value > 0 ? Math.round((value / total) * 100) : 0}%</span>
                            </div>
                            <div className="w-full bg-gray-700 rounded-full h-2 overflow-hidden">
                                <div
                                    className={`h-full rounded-full transition-all duration-1000 ${proto === 'TCP' ? 'bg-blue-500' :
                                        proto === 'UDP' ? 'bg-purple-500' :
                                            proto === 'ICMP' ? 'bg-red-500' : 'bg-gray-500'
                                        }`}
                                    style={{ width: `${value > 0 ? (value / total) * 100 : 0}%` }}
                                ></div>
                            </div>
                        </div>
                    ))}
                </div>
            </div>

            {/* Traffic Volume (Kbps) */}
            <div className="bg-gray-800 p-6 rounded-xl border border-gray-700 shadow-lg">
                <h3 className="text-lg font-semibold text-gray-200 mb-6">Traffic Volume (Kbps)</h3>
                <div className="flex items-end justify-start space-x-4 h-32 px-2">
                    {[...Array(3)].map((_, i) => {
                        const heights = ['80%', '40%', '20%']; // Matching 512, 128, 64
                        const values = [4.1, 1.0, 0.5]; // Kbps conversion
                        return (
                            <div key={i} className="w-6 h-full bg-blue-500/10 rounded-t relative group">
                                <div
                                    className="absolute bottom-0 w-full bg-blue-500 rounded-t transition-all duration-1000"
                                    style={{ height: heights[i] }}
                                >
                                    <div className="absolute -top-6 left-1/2 -translate-x-1/2 bg-gray-900 text-[10px] px-1 rounded opacity-0 group-hover:opacity-100 transition-opacity whitespace-nowrap">
                                        {values[i]} kbps
                                    </div>
                                </div>
                            </div>
                        )
                    })}
                </div>
                <div className="flex justify-between mt-4 text-[10px] text-gray-500 px-1 font-mono uppercase">
                    <span>10s ago</span>
                    <span>Now</span>
                </div>
            </div>
        </div>
    );
};

export default TrafficCharts;
