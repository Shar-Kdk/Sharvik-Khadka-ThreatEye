import { useState, useEffect } from 'react';

const LiveTrafficTable = () => {
    const [packets, setPackets] = useState([
        { id: 1, time: '09:21:45', source: '192.168.1.105', destination: '8.8.8.8', protocol: 'TCP', size: 512, status: 'Allowed' },
        { id: 2, time: '09:21:46', source: '192.168.1.12', destination: '1.1.1.1', protocol: 'UDP', size: 128, status: 'Allowed' },
        { id: 3, time: '09:21:47', source: '10.0.0.5', destination: '192.168.1.1', protocol: 'ICMP', size: 64, status: 'Flagged' }
    ]);

    // Live data will be populated via WebSockets/API in future steps
    useEffect(() => {
        // Real-time data logic will go here
    }, []);

    return (
        <div className="bg-gray-800 rounded-xl border border-gray-700 overflow-hidden shadow-xl">
            <div className="p-4 border-b border-gray-700 flex justify-between items-center bg-gray-800/50">
                <h3 className="font-bold text-gray-200">Live Network Traffic</h3>
                <span className="flex items-center text-xs text-green-400">
                    <span className="w-2 h-2 bg-green-500 rounded-full animate-pulse mr-2"></span>
                    Live Capture
                </span>
            </div>
            <div className="overflow-x-auto">
                <table className="w-full text-left text-sm">
                    <thead>
                        <tr className="text-gray-400 border-b border-gray-700">
                            <th className="p-4 font-semibold">Time</th>
                            <th className="p-4 font-semibold">Source IP</th>
                            <th className="p-4 font-semibold">Destination IP</th>
                            <th className="p-4 font-semibold">Protocol</th>
                            <th className="p-4 font-semibold text-right">Size (B)</th>
                            <th className="p-4 font-semibold">Status</th>
                        </tr>
                    </thead>
                    <tbody className="divide-y divide-gray-700">
                        {packets.map((pkt) => (
                            <tr key={pkt.id} className="hover:bg-gray-700/50 transition-colors animate-in fade-in duration-500">
                                <td className="p-4 text-gray-400 font-mono text-xs">{pkt.time}</td>
                                <td className="p-4 text-gray-300 font-mono">{pkt.source}</td>
                                <td className="p-4 text-gray-300 font-mono">{pkt.destination}</td>
                                <td className="p-4">
                                    <span className={`px-2 py-0.5 rounded text-[10px] font-bold ${pkt.protocol === 'TCP' ? 'bg-blue-500/10 text-blue-400 border border-blue-500/20' :
                                        pkt.protocol === 'UDP' ? 'bg-purple-500/10 text-purple-400 border border-purple-500/20' :
                                            'bg-gray-500/10 text-gray-400 border border-gray-500/20'
                                        }`}>
                                        {pkt.protocol}
                                    </span>
                                </td>
                                <td className="p-4 text-right text-gray-400 font-mono">{pkt.size}</td>
                                <td className="p-4">
                                    <span className={`text-xs font-medium ${pkt.status === 'Flagged' ? 'text-red-400' : 'text-green-400'}`}>
                                        {pkt.status}
                                    </span>
                                </td>
                            </tr>
                        ))}
                    </tbody>
                </table>
            </div>
        </div>
    );
};

export default LiveTrafficTable;
