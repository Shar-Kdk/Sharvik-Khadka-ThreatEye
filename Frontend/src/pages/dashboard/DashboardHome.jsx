import { useState, useEffect } from 'react';
import { getDashboardSummary } from '../../services/api';

export default function DashboardHome({ token }) {
  const [summary, setSummary] = useState({
    totalAlerts24h: 0,
    alertsBySeverity: { high: 0, medium: 0, safe: 0 },
    activeThreats: 0,
    falsePositives: 0,
    topAttackType: 'N/A',
    mostTargetedIp: 'N/A',
    mostFrequentSourceIp: 'N/A',
    ingestionRunning: false,
    lastLogReceived: 'N/A'
  });
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);

  useEffect(() => {
    let active = true;
    const controller = new AbortController();

    const fetchSummary = async () => {
      if (!token) {
        setLoading(false);
        return;
      }

      try {
        const response = await getDashboardSummary(token, controller.signal);
        if (active) {
          setSummary(response);
          setError(null);
        }
      } catch (err) {
        if (active && err?.name !== 'AbortError') {
          setError(err.message);
          console.error('Failed to fetch dashboard summary:', err);
        }
      } finally {
        if (active) {
          setLoading(false);
        }
      }
    };

    fetchSummary();
    const interval = setInterval(fetchSummary, 30000);

    return () => {
      active = false;
      clearInterval(interval);
      controller.abort();
    };
  }, [token]);

  if (loading) {
    return <div className="p-6 text-gray-400">Loading dashboard...</div>;
  }

  const formatLocalTime = (isoString) => {
    if (!isoString || isoString === 'Never') return 'Never';
    try {
      const date = new Date(isoString);
      return date.toLocaleString();
    } catch {
      return isoString;
    }
  };

  return (
    <div className="p-6 space-y-6">
      {error && (
        <div className="bg-red-500/10 border border-red-500/30 text-red-300 px-4 py-3 rounded">
          Error: {error}
        </div>
      )}

      {/* Row 0: System Status (Top) */}
      <div className="bg-[#0d1117] border border-[#30363d] rounded-lg p-6">
        <div className="flex items-center justify-between">
          <div>
            <h3 className="text-gray-400 text-sm font-medium mb-3">System Status</h3>
            <div className="space-y-2">
              <div className="text-gray-300">
                Ingestion: 
                <span className={`ml-2 font-semibold ${summary.ingestionRunning ? 'text-green-400' : 'text-red-400'}`}>
                  {summary.ingestionRunning ? 'Running' : 'Stopped'}
                </span>
              </div>
              <div className="text-gray-300">
                Last Log: 
                <span className="ml-2 font-mono text-gray-400">{formatLocalTime(summary.lastLogReceived)}</span>
              </div>
            </div>
          </div>
        </div>
      </div>

      {/* Row 1: Total Alerts & Severity Breakdown */}
      <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
        {/* Total Alerts */}
        <div className="bg-[#0d1117] border border-[#30363d] rounded-lg p-6">
          <div className="text-gray-400 text-sm font-medium mb-2">Total Alerts (24h)</div>
          <div className="text-4xl font-bold text-white">{summary.totalAlerts24h}</div>
          <div className="text-xs text-gray-500 mt-2">All severity levels</div>
        </div>

        {/* High Severity */}
        <div className="bg-[#0d1117] border border-[#30363d] rounded-lg p-6">
          <div className="text-gray-400 text-sm font-medium mb-2">High Severity</div>
          <div className="text-4xl font-bold text-red-400">{summary.alertsBySeverity.high}</div>
          <div className="text-xs text-gray-500 mt-2">Critical alerts</div>
        </div>

        {/* Medium Severity */}
        <div className="bg-[#0d1117] border border-[#30363d] rounded-lg p-6">
          <div className="text-gray-400 text-sm font-medium mb-2">Medium</div>
          <div className="text-4xl font-bold text-yellow-400">{summary.alertsBySeverity.medium}</div>
          <div className="text-xs text-gray-500 mt-2">Moderate alerts</div>
        </div>

        {/* Safe */}
        <div className="bg-[#0d1117] border border-[#30363d] rounded-lg p-6">
          <div className="text-gray-400 text-sm font-medium mb-2">Safe</div>
          <div className="text-4xl font-bold text-green-400">{summary.alertsBySeverity.safe}</div>
          <div className="text-xs text-gray-500 mt-2">Benign traffic</div>
        </div>
      </div>

      {/* Row 2: Active Threats & False Positives */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
        {/* Active Threats */}
        <div className="bg-[#0d1117] border border-[#30363d] rounded-lg p-6">
          <div className="text-gray-400 text-sm font-medium mb-2">Active Threats</div>
          <div className="text-4xl font-bold text-white">{summary.activeThreats}</div>
          <div className="text-xs text-gray-500 mt-2">Unresolved / Not acknowledged</div>
        </div>

        {/* False Positives */}
        <div className="bg-[#0d1117] border border-[#30363d] rounded-lg p-6">
          <div className="text-gray-400 text-sm font-medium mb-2">False Positives</div>
          <div className="text-4xl font-bold text-blue-400">{summary.falsePositives}</div>
          <div className="text-xs text-gray-500 mt-2">ML classification benign</div>
        </div>
      </div>

      {/* Row 3: Attack Details */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
        {/* Top Attack Type */}
        <div className="bg-[#0d1117] border border-[#30363d] rounded-lg p-6">
          <div className="text-gray-400 text-sm font-medium mb-2">Top Attack Type</div>
          <div className="text-2xl font-bold text-white truncate">{summary.topAttackType}</div>
          <div className="text-xs text-gray-500 mt-2">Most frequent alert</div>
        </div>

        {/* Most Targeted IP */}
        <div className="bg-[#0d1117] border border-[#30363d] rounded-lg p-6">
          <div className="text-gray-400 text-sm font-medium mb-2">Most Targeted IP</div>
          <div className="text-lg font-mono text-white bg-black/20 px-3 py-2 rounded break-all">
            {summary.mostTargetedIp}
          </div>
          <div className="text-xs text-gray-500 mt-2">Target of attacks</div>
        </div>

        {/* Most Frequent Source IP */}
        <div className="bg-[#0d1117] border border-[#30363d] rounded-lg p-6">
          <div className="text-gray-400 text-sm font-medium mb-2">Most Frequent Source IP</div>
          <div className="text-lg font-mono text-white bg-black/20 px-3 py-2 rounded break-all">
            {summary.mostFrequentSourceIp}
          </div>
          <div className="text-xs text-gray-500 mt-2">Primary attacker</div>
        </div>
      </div>

      {/* Row 4: System Status */}
      <div className="hidden">
        Hidden
      </div>
    </div>
  );
}