import { useEffect, useState } from 'react';
import {
  getAlertsTimeline,
  getThreatLevelDistribution,
  getTopAttacks,
  getProtocolStatistics,
} from '../../services/api';
import ThreatLevelDonutChart from '../charts/ThreatLevelDonutChart';
import TopAttacksBarChart from '../charts/TopAttacksBarChart';
import AlertsTimelineChart from '../charts/AlertsTimelineChart';
import ProtocolStatsChart from '../charts/ProtocolStatsChart';

export default function IdsAnalyticsSection({ token }) {
  const [threatDistribution, setThreatDistribution] = useState([]);
  const [topAttacks, setTopAttacks] = useState([]);
  const [alertsTimeline, setAlertsTimeline] = useState([]);
  const [protocolStats, setProtocolStats] = useState([]);
  const [lastSyncedAt, setLastSyncedAt] = useState(null);
  const [error, setError] = useState('');

  useEffect(() => {
    let active = true;

    const fetchAnalytics = async () => {
      const controller = new AbortController();
      const timeoutId = setTimeout(() => controller.abort(), 8000);

      try {
        const [distributionPayload, topAttacksPayload, timelinePayload, protocolPayload] = await Promise.all([
          getThreatLevelDistribution(token, controller.signal),
          getTopAttacks(token, controller.signal),
          getAlertsTimeline(token, controller.signal),
          getProtocolStatistics(token, controller.signal),
        ]);

        if (!active) {
          return;
        }

        setThreatDistribution(distributionPayload.results || []);
        setTopAttacks(topAttacksPayload.results || []);
        setAlertsTimeline(timelinePayload.results || []);
        setProtocolStats(protocolPayload.results || []);
        setLastSyncedAt(new Date());
        setError('');
      } catch (err) {
        if (!active) {
          return;
        }
        if (err?.name === 'AbortError') {
          setError('Analytics request timed out. Retrying...');
        } else {
          setError(err.message || 'Failed to fetch analytics');
        }
      } finally {
        clearTimeout(timeoutId);
      }
    };

    fetchAnalytics();
    const intervalId = setInterval(fetchAnalytics, 5000);

    return () => {
      active = false;
      clearInterval(intervalId);
    };
  }, [token]);

  return (
    <div className="bg-[#0d1117] border border-[#30363d] rounded-xl p-6">
      <div className="flex flex-wrap gap-3 items-center justify-between">
        <div>
          <h2 className="text-white text-lg font-bold">IDS Analytics Dashboard</h2>
          <p className="text-sm text-gray-400 mt-1">
            Real-time analytics refreshed every 5 seconds from alerts data.
          </p>
        </div>
        <p className="text-xs text-gray-500">
          Last sync: {lastSyncedAt ? lastSyncedAt.toLocaleTimeString() : 'Waiting...'}
        </p>
      </div>

      {error && (
        <div className="mt-4 px-4 py-3 bg-red-500/10 border border-red-500/20 rounded-lg text-sm text-red-300">
          {error}
        </div>
      )}

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6 mt-6">
        <ThreatLevelDonutChart data={threatDistribution} />
        <TopAttacksBarChart data={topAttacks} />
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6 mt-6">
        <ProtocolStatsChart data={protocolStats} />
      </div>

      <div className="mt-6">
        <AlertsTimelineChart data={alertsTimeline} />
      </div>
    </div>
  );
}
