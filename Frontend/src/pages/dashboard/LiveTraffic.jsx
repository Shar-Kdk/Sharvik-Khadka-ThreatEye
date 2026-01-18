import { useEffect, useMemo, useState } from 'react';
import { getLiveAlerts } from '../../services/api';
import Pagination from '../../components/common/Pagination';

const MAX_ROWS_PER_PAGE = 50;

const THREAT_STYLES = {
  safe: 'bg-green-500/20 text-green-300 border border-green-400/30',
  medium: 'bg-yellow-500/20 text-yellow-300 border border-yellow-400/30',
  high: 'bg-red-500/20 text-red-300 border border-red-400/30',
};

function formatEndpoint(ip, port) {
  return port ? `${ip}:${port}` : ip;
}

function formatTimestamp(value) {
  try {
    return new Date(value).toLocaleString();
  } catch {
    return value;
  }
}

export default function LiveTraffic({ token }) {
  const [alerts, setAlerts] = useState([]);
  const [isLoading, setIsLoading] = useState(true);
  const [error, setError] = useState('');
  const [lastSyncedAt, setLastSyncedAt] = useState(null);
  const [currentPage, setCurrentPage] = useState(1);
  const [itemsPerPage, setItemsPerPage] = useState(MAX_ROWS_PER_PAGE);

  useEffect(() => {
    let active = true;

    const fetchAlerts = async () => {
      const controller = new AbortController();
      const timeoutId = setTimeout(() => controller.abort(), 8000);

      try {
        const payload = await getLiveAlerts(token, 500, controller.signal);
        if (!active) {
          return;
        }
        setAlerts(payload.results || []);
        setError('');
        setLastSyncedAt(new Date());
      } catch (err) {
        if (!active) {
          return;
        }
        if (err?.name === 'AbortError') {
          setError('Live traffic request timed out. Retrying...');
        } else {
          setError(err.message || 'Failed to fetch live traffic');
        }
      } finally {
        clearTimeout(timeoutId);
        if (active) {
          setIsLoading(false);
        }
      }
    };

    fetchAlerts();
    const intervalId = setInterval(fetchAlerts, 5000);

    return () => {
      active = false;
      clearInterval(intervalId);
    };
  }, [token]);

  const summary = useMemo(() => {
    const counts = { safe: 0, medium: 0, high: 0 };
    alerts.forEach((alert) => {
      const level = alert.threat_level;
      if (counts[level] !== undefined) {
        counts[level] += 1;
      }
    });
    return counts;
  }, [alerts]);

  const totalPages = Math.max(1, Math.ceil(alerts.length / itemsPerPage));

  useEffect(() => {
    if (currentPage > totalPages) {
      setCurrentPage(totalPages);
    }
  }, [currentPage, totalPages]);

  const paginatedAlerts = useMemo(() => {
    const start = (currentPage - 1) * itemsPerPage;
    const end = start + itemsPerPage;
    return alerts.slice(start, end);
  }, [alerts, currentPage, itemsPerPage]);

  return (
    <div className="space-y-6">
      <div className="bg-[#0d1117] border border-[#30363d] rounded-xl p-6">
        <div className="flex flex-wrap gap-3 items-center justify-between">
          <div>
            <h2 className="text-white text-lg font-bold">Live Network Traffic</h2>
            <p className="text-sm text-gray-400 mt-1">
              Auto-refresh every 5 seconds from Snort alerts.
            </p>
          </div>
          <p className="text-xs text-gray-500">
            Last sync: {lastSyncedAt ? lastSyncedAt.toLocaleTimeString() : 'Waiting...'}
          </p>
        </div>

        <div className="grid grid-cols-2 md:grid-cols-4 gap-3 mt-4">
          {Object.entries(summary).map(([level, count]) => (
            <div key={level} className="bg-[#161b22] rounded-lg border border-[#30363d] px-4 py-3">
              <p className="text-[11px] uppercase tracking-wider text-gray-400">{level}</p>
              <p className="text-2xl font-bold text-white mt-1">{count}</p>
            </div>
          ))}
        </div>
      </div>

      <div className="bg-[#0d1117] border border-[#30363d] rounded-xl overflow-hidden">
        {error && (
          <div className="px-4 py-3 bg-red-500/10 border-b border-red-500/20 text-sm text-red-300">
            {error}
          </div>
        )}
        {isLoading ? (
          <div className="p-8 text-center text-gray-400">Loading live traffic...</div>
        ) : (
          <div className="overflow-auto">
            <table className="min-w-full text-sm">
              <thead className="bg-[#161b22] text-gray-300 uppercase text-xs tracking-wider">
                <tr>
                  <th className="text-left px-4 py-3">Time</th>
                  <th className="text-left px-4 py-3">Source</th>
                  <th className="text-left px-4 py-3">Destination</th>
                  <th className="text-left px-4 py-3">Protocol</th>
                  <th className="text-left px-4 py-3">SID</th>
                  <th className="text-left px-4 py-3">Message</th>
                  <th className="text-left px-4 py-3">Threat</th>
                </tr>
              </thead>
              <tbody>
                {alerts.length === 0 && (
                  <tr>
                    <td colSpan={7} className="px-4 py-8 text-center text-gray-400">
                      No alerts ingested yet.
                    </td>
                  </tr>
                )}
                {paginatedAlerts.map((alert) => (
                  <tr key={alert.id} className="border-t border-[#222a35] hover:bg-[#111827]">
                    <td className="px-4 py-3 whitespace-nowrap">{formatTimestamp(alert.timestamp)}</td>
                    <td className="px-4 py-3 whitespace-nowrap">{formatEndpoint(alert.src_ip, alert.src_port)}</td>
                    <td className="px-4 py-3 whitespace-nowrap">{formatEndpoint(alert.dest_ip, alert.dest_port)}</td>
                    <td className="px-4 py-3">{alert.protocol}</td>
                    <td className="px-4 py-3">{alert.sid}</td>
                    <td className="px-4 py-3 max-w-[420px] truncate" title={alert.message}>{alert.message}</td>
                    <td className="px-4 py-3">
                      <span className={`inline-block px-2 py-1 rounded text-[11px] font-semibold uppercase ${THREAT_STYLES[alert.threat_level] || THREAT_STYLES.safe}`}>
                        {alert.threat_level}
                      </span>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
        {!isLoading && alerts.length > 0 && (
          <Pagination
            totalItems={alerts.length}
            itemsPerPage={itemsPerPage}
            currentPage={currentPage}
            onPageChange={setCurrentPage}
            onItemsPerPageChange={(value) => {
              setItemsPerPage(Math.min(MAX_ROWS_PER_PAGE, value));
              setCurrentPage(1);
            }}
            itemsPerPageOptions={[10, 20, 50]}
          />
        )}
      </div>
    </div>
  );
}
