import { useEffect, useMemo, useRef, useState } from 'react';
import { getLiveAlerts } from '../../services/api';
import Pagination from '../../components/common/Pagination';

const MAX_ROWS_PER_PAGE = 50;
const MAX_ITEMS_PER_PAGE = 500;

const BASE_URL = (import.meta.env.VITE_API_URL || 'http://localhost:8000').replace(/\/$/, '');
const POLL_INTERVAL = 3000; // Poll every 3 seconds

const THREAT_STYLES = {
  safe: 'bg-green-500/20 text-green-300 border border-green-400/30',
  medium: 'bg-yellow-500/20 text-yellow-300 border border-yellow-400/30',
  high: 'bg-red-500/20 text-red-300 border border-red-400/30',
};

function formatTimestamp(value) {
  try {
    return new Date(value).toLocaleString();
  } catch {
    return value;
  }
}

function formatPort(port) {
  if (port === null || port === undefined) {
    return '-';
  }
  return String(port);
}

export default function LiveTraffic({ token }) {
  const [alerts, setAlerts] = useState([]);
  const [isLoading, setIsLoading] = useState(true);
  const [error, setError] = useState('');
  const [lastSyncedAt, setLastSyncedAt] = useState(null);
  const [currentPage, setCurrentPage] = useState(1);
  const [itemsPerPage, setItemsPerPage] = useState(MAX_ROWS_PER_PAGE);
  const seenAlertIdsRef = useRef(new Set());

  // Fetch alerts only on initial page load
  useEffect(() => {
    let active = true;

    const fetchAlerts = async () => {
      console.log('[LiveTraffic] Starting fetch with token:', token ? token.substring(0, 20) + '...' : 'NO TOKEN');
      const controller = new AbortController();
      const timeoutId = setTimeout(() => controller.abort(), 8000);

      try {
        const livePayload = await getLiveAlerts(token, MAX_ITEMS_PER_PAGE, controller.signal);
        console.log('[LiveTraffic] Fetch succeeded, got', livePayload?.results?.length || 0, 'results');

        if (!active) {
          return;
        }

        const results = livePayload.results || [];
        // CRITICAL FIX: Merge with WS updates that arrived during fetch
        // Fetch results and merge with previous data
        setAlerts((prev) => {
          const seenIds = new Set(results.map(r => r.id));
          const merged = [
            ...results,  // Fresh REST data first
            ...prev.filter(p => !seenIds.has(p.id))  // Keep WS-added alerts not in REST
          ];
          seenAlertIdsRef.current = new Set(merged.map(a => a.id));
          console.log('[LiveTraffic] Merged alerts, total now:', merged.length);
          return merged.slice(0, MAX_ITEMS_PER_PAGE);
        });
        setError('');
        setLastSyncedAt(new Date());
      } catch (err) {
        console.error('[LiveTraffic] Fetch failed:', err);
        if (!active) {
          return;
        }
        if (err?.name === 'AbortError') {
          setError('Initial load timed out. Please refresh.');
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

    return () => {
      active = false;
    };
  }, [token]);

  // Polling for live updates (replaces WebSocket)
  useEffect(() => {
    if (!token) {
      return;
    }

    let active = true;
    let intervalId;

    const poll = async () => {
      try {
        const livePayload = await getLiveAlerts(token, MAX_ITEMS_PER_PAGE);
        if (!active) {
          return;
        }

        const results = livePayload.results || [];
        setAlerts((prev) => {
          const seenIds = new Set(results.map(r => r.id));
          const merged = [
            ...results,
            ...prev.filter(p => !seenIds.has(p.id))
          ];
          seenAlertIdsRef.current = new Set(merged.map(a => a.id));
          return merged.slice(0, MAX_ITEMS_PER_PAGE);
        });
        setLastSyncedAt(new Date());
        setError('');
      } catch (err) {
        console.error('[LiveTraffic] Polling failed:', err);
        if (active) {
          setError('Failed to fetch live traffic. Retrying...');
        }
      }
    };

    // Initial poll
    poll();

    // Set up polling interval
    intervalId = setInterval(poll, POLL_INTERVAL);

    return () => {
      active = false;
      clearInterval(intervalId);
    };
  }, [token]);

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
            <div className="flex gap-4 mt-2">
              <p className="text-sm text-gray-300">
                <span className="font-semibold text-blue-400">{alerts.length}</span> alerts detected
              </p>
            </div>
          </div>
          <p className="text-xs text-gray-500">
            Last sync: {lastSyncedAt ? lastSyncedAt.toLocaleTimeString() : 'Waiting...'}
          </p>
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
          <div className="overflow-x-hidden">
            <table className="w-full table-fixed text-xs">
              <thead className="bg-[#161b22] text-gray-300 uppercase text-xs tracking-wider">
                <tr>
                  <th className="text-left px-3 py-3 w-[14%]">Time</th>
                  <th className="text-left px-3 py-3 w-[17%]">Source</th>
                  <th className="text-left px-3 py-3 w-[17%]">Destination</th>
                  <th className="text-left px-3 py-3 w-[8%]">Protocol</th>
                  <th className="text-left px-3 py-3 w-[9%]">SID</th>
                  <th className="text-left px-3 py-3 w-[27%]">Message</th>
                  <th className="text-left px-3 py-3 w-[8%]">Threat</th>
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
                    <td className="px-3 py-3 align-top">{formatTimestamp(alert.timestamp)}</td>
                    <td className="px-3 py-3 align-top">
                      <div className="leading-tight break-all">{alert.src_ip}</div>
                      <div className="text-[11px] text-gray-500">Port: {formatPort(alert.src_port)}</div>
                    </td>
                    <td className="px-3 py-3 align-top">
                      <div className="leading-tight break-all">{alert.dest_ip}</div>
                      <div className="text-[11px] text-gray-500">Port: {formatPort(alert.dest_port)}</div>
                    </td>
                    <td className="px-3 py-3 align-top">{alert.protocol}</td>
                    <td className="px-3 py-3 align-top">{alert.sid}</td>
                    <td className="px-3 py-3 align-top whitespace-normal break-words" title={alert.message}>{alert.message}</td>
                    <td className="px-3 py-3 align-top">
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
              setItemsPerPage(Math.min(MAX_ITEMS_PER_PAGE, value));
              setCurrentPage(1);
            }}
            itemsPerPageOptions={[10, 25, 50, 100, 200, 500]}
          />
        )}
      </div>
    </div>
  );
}
