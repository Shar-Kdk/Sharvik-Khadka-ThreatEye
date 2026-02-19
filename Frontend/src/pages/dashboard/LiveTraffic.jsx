import { useEffect, useMemo, useRef, useState } from 'react';
import { getLiveAlerts, getFilterOptions } from '../../services/api';
import Pagination from '../../components/common/Pagination';

const MAX_ROWS_PER_PAGE = 50;
const MAX_ITEMS_PER_PAGE = 500;

const BASE_URL = (import.meta.env.VITE_API_URL || 'http://localhost:8000').replace(/\/$/, '');
const FILTER_OPTIONS_POLL_INTERVAL = 15000; // Refresh dropdown options every 15 seconds

const THREAT_STYLES = {
  safe: 'bg-green-500/20 text-green-300 border border-green-400/30',
  medium: 'bg-yellow-500/20 text-yellow-300 border border-yellow-400/30',
  high: 'bg-red-500/20 text-red-300 border border-red-400/30',
};

// Shared styling for dark-themed select dropdowns
const SELECT_CLASS =
  'w-full px-3 py-2 bg-[#161b22] border border-[#30363d] rounded text-white text-sm focus:border-blue-500 outline-none appearance-none cursor-pointer';

// Connection status indicator styles (driven by Dashboard's WebSocket state)
const CONNECTION_STYLES = {
  connected: { dot: 'bg-green-400', text: 'text-green-400', label: 'Live' },
  connecting: { dot: 'bg-yellow-400 animate-pulse', text: 'text-yellow-400', label: 'Connecting...' },
  reconnecting: { dot: 'bg-yellow-400 animate-pulse', text: 'text-yellow-400', label: 'Reconnecting...' },
  disconnected: { dot: 'bg-gray-500', text: 'text-gray-500', label: 'Disconnected' },
  auth_failed: { dot: 'bg-red-500', text: 'text-red-400', label: 'Auth Failed' },
  failed: { dot: 'bg-red-500', text: 'text-red-400', label: 'Connection Failed' },
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

/**
 * Checks if an incoming WebSocket alert matches the currently active filters.
 */
function alertMatchesFilters(alert, filters) {
  if (!filters || Object.keys(filters).length === 0) return true;

  if (filters.threat_level) {
    const levels = filters.threat_level.split(',');
    if (!levels.includes(alert.threat_level)) return false;
  }
  if (filters.protocol) {
    const protocols = filters.protocol.split(',').map(p => p.toLowerCase());
    if (!protocols.includes((alert.protocol || '').toLowerCase())) return false;
  }
  if (filters.sid && alert.sid !== filters.sid) return false;
  if (filters.src_ip && alert.src_ip !== filters.src_ip) return false;
  if (filters.dest_ip && alert.dest_ip !== filters.dest_ip) return false;
  if (filters.search) {
    const term = filters.search.toLowerCase();
    const searchable = `${alert.message} ${alert.src_ip} ${alert.dest_ip} ${alert.sid}`.toLowerCase();
    if (!searchable.includes(term)) return false;
  }
  return true;
}

/**
 * LiveTraffic - Displays real-time alert table.
 * Receives latestWsAlert from Dashboard (single WebSocket connection).
 */
export default function LiveTraffic({ token, latestWsAlert, wsConnectionStatus, wsClearSignal }) {
  const [alerts, setAlerts] = useState([]);
  const [totalAvailable, setTotalAvailable] = useState(0);
  const [isLoading, setIsLoading] = useState(true);
  const [error, setError] = useState('');
  const [lastSyncedAt, setLastSyncedAt] = useState(null);
  const [currentPage, setCurrentPage] = useState(1);
  const [itemsPerPage, setItemsPerPage] = useState(MAX_ROWS_PER_PAGE);
  const [showFilterModal, setShowFilterModal] = useState(false);
  const [threatLevelFilter, setThreatLevelFilter] = useState([]);
  const [protocolFilter, setProtocolFilter] = useState([]);
  const [sidFilter, setSidFilter] = useState('');
  const [srcIpFilter, setSrcIpFilter] = useState('');
  const [destIpFilter, setDestIpFilter] = useState('');
  const [dateFromFilter, setDateFromFilter] = useState('');
  const [dateToFilter, setDateToFilter] = useState('');
  const [searchFilter, setSearchFilter] = useState('');
  const [forceRefresh, setForceRefresh] = useState(0);
  const seenAlertIdsRef = useRef(new Set());
  const filterModalRef = useRef(null);

  // Dropdown options populated from backend (distinct values)
  const [filterOptions, setFilterOptions] = useState({
    sids: [],
    src_ips: [],
    dest_ips: [],
  });

  // Fetch filter dropdown options on mount + poll for new values
  useEffect(() => {
    if (!token) return;
    let active = true;

    const fetchOptions = async () => {
      try {
        const data = await getFilterOptions(token);
        if (active) {
          setFilterOptions({
            sids: data.sids || [],
            src_ips: data.src_ips || [],
            dest_ips: data.dest_ips || [],
          });
        }
      } catch (err) {
        console.error('[LiveTraffic] Failed to fetch filter options:', err);
      }
    };

    fetchOptions();
    const interval = setInterval(fetchOptions, FILTER_OPTIONS_POLL_INTERVAL);

    return () => {
      active = false;
      clearInterval(interval);
    };
  }, [token]);

  // Build active filters object for API calls
  const activeFilters = useMemo(() => {
    const filters = {};
    if (threatLevelFilter.length > 0) filters.threat_level = threatLevelFilter.join(',');
    if (protocolFilter.length > 0) filters.protocol = protocolFilter.join(',');
    if (sidFilter) filters.sid = sidFilter;
    if (srcIpFilter) filters.src_ip = srcIpFilter;
    if (destIpFilter) filters.dest_ip = destIpFilter;
    if (dateFromFilter.trim()) filters.date_from = dateFromFilter.trim();
    if (dateToFilter.trim()) filters.date_to = dateToFilter.trim();
    if (searchFilter.trim()) filters.search = searchFilter.trim();
    return filters;
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [threatLevelFilter, protocolFilter, sidFilter, srcIpFilter, destIpFilter, dateFromFilter, dateToFilter, searchFilter]);

  const activeFiltersKey = useMemo(
    () => JSON.stringify(activeFilters) + '|' + forceRefresh,
    [activeFilters, forceRefresh]
  );

  const hasActiveFilters = Object.keys(activeFilters).length > 0;

  // ===== WEBSOCKET: Receive alerts from Dashboard's central WebSocket =====
  // React to latestWsAlert prop changes (pushed from Dashboard.jsx)
  useEffect(() => {
    if (!latestWsAlert) return;
    // Avoid shifting historical pages while the user is browsing.
    if (currentPage !== 1) return;
    const alert = latestWsAlert.alert;
    if (!alert || !alert.id) return;

    // Skip if we've already seen this alert (dedup)
    if (seenAlertIdsRef.current.has(alert.id)) return;

    // Check if alert matches current filters before adding
    if (!alertMatchesFilters(alert, activeFilters)) return;

    seenAlertIdsRef.current.add(alert.id);
    setAlerts((prev) => {
      const updated = [alert, ...prev].slice(0, itemsPerPage);
      return updated;
    });
    setTotalAvailable((prev) => Math.max(0, prev) + 1);
    setLastSyncedAt(new Date());
    setError('');
  }, [latestWsAlert, currentPage, itemsPerPage]); // eslint-disable-line react-hooks/exhaustive-deps

  // Handle WebSocket CLEAR signal
  useEffect(() => {
    if (wsClearSignal > 0) {
      console.log('[LiveTraffic] Clearing alerts due to WS signal');
      setAlerts([]);
      setTotalAvailable(0);
      seenAlertIdsRef.current.clear();
      setLastSyncedAt(new Date());
    }
  }, [wsClearSignal]);

  // Connection status: driven by Dashboard's real WebSocket state
  const connStyle = CONNECTION_STYLES[wsConnectionStatus] || CONNECTION_STYLES.disconnected;

  // ===== HTTP FETCH: Load existing alerts on mount and when filters change =====
  useEffect(() => {
    if (!token) return;
    let active = true;
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), 8000);

    setIsLoading(true);

    const fetchAlerts = async () => {
      try {
        const offset = Math.max(0, (currentPage - 1) * itemsPerPage);
        const livePayload = await getLiveAlerts(token, itemsPerPage, controller.signal, activeFilters, offset);

        if (!active) return;

        const results = livePayload.results || [];
        setAlerts(results);
        seenAlertIdsRef.current = new Set(results.map((a) => a.id));
        setTotalAvailable(
          Number.isFinite(livePayload.total_available) ? livePayload.total_available : results.length
        );
        setError('');
        setLastSyncedAt(new Date());
      } catch (err) {
        if (!active) return;
        if (err?.name === 'AbortError') {
          setError('Request timed out.');
        } else {
          setError(err.message || 'Failed to fetch live traffic');
        }
      } finally {
        clearTimeout(timeoutId);
        if (active) setIsLoading(false);
      }
    };

    fetchAlerts();
    return () => { active = false; };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [token, activeFilters, forceRefresh, currentPage, itemsPerPage]);

  // Close filter modal when clicking outside
  useEffect(() => {
    const handleClickOutside = (event) => {
      if (filterModalRef.current && !filterModalRef.current.contains(event.target)) {
        if (!event.target.closest('button[data-filter-btn]')) {
          setShowFilterModal(false);
        }
      }
    };

    if (showFilterModal) {
      document.addEventListener('mousedown', handleClickOutside);
      return () => document.removeEventListener('mousedown', handleClickOutside);
    }
  }, [showFilterModal]);

  const handleThreatLevelToggle = (level) => {
    setThreatLevelFilter((prev) =>
      prev.includes(level) ? prev.filter((l) => l !== level) : [...prev, level]
    );
  };

  const handleProtocolToggle = (protocol) => {
    setProtocolFilter((prev) =>
      prev.includes(protocol) ? prev.filter((p) => p !== protocol) : [...prev, protocol]
    );
  };

  const handleResetFilters = () => {
    setThreatLevelFilter([]);
    setProtocolFilter([]);
    setSidFilter('');
    setSrcIpFilter('');
    setDestIpFilter('');
    setDateFromFilter('');
    setDateToFilter('');
    setSearchFilter('');
    setCurrentPage(1);
    setForceRefresh(prev => prev + 1);
  };

  const totalPages = Math.max(1, Math.ceil(totalAvailable / itemsPerPage));

  useEffect(() => {
    if (currentPage > totalPages) {
      setCurrentPage(totalPages);
    }
  }, [currentPage, totalPages]);

  const paginatedAlerts = useMemo(() => alerts, [alerts]);

  return (
    <div className="space-y-6">
      {/* Summary Header with Filter Button + Connection Status */}
      <div className="bg-[#0d1117] border border-[#30363d] rounded-xl p-6">
        <div className="flex flex-wrap gap-3 items-center justify-between">
          <div className="flex-grow">
            <h2 className="text-white text-lg font-bold">Live Network Traffic</h2>
            <div className="flex gap-4 mt-2 items-center">
              <p className="text-sm text-gray-300">
                <span className="font-semibold text-blue-400">{totalAvailable}</span> alerts detected
              </p>
              {hasActiveFilters && (
                <p className="text-sm text-yellow-300">(Filtered)</p>
              )}
              {/* Connection Status */}
              <div className="flex items-center gap-1.5">
                <span className={`w-2 h-2 rounded-full ${connStyle.dot}`} />
                <span className={`text-xs font-medium ${connStyle.text}`}>{connStyle.label}</span>
              </div>
            </div>
          </div>
          <div className="flex gap-3 items-center">
            <div className="relative">
              <button
                data-filter-btn
                onClick={() => setShowFilterModal(!showFilterModal)}
                className={`px-4 py-2 rounded text-sm font-semibold transition flex items-center gap-2 ${hasActiveFilters
                    ? 'bg-blue-600 hover:bg-blue-700 text-white'
                    : 'bg-[#1f6feb] hover:bg-[#388bfd] text-white'
                  }`}
              >
                <span>🔍</span>
                <span>Filter</span>
                {hasActiveFilters && (
                  <span className="bg-white/20 px-2 py-0.5 rounded text-xs">
                    {Object.keys(activeFilters).length}
                  </span>
                )}
              </button>

              {/* Filter Modal */}
              {showFilterModal && (
                <div
                  ref={filterModalRef}
                  className="absolute top-full mt-2 right-0 bg-[#0d1117] border border-[#30363d] rounded-lg p-6 shadow-2xl z-50 w-96 max-h-[80vh] overflow-y-auto"
                >
                  {/* Search */}
                  <div className="mb-4">
                    <label className="block text-sm text-gray-300 mb-2">Search</label>
                    <input
                      type="text"
                      placeholder="Search alerts..."
                      value={searchFilter}
                      onChange={(e) => setSearchFilter(e.target.value)}
                      className="w-full px-3 py-2 bg-[#161b22] border border-[#30363d] rounded text-white text-sm focus:border-blue-500 outline-none"
                    />
                  </div>

                  {/* Threat Level */}
                  <div className="mb-4">
                    <label className="block text-sm text-gray-300 mb-2">Threat Level</label>
                    <div className="space-y-2">
                      {['safe', 'medium', 'high'].map((level) => (
                        <label key={level} className="flex items-center gap-2 cursor-pointer">
                          <input
                            type="checkbox"
                            checked={threatLevelFilter.includes(level)}
                            onChange={() => handleThreatLevelToggle(level)}
                            className="w-4 h-4 rounded bg-[#161b22] border border-[#30363d] accent-blue-600"
                          />
                          <span className="text-sm text-gray-300 capitalize">{level}</span>
                        </label>
                      ))}
                    </div>
                  </div>

                  {/* Protocol */}
                  <div className="mb-4">
                    <label className="block text-sm text-gray-300 mb-2">Protocol</label>
                    <div className="space-y-2">
                      {['TCP', 'UDP', 'ICMP'].map((protocol) => (
                        <label key={protocol} className="flex items-center gap-2 cursor-pointer">
                          <input
                            type="checkbox"
                            checked={protocolFilter.includes(protocol)}
                            onChange={() => handleProtocolToggle(protocol)}
                            className="w-4 h-4 rounded bg-[#161b22] border border-[#30363d] accent-blue-600"
                          />
                          <span className="text-sm text-gray-300">{protocol}</span>
                        </label>
                      ))}
                    </div>
                  </div>

                  {/* SID — Dropdown */}
                  <div className="mb-4">
                    <label className="block text-sm text-gray-300 mb-2">Signature ID (SID)</label>
                    <div className="relative">
                      <select
                        id="sid-filter"
                        value={sidFilter}
                        onChange={(e) => setSidFilter(e.target.value)}
                        className={SELECT_CLASS}
                      >
                        <option value="">All</option>
                        {filterOptions.sids.map((sid) => (
                          <option key={sid.value} value={sid.value}>
                            {sid.label}
                          </option>
                        ))}
                      </select>
                      <div className="pointer-events-none absolute inset-y-0 right-0 flex items-center pr-3">
                        <svg className="w-4 h-4 text-gray-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M19 9l-7 7-7-7" />
                        </svg>
                      </div>
                    </div>
                  </div>

                  {/* Source IP — Dropdown */}
                  <div className="mb-4">
                    <label className="block text-sm text-gray-300 mb-2">Attacker IP</label>
                    <div className="relative">
                      <select
                        id="src-ip-filter"
                        value={srcIpFilter}
                        onChange={(e) => setSrcIpFilter(e.target.value)}
                        className={SELECT_CLASS}
                      >
                        <option value="">All</option>
                        {filterOptions.src_ips.map((ip) => (
                          <option key={ip} value={ip}>
                            {ip}
                          </option>
                        ))}
                      </select>
                      <div className="pointer-events-none absolute inset-y-0 right-0 flex items-center pr-3">
                        <svg className="w-4 h-4 text-gray-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M19 9l-7 7-7-7" />
                        </svg>
                      </div>
                    </div>
                  </div>

                  {/* Destination IP — Dropdown */}
                  <div className="mb-4">
                    <label className="block text-sm text-gray-300 mb-2">Target IP</label>
                    <div className="relative">
                      <select
                        id="dest-ip-filter"
                        value={destIpFilter}
                        onChange={(e) => setDestIpFilter(e.target.value)}
                        className={SELECT_CLASS}
                      >
                        <option value="">All</option>
                        {filterOptions.dest_ips.map((ip) => (
                          <option key={ip} value={ip}>
                            {ip}
                          </option>
                        ))}
                      </select>
                      <div className="pointer-events-none absolute inset-y-0 right-0 flex items-center pr-3">
                        <svg className="w-4 h-4 text-gray-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M19 9l-7 7-7-7" />
                        </svg>
                      </div>
                    </div>
                  </div>

                  {/* Date From */}
                  <div className="mb-4">
                    <label className="block text-sm text-gray-300 mb-2">From Date</label>
                    <input
                      type="datetime-local"
                      value={dateFromFilter}
                      onChange={(e) => setDateFromFilter(e.target.value)}
                      className="w-full px-3 py-2 bg-[#161b22] border border-[#30363d] rounded text-white text-sm focus:border-blue-500 outline-none"
                    />
                  </div>

                  {/* Date To */}
                  <div className="mb-4">
                    <label className="block text-sm text-gray-300 mb-2">To Date</label>
                    <input
                      type="datetime-local"
                      value={dateToFilter}
                      onChange={(e) => setDateToFilter(e.target.value)}
                      className="w-full px-3 py-2 bg-[#161b22] border border-[#30363d] rounded text-white text-sm focus:border-blue-500 outline-none"
                    />
                  </div>

                  {/* Action Buttons */}
                  <div className="flex gap-2 pt-4 border-t border-[#30363d]">
                    <button
                      onClick={() => {
                        setShowFilterModal(false);
                        setCurrentPage(1);
                        setForceRefresh(prev => prev + 1);
                      }}
                      className="flex-1 px-3 py-2 bg-green-600 hover:bg-green-700 text-white text-sm font-semibold rounded transition"
                    >
                      Apply
                    </button>
                    <button
                      onClick={() => {
                        handleResetFilters();
                        setShowFilterModal(false);
                      }}
                      className="flex-1 px-3 py-2 bg-gray-600 hover:bg-gray-700 text-white text-sm font-semibold rounded transition"
                    >
                      Reset
                    </button>
                  </div>
                </div>
              )}
            </div>
            <p className="text-xs text-gray-500 whitespace-nowrap">
              Last sync: {lastSyncedAt ? lastSyncedAt.toLocaleTimeString() : 'Waiting...'}
            </p>
          </div>
        </div>
      </div>

      {/* Alerts Table */}
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
                      No alerts found{hasActiveFilters ? ' matching your filters' : ' ingested yet'}.
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
                    <td className="px-3 py-3 align-top whitespace-normal break-words" title={alert.message}>
                      {alert.message}
                    </td>
                    <td className="px-3 py-3 align-top">
                      <span
                        className={`inline-block px-2 py-1 rounded text-[11px] font-semibold uppercase ${THREAT_STYLES[alert.threat_level] || THREAT_STYLES.safe
                          }`}
                      >
                        {alert.threat_level}
                      </span>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
        {!isLoading && totalAvailable > 0 && (
          <Pagination
            totalItems={totalAvailable}
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
