import { useState } from 'react';

export default function AlertFilters({ onFilterChange, onReset }) {
  const [showFilters, setShowFilters] = useState(false);
  const [filters, setFilters] = useState({
    threat_level: [],
    protocol: [],
    sid: '',
    src_ip: '',
    dest_ip: '',
    date_from: '',
    date_to: '',
    search: '',
  });

  const handleThreatLevelChange = (level) => {
    setFilters((prev) => {
      const newLevels = prev.threat_level.includes(level)
        ? prev.threat_level.filter((l) => l !== level)
        : [...prev.threat_level, level];
      return { ...prev, threat_level: newLevels };
    });
  };

  const handleProtocolChange = (protocol) => {
    setFilters((prev) => {
      const newProtocols = prev.protocol.includes(protocol)
        ? prev.protocol.filter((p) => p !== protocol)
        : [...prev.protocol, protocol];
      return { ...prev, protocol: newProtocols };
    });
  };

  const handleInputChange = (field, value) => {
    setFilters((prev) => ({ ...prev, [field]: value }));
  };

  const handleApplyFilters = () => {
    onFilterChange({
      threat_level: filters.threat_level.length > 0 ? filters.threat_level.join(',') : '',
      protocol: filters.protocol.length > 0 ? filters.protocol.join(',') : '',
      sid: filters.sid,
      src_ip: filters.src_ip,
      dest_ip: filters.dest_ip,
      date_from: filters.date_from,
      date_to: filters.date_to,
      search: filters.search,
    });
  };

  const handleResetFilters = () => {
    setFilters({
      threat_level: [],
      protocol: [],
      sid: '',
      src_ip: '',
      dest_ip: '',
      date_from: '',
      date_to: '',
      search: '',
    });
    onReset();
  };

  const hasActiveFilters = Object.values(filters).some(
    (val) => (Array.isArray(val) && val.length > 0) || (typeof val === 'string' && val.trim() !== '')
  );

  return (
    <div className="bg-[#0d1117] border border-[#30363d] rounded-xl p-6 space-y-4">
      {/* Filter Toggle Button */}
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-2">
          <h3 className="text-white font-semibold">Alert Filters</h3>
          {hasActiveFilters && (
            <span className="px-2 py-1 bg-blue-500/20 text-blue-300 text-xs rounded-full">
              {Object.values(filters).filter(
                (val) => (Array.isArray(val) && val.length > 0) || (typeof val === 'string' && val.trim() !== '')
              ).length} active
            </span>
          )}
        </div>
        <button
          onClick={() => setShowFilters(!showFilters)}
          className="px-3 py-1 bg-[#1f6feb] hover:bg-[#388bfd] text-white text-sm rounded transition"
        >
          {showFilters ? 'Hide' : 'Show'} Filters
        </button>
      </div>

      {/* Expanded Filter Panel */}
      {showFilters && (
        <div className="space-y-5 pt-4 border-t border-[#30363d]">
          {/* Search Bar */}
          <div>
            <label className="block text-sm text-gray-300 mb-2">Search (Message, IP, SID)</label>
            <input
              type="text"
              placeholder="Search alerts..."
              value={filters.search}
              onChange={(e) => handleInputChange('search', e.target.value)}
              className="w-full px-3 py-2 bg-[#161b22] border border-[#30363d] rounded text-white text-sm placeholder-gray-500 focus:border-blue-500 outline-none"
            />
          </div>

          {/* Threat Level Checkboxes */}
          <div>
            <label className="block text-sm text-gray-300 mb-2">Threat Level</label>
            <div className="space-y-2">
              {['safe', 'medium', 'high'].map((level) => (
                <label key={level} className="flex items-center gap-2 cursor-pointer">
                  <input
                    type="checkbox"
                    checked={filters.threat_level.includes(level)}
                    onChange={() => handleThreatLevelChange(level)}
                    className="w-4 h-4 rounded bg-[#161b22] border border-[#30363d] checked:bg-blue-600 checked:border-blue-600 accent-blue-600"
                  />
                  <span className="text-sm text-gray-300 capitalize">{level}</span>
                </label>
              ))}
            </div>
          </div>

          {/* Protocol Checkboxes */}
          <div>
            <label className="block text-sm text-gray-300 mb-2">Protocol</label>
            <div className="space-y-2">
              {['TCP', 'UDP', 'ICMP'].map((protocol) => (
                <label key={protocol} className="flex items-center gap-2 cursor-pointer">
                  <input
                    type="checkbox"
                    checked={filters.protocol.includes(protocol)}
                    onChange={() => handleProtocolChange(protocol)}
                    className="w-4 h-4 rounded bg-[#161b22] border border-[#30363d] checked:bg-blue-600 checked:border-blue-600 accent-blue-600"
                  />
                  <span className="text-sm text-gray-300">{protocol}</span>
                </label>
              ))}
            </div>
          </div>

          {/* SID Input */}
          <div>
            <label className="block text-sm text-gray-300 mb-2">Signature ID (SID)</label>
            <input
              type="text"
              placeholder="e.g., 1000015 or 1000015,1000014"
              value={filters.sid}
              onChange={(e) => handleInputChange('sid', e.target.value)}
              className="w-full px-3 py-2 bg-[#161b22] border border-[#30363d] rounded text-white text-sm placeholder-gray-500 focus:border-blue-500 outline-none"
            />
            <p className="text-xs text-gray-500 mt-1">Comma-separated for multiple SIDs</p>
          </div>

          {/* IP Filters */}
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            <div>
              <label className="block text-sm text-gray-300 mb-2">Attacker IP (src_ip)</label>
              <input
                type="text"
                placeholder="e.g., 192.168.1.100"
                value={filters.src_ip}
                onChange={(e) => handleInputChange('src_ip', e.target.value)}
                className="w-full px-3 py-2 bg-[#161b22] border border-[#30363d] rounded text-white text-sm placeholder-gray-500 focus:border-blue-500 outline-none"
              />
            </div>
            <div>
              <label className="block text-sm text-gray-300 mb-2">Target IP (dest_ip)</label>
              <input
                type="text"
                placeholder="e.g., 192.168.1.50"
                value={filters.dest_ip}
                onChange={(e) => handleInputChange('dest_ip', e.target.value)}
                className="w-full px-3 py-2 bg-[#161b22] border border-[#30363d] rounded text-white text-sm placeholder-gray-500 focus:border-blue-500 outline-none"
              />
            </div>
          </div>

          {/* Date Range */}
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            <div>
              <label className="block text-sm text-gray-300 mb-2">From Date</label>
              <input
                type="datetime-local"
                value={filters.date_from}
                onChange={(e) => handleInputChange('date_from', e.target.value)}
                className="w-full px-3 py-2 bg-[#161b22] border border-[#30363d] rounded text-white text-sm focus:border-blue-500 outline-none"
              />
            </div>
            <div>
              <label className="block text-sm text-gray-300 mb-2">To Date</label>
              <input
                type="datetime-local"
                value={filters.date_to}
                onChange={(e) => handleInputChange('date_to', e.target.value)}
                className="w-full px-3 py-2 bg-[#161b22] border border-[#30363d] rounded text-white text-sm focus:border-blue-500 outline-none"
              />
            </div>
          </div>

          {/* Action Buttons */}
          <div className="flex gap-3 pt-2">
            <button
              onClick={handleApplyFilters}
              className="flex-1 px-4 py-2 bg-green-600 hover:bg-green-700 text-white text-sm font-semibold rounded transition"
            >
              Apply Filters
            </button>
            <button
              onClick={handleResetFilters}
              className="flex-1 px-4 py-2 bg-gray-600 hover:bg-gray-700 text-white text-sm font-semibold rounded transition"
            >
              Reset
            </button>
          </div>
        </div>
      )}
    </div>
  );
}
