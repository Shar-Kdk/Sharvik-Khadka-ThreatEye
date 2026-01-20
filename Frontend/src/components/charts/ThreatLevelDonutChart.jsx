import {
  Cell,
  Legend,
  Pie,
  PieChart,
  ResponsiveContainer,
  Tooltip,
} from 'recharts';

const COLORS = {
  safe: '#22c55e',
  medium: '#eab308',
  high: '#ef4444',
};

export default function ThreatLevelDonutChart({ data }) {
  const chartData = (data || []).map((row) => ({
    name: row.threat_level?.toUpperCase() || 'UNKNOWN',
    value: row.count || 0,
    key: row.threat_level || 'safe',
  }));

  return (
    <div className="bg-[#161b22] rounded-xl border border-[#30363d] p-4">
      <h3 className="text-sm font-semibold text-gray-200 mb-3">Threat Level Distribution</h3>
      <div className="h-72">
        <ResponsiveContainer width="100%" height="100%">
          <PieChart>
            <Pie
              data={chartData}
              dataKey="value"
              nameKey="name"
              innerRadius={60}
              outerRadius={95}
              paddingAngle={3}
            >
              {chartData.map((entry) => (
                <Cell key={entry.name} fill={COLORS[entry.key] || '#64748b'} />
              ))}
            </Pie>
            <Tooltip
              formatter={(value) => [value, 'Alerts']}
              contentStyle={{
                backgroundColor: '#0d1117',
                border: '1px solid #30363d',
                borderRadius: '8px',
                color: '#e5e7eb',
              }}
            />
            <Legend />
          </PieChart>
        </ResponsiveContainer>
      </div>
    </div>
  );
}
