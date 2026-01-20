import {
  Bar,
  BarChart,
  CartesianGrid,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from 'recharts';

function shorten(text) {
  if (!text) {
    return 'Other';
  }
  if (text.length <= 16) {
    return text;
  }
  return `${text.slice(0, 13)}...`;
}

export default function ProtocolStatsChart({ data }) {
  const chartData = (data || []).map((row) => ({
    protocol: shorten(row.protocol),
    count: row.count || 0,
  }));

  return (
    <div className="bg-[#161b22] rounded-xl border border-[#30363d] p-4">
      <h3 className="text-sm font-semibold text-gray-200 mb-3">Protocol Statistics</h3>
      <div className="h-72">
        <ResponsiveContainer width="100%" height="100%">
          <BarChart data={chartData} margin={{ top: 8, right: 16, left: 8, bottom: 8 }}>
            <CartesianGrid strokeDasharray="3 3" stroke="#30363d" />
            <XAxis
              dataKey="protocol"
              stroke="#9ca3af"
              tick={{ fontSize: 11 }}
              angle={-45}
              textAnchor="end"
              height={72}
            />
            <YAxis stroke="#9ca3af" allowDecimals={false} />
            <Tooltip
              formatter={(value) => [value, 'Alerts']}
              contentStyle={{
                backgroundColor: '#0d1117',
                border: '1px solid #30363d',
                borderRadius: '8px',
                color: '#e5e7eb',
              }}
            />
            <Bar dataKey="count" fill="#8b5cf6" radius={[6, 6, 0, 0]} />
          </BarChart>
        </ResponsiveContainer>
      </div>
    </div>
  );
}
