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
    return 'Unknown';
  }
  if (text.length <= 36) {
    return text;
  }
  return `${text.slice(0, 33)}...`;
}

export default function TopAttacksBarChart({ data }) {
  const chartData = (data || []).map((row) => ({
    attack_name: shorten(row.attack_name),
    count: row.count || 0,
  }));

  return (
    <div className="bg-[#161b22] rounded-xl border border-[#30363d] p-4">
      <h3 className="text-sm font-semibold text-gray-200 mb-3">Top Attack Types</h3>
      <div className="h-72">
        <ResponsiveContainer width="100%" height="100%">
          <BarChart data={chartData} layout="vertical" margin={{ top: 8, right: 16, left: 4, bottom: 8 }}>
            <CartesianGrid strokeDasharray="3 3" stroke="#30363d" />
            <XAxis type="number" stroke="#9ca3af" allowDecimals={false} />
            <YAxis
              type="category"
              dataKey="attack_name"
              stroke="#9ca3af"
              width={170}
              tick={{ fontSize: 11 }}
            />
            <Tooltip
              formatter={(value) => [value, 'Alerts']}
              contentStyle={{
                backgroundColor: '#0d1117',
                border: '1px solid #30363d',
                borderRadius: '8px',
                color: '#e5e7eb',
              }}
            />
            <Bar dataKey="count" fill="#3b82f6" radius={[0, 6, 6, 0]} />
          </BarChart>
        </ResponsiveContainer>
      </div>
    </div>
  );
}
