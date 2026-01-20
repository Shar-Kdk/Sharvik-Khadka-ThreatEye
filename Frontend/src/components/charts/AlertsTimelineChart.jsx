import {
  CartesianGrid,
  Line,
  LineChart,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from 'recharts';

function formatTimeLabel(value) {
  if (!value) {
    return '';
  }
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) {
    return value;
  }
  return date.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
}

export default function AlertsTimelineChart({ data }) {
  const chartData = (data || []).map((row) => ({
    time: row.time,
    count: row.count || 0,
  }));

  return (
    <div className="bg-[#161b22] rounded-xl border border-[#30363d] p-4">
      <h3 className="text-sm font-semibold text-gray-200 mb-3">Alerts Timeline</h3>
      <div className="h-80">
        <ResponsiveContainer width="100%" height="100%">
          <LineChart data={chartData} margin={{ top: 8, right: 16, left: 8, bottom: 8 }}>
            <CartesianGrid strokeDasharray="3 3" stroke="#30363d" />
            <XAxis
              dataKey="time"
              stroke="#9ca3af"
              tickFormatter={formatTimeLabel}
              tick={{ fontSize: 11 }}
              minTickGap={24}
            />
            <YAxis stroke="#9ca3af" allowDecimals={false} />
            <Tooltip
              labelFormatter={(label) => formatTimeLabel(label)}
              formatter={(value) => [value, 'Alerts']}
              contentStyle={{
                backgroundColor: '#0d1117',
                border: '1px solid #30363d',
                borderRadius: '8px',
                color: '#e5e7eb',
              }}
            />
            <Line
              type="monotone"
              dataKey="count"
              stroke="#38bdf8"
              strokeWidth={2}
              dot={false}
              activeDot={{ r: 4 }}
            />
          </LineChart>
        </ResponsiveContainer>
      </div>
    </div>
  );
}
