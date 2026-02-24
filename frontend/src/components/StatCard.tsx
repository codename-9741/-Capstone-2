export interface StatCardProps {
  label: string;
  value: string | number;
  subtitle?: string;
  color?: 'cyan' | 'red' | 'yellow' | 'green' | 'purple';
}

export function StatCard({ label, value, subtitle, color = 'cyan' }: StatCardProps) {
  const colorClasses = {
    cyan: 'text-cyan-400',
    red: 'text-red-400',
    yellow: 'text-yellow-400',
    green: 'text-green-400',
    purple: 'text-purple-400',
  };

  return (
    <div className="bg-gray-800 rounded-lg p-6 border border-gray-700">
      <p className="text-sm text-gray-400 mb-2">{label}</p>
      <p className={`text-3xl font-bold ${colorClasses[color]}`}>{value}</p>
      {subtitle && <p className="text-sm text-gray-500 mt-1">{subtitle}</p>}
    </div>
  );
}
