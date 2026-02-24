export interface RiskGaugeProps {
  score: number;
  grade?: string;
}

export function RiskGauge({ score, grade }: RiskGaugeProps) {
  const getColor = () => {
    if (score >= 70) return 'text-red-500';
    if (score >= 40) return 'text-yellow-500';
    return 'text-green-500';
  };

  const calculatedGrade = grade || (score >= 70 ? 'HIGH' : score >= 40 ? 'MEDIUM' : 'LOW');

  return (
    <div className="bg-gray-800 rounded-lg p-6 border border-gray-700">
      <div className="flex items-center justify-center">
        <div className="relative w-32 h-32">
          <svg className="transform -rotate-90 w-32 h-32">
            <circle
              cx="64"
              cy="64"
              r="56"
              stroke="currentColor"
              strokeWidth="8"
              fill="transparent"
              className="text-gray-700"
            />
            <circle
              cx="64"
              cy="64"
              r="56"
              stroke="currentColor"
              strokeWidth="8"
              fill="transparent"
              strokeDasharray={`${(score / 100) * 351.68} 351.68`}
              className={getColor()}
            />
          </svg>
          <div className="absolute inset-0 flex flex-col items-center justify-center">
            <span className={`text-2xl font-bold ${getColor()}`}>{score}</span>
            <span className="text-xs text-gray-400">{calculatedGrade}</span>
          </div>
        </div>
      </div>
    </div>
  );
}
