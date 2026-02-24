import { useEffect } from 'react';
import { useFindingStore } from '../stores/findingStore';

export const FindingsPage = () => {
  const { findings, isLoading, fetchFindings, filters, setFilters } = useFindingStore();

  useEffect(() => {
    fetchFindings();
  }, [filters]);

  const severityColors: Record<string, string> = {
    Critical: 'bg-red-500',
    High: 'bg-orange-500',
    Medium: 'bg-yellow-500',
    Low: 'bg-green-500',
    Info: 'bg-blue-500',
  };

  return (
    <div className="min-h-screen bg-gradient-to-br from-purple-900 via-black to-black p-6">
      <div className="max-w-7xl mx-auto">
        <h1 className="text-4xl font-bold text-white mb-8">Security Findings</h1>

        {/* Filters */}
        <div className="mb-6 flex gap-4">
          <select
            className="px-4 py-2 bg-gray-800 text-white rounded border border-purple-500"
            onChange={(e) => setFilters({ severity: e.target.value })}
          >
            <option value="">All Severities</option>
            <option value="Critical">Critical</option>
            <option value="High">High</option>
            <option value="Medium">Medium</option>
            <option value="Low">Low</option>
          </select>

          <select
            className="px-4 py-2 bg-gray-800 text-white rounded border border-purple-500"
            onChange={(e) => setFilters({ status: e.target.value })}
          >
            <option value="">All Statuses</option>
            <option value="new">New</option>
            <option value="investigating">Investigating</option>
            <option value="verified">Verified</option>
            <option value="fixed">Fixed</option>
          </select>
        </div>

        {/* Findings List */}
        {isLoading ? (
          <div className="text-white text-center py-12">Loading findings...</div>
        ) : findings.length === 0 ? (
          <div className="text-gray-400 text-center py-12">No findings found</div>
        ) : (
          <div className="space-y-4">
            {findings.map((finding) => (
              <div
                key={finding.id}
                className="bg-gray-900 border border-purple-500/30 rounded-lg p-6 hover:border-purple-500 transition"
              >
                <div className="flex items-start justify-between">
                  <div className="flex-1">
                    <div className="flex items-center gap-3 mb-2">
                      <span className={`px-3 py-1 rounded text-sm font-bold ${severityColors[finding.severity]}`}>
                        {finding.severity}
                      </span>
                      <span className="text-gray-400">{finding.category}</span>
                    </div>
                    <h3 className="text-xl font-semibold text-white mb-2">{finding.finding}</h3>
                    <p className="text-gray-300 mb-3">{finding.remediation}</p>
                    <div className="text-sm text-gray-500">
                      Status: {finding.status} • {new Date(finding.created_at).toLocaleDateString()}
                    </div>
                  </div>
                </div>
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  );
};
