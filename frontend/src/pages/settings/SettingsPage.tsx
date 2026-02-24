import { useState, useEffect } from 'react';
import { RefreshCw } from 'lucide-react';

interface PlatformStatus {
  name: string; url: string; status: string; latency_ms: number;
}

export const SettingsPage = () => {
  const [platforms, setPlatforms] = useState<PlatformStatus[]>([]);
  const [loading, setLoading] = useState(true);
  const [lastChecked, setLastChecked] = useState<Date | null>(null);

  const fetchStatus = async () => {
    setLoading(true);
    const checks: PlatformStatus[] = [];
    // Nightfall Backend
    try {
      const start = Date.now();
      const resp = await fetch('/api/health');
      checks.push({ name: 'Nightfall Scanner', url: '/api', status: resp.ok ? 'healthy' : 'unhealthy', latency_ms: Date.now() - start });
    } catch { checks.push({ name: 'Nightfall Scanner', url: '/api', status: 'unhealthy', latency_ms: 0 }); }
    setPlatforms(checks);
    setLastChecked(new Date());
    setLoading(false);
  };

  useEffect(() => { fetchStatus(); }, []);

  const healthyCount = platforms.filter((p) => p.status === 'healthy').length;

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-slate-900 dark:text-white">Settings</h1>
          <p className="text-sm text-slate-500">Platform configuration and status</p>
        </div>
        <button onClick={fetchStatus} className="btn-secondary">
          <RefreshCw className={`h-4 w-4 mr-1.5 ${loading ? 'animate-spin' : ''}`} />
          Refresh
        </button>
      </div>

      {/* Overall Health */}
      <div className="rounded-xl border border-slate-200 bg-white p-6 dark:border-slate-800 dark:bg-slate-900">
        <div className="flex items-center gap-4">
          <div className={`flex h-12 w-12 items-center justify-center rounded-xl ${
            healthyCount === platforms.length ? 'bg-emerald-50 dark:bg-emerald-900/20' : 'bg-red-50 dark:bg-red-900/20'
          }`}>
            <div className={`h-3 w-3 rounded-full ${healthyCount === platforms.length ? 'bg-emerald-500' : 'bg-red-500'}`} />
          </div>
          <div>
            <h2 className="text-base font-semibold text-slate-900 dark:text-white">
              {healthyCount === platforms.length ? 'All Systems Operational' : `${healthyCount}/${platforms.length} Online`}
            </h2>
            <p className="text-xs text-slate-400">
              {lastChecked ? `Last checked: ${lastChecked.toLocaleTimeString()}` : 'Checking...'}
            </p>
          </div>
        </div>
      </div>

      {/* Platform Status */}
      <div className="space-y-3">
        {platforms.map((platform) => (
          <div key={platform.name} className="rounded-xl border border-slate-200 bg-white p-4 dark:border-slate-800 dark:bg-slate-900">
            <div className="flex items-center justify-between">
              <div className="flex items-center gap-3">
                <div className={`h-2.5 w-2.5 rounded-full ${platform.status === 'healthy' ? 'bg-emerald-500' : 'bg-red-500'}`} />
                <div>
                  <h3 className="text-sm font-semibold text-slate-900 dark:text-white">{platform.name}</h3>
                  <p className="text-xs text-slate-400">{platform.url}</p>
                </div>
              </div>
              <div className="flex items-center gap-3">
                <span className="text-xs text-slate-400">{platform.latency_ms}ms</span>
                <span className={`rounded-md px-2 py-0.5 text-xs font-medium ${
                  platform.status === 'healthy'
                    ? 'bg-emerald-50 text-emerald-700 dark:bg-emerald-900/20 dark:text-emerald-400'
                    : 'bg-red-50 text-red-700 dark:bg-red-900/20 dark:text-red-400'
                }`}>{platform.status}</span>
              </div>
            </div>
          </div>
        ))}
      </div>

      {/* API Access */}
      <div className="rounded-xl border border-slate-200 bg-white p-6 dark:border-slate-800 dark:bg-slate-900">
        <h2 className="text-sm font-semibold text-slate-900 dark:text-white mb-4">API Access</h2>
        <div className="rounded-lg border border-slate-200 p-3 dark:border-slate-800">
          <div className="flex items-center justify-between">
            <div>
              <span className="text-sm font-medium text-slate-900 dark:text-white">Nightfall API</span>
              <p className="text-xs text-slate-400">No authentication required</p>
            </div>
            <span className="rounded-md bg-emerald-50 px-2 py-0.5 text-xs font-medium text-emerald-700 dark:bg-emerald-900/20 dark:text-emerald-400">
              Open Access
            </span>
          </div>
        </div>
      </div>
    </div>
  );
};
