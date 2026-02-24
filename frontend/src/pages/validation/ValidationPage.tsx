import { useState, useEffect } from 'react';
import { FlaskConical, ExternalLink, RefreshCw, Play, Shield, Activity } from 'lucide-react';

const OPENBAS_URL = '/openbas';
const OPENBAS_TOKEN = '8e2dfb71-51a1-4a19-91e0-f80a91865b29';

interface Simulation {
  exercise_id: string;
  exercise_name: string;
  exercise_status: string;
  exercise_start_date: string;
  exercise_updated_at: string;
}

interface Scenario {
  scenario_id: string;
  scenario_name: string;
  scenario_severity: string;
  scenario_category: string;
  scenario_updated_at: string;
}

export const ValidationPage = () => {
  const [activeTab, setActiveTab] = useState<'dashboard' | 'simulations' | 'scenarios'>('dashboard');
  const [simulations, setSimulations] = useState<Simulation[]>([]);
  const [scenarios, setScenarios] = useState<Scenario[]>([]);
  const [loading, setLoading] = useState(true);
  const [basHealthy, setBasHealthy] = useState(false);

  useEffect(() => {
    checkHealth();
  }, []);

  const checkHealth = async () => {
    try {
      const resp = await fetch(`${OPENBAS_URL}/api/health?health_access_key=nightfall123`);
      setBasHealthy(resp.ok);
    } catch {
      setBasHealthy(false);
    }
  };

  const fetchSimulations = async () => {
    setLoading(true);
    try {
      const resp = await fetch(`${OPENBAS_URL}/api/exercises`, {
        headers: { 'Authorization': `Bearer ${OPENBAS_TOKEN}` },
      });
      if (resp.ok) {
        const data = await resp.json();
        setSimulations(Array.isArray(data) ? data.slice(0, 50) : []);
      }
    } catch {
      // remain empty
    }
    setLoading(false);
  };

  const fetchScenarios = async () => {
    setLoading(true);
    try {
      const resp = await fetch(`${OPENBAS_URL}/api/scenarios`, {
        headers: { 'Authorization': `Bearer ${OPENBAS_TOKEN}` },
      });
      if (resp.ok) {
        const data = await resp.json();
        setScenarios(Array.isArray(data) ? data.slice(0, 50) : []);
      }
    } catch {
      // remain empty
    }
    setLoading(false);
  };

  useEffect(() => {
    if (activeTab === 'simulations') fetchSimulations();
    if (activeTab === 'scenarios') fetchScenarios();
    if (activeTab === 'dashboard') setLoading(false);
  }, [activeTab]);

  const statusColor = (status: string) => {
    switch (status?.toLowerCase()) {
      case 'running': return 'bg-green-500/20 text-green-400';
      case 'finished': return 'bg-blue-500/20 text-blue-400';
      case 'canceled': return 'bg-red-500/20 text-red-400';
      default: return 'bg-slate-500/20 text-slate-400';
    }
  };

  const severityColor = (sev: string) => {
    switch (sev?.toLowerCase()) {
      case 'critical': return 'bg-red-500/20 text-red-400';
      case 'high': return 'bg-orange-500/20 text-orange-400';
      case 'medium': return 'bg-yellow-500/20 text-yellow-400';
      case 'low': return 'bg-green-500/20 text-green-400';
      default: return 'bg-slate-500/20 text-slate-400';
    }
  };

  return (
    <div className="flex-1 p-6 overflow-auto bg-slate-950">
      {/* Header */}
      <div className="flex items-center justify-between mb-6">
        <div className="flex items-center gap-3">
          <FlaskConical className="w-8 h-8 text-orange-400" />
          <div>
            <h1 className="text-2xl font-bold text-white">Breach & Attack Simulation</h1>
            <p className="text-sm text-slate-400">Powered by OpenBAS — Adversary Simulation Platform</p>
          </div>
        </div>
        <div className="flex items-center gap-3">
          <div className={`flex items-center gap-2 px-3 py-1.5 rounded-full text-xs font-medium ${basHealthy ? 'bg-green-500/20 text-green-400' : 'bg-red-500/20 text-red-400'}`}>
            <div className={`w-2 h-2 rounded-full ${basHealthy ? 'bg-green-400' : 'bg-red-400'}`} />
            {basHealthy ? 'OpenBAS Connected' : 'OpenBAS Offline'}
          </div>
          <a
            href="http://localhost:8082"
            target="_blank"
            rel="noopener noreferrer"
            className="flex items-center gap-2 px-3 py-1.5 bg-slate-800 hover:bg-slate-700 text-slate-300 rounded-lg text-sm transition-colors"
          >
            <ExternalLink className="w-4 h-4" />
            Open Full BAS
          </a>
        </div>
      </div>

      {/* Stats Cards */}
      <div className="grid grid-cols-3 gap-4 mb-6">
        <div className="bg-slate-900 border border-slate-800 rounded-xl p-5">
          <div className="flex items-center gap-3 mb-2">
            <Play className="w-5 h-5 text-green-400" />
            <span className="text-slate-400 text-sm">Simulations</span>
          </div>
          <div className="text-3xl font-bold text-white">{simulations.length}</div>
        </div>
        <div className="bg-slate-900 border border-slate-800 rounded-xl p-5">
          <div className="flex items-center gap-3 mb-2">
            <Shield className="w-5 h-5 text-blue-400" />
            <span className="text-slate-400 text-sm">Scenarios</span>
          </div>
          <div className="text-3xl font-bold text-white">{scenarios.length}</div>
        </div>
        <div className="bg-slate-900 border border-slate-800 rounded-xl p-5">
          <div className="flex items-center gap-3 mb-2">
            <Activity className="w-5 h-5 text-purple-400" />
            <span className="text-slate-400 text-sm">Platform</span>
          </div>
          <div className={`text-xl font-bold ${basHealthy ? 'text-green-400' : 'text-red-400'}`}>
            {basHealthy ? 'Operational' : 'Offline'}
          </div>
        </div>
      </div>

      {/* Tabs */}
      <div className="flex gap-1 mb-6 bg-slate-900 p-1 rounded-lg w-fit">
        {(['dashboard', 'simulations', 'scenarios'] as const).map((tab) => (
          <button
            key={tab}
            onClick={() => setActiveTab(tab)}
            className={`px-4 py-2 rounded-md text-sm font-medium transition-colors capitalize ${
              activeTab === tab ? 'bg-orange-600 text-white' : 'text-slate-400 hover:text-white'
            }`}
          >
            {tab}
          </button>
        ))}
      </div>

      {/* Content */}
      {activeTab === 'dashboard' && (
        <div className="bg-slate-900 border border-slate-800 rounded-xl overflow-hidden" style={{ height: 'calc(100vh - 360px)' }}>
          <iframe
            src="http://localhost:8082"
            className="w-full h-full border-0"
            title="OpenBAS Dashboard"
            sandbox="allow-same-origin allow-scripts allow-forms allow-popups"
          />
        </div>
      )}

      {activeTab === 'simulations' && (
        <div className="bg-slate-900 border border-slate-800 rounded-xl">
          <div className="flex items-center justify-between p-4 border-b border-slate-800">
            <h2 className="text-lg font-semibold text-white">Attack Simulations</h2>
            <button onClick={fetchSimulations} className="p-2 text-slate-400 hover:text-white transition-colors">
              <RefreshCw className={`w-4 h-4 ${loading ? 'animate-spin' : ''}`} />
            </button>
          </div>
          <div className="divide-y divide-slate-800">
            {simulations.length === 0 && !loading && (
              <div className="p-8 text-center text-slate-500">No simulations found. Create attack simulations in OpenBAS to populate.</div>
            )}
            {simulations.map((sim) => (
              <div key={sim.exercise_id} className="p-4 hover:bg-slate-800/50 transition-colors">
                <div className="flex items-center justify-between">
                  <span className="text-white font-medium">{sim.exercise_name}</span>
                  <span className={`px-2 py-0.5 rounded text-xs font-medium ${statusColor(sim.exercise_status)}`}>
                    {sim.exercise_status}
                  </span>
                </div>
                <div className="text-xs text-slate-500 mt-1">
                  {sim.exercise_start_date && `Started: ${new Date(sim.exercise_start_date).toLocaleDateString()}`}
                </div>
              </div>
            ))}
          </div>
        </div>
      )}

      {activeTab === 'scenarios' && (
        <div className="bg-slate-900 border border-slate-800 rounded-xl">
          <div className="flex items-center justify-between p-4 border-b border-slate-800">
            <h2 className="text-lg font-semibold text-white">Attack Scenarios</h2>
            <button onClick={fetchScenarios} className="p-2 text-slate-400 hover:text-white transition-colors">
              <RefreshCw className={`w-4 h-4 ${loading ? 'animate-spin' : ''}`} />
            </button>
          </div>
          <div className="divide-y divide-slate-800">
            {scenarios.length === 0 && !loading && (
              <div className="p-8 text-center text-slate-500">No scenarios found. Create attack scenarios in OpenBAS to populate.</div>
            )}
            {scenarios.map((sc) => (
              <div key={sc.scenario_id} className="p-4 hover:bg-slate-800/50 transition-colors">
                <div className="flex items-center justify-between">
                  <span className="text-white font-medium">{sc.scenario_name}</span>
                  <div className="flex gap-2">
                    {sc.scenario_severity && (
                      <span className={`px-2 py-0.5 rounded text-xs font-medium ${severityColor(sc.scenario_severity)}`}>
                        {sc.scenario_severity}
                      </span>
                    )}
                    {sc.scenario_category && (
                      <span className="px-2 py-0.5 bg-slate-700 text-slate-300 rounded text-xs">{sc.scenario_category}</span>
                    )}
                  </div>
                </div>
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
};
