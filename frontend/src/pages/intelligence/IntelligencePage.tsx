import { useState, useEffect } from 'react';
import { Brain, ExternalLink, RefreshCw, Shield, AlertTriangle, Globe } from 'lucide-react';

const OPENCTI_URL = '/opencti';
const OPENCTI_TOKEN = '6476505b-4674-49c3-8acb-57f6f98998ae';

interface Indicator {
  id: string;
  name: string;
  pattern: string;
  indicator_types: string[];
  valid_from: string;
  created: string;
}

interface CTIStats {
  indicators: number;
  threats: number;
  reports: number;
}

export const IntelligencePage = () => {
  const [activeTab, setActiveTab] = useState<'dashboard' | 'indicators' | 'threats'>('dashboard');
  const [indicators, setIndicators] = useState<Indicator[]>([]);
  const [stats, setStats] = useState<CTIStats>({ indicators: 0, threats: 0, reports: 0 });
  const [loading, setLoading] = useState(true);
  const [ctiHealthy, setCtiHealthy] = useState(false);

  useEffect(() => {
    checkHealth();
    fetchStats();
  }, []);

  const checkHealth = async () => {
    try {
      const resp = await fetch(`${OPENCTI_URL}/health?health_access_key=nightfall123`);
      setCtiHealthy(resp.ok);
    } catch {
      setCtiHealthy(false);
    }
  };

  const fetchStats = async () => {
    setLoading(true);
    try {
      const resp = await fetch(`${OPENCTI_URL}/graphql`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${OPENCTI_TOKEN}`,
        },
        body: JSON.stringify({
          query: `{
            indicators(first: 0) { pageInfo { globalCount } }
            threatActorsIndividuals(first: 0) { pageInfo { globalCount } }
            reports(first: 0) { pageInfo { globalCount } }
          }`
        }),
      });
      if (resp.ok) {
        const data = await resp.json();
        setStats({
          indicators: data?.data?.indicators?.pageInfo?.globalCount ?? 0,
          threats: data?.data?.threatActorsIndividuals?.pageInfo?.globalCount ?? 0,
          reports: data?.data?.reports?.pageInfo?.globalCount ?? 0,
        });
      }
    } catch {
      // stats stay at 0
    }
    setLoading(false);
  };

  const fetchIndicators = async () => {
    setLoading(true);
    try {
      const resp = await fetch(`${OPENCTI_URL}/graphql`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${OPENCTI_TOKEN}`,
        },
        body: JSON.stringify({
          query: `{
            indicators(first: 50, orderBy: created_at, orderMode: desc) {
              edges {
                node { id name pattern indicator_types valid_from created }
              }
            }
          }`
        }),
      });
      if (resp.ok) {
        const data = await resp.json();
        const edges = data?.data?.indicators?.edges ?? [];
        setIndicators(edges.map((e: any) => e.node));
      }
    } catch {
      // remain empty
    }
    setLoading(false);
  };

  useEffect(() => {
    if (activeTab === 'indicators') fetchIndicators();
    if (activeTab === 'dashboard') fetchStats();
  }, [activeTab]);

  return (
    <div className="flex-1 p-6 overflow-auto bg-slate-950">
      {/* Header */}
      <div className="flex items-center justify-between mb-6">
        <div className="flex items-center gap-3">
          <Brain className="w-8 h-8 text-purple-400" />
          <div>
            <h1 className="text-2xl font-bold text-white">Threat Intelligence</h1>
            <p className="text-sm text-slate-400">Powered by OpenCTI — Cyber Threat Intelligence Platform</p>
          </div>
        </div>
        <div className="flex items-center gap-3">
          <div className={`flex items-center gap-2 px-3 py-1.5 rounded-full text-xs font-medium ${ctiHealthy ? 'bg-green-500/20 text-green-400' : 'bg-red-500/20 text-red-400'}`}>
            <div className={`w-2 h-2 rounded-full ${ctiHealthy ? 'bg-green-400' : 'bg-red-400'}`} />
            {ctiHealthy ? 'OpenCTI Connected' : 'OpenCTI Offline'}
          </div>
          <a
            href="http://localhost:8081"
            target="_blank"
            rel="noopener noreferrer"
            className="flex items-center gap-2 px-3 py-1.5 bg-slate-800 hover:bg-slate-700 text-slate-300 rounded-lg text-sm transition-colors"
          >
            <ExternalLink className="w-4 h-4" />
            Open Full CTI
          </a>
        </div>
      </div>

      {/* Stats Cards */}
      <div className="grid grid-cols-3 gap-4 mb-6">
        <div className="bg-slate-900 border border-slate-800 rounded-xl p-5">
          <div className="flex items-center gap-3 mb-2">
            <Shield className="w-5 h-5 text-blue-400" />
            <span className="text-slate-400 text-sm">Indicators of Compromise</span>
          </div>
          <div className="text-3xl font-bold text-white">{loading ? '...' : stats.indicators.toLocaleString()}</div>
        </div>
        <div className="bg-slate-900 border border-slate-800 rounded-xl p-5">
          <div className="flex items-center gap-3 mb-2">
            <AlertTriangle className="w-5 h-5 text-red-400" />
            <span className="text-slate-400 text-sm">Threat Actors</span>
          </div>
          <div className="text-3xl font-bold text-white">{loading ? '...' : stats.threats.toLocaleString()}</div>
        </div>
        <div className="bg-slate-900 border border-slate-800 rounded-xl p-5">
          <div className="flex items-center gap-3 mb-2">
            <Globe className="w-5 h-5 text-green-400" />
            <span className="text-slate-400 text-sm">Intelligence Reports</span>
          </div>
          <div className="text-3xl font-bold text-white">{loading ? '...' : stats.reports.toLocaleString()}</div>
        </div>
      </div>

      {/* Tabs */}
      <div className="flex gap-1 mb-6 bg-slate-900 p-1 rounded-lg w-fit">
        {(['dashboard', 'indicators', 'threats'] as const).map((tab) => (
          <button
            key={tab}
            onClick={() => setActiveTab(tab)}
            className={`px-4 py-2 rounded-md text-sm font-medium transition-colors capitalize ${
              activeTab === tab ? 'bg-purple-600 text-white' : 'text-slate-400 hover:text-white'
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
            src="http://localhost:8081/dashboard"
            className="w-full h-full border-0"
            title="OpenCTI Dashboard"
            sandbox="allow-same-origin allow-scripts allow-forms allow-popups"
          />
        </div>
      )}

      {activeTab === 'indicators' && (
        <div className="bg-slate-900 border border-slate-800 rounded-xl">
          <div className="flex items-center justify-between p-4 border-b border-slate-800">
            <h2 className="text-lg font-semibold text-white">Indicators of Compromise</h2>
            <button onClick={fetchIndicators} className="p-2 text-slate-400 hover:text-white transition-colors">
              <RefreshCw className={`w-4 h-4 ${loading ? 'animate-spin' : ''}`} />
            </button>
          </div>
          <div className="divide-y divide-slate-800">
            {indicators.length === 0 && !loading && (
              <div className="p-8 text-center text-slate-500">No indicators found. Import threat feeds in OpenCTI to populate.</div>
            )}
            {indicators.map((ind) => (
              <div key={ind.id} className="p-4 hover:bg-slate-800/50 transition-colors">
                <div className="flex items-center justify-between mb-1">
                  <span className="text-white font-medium">{ind.name}</span>
                  <div className="flex gap-2">
                    {(ind.indicator_types || []).map((t) => (
                      <span key={t} className="px-2 py-0.5 bg-blue-500/20 text-blue-400 rounded text-xs">{t}</span>
                    ))}
                  </div>
                </div>
                <code className="text-xs text-slate-500 font-mono block truncate">{ind.pattern}</code>
              </div>
            ))}
          </div>
        </div>
      )}

      {activeTab === 'threats' && (
        <div className="bg-slate-900 border border-slate-800 rounded-xl overflow-hidden" style={{ height: 'calc(100vh - 360px)' }}>
          <iframe
            src="http://localhost:8081/dashboard/threats/threat_actors_individual"
            className="w-full h-full border-0"
            title="OpenCTI Threats"
            sandbox="allow-same-origin allow-scripts allow-forms allow-popups"
          />
        </div>
      )}
    </div>
  );
};
