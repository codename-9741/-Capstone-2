import { useEffect, useMemo, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import {
  PieChart, Pie, Cell, ResponsiveContainer, Tooltip,
  BarChart, Bar, XAxis, YAxis, CartesianGrid,
  RadialBarChart, RadialBar, Legend,
} from 'recharts';
import { Shield, AlertTriangle, Target, Activity, Radar, ChevronRight, TrendingUp, TrendingDown } from 'lucide-react';

type TargetData = { id: number; domain: string; created_at?: string };
type ScanData = {
  id: number; target_id: number; status: string;
  risk_score?: number; risk_grade?: string;
  enabled_modules?: number; completed_modules?: number;
  findings?: any[];
};
type SeverityEntry = { severity: string; count: number };
type FindingData = {
  id: number; severity: string; category: string; finding: string;
  mitre_tactic?: string; mitre_technique?: string; mitre_attack_id?: string;
  owasp_category?: string; owasp_name?: string;
  kill_chain_phase?: string; tool_source?: string; tool_count?: number;
};

const SEV_COLORS: Record<string, string> = {
  Critical: '#ef4444', High: '#f97316', Medium: '#eab308', Low: '#22c55e', Info: '#6366f1',
};
const SEV_BG: Record<string, string> = {
  Critical: 'bg-red-600', High: 'bg-orange-500', Medium: 'bg-yellow-500', Low: 'bg-emerald-500',
};
const SEV_TEXT: Record<string, string> = {
  Critical: 'text-white', High: 'text-white', Medium: 'text-slate-900', Low: 'text-white',
};

const GRADE_COLOR: Record<string, string> = {
  A: 'text-emerald-400', B: 'text-green-400', C: 'text-yellow-400',
  D: 'text-orange-400', F: 'text-red-400',
};

function formatCount(n: number): string {
  if (n >= 1000) return (n / 1000).toFixed(2) + 'K';
  return n.toString();
}

export function Dashboard() {
  const navigate = useNavigate();
  const [targets, setTargets] = useState<TargetData[]>([]);
  const [scans, setScans] = useState<ScanData[]>([]);
  const [severity, setSeverity] = useState<SeverityEntry[]>([]);
  const [allFindings, setAllFindings] = useState<FindingData[]>([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => { loadDashboard(); }, []);

  const loadDashboard = async () => {
    setLoading(true);
    try {
      const [tRes, sRes, sevRes, fRes] = await Promise.all([
        fetch('/api/targets'), fetch('/api/scans'), fetch('/api/findings/stats'),
        fetch('/api/findings?per_page=2000'),
      ]);
      const t = await tRes.json(), s = await sRes.json(), sv = await sevRes.json(), f = await fRes.json();
      setTargets(t.data || []);
      setScans(s.data || []);
      setSeverity(sv.data || []);
      setAllFindings(f.data || []);
    } catch (err) { console.error('dashboard load failed', err); }
    setLoading(false);
  };

  const stats = useMemo(() => {
    const totalFindings = severity.reduce((s, e) => s + e.count, 0);
    const critical = severity.find(r => r.severity === 'Critical')?.count || 0;
    const high = severity.find(r => r.severity === 'High')?.count || 0;
    const medium = severity.find(r => r.severity === 'Medium')?.count || 0;
    const low = severity.find(r => r.severity === 'Low')?.count || 0;

    const completedScans = scans.filter(s => s.status === 'completed').length;
    const runningScans = scans.filter(s => s.status === 'running').length;
    const avgRisk = scans.length > 0
      ? Math.round(scans.reduce((a, sc) => a + (sc.risk_score || 0), 0) / scans.length)
      : 0;

    // Category breakdown
    const categoryMap: Record<string, number> = {};
    allFindings.forEach(f => {
      const cat = f.category || 'Unknown';
      categoryMap[cat] = (categoryMap[cat] || 0) + 1;
    });
    const topCategories = Object.entries(categoryMap)
      .sort((a, b) => b[1] - a[1])
      .slice(0, 8)
      .map(([name, value]) => ({ name, value }));

    // Tool source breakdown
    const toolMap: Record<string, number> = {};
    allFindings.forEach(f => {
      const tool = f.tool_source || 'native';
      toolMap[tool] = (toolMap[tool] || 0) + 1;
    });
    const toolBreakdown = Object.entries(toolMap)
      .sort((a, b) => b[1] - a[1])
      .slice(0, 6)
      .map(([name, value]) => ({ name, value }));

    // MITRE tactics count
    const mitreMap: Record<string, number> = {};
    allFindings.forEach(f => {
      if (f.mitre_tactic) {
        mitreMap[f.mitre_tactic] = (mitreMap[f.mitre_tactic] || 0) + 1;
      }
    });
    const mitreTactics = Object.entries(mitreMap)
      .sort((a, b) => b[1] - a[1])
      .map(([name, value]) => ({ name, value }));

    // OWASP distribution
    const owaspMap: Record<string, number> = {};
    allFindings.forEach(f => {
      if (f.owasp_category) {
        owaspMap[f.owasp_category] = (owaspMap[f.owasp_category] || 0) + 1;
      }
    });
    const owaspCategories = Object.entries(owaspMap)
      .sort((a, b) => b[1] - a[1])
      .map(([name, value]) => ({ name: name.length > 20 ? name.substring(0, 20) + '...' : name, value, fullName: name }));

    // Kill chain phases
    const killChainMap: Record<string, number> = {};
    allFindings.forEach(f => {
      if (f.kill_chain_phase) {
        killChainMap[f.kill_chain_phase] = (killChainMap[f.kill_chain_phase] || 0) + 1;
      }
    });
    const killChainPhases = Object.entries(killChainMap)
      .sort((a, b) => b[1] - a[1])
      .map(([name, value]) => ({ name, value }));

    // Multi-tool correlated findings
    const correlated = allFindings.filter(f => f.tool_count && f.tool_count > 1).length;

    return {
      totalTargets: targets.length, totalFindings, critical, high, medium, low,
      completedScans, runningScans, avgRisk,
      topCategories, toolBreakdown, mitreTactics, owaspCategories, killChainPhases, correlated,
    };
  }, [targets, scans, severity, allFindings]);

  // Severity pie data
  const sevPieData = [
    { name: 'Critical', value: stats.critical, color: SEV_COLORS.Critical },
    { name: 'High', value: stats.high, color: SEV_COLORS.High },
    { name: 'Medium', value: stats.medium, color: SEV_COLORS.Medium },
    { name: 'Low', value: stats.low, color: SEV_COLORS.Low },
  ].filter(d => d.value > 0);

  // Risk gauge data
  const riskLabel = stats.avgRisk <= 200 ? 'Low' : stats.avgRisk <= 500 ? 'Medium' : stats.avgRisk <= 700 ? 'High' : 'Critical';
  const riskColor = stats.avgRisk <= 200 ? '#22c55e' : stats.avgRisk <= 500 ? '#eab308' : stats.avgRisk <= 700 ? '#f97316' : '#ef4444';

  const TOOL_COLORS = ['#6366f1', '#8b5cf6', '#a78bfa', '#c4b5fd', '#818cf8', '#4f46e5'];
  const CAT_COLORS = ['#ef4444', '#f97316', '#eab308', '#22c55e', '#06b6d4', '#6366f1', '#a855f7', '#ec4899'];

  if (loading) {
    return (
      <div className="flex items-center justify-center h-96">
        <div className="flex flex-col items-center gap-3">
          <div className="h-8 w-8 animate-spin rounded-full border-2 border-brand-600 border-t-transparent" />
          <p className="text-sm text-slate-400">Loading dashboard...</p>
        </div>
      </div>
    );
  }

  return (
    <div className="space-y-5">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-slate-900 dark:text-white">EASM Executive Dashboard</h1>
          <p className="text-sm text-slate-500">External Attack Surface Management</p>
        </div>
        <div className="flex items-center gap-3">
          <button onClick={() => navigate('/target-dashboard')} className="btn-secondary flex items-center gap-1.5">
            <Target className="h-4 w-4" /> Target View
          </button>
          <button onClick={() => navigate('/scan')} className="btn-primary flex items-center gap-1.5">
            <Radar className="h-4 w-4" /> Start Scan
          </button>
        </div>
      </div>

      {/* Top Stat Cards Row - Qualys Style */}
      <div className="grid grid-cols-2 sm:grid-cols-3 md:grid-cols-5 gap-3">
        {[
          { label: 'External Attack Surface', value: stats.totalTargets, bg: 'bg-red-600', text: 'text-white', icon: Shield },
          { label: 'Total Findings', value: stats.totalFindings, bg: 'bg-slate-100 dark:bg-slate-800', text: 'text-slate-900 dark:text-white', icon: AlertTriangle },
          { label: 'Completed Scans', value: stats.completedScans, bg: 'bg-green-600', text: 'text-white', icon: Activity },
          { label: 'Active Scans', value: stats.runningScans, bg: 'bg-yellow-500', text: 'text-slate-900', icon: Radar },
          { label: 'Correlated Findings', value: stats.correlated, bg: 'bg-red-700', text: 'text-white', icon: Target },
        ].map(card => {
          const Icon = card.icon;
          return (
            <div key={card.label} className={`rounded-xl ${card.bg} p-4 shadow-sm`}>
              <div className="flex items-center gap-2 mb-2">
                <Icon className={`h-4 w-4 ${card.text} opacity-70`} />
              </div>
              <p className={`text-3xl font-bold ${card.text}`}>{formatCount(card.value)}</p>
              <p className={`text-xs mt-1 ${card.text} opacity-80`}>{card.label}</p>
            </div>
          );
        })}
      </div>

      {/* Severity Stat Cards */}
      <div className="grid grid-cols-4 gap-3">
        {(['Critical', 'High', 'Medium', 'Low'] as const).map(sev => {
          const count = stats[sev.toLowerCase() as 'critical' | 'high' | 'medium' | 'low'];
          return (
            <div key={sev} className={`rounded-xl ${SEV_BG[sev]} p-4 shadow-sm`}>
              <p className={`text-3xl font-bold ${SEV_TEXT[sev]}`}>{formatCount(count)}</p>
              <p className={`text-xs mt-1 ${SEV_TEXT[sev]} opacity-80 uppercase font-medium tracking-wide`}>{sev} Severity</p>
            </div>
          );
        })}
      </div>

      {/* Charts Row 1: Risk Score + Severity Donut + Category Distribution */}
      <div className="grid gap-5 lg:grid-cols-3">
        {/* Overall Risk Score */}
        <div className="rounded-xl border border-slate-200 bg-white p-5 dark:border-slate-800 dark:bg-slate-900">
          <h3 className="text-xs font-semibold uppercase tracking-wider text-slate-400 mb-4">Overall Risk Score</h3>
          <div className="flex items-center justify-center">
            <ResponsiveContainer width="100%" height={200}>
              <RadialBarChart
                cx="50%" cy="50%" innerRadius="60%" outerRadius="90%"
                startAngle={180} endAngle={0}
                data={[{ value: Math.min(stats.avgRisk, 1000), fill: riskColor }]}
              >
                <RadialBar dataKey="value" cornerRadius={10} background={{ fill: '#1e293b' }} />
              </RadialBarChart>
            </ResponsiveContainer>
          </div>
          <div className="text-center -mt-16 relative z-10">
            <p className="text-4xl font-bold" style={{ color: riskColor }}>{stats.avgRisk}</p>
            <p className="text-sm text-slate-400">{riskLabel}</p>
          </div>
          <div className="mt-8 flex justify-between text-xs text-slate-400">
            <span>0</span>
            <span>Total Contributing Vulns: <span className="font-bold text-slate-200">{stats.totalFindings}</span></span>
            <span>1000</span>
          </div>
          <div className="mt-2 text-center">
            <p className="text-xs text-slate-400">Total Assets: <span className="text-lg font-bold text-white">{stats.totalTargets}</span></p>
          </div>
        </div>

        {/* Severity Distribution Donut */}
        <div className="rounded-xl border border-slate-200 bg-white p-5 dark:border-slate-800 dark:bg-slate-900">
          <h3 className="text-xs font-semibold uppercase tracking-wider text-slate-400 mb-4">Severity Distribution</h3>
          {sevPieData.length > 0 ? (
            <>
              <ResponsiveContainer width="100%" height={200}>
                <PieChart>
                  <Pie
                    data={sevPieData}
                    cx="50%" cy="50%"
                    innerRadius={55} outerRadius={85}
                    paddingAngle={3}
                    dataKey="value"
                    stroke="none"
                  >
                    {sevPieData.map((entry, i) => (
                      <Cell key={i} fill={entry.color} />
                    ))}
                  </Pie>
                  <Tooltip
                    contentStyle={{ background: '#1e293b', border: 'none', borderRadius: '8px', color: '#fff' }}
                  />
                </PieChart>
              </ResponsiveContainer>
              <div className="grid grid-cols-2 gap-2 mt-2">
                {sevPieData.map(d => (
                  <div key={d.name} className="flex items-center gap-2">
                    <span className="h-2.5 w-2.5 rounded-full" style={{ backgroundColor: d.color }} />
                    <span className="text-xs text-slate-400">{d.name}</span>
                    <span className="text-xs font-bold text-slate-200 ml-auto">{d.value}</span>
                  </div>
                ))}
              </div>
            </>
          ) : (
            <div className="flex items-center justify-center h-48 text-sm text-slate-500">No findings yet</div>
          )}
        </div>

        {/* Global Risk Score: Attack Surface */}
        <div className="rounded-xl border border-slate-200 bg-white p-5 dark:border-slate-800 dark:bg-slate-900">
          <h3 className="text-xs font-semibold uppercase tracking-wider text-slate-400 mb-4">Attack Surface Risk</h3>
          {sevPieData.length > 0 ? (
            <>
              <ResponsiveContainer width="100%" height={200}>
                <PieChart>
                  <Pie
                    data={sevPieData}
                    cx="50%" cy="50%"
                    outerRadius={85}
                    paddingAngle={2}
                    dataKey="value"
                    stroke="none"
                  >
                    {sevPieData.map((entry, i) => (
                      <Cell key={i} fill={entry.color} />
                    ))}
                  </Pie>
                  <Tooltip
                    contentStyle={{ background: '#1e293b', border: 'none', borderRadius: '8px', color: '#fff' }}
                  />
                </PieChart>
              </ResponsiveContainer>
              <div className="space-y-1 mt-2">
                {sevPieData.map(d => (
                  <div key={d.name} className="flex items-center justify-between">
                    <div className="flex items-center gap-2">
                      <span className="h-2 w-2 rounded-full" style={{ backgroundColor: d.color }} />
                      <span className="text-xs text-slate-400">{d.name}</span>
                    </div>
                    <span className="text-xs font-bold text-slate-200">{d.value}</span>
                  </div>
                ))}
              </div>
            </>
          ) : (
            <div className="flex items-center justify-center h-48 text-sm text-slate-500">No data</div>
          )}
        </div>
      </div>

      {/* Charts Row 2: Category + Tool Source */}
      <div className="grid gap-5 lg:grid-cols-2">
        {/* Findings by Category */}
        <div className="rounded-xl border border-slate-200 bg-white p-5 dark:border-slate-800 dark:bg-slate-900">
          <h3 className="text-xs font-semibold uppercase tracking-wider text-slate-400 mb-4">Findings by Category</h3>
          {stats.topCategories.length > 0 ? (
            <ResponsiveContainer width="100%" height={280}>
              <BarChart data={stats.topCategories} layout="vertical" margin={{ left: 10, right: 20 }}>
                <CartesianGrid strokeDasharray="3 3" stroke="#334155" />
                <XAxis type="number" tick={{ fill: '#94a3b8', fontSize: 11 }} />
                <YAxis dataKey="name" type="category" width={120} tick={{ fill: '#94a3b8', fontSize: 11 }} />
                <Tooltip contentStyle={{ background: '#1e293b', border: 'none', borderRadius: '8px', color: '#fff' }} />
                <Bar dataKey="value" radius={[0, 4, 4, 0]}>
                  {stats.topCategories.map((_, i) => (
                    <Cell key={i} fill={CAT_COLORS[i % CAT_COLORS.length]} />
                  ))}
                </Bar>
              </BarChart>
            </ResponsiveContainer>
          ) : (
            <div className="flex items-center justify-center h-48 text-sm text-slate-500">No category data</div>
          )}
        </div>

        {/* Findings by Tool Source */}
        <div className="rounded-xl border border-slate-200 bg-white p-5 dark:border-slate-800 dark:bg-slate-900">
          <h3 className="text-xs font-semibold uppercase tracking-wider text-slate-400 mb-4">Risk Distribution by Tool</h3>
          {stats.toolBreakdown.length > 0 ? (
            <>
              <ResponsiveContainer width="100%" height={200}>
                <PieChart>
                  <Pie
                    data={stats.toolBreakdown}
                    cx="50%" cy="50%"
                    outerRadius={80}
                    paddingAngle={3}
                    dataKey="value"
                    stroke="none"
                    label={({ name, percent }) => `${name}: ${(percent * 100).toFixed(0)}%`}
                  >
                    {stats.toolBreakdown.map((_, i) => (
                      <Cell key={i} fill={TOOL_COLORS[i % TOOL_COLORS.length]} />
                    ))}
                  </Pie>
                  <Tooltip contentStyle={{ background: '#1e293b', border: 'none', borderRadius: '8px', color: '#fff' }} />
                </PieChart>
              </ResponsiveContainer>
              <div className="grid grid-cols-2 gap-1 mt-3">
                {stats.toolBreakdown.map((t, i) => (
                  <div key={t.name} className="flex items-center gap-2">
                    <span className="h-2.5 w-2.5 rounded-full" style={{ backgroundColor: TOOL_COLORS[i % TOOL_COLORS.length] }} />
                    <span className="text-xs text-slate-400 truncate">{t.name}</span>
                    <span className="text-xs font-bold text-slate-200 ml-auto">{t.value}</span>
                  </div>
                ))}
              </div>
            </>
          ) : (
            <div className="flex items-center justify-center h-48 text-sm text-slate-500">No tool data</div>
          )}
        </div>
      </div>

      {/* Charts Row 3: MITRE + OWASP + Kill Chain */}
      <div className="grid gap-5 lg:grid-cols-3">
        {/* MITRE Tactics */}
        <div className="rounded-xl border border-slate-200 bg-white p-5 dark:border-slate-800 dark:bg-slate-900">
          <div className="flex items-center justify-between mb-4">
            <h3 className="text-xs font-semibold uppercase tracking-wider text-slate-400">MITRE ATT&CK Tactics</h3>
            <button onClick={() => navigate('/mitre')} className="text-xs text-brand-400 hover:text-brand-300 flex items-center gap-0.5">
              View <ChevronRight className="h-3 w-3" />
            </button>
          </div>
          {stats.mitreTactics.length > 0 ? (
            <div className="space-y-2">
              {stats.mitreTactics.slice(0, 6).map(t => {
                const max = stats.mitreTactics[0].value;
                return (
                  <div key={t.name}>
                    <div className="flex items-center justify-between mb-1">
                      <span className="text-xs text-slate-300 truncate max-w-[70%]">{t.name}</span>
                      <span className="text-xs font-bold text-slate-200">{t.value}</span>
                    </div>
                    <div className="h-1.5 rounded-full bg-slate-800 overflow-hidden">
                      <div className="h-full rounded-full bg-indigo-500" style={{ width: `${(t.value / max) * 100}%` }} />
                    </div>
                  </div>
                );
              })}
            </div>
          ) : (
            <div className="flex items-center justify-center h-32 text-sm text-slate-500">No MITRE data</div>
          )}
        </div>

        {/* OWASP Top 10 */}
        <div className="rounded-xl border border-slate-200 bg-white p-5 dark:border-slate-800 dark:bg-slate-900">
          <div className="flex items-center justify-between mb-4">
            <h3 className="text-xs font-semibold uppercase tracking-wider text-slate-400">OWASP Categories</h3>
            <button onClick={() => navigate('/owasp')} className="text-xs text-brand-400 hover:text-brand-300 flex items-center gap-0.5">
              View <ChevronRight className="h-3 w-3" />
            </button>
          </div>
          {stats.owaspCategories.length > 0 ? (
            <div className="space-y-2">
              {stats.owaspCategories.slice(0, 6).map(o => {
                const max = stats.owaspCategories[0].value;
                return (
                  <div key={o.name}>
                    <div className="flex items-center justify-between mb-1">
                      <span className="text-xs text-slate-300 truncate max-w-[70%]">{o.name}</span>
                      <span className="text-xs font-bold text-slate-200">{o.value}</span>
                    </div>
                    <div className="h-1.5 rounded-full bg-slate-800 overflow-hidden">
                      <div className="h-full rounded-full bg-amber-500" style={{ width: `${(o.value / max) * 100}%` }} />
                    </div>
                  </div>
                );
              })}
            </div>
          ) : (
            <div className="flex items-center justify-center h-32 text-sm text-slate-500">No OWASP data</div>
          )}
        </div>

        {/* Kill Chain Phases */}
        <div className="rounded-xl border border-slate-200 bg-white p-5 dark:border-slate-800 dark:bg-slate-900">
          <div className="flex items-center justify-between mb-4">
            <h3 className="text-xs font-semibold uppercase tracking-wider text-slate-400">Kill Chain Phases</h3>
            <button onClick={() => navigate('/killchain')} className="text-xs text-brand-400 hover:text-brand-300 flex items-center gap-0.5">
              View <ChevronRight className="h-3 w-3" />
            </button>
          </div>
          {stats.killChainPhases.length > 0 ? (
            <div className="space-y-2">
              {stats.killChainPhases.slice(0, 6).map(k => {
                const max = stats.killChainPhases[0].value;
                return (
                  <div key={k.name}>
                    <div className="flex items-center justify-between mb-1">
                      <span className="text-xs text-slate-300 truncate max-w-[70%]">{k.name}</span>
                      <span className="text-xs font-bold text-slate-200">{k.value}</span>
                    </div>
                    <div className="h-1.5 rounded-full bg-slate-800 overflow-hidden">
                      <div className="h-full rounded-full bg-red-500" style={{ width: `${(k.value / max) * 100}%` }} />
                    </div>
                  </div>
                );
              })}
            </div>
          ) : (
            <div className="flex items-center justify-center h-32 text-sm text-slate-500">No kill chain data</div>
          )}
        </div>
      </div>

      {/* Target List */}
      <div className="rounded-xl border border-slate-200 bg-white p-5 dark:border-slate-800 dark:bg-slate-900">
        <div className="flex items-center justify-between mb-4">
          <h3 className="text-xs font-semibold uppercase tracking-wider text-slate-400">Assets / Targets</h3>
          <span className="text-xs text-slate-500">{targets.length} total</span>
        </div>
        <div className="overflow-x-auto">
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-slate-800">
                <th className="text-left py-2 px-3 text-xs font-medium text-slate-400">Domain</th>
                <th className="text-left py-2 px-3 text-xs font-medium text-slate-400">Status</th>
                <th className="text-left py-2 px-3 text-xs font-medium text-slate-400">Risk</th>
                <th className="text-left py-2 px-3 text-xs font-medium text-slate-400">Grade</th>
                <th className="text-left py-2 px-3 text-xs font-medium text-slate-400">Modules</th>
                <th className="text-right py-2 px-3 text-xs font-medium text-slate-400">Actions</th>
              </tr>
            </thead>
            <tbody>
              {targets.map(target => {
                const tScans = scans.filter(s => s.target_id === target.id);
                const latest = tScans.sort((a, b) => b.id - a.id)[0];
                const grade = latest?.risk_grade || '-';
                return (
                  <tr key={target.id} className="border-b border-slate-800/50 hover:bg-slate-800/30 transition-colors">
                    <td className="py-3 px-3">
                      <span className="font-medium text-slate-200">{target.domain}</span>
                    </td>
                    <td className="py-3 px-3">
                      <span className={`inline-flex items-center rounded-full px-2 py-0.5 text-xs font-medium ${
                        latest?.status === 'completed' ? 'bg-emerald-900/30 text-emerald-400' :
                        latest?.status === 'running' ? 'bg-blue-900/30 text-blue-400' :
                        'bg-slate-800 text-slate-400'
                      }`}>
                        {latest?.status || 'Not scanned'}
                      </span>
                    </td>
                    <td className="py-3 px-3">
                      <span className="text-sm font-bold text-slate-200">{latest?.risk_score ?? '-'}</span>
                    </td>
                    <td className="py-3 px-3">
                      <span className={`text-sm font-bold ${GRADE_COLOR[grade] || 'text-slate-400'}`}>{grade}</span>
                    </td>
                    <td className="py-3 px-3 text-xs text-slate-400">
                      {latest ? `${latest.completed_modules || 0}/${latest.enabled_modules || 0}` : '-'}
                    </td>
                    <td className="py-3 px-3 text-right">
                      <button
                        onClick={() => navigate(`/target-dashboard?id=${target.id}`)}
                        className="text-xs text-brand-400 hover:text-brand-300 font-medium"
                      >
                        Details
                      </button>
                    </td>
                  </tr>
                );
              })}
              {targets.length === 0 && (
                <tr>
                  <td colSpan={6} className="py-8 text-center text-sm text-slate-500">
                    No targets yet. Start a scan to add targets.
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}
