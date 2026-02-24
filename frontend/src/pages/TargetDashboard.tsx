import { useEffect, useMemo, useState } from 'react';
import { useNavigate, useSearchParams } from 'react-router-dom';
import {
  PieChart, Pie, Cell, ResponsiveContainer, Tooltip,
  BarChart, Bar, XAxis, YAxis, CartesianGrid,
} from 'recharts';
import {
  Shield, AlertTriangle, ChevronLeft, Target, Bug, Link, Crosshair,
  Server, Code, Globe, Database, Cpu, Lock,
} from 'lucide-react';

type TargetData = { id: number; domain: string; created_at?: string };
type ScanData = {
  id: number; target_id: number; status: string;
  risk_score?: number; risk_grade?: string;
  enabled_modules?: number; completed_modules?: number;
};
type FindingData = {
  id: number; severity: string; category: string; finding: string;
  remediation?: string; evidence?: string; confidence?: string;
  mitre_tactic?: string; mitre_technique?: string; mitre_attack_id?: string;
  owasp_category?: string; owasp_name?: string;
  kill_chain_phase?: string; tool_source?: string; tool_count?: number;
};
type TechItem = { name: string; source: string; confidence: string; count: number };
type TechStack = {
  domain: string;
  servers: TechItem[]; frameworks: TechItem[]; languages: TechItem[];
  cms: TechItem[]; databases: TechItem[]; cdn: TechItem[];
  analytics: TechItem[]; javascript: TechItem[]; security: TechItem[];
  other: TechItem[];
};

const SEV_COLORS: Record<string, string> = {
  Critical: '#ef4444', High: '#f97316', Medium: '#eab308', Low: '#22c55e',
};
const MITRE_COLORS = ['#6366f1', '#818cf8', '#a5b4fc', '#c7d2fe', '#4f46e5', '#4338ca'];
const OWASP_COLORS = ['#f97316', '#fb923c', '#fdba74', '#fed7aa', '#ea580c', '#c2410c'];
const KC_COLORS = ['#ef4444', '#f87171', '#fca5a5', '#fecaca', '#dc2626', '#b91c1c', '#991b1b'];
const TECH_ICONS: Record<string, any> = {
  servers: Server, frameworks: Code, languages: Code, cms: Globe,
  databases: Database, cdn: Globe, analytics: Cpu, javascript: Code,
  security: Lock, other: Cpu,
};

export function TargetDashboard() {
  const navigate = useNavigate();
  const [searchParams] = useSearchParams();
  const targetIdParam = searchParams.get('id');

  const [targets, setTargets] = useState<TargetData[]>([]);
  const [selectedTargetId, setSelectedTargetId] = useState<number | null>(
    targetIdParam ? parseInt(targetIdParam) : null
  );
  const [scans, setScans] = useState<ScanData[]>([]);
  const [findings, setFindings] = useState<FindingData[]>([]);
  const [techStack, setTechStack] = useState<TechStack | null>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    fetchTargets();
  }, []);

  useEffect(() => {
    if (selectedTargetId) fetchTargetData(selectedTargetId);
  }, [selectedTargetId]);

  const fetchTargets = async () => {
    try {
      const res = await fetch('/api/targets');
      const data = await res.json();
      const list = data.data || [];
      setTargets(list);
      if (!selectedTargetId && list.length > 0) setSelectedTargetId(list[0].id);
    } catch { }
  };

  const fetchTargetData = async (id: number) => {
    setLoading(true);
    try {
      const [sRes, fRes, tRes] = await Promise.all([
        fetch('/api/scans'),
        fetch(`/api/findings?target_id=${id}&per_page=2000`),
        fetch(`/api/findings/techstack?target_id=${id}`),
      ]);
      const s = await sRes.json(), f = await fRes.json(), t = await tRes.json();
      setScans((s.data || []).filter((sc: ScanData) => sc.target_id === id));
      setFindings(f.data || []);
      const techData = t.data || [];
      setTechStack(techData.length > 0 ? techData[0] : null);
    } catch (err) { console.error('target data load failed', err); }
    setLoading(false);
  };

  const selectedTarget = targets.find(t => t.id === selectedTargetId);
  const latestScan = scans.sort((a, b) => b.id - a.id)[0];

  const analysis = useMemo(() => {
    const critical = findings.filter(f => f.severity === 'Critical').length;
    const high = findings.filter(f => f.severity === 'High').length;
    const medium = findings.filter(f => f.severity === 'Medium').length;
    const low = findings.filter(f => f.severity === 'Low').length;

    // Top vulns by severity
    const topVulns = [...findings]
      .sort((a, b) => {
        const order: Record<string, number> = { Critical: 0, High: 1, Medium: 2, Low: 3 };
        return (order[a.severity] ?? 4) - (order[b.severity] ?? 4);
      })
      .slice(0, 10);

    // MITRE TTPs
    const mitreMap: Record<string, { tactic: string; technique: string; id: string; count: number; severity: string }> = {};
    findings.forEach(f => {
      if (f.mitre_tactic && f.mitre_technique) {
        const key = `${f.mitre_tactic}|${f.mitre_technique}`;
        if (!mitreMap[key]) {
          mitreMap[key] = { tactic: f.mitre_tactic, technique: f.mitre_technique, id: f.mitre_attack_id || '', count: 0, severity: f.severity };
        }
        mitreMap[key].count++;
      }
    });
    const mitreTTPs = Object.values(mitreMap).sort((a, b) => b.count - a.count);

    // MITRE tactic distribution for chart
    const tacticMap: Record<string, number> = {};
    findings.forEach(f => {
      if (f.mitre_tactic) tacticMap[f.mitre_tactic] = (tacticMap[f.mitre_tactic] || 0) + 1;
    });
    const mitreTacticChart = Object.entries(tacticMap).sort((a, b) => b[1] - a[1]).map(([name, value]) => ({ name, value }));

    // OWASP
    const owaspMap: Record<string, { category: string; name: string; count: number; findings: FindingData[] }> = {};
    findings.forEach(f => {
      if (f.owasp_category) {
        if (!owaspMap[f.owasp_category]) {
          owaspMap[f.owasp_category] = { category: f.owasp_category, name: f.owasp_name || '', count: 0, findings: [] };
        }
        owaspMap[f.owasp_category].count++;
        if (owaspMap[f.owasp_category].findings.length < 3) owaspMap[f.owasp_category].findings.push(f);
      }
    });
    const owaspCategories = Object.values(owaspMap).sort((a, b) => b.count - a.count);
    const owaspChart = owaspCategories.map(o => ({
      name: o.category.length > 15 ? o.category.substring(0, 15) + '...' : o.category,
      value: o.count,
    }));

    // Kill Chain
    const kcMap: Record<string, number> = {};
    findings.forEach(f => {
      if (f.kill_chain_phase) kcMap[f.kill_chain_phase] = (kcMap[f.kill_chain_phase] || 0) + 1;
    });
    const killChainPhases = Object.entries(kcMap).sort((a, b) => b[1] - a[1]).map(([name, value]) => ({ name, value }));

    // Tool sources
    const toolMap: Record<string, number> = {};
    findings.forEach(f => {
      const tool = f.tool_source || 'native';
      toolMap[tool] = (toolMap[tool] || 0) + 1;
    });
    const toolSources = Object.entries(toolMap).sort((a, b) => b[1] - a[1]).map(([name, value]) => ({ name, value }));

    return {
      critical, high, medium, low, total: findings.length,
      topVulns, mitreTTPs, mitreTacticChart,
      owaspCategories, owaspChart, killChainPhases, toolSources,
    };
  }, [findings]);

  const sevPieData = [
    { name: 'Critical', value: analysis.critical, color: SEV_COLORS.Critical },
    { name: 'High', value: analysis.high, color: SEV_COLORS.High },
    { name: 'Medium', value: analysis.medium, color: SEV_COLORS.Medium },
    { name: 'Low', value: analysis.low, color: SEV_COLORS.Low },
  ].filter(d => d.value > 0);

  // Tech stack sections
  const techSections = techStack ? [
    { key: 'servers', label: 'Web Servers', items: techStack.servers },
    { key: 'frameworks', label: 'Frameworks', items: techStack.frameworks },
    { key: 'languages', label: 'Languages', items: techStack.languages },
    { key: 'cms', label: 'CMS', items: techStack.cms },
    { key: 'databases', label: 'Databases', items: techStack.databases },
    { key: 'cdn', label: 'CDN / WAF', items: techStack.cdn },
    { key: 'javascript', label: 'JavaScript', items: techStack.javascript },
    { key: 'security', label: 'Security Headers', items: techStack.security },
    { key: 'analytics', label: 'Analytics', items: techStack.analytics },
  ].filter(s => s.items && s.items.length > 0) : [];

  return (
    <div className="space-y-5">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-3">
          <button onClick={() => navigate('/')} className="p-1.5 rounded-lg hover:bg-slate-800 transition-colors">
            <ChevronLeft className="h-5 w-5 text-slate-400" />
          </button>
          <div>
            <h1 className="text-2xl font-bold text-white">Target Dashboard</h1>
            <p className="text-sm text-slate-500">
              {selectedTarget?.domain || 'Select a target'}
            </p>
          </div>
        </div>

        {/* Target Selector */}
        <select
          value={selectedTargetId || ''}
          onChange={e => setSelectedTargetId(parseInt(e.target.value))}
          className="input max-w-xs"
        >
          {targets.map(t => (
            <option key={t.id} value={t.id}>{t.domain}</option>
          ))}
        </select>
      </div>

      {loading ? (
        <div className="flex items-center justify-center h-96">
          <div className="flex flex-col items-center gap-3">
            <div className="h-8 w-8 animate-spin rounded-full border-2 border-brand-600 border-t-transparent" />
            <p className="text-sm text-slate-400">Loading target data...</p>
          </div>
        </div>
      ) : (
        <>
          {/* Summary Cards */}
          <div className="grid grid-cols-2 sm:grid-cols-3 md:grid-cols-6 gap-3">
            <div className="rounded-xl bg-slate-800 p-4">
              <p className="text-2xl font-bold text-white">{analysis.total}</p>
              <p className="text-xs text-slate-400 mt-1">Total Findings</p>
            </div>
            <div className="rounded-xl bg-red-600 p-4">
              <p className="text-2xl font-bold text-white">{analysis.critical}</p>
              <p className="text-xs text-white/80 mt-1">Critical</p>
            </div>
            <div className="rounded-xl bg-orange-500 p-4">
              <p className="text-2xl font-bold text-white">{analysis.high}</p>
              <p className="text-xs text-white/80 mt-1">High</p>
            </div>
            <div className="rounded-xl bg-yellow-500 p-4">
              <p className="text-2xl font-bold text-slate-900">{analysis.medium}</p>
              <p className="text-xs text-slate-900/80 mt-1">Medium</p>
            </div>
            <div className="rounded-xl bg-emerald-500 p-4">
              <p className="text-2xl font-bold text-white">{analysis.low}</p>
              <p className="text-xs text-white/80 mt-1">Low</p>
            </div>
            <div className="rounded-xl bg-indigo-600 p-4">
              <p className="text-2xl font-bold text-white">{latestScan?.risk_score ?? '-'}</p>
              <p className="text-xs text-white/80 mt-1">Risk Score ({latestScan?.risk_grade || '-'})</p>
            </div>
          </div>

          {/* Row 1: Severity Donut + Top Vulns */}
          <div className="grid gap-5 lg:grid-cols-[1fr_2fr]">
            {/* Severity Donut */}
            <div className="rounded-xl border border-slate-800 bg-slate-900 p-5">
              <h3 className="text-xs font-semibold uppercase tracking-wider text-slate-400 mb-4">Severity Distribution</h3>
              {sevPieData.length > 0 ? (
                <>
                  <ResponsiveContainer width="100%" height={200}>
                    <PieChart>
                      <Pie data={sevPieData} cx="50%" cy="50%" innerRadius={50} outerRadius={80} paddingAngle={3} dataKey="value" stroke="none">
                        {sevPieData.map((entry, i) => <Cell key={i} fill={entry.color} />)}
                      </Pie>
                      <Tooltip contentStyle={{ background: '#1e293b', border: 'none', borderRadius: '8px', color: '#fff' }} />
                    </PieChart>
                  </ResponsiveContainer>
                  <div className="space-y-1.5 mt-2">
                    {sevPieData.map(d => (
                      <div key={d.name} className="flex items-center justify-between">
                        <div className="flex items-center gap-2">
                          <span className="h-2.5 w-2.5 rounded-full" style={{ backgroundColor: d.color }} />
                          <span className="text-xs text-slate-400">{d.name}</span>
                        </div>
                        <span className="text-xs font-bold text-slate-200">{d.value}</span>
                      </div>
                    ))}
                  </div>
                </>
              ) : (
                <div className="flex items-center justify-center h-48 text-sm text-slate-500">No findings</div>
              )}
            </div>

            {/* Top Vulnerabilities */}
            <div className="rounded-xl border border-slate-800 bg-slate-900 p-5">
              <h3 className="text-xs font-semibold uppercase tracking-wider text-slate-400 mb-4">Top Vulnerabilities</h3>
              <div className="overflow-x-auto">
                <table className="w-full text-sm">
                  <thead>
                    <tr className="border-b border-slate-800">
                      <th className="text-left py-2 px-2 text-xs font-medium text-slate-400">Severity</th>
                      <th className="text-left py-2 px-2 text-xs font-medium text-slate-400">Category</th>
                      <th className="text-left py-2 px-2 text-xs font-medium text-slate-400">Finding</th>
                      <th className="text-left py-2 px-2 text-xs font-medium text-slate-400">Tool</th>
                    </tr>
                  </thead>
                  <tbody>
                    {analysis.topVulns.map(v => (
                      <tr key={v.id} className="border-b border-slate-800/50">
                        <td className="py-2 px-2">
                          <span className="inline-flex items-center rounded-full px-2 py-0.5 text-xs font-medium" style={{
                            backgroundColor: (SEV_COLORS[v.severity] || '#6366f1') + '20',
                            color: SEV_COLORS[v.severity] || '#6366f1',
                          }}>
                            {v.severity}
                          </span>
                        </td>
                        <td className="py-2 px-2 text-xs text-slate-300">{v.category}</td>
                        <td className="py-2 px-2 text-xs text-slate-400 max-w-xs truncate">{v.finding}</td>
                        <td className="py-2 px-2 text-xs text-slate-500">{v.tool_source || 'native'}</td>
                      </tr>
                    ))}
                    {analysis.topVulns.length === 0 && (
                      <tr><td colSpan={4} className="py-6 text-center text-sm text-slate-500">No findings yet</td></tr>
                    )}
                  </tbody>
                </table>
              </div>
            </div>
          </div>

          {/* Row 2: MITRE ATT&CK */}
          <div className="rounded-xl border border-slate-800 bg-slate-900 p-5">
            <div className="flex items-center justify-between mb-4">
              <h3 className="text-xs font-semibold uppercase tracking-wider text-slate-400 flex items-center gap-2">
                <Target className="h-4 w-4 text-indigo-400" /> MITRE ATT&CK Mapped TTPs
              </h3>
              <button onClick={() => navigate('/mitre')} className="text-xs text-brand-400 hover:text-brand-300">Full Matrix</button>
            </div>
            <div className="grid gap-5 lg:grid-cols-[1fr_1.5fr]">
              {/* MITRE Chart */}
              {analysis.mitreTacticChart.length > 0 ? (
                <ResponsiveContainer width="100%" height={250}>
                  <BarChart data={analysis.mitreTacticChart.slice(0, 8)} layout="vertical" margin={{ left: 10, right: 20 }}>
                    <CartesianGrid strokeDasharray="3 3" stroke="#334155" />
                    <XAxis type="number" tick={{ fill: '#94a3b8', fontSize: 11 }} />
                    <YAxis dataKey="name" type="category" width={130} tick={{ fill: '#94a3b8', fontSize: 10 }} />
                    <Tooltip contentStyle={{ background: '#1e293b', border: 'none', borderRadius: '8px', color: '#fff' }} />
                    <Bar dataKey="value" radius={[0, 4, 4, 0]}>
                      {analysis.mitreTacticChart.slice(0, 8).map((_, i) => <Cell key={i} fill={MITRE_COLORS[i % MITRE_COLORS.length]} />)}
                    </Bar>
                  </BarChart>
                </ResponsiveContainer>
              ) : (
                <div className="flex items-center justify-center h-48 text-sm text-slate-500">No MITRE mappings</div>
              )}

              {/* MITRE TTP Table */}
              <div className="overflow-y-auto max-h-64">
                <table className="w-full text-sm">
                  <thead className="sticky top-0 bg-slate-900">
                    <tr className="border-b border-slate-800">
                      <th className="text-left py-2 px-2 text-xs font-medium text-slate-400">ID</th>
                      <th className="text-left py-2 px-2 text-xs font-medium text-slate-400">Tactic</th>
                      <th className="text-left py-2 px-2 text-xs font-medium text-slate-400">Technique</th>
                      <th className="text-right py-2 px-2 text-xs font-medium text-slate-400">Count</th>
                    </tr>
                  </thead>
                  <tbody>
                    {analysis.mitreTTPs.slice(0, 12).map((t, i) => (
                      <tr key={i} className="border-b border-slate-800/50">
                        <td className="py-1.5 px-2 text-xs font-mono text-indigo-400">{t.id || '-'}</td>
                        <td className="py-1.5 px-2 text-xs text-slate-300">{t.tactic}</td>
                        <td className="py-1.5 px-2 text-xs text-slate-400 truncate max-w-[200px]">{t.technique}</td>
                        <td className="py-1.5 px-2 text-xs font-bold text-slate-200 text-right">{t.count}</td>
                      </tr>
                    ))}
                    {analysis.mitreTTPs.length === 0 && (
                      <tr><td colSpan={4} className="py-4 text-center text-xs text-slate-500">No MITRE mappings</td></tr>
                    )}
                  </tbody>
                </table>
              </div>
            </div>
          </div>

          {/* Row 3: OWASP + Kill Chain */}
          <div className="grid gap-5 lg:grid-cols-2">
            {/* OWASP */}
            <div className="rounded-xl border border-slate-800 bg-slate-900 p-5">
              <div className="flex items-center justify-between mb-4">
                <h3 className="text-xs font-semibold uppercase tracking-wider text-slate-400 flex items-center gap-2">
                  <Bug className="h-4 w-4 text-amber-400" /> OWASP Categories
                </h3>
                <button onClick={() => navigate('/owasp')} className="text-xs text-brand-400 hover:text-brand-300">Full View</button>
              </div>
              {analysis.owaspChart.length > 0 ? (
                <>
                  <ResponsiveContainer width="100%" height={180}>
                    <PieChart>
                      <Pie data={analysis.owaspChart} cx="50%" cy="50%" outerRadius={70} paddingAngle={2} dataKey="value" stroke="none">
                        {analysis.owaspChart.map((_, i) => <Cell key={i} fill={OWASP_COLORS[i % OWASP_COLORS.length]} />)}
                      </Pie>
                      <Tooltip contentStyle={{ background: '#1e293b', border: 'none', borderRadius: '8px', color: '#fff' }} />
                    </PieChart>
                  </ResponsiveContainer>
                  <div className="space-y-2 mt-3">
                    {analysis.owaspCategories.slice(0, 5).map((o, i) => (
                      <div key={o.category} className="flex items-center justify-between">
                        <div className="flex items-center gap-2">
                          <span className="h-2 w-2 rounded-full" style={{ backgroundColor: OWASP_COLORS[i % OWASP_COLORS.length] }} />
                          <span className="text-xs text-slate-300 truncate max-w-[200px]">{o.category}</span>
                        </div>
                        <span className="text-xs font-bold text-slate-200">{o.count}</span>
                      </div>
                    ))}
                  </div>
                </>
              ) : (
                <div className="flex items-center justify-center h-48 text-sm text-slate-500">No OWASP data</div>
              )}
            </div>

            {/* Kill Chain */}
            <div className="rounded-xl border border-slate-800 bg-slate-900 p-5">
              <div className="flex items-center justify-between mb-4">
                <h3 className="text-xs font-semibold uppercase tracking-wider text-slate-400 flex items-center gap-2">
                  <Link className="h-4 w-4 text-red-400" /> Kill Chain Phases
                </h3>
                <button onClick={() => navigate('/killchain')} className="text-xs text-brand-400 hover:text-brand-300">Full View</button>
              </div>
              {analysis.killChainPhases.length > 0 ? (
                <>
                  <ResponsiveContainer width="100%" height={200}>
                    <BarChart data={analysis.killChainPhases} margin={{ left: 0, right: 10 }}>
                      <CartesianGrid strokeDasharray="3 3" stroke="#334155" />
                      <XAxis dataKey="name" tick={{ fill: '#94a3b8', fontSize: 9 }} angle={-30} textAnchor="end" height={60} />
                      <YAxis tick={{ fill: '#94a3b8', fontSize: 11 }} />
                      <Tooltip contentStyle={{ background: '#1e293b', border: 'none', borderRadius: '8px', color: '#fff' }} />
                      <Bar dataKey="value" radius={[4, 4, 0, 0]}>
                        {analysis.killChainPhases.map((_, i) => <Cell key={i} fill={KC_COLORS[i % KC_COLORS.length]} />)}
                      </Bar>
                    </BarChart>
                  </ResponsiveContainer>
                  <div className="grid grid-cols-2 gap-1 mt-2">
                    {analysis.killChainPhases.map((k, i) => (
                      <div key={k.name} className="flex items-center gap-2">
                        <span className="h-2 w-2 rounded-full" style={{ backgroundColor: KC_COLORS[i % KC_COLORS.length] }} />
                        <span className="text-xs text-slate-400 truncate">{k.name}</span>
                        <span className="text-xs font-bold text-slate-200 ml-auto">{k.value}</span>
                      </div>
                    ))}
                  </div>
                </>
              ) : (
                <div className="flex items-center justify-center h-48 text-sm text-slate-500">No kill chain data</div>
              )}
            </div>
          </div>

          {/* Row 4: BAS + Tech Stack */}
          <div className="grid gap-5 lg:grid-cols-2">
            {/* BAS - Breach Simulation Summary */}
            <div className="rounded-xl border border-slate-800 bg-slate-900 p-5">
              <div className="flex items-center justify-between mb-4">
                <h3 className="text-xs font-semibold uppercase tracking-wider text-slate-400 flex items-center gap-2">
                  <Crosshair className="h-4 w-4 text-purple-400" /> Breach & Attack Simulation
                </h3>
                <button onClick={() => navigate('/breach')} className="text-xs text-brand-400 hover:text-brand-300">Full View</button>
              </div>
              <div className="grid grid-cols-2 gap-3 mb-4">
                <div className="rounded-lg bg-slate-800 p-3">
                  <p className="text-xs text-slate-400">Scan Status</p>
                  <p className="text-lg font-bold text-white">{latestScan?.status || 'N/A'}</p>
                </div>
                <div className="rounded-lg bg-slate-800 p-3">
                  <p className="text-xs text-slate-400">Risk Grade</p>
                  <p className={`text-lg font-bold ${
                    latestScan?.risk_grade === 'A' ? 'text-emerald-400' :
                    latestScan?.risk_grade === 'B' ? 'text-green-400' :
                    latestScan?.risk_grade === 'C' ? 'text-yellow-400' :
                    latestScan?.risk_grade === 'D' ? 'text-orange-400' :
                    latestScan?.risk_grade === 'F' ? 'text-red-400' : 'text-slate-400'
                  }`}>{latestScan?.risk_grade || '-'}</p>
                </div>
              </div>

              {/* Tool coverage */}
              <div className="space-y-2">
                <p className="text-xs text-slate-400 mb-2">Tool Coverage</p>
                {analysis.toolSources.slice(0, 5).map(t => {
                  const max = analysis.toolSources[0]?.value || 1;
                  return (
                    <div key={t.name}>
                      <div className="flex items-center justify-between mb-1">
                        <span className="text-xs text-slate-300">{t.name}</span>
                        <span className="text-xs font-bold text-slate-200">{t.value} findings</span>
                      </div>
                      <div className="h-1.5 rounded-full bg-slate-800 overflow-hidden">
                        <div className="h-full rounded-full bg-purple-500" style={{ width: `${(t.value / max) * 100}%` }} />
                      </div>
                    </div>
                  );
                })}
                {analysis.toolSources.length === 0 && (
                  <p className="text-xs text-slate-500">No tool data available</p>
                )}
              </div>
            </div>

            {/* Tech Stack */}
            <div className="rounded-xl border border-slate-800 bg-slate-900 p-5">
              <div className="flex items-center justify-between mb-4">
                <h3 className="text-xs font-semibold uppercase tracking-wider text-slate-400 flex items-center gap-2">
                  <Cpu className="h-4 w-4 text-cyan-400" /> Tech Stack
                </h3>
                <button onClick={() => navigate('/passive-intel')} className="text-xs text-brand-400 hover:text-brand-300">Full View</button>
              </div>
              {techSections.length > 0 ? (
                <div className="space-y-3 max-h-80 overflow-y-auto">
                  {techSections.map(section => {
                    const Icon = TECH_ICONS[section.key] || Cpu;
                    return (
                      <div key={section.key}>
                        <div className="flex items-center gap-2 mb-1.5">
                          <Icon className="h-3.5 w-3.5 text-cyan-400" />
                          <span className="text-xs font-medium text-slate-300">{section.label}</span>
                          <span className="text-xs text-slate-500 ml-auto">{section.items.length}</span>
                        </div>
                        <div className="flex flex-wrap gap-1.5">
                          {section.items.map(item => (
                            <span key={item.name} className="inline-flex items-center rounded-md bg-slate-800 px-2 py-1 text-xs text-slate-300 border border-slate-700">
                              {item.name}
                              {item.confidence === 'High' && <span className="ml-1 h-1.5 w-1.5 rounded-full bg-emerald-400" />}
                            </span>
                          ))}
                        </div>
                      </div>
                    );
                  })}
                </div>
              ) : (
                <div className="flex items-center justify-center h-48 text-sm text-slate-500">
                  No tech stack detected. Run a scan first.
                </div>
              )}
            </div>
          </div>
        </>
      )}
    </div>
  );
}
