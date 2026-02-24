import { useState, useEffect, useMemo } from 'react';

interface Finding {
  id: number;
  severity: string;
  category: string;
  finding: string;
  owasp_category: string;
  owasp_name: string;
  tool_source: string;
}

interface Target { id: number; domain: string; }

const SEV_COLORS: Record<string, string> = {
  Critical: 'bg-red-500', High: 'bg-orange-500', Medium: 'bg-amber-400', Low: 'bg-emerald-500', Info: 'bg-blue-500',
};
const SEV_ORDER = ['Critical', 'High', 'Medium', 'Low', 'Info'];
const BAR_COLORS: Record<string, string> = {
  Critical: 'bg-red-500', High: 'bg-orange-500', Medium: 'bg-amber-400', Low: 'bg-emerald-400', Info: 'bg-blue-400',
};

const OWASP_CATEGORIES = [
  { id: 'A01:2021', name: 'Broken Access Control', icon: '🔓', color: 'from-red-500 to-red-600' },
  { id: 'A02:2021', name: 'Cryptographic Failures', icon: '🔐', color: 'from-orange-500 to-orange-600' },
  { id: 'A03:2021', name: 'Injection', icon: '💉', color: 'from-amber-500 to-amber-600' },
  { id: 'A04:2021', name: 'Insecure Design', icon: '📐', color: 'from-yellow-500 to-yellow-600' },
  { id: 'A05:2021', name: 'Security Misconfiguration', icon: '⚙️', color: 'from-lime-500 to-lime-600' },
  { id: 'A06:2021', name: 'Vulnerable Components', icon: '📦', color: 'from-emerald-500 to-emerald-600' },
  { id: 'A07:2021', name: 'Auth Failures', icon: '🔑', color: 'from-teal-500 to-teal-600' },
  { id: 'A08:2021', name: 'Data Integrity', icon: '📝', color: 'from-cyan-500 to-cyan-600' },
  { id: 'A09:2021', name: 'Logging Failures', icon: '📋', color: 'from-blue-500 to-blue-600' },
  { id: 'A10:2021', name: 'SSRF', icon: '🌐', color: 'from-violet-500 to-violet-600' },
];

export function OwaspPage() {
  const [findings, setFindings] = useState<Finding[]>([]);
  const [targets, setTargets] = useState<Target[]>([]);
  const [selectedTarget, setSelectedTarget] = useState('');
  const [expandedCategory, setExpandedCategory] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);

  const loadData = async (targetId?: string) => {
    setLoading(true);
    try {
      const qs = targetId ? `&target_id=${targetId}` : '';
      const [findingsRes, targetsRes] = await Promise.all([
        fetch(`/api/findings?per_page=1000${qs}`).then(r => r.json()),
        fetch('/api/targets').then(r => r.json()),
      ]);
      setFindings((findingsRes.data || []).filter((f: Finding) => f.owasp_category));
      setTargets(targetsRes.data || []);
    } catch (e) { console.error(e); }
    setLoading(false);
  };

  useEffect(() => { loadData(); }, []);

  const handleTargetChange = (tid: string) => {
    setSelectedTarget(tid);
    loadData(tid || undefined);
  };

  const categoryMap = useMemo(() => {
    const m = new Map<string, Finding[]>();
    for (const f of findings) {
      const existing = m.get(f.owasp_category) || [];
      existing.push(f);
      m.set(f.owasp_category, existing);
    }
    return m;
  }, [findings]);

  const coveredCount = OWASP_CATEGORIES.filter(c => categoryMap.has(c.id)).length;
  const maxCount = Math.max(...OWASP_CATEGORIES.map(c => (categoryMap.get(c.id) || []).length), 1);

  if (loading) return <div className="py-12 text-center text-slate-400">Loading OWASP Top 10 mapping...</div>;

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-slate-900 dark:text-white">OWASP Top 10 (2021)</h1>
          <p className="text-sm text-slate-500">{findings.length} findings mapped across {coveredCount} of 10 categories</p>
        </div>
        <select value={selectedTarget} onChange={e => handleTargetChange(e.target.value)}
          className="rounded-lg border border-slate-200 bg-white px-3 py-1.5 text-sm dark:border-slate-700 dark:bg-slate-800 dark:text-white">
          <option value="">All Targets</option>
          {targets.map(t => <option key={t.id} value={t.id}>{t.domain}</option>)}
        </select>
      </div>

      {/* Coverage + Chart */}
      <div className="grid grid-cols-3 gap-4">
        <div className="rounded-xl border border-slate-200 bg-white p-5 dark:border-slate-800 dark:bg-slate-900">
          <p className="text-[10px] font-medium uppercase tracking-wide text-slate-400">Coverage</p>
          <p className="mt-1 text-3xl font-bold text-brand-600">{coveredCount}<span className="text-sm font-normal text-slate-400">/10</span></p>
          <div className="mt-2 h-2 w-full rounded-full bg-slate-100 dark:bg-slate-800 overflow-hidden">
            <div className="h-full rounded-full bg-brand-500 transition-all" style={{ width: `${coveredCount * 10}%` }} />
          </div>
        </div>
        <div className="rounded-xl border border-slate-200 bg-white p-5 dark:border-slate-800 dark:bg-slate-900">
          <p className="text-[10px] font-medium uppercase tracking-wide text-slate-400">Total Findings</p>
          <p className="mt-1 text-3xl font-bold text-blue-600">{findings.length}</p>
        </div>
        <div className="rounded-xl border border-slate-200 bg-white p-5 dark:border-slate-800 dark:bg-slate-900">
          <p className="text-[10px] font-medium uppercase tracking-wide text-slate-400">Severity Breakdown</p>
          <div className="mt-2 flex items-end gap-1 h-10">
            {SEV_ORDER.map(sev => {
              const count = findings.filter(f => f.severity === sev).length;
              const h = findings.length > 0 ? Math.max(4, (count / findings.length) * 40) : 0;
              return (
                <div key={sev} className="flex-1 flex flex-col items-center">
                  <span className="text-[9px] font-bold text-slate-500">{count}</span>
                  <div className={`w-full rounded-t ${BAR_COLORS[sev]}`} style={{ height: `${h}px` }} />
                  <span className="text-[7px] text-slate-400 mt-0.5">{sev[0]}</span>
                </div>
              );
            })}
          </div>
        </div>
      </div>

      {/* Bar chart */}
      <div className="rounded-xl border border-slate-200 bg-white p-5 dark:border-slate-800 dark:bg-slate-900">
        <h3 className="text-xs font-semibold uppercase tracking-wide text-slate-400 mb-4">Distribution by Category</h3>
        <div className="space-y-2">
          {OWASP_CATEGORIES.map(cat => {
            const count = (categoryMap.get(cat.id) || []).length;
            const pct = maxCount > 0 ? (count / maxCount) * 100 : 0;
            return (
              <div key={cat.id} className="flex items-center gap-3">
                <span className="w-16 text-[10px] font-bold text-slate-500 shrink-0">{cat.id.split(':')[0]}</span>
                <div className="flex-1 h-5 rounded bg-slate-50 dark:bg-slate-800 overflow-hidden relative">
                  <div className={`h-full rounded bg-gradient-to-r ${cat.color} transition-all`} style={{ width: `${pct}%` }} />
                  {count > 0 && (
                    <span className="absolute right-2 top-0.5 text-[10px] font-bold text-slate-600 dark:text-slate-300">{count}</span>
                  )}
                </div>
              </div>
            );
          })}
        </div>
      </div>

      {/* Category cards */}
      <div className="grid gap-3 md:grid-cols-2">
        {OWASP_CATEGORIES.map(cat => {
          const catFindings = categoryMap.get(cat.id) || [];
          const hasFindings = catFindings.length > 0;
          const isExpanded = expandedCategory === cat.id;
          const sevDist: Record<string, number> = {};
          catFindings.forEach(f => { sevDist[f.severity] = (sevDist[f.severity] || 0) + 1; });

          return (
            <div key={cat.id} className={`rounded-xl border bg-white dark:bg-slate-900 overflow-hidden ${
              hasFindings ? 'border-slate-200 dark:border-slate-800' : 'border-slate-100 dark:border-slate-800/50 opacity-50'
            }`}>
              <button
                onClick={() => hasFindings && setExpandedCategory(isExpanded ? null : cat.id)}
                disabled={!hasFindings}
                className="flex w-full items-center gap-4 p-4 text-left"
              >
                <div className={`flex h-10 w-10 shrink-0 items-center justify-center rounded-lg bg-gradient-to-br ${cat.color} text-lg`}>
                  {hasFindings ? <span className="text-lg font-bold text-white">{catFindings.length}</span> : <span className="text-white/40 text-sm">0</span>}
                </div>
                <div className="flex-1 min-w-0">
                  <div className="flex items-center gap-2">
                    <span className="text-[10px] font-bold text-slate-400">{cat.id}</span>
                    <h3 className="text-sm font-semibold text-slate-900 dark:text-white truncate">{cat.name}</h3>
                  </div>
                  {hasFindings && (
                    <div className="flex items-center gap-1 mt-1">
                      {SEV_ORDER.filter(s => sevDist[s]).map(sev => (
                        <span key={sev} className={`rounded px-1 py-0 text-[9px] font-medium text-white ${SEV_COLORS[sev]}`}>{sevDist[sev]}</span>
                      ))}
                    </div>
                  )}
                </div>
                {hasFindings && (
                  <svg className={`h-4 w-4 text-slate-400 transition-transform ${isExpanded ? 'rotate-180' : ''}`} fill="none" viewBox="0 0 24 24" stroke="currentColor">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M19 9l-7 7-7-7" />
                  </svg>
                )}
              </button>
              {isExpanded && (
                <div className="border-t border-slate-100 bg-slate-50/50 px-4 py-3 dark:border-slate-800 dark:bg-slate-800/30 max-h-64 overflow-y-auto space-y-2">
                  {catFindings.map(f => (
                    <div key={f.id} className="flex items-start gap-2 text-xs">
                      <span className={`mt-0.5 shrink-0 rounded px-1.5 py-0.5 text-[10px] font-medium text-white ${SEV_COLORS[f.severity]}`}>{f.severity}</span>
                      <div className="flex-1 min-w-0">
                        <p className="text-slate-700 dark:text-slate-300 truncate">{f.finding}</p>
                        <p className="text-slate-400 text-[10px]">{f.tool_source} | {f.category}</p>
                      </div>
                    </div>
                  ))}
                </div>
              )}
            </div>
          );
        })}
      </div>
    </div>
  );
}
