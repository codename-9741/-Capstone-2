import { useState, useEffect, useMemo } from 'react';

interface Finding {
  id: number;
  severity: string;
  category: string;
  finding: string;
  kill_chain_phase: string;
  tool_source: string;
  mitre_attack_id: string;
  mitre_technique: string;
}

interface Target { id: number; domain: string; }

const SEV_COLORS: Record<string, string> = {
  Critical: 'bg-red-500', High: 'bg-orange-500', Medium: 'bg-amber-400', Low: 'bg-emerald-500', Info: 'bg-blue-500',
};
const SEV_ORDER = ['Critical', 'High', 'Medium', 'Low', 'Info'];

const PHASES = [
  { id: 'Reconnaissance', short: 'Recon', description: 'Information gathering about the target', color: 'from-blue-500 to-blue-600', bg: 'bg-blue-500', ring: 'ring-blue-400' },
  { id: 'Weaponization', short: 'Weapon', description: 'Creating attack tools and payloads', color: 'from-indigo-500 to-indigo-600', bg: 'bg-indigo-500', ring: 'ring-indigo-400' },
  { id: 'Delivery', short: 'Deliver', description: 'Transmitting the weapon to the target', color: 'from-violet-500 to-violet-600', bg: 'bg-violet-500', ring: 'ring-violet-400' },
  { id: 'Exploitation', short: 'Exploit', description: 'Exploiting vulnerabilities to gain access', color: 'from-purple-500 to-purple-600', bg: 'bg-purple-500', ring: 'ring-purple-400' },
  { id: 'Installation', short: 'Install', description: 'Installing malware or backdoors', color: 'from-pink-500 to-pink-600', bg: 'bg-pink-500', ring: 'ring-pink-400' },
  { id: 'Command and Control', short: 'C2', description: 'Establishing remote control channels', color: 'from-rose-500 to-rose-600', bg: 'bg-rose-500', ring: 'ring-rose-400' },
  { id: 'Actions on Objectives', short: 'Actions', description: "Achieving the attacker's goals", color: 'from-red-500 to-red-600', bg: 'bg-red-500', ring: 'ring-red-400' },
];

export function KillChainPage() {
  const [findings, setFindings] = useState<Finding[]>([]);
  const [targets, setTargets] = useState<Target[]>([]);
  const [selectedTarget, setSelectedTarget] = useState('');
  const [expandedPhase, setExpandedPhase] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);

  const loadData = async (targetId?: string) => {
    setLoading(true);
    try {
      const qs = targetId ? `&target_id=${targetId}` : '';
      const [findingsRes, targetsRes] = await Promise.all([
        fetch(`/api/findings?per_page=1000${qs}`).then(r => r.json()),
        fetch('/api/targets').then(r => r.json()),
      ]);
      setFindings((findingsRes.data || []).filter((f: Finding) => f.kill_chain_phase));
      setTargets(targetsRes.data || []);
    } catch (e) { console.error(e); }
    setLoading(false);
  };

  useEffect(() => { loadData(); }, []);

  const handleTargetChange = (tid: string) => {
    setSelectedTarget(tid);
    loadData(tid || undefined);
  };

  const phaseMap = useMemo(() => {
    const m = new Map<string, Finding[]>();
    for (const f of findings) {
      const existing = m.get(f.kill_chain_phase) || [];
      existing.push(f);
      m.set(f.kill_chain_phase, existing);
    }
    return m;
  }, [findings]);

  const maxCount = Math.max(...PHASES.map(p => (phaseMap.get(p.id) || []).length), 1);
  const activePhasesCount = PHASES.filter(p => (phaseMap.get(p.id) || []).length > 0).length;

  if (loading) return <div className="py-12 text-center text-slate-400">Loading Kill Chain analysis...</div>;

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-slate-900 dark:text-white">Cyber Kill Chain</h1>
          <p className="text-sm text-slate-500">{findings.length} findings across {activePhasesCount} active phases</p>
        </div>
        <select value={selectedTarget} onChange={e => handleTargetChange(e.target.value)}
          className="rounded-lg border border-slate-200 bg-white px-3 py-1.5 text-sm dark:border-slate-700 dark:bg-slate-800 dark:text-white">
          <option value="">All Targets</option>
          {targets.map(t => <option key={t.id} value={t.id}>{t.domain}</option>)}
        </select>
      </div>

      {/* Stats */}
      <div className="grid grid-cols-3 gap-4">
        <div className="rounded-xl border border-slate-200 bg-white p-4 dark:border-slate-800 dark:bg-slate-900">
          <p className="text-[10px] font-medium uppercase tracking-wide text-slate-400">Active Phases</p>
          <p className="mt-1 text-2xl font-bold text-brand-600">{activePhasesCount}<span className="text-sm font-normal text-slate-400">/{PHASES.length}</span></p>
        </div>
        <div className="rounded-xl border border-slate-200 bg-white p-4 dark:border-slate-800 dark:bg-slate-900">
          <p className="text-[10px] font-medium uppercase tracking-wide text-slate-400">Total Findings</p>
          <p className="mt-1 text-2xl font-bold text-blue-600">{findings.length}</p>
        </div>
        <div className="rounded-xl border border-slate-200 bg-white p-4 dark:border-slate-800 dark:bg-slate-900">
          <p className="text-[10px] font-medium uppercase tracking-wide text-slate-400">Highest Risk Phase</p>
          <p className="mt-1 text-lg font-bold text-red-600">
            {PHASES.reduce((max, p) => (phaseMap.get(p.id) || []).length > (phaseMap.get(max) || []).length ? p.id : max, PHASES[0].id)}
          </p>
        </div>
      </div>

      {/* Pipeline visualization */}
      <div className="rounded-xl border border-slate-200 bg-white p-6 dark:border-slate-800 dark:bg-slate-900">
        <h3 className="text-xs font-semibold uppercase tracking-wide text-slate-400 mb-5">Kill Chain Pipeline</h3>
        <div className="relative">
          {/* Connection line */}
          <div className="absolute top-[44px] left-[5%] right-[5%] h-1 bg-slate-100 dark:bg-slate-800 rounded-full" />
          <div className="flex items-start justify-between relative">
            {PHASES.map((phase, i) => {
              const count = (phaseMap.get(phase.id) || []).length;
              const hasFindings = count > 0;
              const intensity = hasFindings ? Math.max(0.3, count / maxCount) : 0.08;
              const size = hasFindings ? Math.max(48, 48 + (count / maxCount) * 32) : 40;
              return (
                <div key={phase.id} className="flex flex-col items-center relative z-10" style={{ width: `${100 / PHASES.length}%` }}>
                  {/* Circle node */}
                  <button
                    onClick={() => hasFindings && setExpandedPhase(expandedPhase === phase.id ? null : phase.id)}
                    className={`rounded-full flex items-center justify-center transition-all shadow-lg ${
                      hasFindings ? `${phase.bg} ring-4 ${phase.ring}/30 hover:scale-110` : 'bg-slate-200 dark:bg-slate-700'
                    }`}
                    style={{ width: `${size}px`, height: `${size}px`, opacity: hasFindings ? 1 : 0.4 }}
                  >
                    <span className={`text-sm font-bold ${hasFindings ? 'text-white' : 'text-slate-400'}`}>{count}</span>
                  </button>
                  <p className={`mt-2 text-[10px] font-bold text-center leading-tight ${hasFindings ? 'text-slate-800 dark:text-white' : 'text-slate-400'}`}>
                    {phase.short}
                  </p>
                  {/* Mini severity bar */}
                  {hasFindings && (
                    <div className="flex gap-0.5 mt-1">
                      {SEV_ORDER.map(sev => {
                        const c = (phaseMap.get(phase.id) || []).filter(f => f.severity === sev).length;
                        return c > 0 ? (
                          <div key={sev} className={`h-1.5 rounded-full ${SEV_COLORS[sev]}`} style={{ width: `${Math.max(4, (c / count) * 24)}px` }} />
                        ) : null;
                      })}
                    </div>
                  )}
                </div>
              );
            })}
          </div>
        </div>
      </div>

      {/* Phase detail cards */}
      <div className="space-y-3">
        {PHASES.map(phase => {
          const phaseFindings = phaseMap.get(phase.id) || [];
          const count = phaseFindings.length;
          const isExpanded = expandedPhase === phase.id;
          const sevDist: Record<string, number> = {};
          phaseFindings.forEach(f => { sevDist[f.severity] = (sevDist[f.severity] || 0) + 1; });

          // Group by technique within the phase
          const techniqueGroups = new Map<string, Finding[]>();
          phaseFindings.forEach(f => {
            const key = f.mitre_technique || f.category || 'Unknown';
            const existing = techniqueGroups.get(key) || [];
            existing.push(f);
            techniqueGroups.set(key, existing);
          });

          return (
            <div key={phase.id} className={`rounded-xl border bg-white dark:bg-slate-900 overflow-hidden ${
              count > 0 ? 'border-slate-200 dark:border-slate-800' : 'border-slate-100 dark:border-slate-800/50 opacity-40'
            }`}>
              <button
                onClick={() => count > 0 && setExpandedPhase(isExpanded ? null : phase.id)}
                disabled={count === 0}
                className="flex w-full items-center gap-4 p-4 text-left"
              >
                <div className={`flex h-12 w-12 shrink-0 items-center justify-center rounded-xl bg-gradient-to-br ${phase.color} shadow`}>
                  <span className="text-lg font-bold text-white">{count}</span>
                </div>
                <div className="flex-1 min-w-0">
                  <h3 className="text-sm font-semibold text-slate-900 dark:text-white">{phase.id}</h3>
                  <p className="text-[10px] text-slate-400 mt-0.5">{phase.description}</p>
                  {count > 0 && (
                    <div className="flex items-center gap-1 mt-1.5">
                      {SEV_ORDER.filter(s => sevDist[s]).map(sev => (
                        <span key={sev} className={`rounded px-1.5 py-0 text-[9px] font-medium text-white ${SEV_COLORS[sev]}`}>{sevDist[sev]}</span>
                      ))}
                      <span className="text-[10px] text-slate-400 ml-2">{techniqueGroups.size} technique{techniqueGroups.size !== 1 ? 's' : ''}</span>
                    </div>
                  )}
                </div>
                {/* Mini bar chart */}
                {count > 0 && (
                  <div className="flex items-end gap-0.5 h-8 mr-2">
                    {SEV_ORDER.map(sev => {
                      const c = sevDist[sev] || 0;
                      const h = c > 0 ? Math.max(4, (c / count) * 32) : 0;
                      return <div key={sev} className={`w-2 rounded-t ${SEV_COLORS[sev]}`} style={{ height: `${h}px` }} />;
                    })}
                  </div>
                )}
                {count > 0 && (
                  <svg className={`h-4 w-4 text-slate-400 transition-transform ${isExpanded ? 'rotate-180' : ''}`} fill="none" viewBox="0 0 24 24" stroke="currentColor">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M19 9l-7 7-7-7" />
                  </svg>
                )}
              </button>
              {isExpanded && (
                <div className="border-t border-slate-100 bg-slate-50/50 px-4 py-3 dark:border-slate-800 dark:bg-slate-800/30 max-h-80 overflow-y-auto">
                  {Array.from(techniqueGroups.entries()).map(([tech, techFindings]) => (
                    <div key={tech} className="mb-3 last:mb-0">
                      <p className="text-[10px] font-bold uppercase tracking-wide text-slate-400 mb-1">{tech}</p>
                      <div className="space-y-1.5">
                        {techFindings.map(f => (
                          <div key={f.id} className="flex items-start gap-2 text-xs">
                            <span className={`mt-0.5 shrink-0 rounded px-1.5 py-0.5 text-[10px] font-medium text-white ${SEV_COLORS[f.severity]}`}>{f.severity}</span>
                            <div className="flex-1 min-w-0">
                              <p className="text-slate-700 dark:text-slate-300 truncate">{f.finding}</p>
                              <p className="text-slate-400 text-[10px]">{f.tool_source} | {f.category}</p>
                            </div>
                          </div>
                        ))}
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
