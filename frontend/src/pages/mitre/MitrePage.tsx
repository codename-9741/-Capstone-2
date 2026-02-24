import { useEffect, useMemo, useState } from 'react';
import { RefreshCw, DatabaseZap, Wand2 } from 'lucide-react';

interface Finding {
  id: number;
  scan_id: number;
  severity: string;
  category: string;
  finding: string;
  mitre_attack_id: string;
  mitre_tactic: string;
  mitre_technique: string;
  tool_source: string;
}

interface Target {
  id: number;
  domain: string;
}

interface Scan {
  id: number;
  target_id: number;
  status: string;
  created_at?: string;
}

interface MitreTTP {
  attack_id: string;
  name: string;
  tactic: string;
  description: string;
  url: string;
}

const TACTIC_ORDER = [
  'Reconnaissance',
  'Resource Development',
  'Initial Access',
  'Execution',
  'Persistence',
  'Privilege Escalation',
  'Defense Evasion',
  'Credential Access',
  'Discovery',
  'Lateral Movement',
  'Collection',
  'Command and Control',
  'Exfiltration',
  'Impact',
];

const TACTIC_CANONICAL: Record<string, string> = TACTIC_ORDER.reduce((acc, tactic) => {
  acc[normalizeTacticKey(tactic)] = tactic;
  return acc;
}, {} as Record<string, string>);

const SEV_COLORS: Record<string, string> = {
  Critical: 'bg-red-500',
  High: 'bg-orange-500',
  Medium: 'bg-amber-400',
  Low: 'bg-emerald-500',
  Info: 'bg-blue-500',
};

export function MitrePage() {
  const [targets, setTargets] = useState<Target[]>([]);
  const [scans, setScans] = useState<Scan[]>([]);
  const [mitre, setMitre] = useState<MitreTTP[]>([]);
  const [findings, setFindings] = useState<Finding[]>([]);
  const [selectedTarget, setSelectedTarget] = useState('');
  const [selectedScan, setSelectedScan] = useState('');
  const [selectedTechnique, setSelectedTechnique] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);
  const [busy, setBusy] = useState(false);
  const [status, setStatus] = useState({ mitre_ttps: 0, owasp_categories: 0, kill_chain_phases: 0 });

  const loadMeta = async () => {
    const [targetsRes, scansRes, frameworkRes, statusRes] = await Promise.all([
      fetch('/api/targets').then(r => r.json()),
      fetch('/api/scans').then(r => r.json()),
      fetch('/api/frameworks/mitre').then(r => r.json()),
      fetch('/api/frameworks/status').then(r => r.json()),
    ]);
    setTargets(targetsRes.data || []);
    setScans(scansRes.data || []);
    setMitre(frameworkRes.data || []);
    setStatus(statusRes.data || { mitre_ttps: 0, owasp_categories: 0, kill_chain_phases: 0 });
  };

  const loadFindings = async (targetId?: string, scanId?: string) => {
    const params = new URLSearchParams({ per_page: '5000' });
    if (scanId) params.set('scan_id', scanId);
    else if (targetId) params.set('target_id', targetId);

    const findingsRes = await fetch(`/api/findings?${params.toString()}`).then(r => r.json());
    const rows = (findingsRes.data || []) as Finding[];
    setFindings(rows.filter(f => f.mitre_attack_id));
  };

  const loadAll = async (targetId?: string, scanId?: string) => {
    setLoading(true);
    try {
      await loadMeta();
      await loadFindings(targetId, scanId);
    } catch (err) {
      console.error('MITRE page load failed:', err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadAll();
  }, []);

  const filteredScans = useMemo(() => {
    if (!selectedTarget) return scans;
    return scans.filter(s => String(s.target_id) === selectedTarget);
  }, [scans, selectedTarget]);

  const matrix = useMemo(() => {
    const map: Record<string, MitreTTP[]> = {};
    for (const tactic of TACTIC_ORDER) map[tactic] = [];
    for (const t of mitre) {
      const tactic = normalizeTacticName(t.tactic);
      if (!map[tactic]) map[tactic] = [];
      map[tactic].push({ ...t, tactic });
    }
    for (const key of Object.keys(map)) {
      map[key].sort((a, b) => a.attack_id.localeCompare(b.attack_id));
    }
    return map;
  }, [mitre]);

  const displayTactics = useMemo(() => {
    const extra = Object.keys(matrix)
      .filter(t => !TACTIC_ORDER.includes(t) && (matrix[t]?.length || 0) > 0)
      .sort((a, b) => a.localeCompare(b));
    return [...TACTIC_ORDER, ...extra];
  }, [matrix]);

  const hitMap = useMemo(() => {
    const m = new Map<string, { count: number; severities: Record<string, number> }>();
    for (const f of findings) {
      const row = m.get(f.mitre_attack_id) || { count: 0, severities: {} };
      row.count++;
      row.severities[f.severity] = (row.severities[f.severity] || 0) + 1;
      m.set(f.mitre_attack_id, row);
    }
    return m;
  }, [findings]);

  const attackPath = useMemo(() => {
    return TACTIC_ORDER
      .map(tactic => ({
        tactic,
        techniques: (matrix[tactic] || []).filter(t => hitMap.has(t.attack_id)),
      }))
      .filter(x => x.techniques.length > 0);
  }, [matrix, hitMap]);

  const totalTechniques = mitre.length;
  const coveredTechniques = hitMap.size;
  const totalHits = Array.from(hitMap.values()).reduce((s, v) => s + v.count, 0);

  const selectedTechniqueDetails = useMemo(() => {
    if (!selectedTechnique) return null;
    const t = mitre.find(x => x.attack_id === selectedTechnique);
    if (!t) return null;
    const tf = findings.filter(f => f.mitre_attack_id === selectedTechnique);
    return { t, findings: tf };
  }, [selectedTechnique, mitre, findings]);

  const runSync = async () => {
    setBusy(true);
    try {
      await fetch('/api/frameworks/sync', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ remap_all: false }),
      });
      await loadAll(selectedTarget || undefined, selectedScan || undefined);
    } finally {
      setBusy(false);
    }
  };

  const runRemap = async (onlyUnmapped: boolean) => {
    setBusy(true);
    try {
      await fetch('/api/frameworks/remap', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          target_id: selectedTarget ? Number(selectedTarget) : undefined,
          scan_id: selectedScan ? Number(selectedScan) : undefined,
          only_unmapped: onlyUnmapped,
        }),
      });
      await loadAll(selectedTarget || undefined, selectedScan || undefined);
    } finally {
      setBusy(false);
    }
  };

  const onTargetChange = async (value: string) => {
    setSelectedTarget(value);
    setSelectedScan('');
    setSelectedTechnique(null);
    await loadAll(value || undefined, undefined);
  };

  const onScanChange = async (value: string) => {
    setSelectedScan(value);
    setSelectedTechnique(null);
    await loadAll(selectedTarget || undefined, value || undefined);
  };

  if (loading) return <div className="py-12 text-center text-slate-400">Loading MITRE ATT&CK data...</div>;

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-slate-900 dark:text-white">MITRE ATT&CK Navigator</h1>
          <p className="text-sm text-slate-500">
            {coveredTechniques}/{totalTechniques} techniques hit across {totalHits} findings
          </p>
        </div>
        <div className="flex items-center gap-2">
          <button className="btn-secondary" onClick={() => loadAll(selectedTarget || undefined, selectedScan || undefined)} disabled={busy}>
            <RefreshCw className="mr-1.5 h-4 w-4" /> Refresh
          </button>
          <button className="btn-primary" onClick={runSync} disabled={busy}>
            <DatabaseZap className="mr-1.5 h-4 w-4" /> Sync Frameworks
          </button>
          <button className="btn-secondary" onClick={() => runRemap(true)} disabled={busy}>
            <Wand2 className="mr-1.5 h-4 w-4" /> Remap Missing
          </button>
          <button className="btn-secondary" onClick={() => runRemap(false)} disabled={busy}>
            Remap All
          </button>
        </div>
      </div>

      <div className="grid grid-cols-4 gap-4">
        <div className="card"><p className="text-xs text-slate-400">MITRE TTPs Loaded</p><p className="text-2xl font-bold text-brand-600">{status.mitre_ttps}</p></div>
        <div className="card"><p className="text-xs text-slate-400">OWASP Loaded</p><p className="text-2xl font-bold text-orange-600">{status.owasp_categories}</p></div>
        <div className="card"><p className="text-xs text-slate-400">Kill Chain Loaded</p><p className="text-2xl font-bold text-emerald-600">{status.kill_chain_phases}</p></div>
        <div className="card"><p className="text-xs text-slate-400">Scope Hits</p><p className="text-2xl font-bold text-blue-600">{totalHits}</p></div>
      </div>

      <div className="grid gap-3 md:grid-cols-3">
        <div>
          <label className="mb-1.5 block text-xs font-medium text-slate-500">Target</label>
          <select value={selectedTarget} onChange={e => onTargetChange(e.target.value)} className="input">
            <option value="">All Targets</option>
            {targets.map(t => <option key={t.id} value={t.id}>{t.domain}</option>)}
          </select>
        </div>
        <div>
          <label className="mb-1.5 block text-xs font-medium text-slate-500">Scan</label>
          <select value={selectedScan} onChange={e => onScanChange(e.target.value)} className="input">
            <option value="">All Scans</option>
            {filteredScans.map(s => <option key={s.id} value={s.id}>#{s.id} - {s.status}</option>)}
          </select>
        </div>
        <div className="card flex items-center">
          <p className="text-xs text-slate-500">
            Scope: <span className="font-semibold text-slate-700 dark:text-slate-200">{selectedScan ? `Scan #${selectedScan}` : selectedTarget ? `Target #${selectedTarget}` : 'Global'}</span>
          </p>
        </div>
      </div>

      <div className="card">
        <h3 className="mb-3 text-xs font-semibold uppercase tracking-wide text-slate-400">Attack Path</h3>
        {attackPath.length === 0 ? (
          <p className="text-sm text-slate-400">No mapped findings in this scope.</p>
        ) : (
          <div className="flex items-center gap-2 overflow-x-auto pb-2">
            {attackPath.map((phase, idx) => (
              <div key={phase.tactic} className="flex items-center gap-2">
                <div className="rounded-lg bg-slate-900 px-3 py-2 text-white dark:bg-slate-800">
                  <p className="text-[10px] uppercase text-slate-300">{phase.tactic}</p>
                  <p className="text-lg font-bold">{phase.techniques.reduce((s, t) => s + (hitMap.get(t.attack_id)?.count || 0), 0)}</p>
                </div>
                {idx < attackPath.length - 1 && <span className="text-slate-400">→</span>}
              </div>
            ))}
          </div>
        )}
      </div>

      <div className="overflow-x-auto rounded-xl border border-slate-200 bg-white dark:border-slate-800 dark:bg-slate-900">
        <div className="flex min-w-max">
          {displayTactics.map(tactic => {
            const ttps = matrix[tactic] || [];
            return (
              <div key={tactic} className="w-56 shrink-0 border-r border-slate-100 dark:border-slate-800">
                <div className="sticky top-0 border-b border-slate-100 bg-slate-900 px-2 py-2 text-white dark:border-slate-800 dark:bg-slate-800">
                  <p className="text-[10px] font-bold uppercase">{tactic}</p>
                  <p className="text-[10px] text-slate-300">{ttps.filter(t => hitMap.has(t.attack_id)).length}/{ttps.length}</p>
                </div>
                <div className="max-h-[70vh] space-y-1 overflow-y-auto p-2">
                  {ttps.map(tech => {
                    const hit = hitMap.get(tech.attack_id);
                    const open = selectedTechnique === tech.attack_id;
                    const sev = hit ? getMaxSeverity(hit.severities) : 'Info';
                    return (
                      <button
                        key={tech.attack_id}
                        onClick={() => setSelectedTechnique(open ? null : tech.attack_id)}
                        className={`w-full rounded border px-2 py-1 text-left transition-colors ${
                          hit
                            ? 'border-brand-300 bg-brand-50 hover:bg-brand-100 dark:border-brand-700 dark:bg-brand-900/20 dark:hover:bg-brand-900/30'
                            : 'border-slate-200 hover:bg-slate-50 dark:border-slate-700 dark:hover:bg-slate-800'
                        } ${open ? 'ring-1 ring-brand-500' : ''}`}
                      >
                        <div className="flex items-center justify-between gap-2">
                          <span className="truncate text-[11px] font-medium text-slate-800 dark:text-slate-200">{tech.name}</span>
                          {hit && <span className={`rounded px-1 py-0 text-[9px] font-bold text-white ${SEV_COLORS[sev]}`}>{hit.count}</span>}
                        </div>
                        <p className="mt-0.5 text-[10px] font-mono text-slate-500">{tech.attack_id}</p>
                      </button>
                    );
                  })}
                </div>
              </div>
            );
          })}
        </div>
      </div>

      {selectedTechniqueDetails && (
        <div className="card">
          <div className="mb-3 flex items-start justify-between">
            <div>
              <p className="text-xs font-mono text-brand-600">{selectedTechniqueDetails.t.attack_id}</p>
              <h3 className="text-sm font-bold text-slate-900 dark:text-white">{selectedTechniqueDetails.t.name}</h3>
              <p className="text-xs text-slate-500">{selectedTechniqueDetails.t.tactic}</p>
              <p className="mt-1 text-xs text-slate-500">{selectedTechniqueDetails.t.description}</p>
              {selectedTechniqueDetails.t.url && (
                <a href={selectedTechniqueDetails.t.url} target="_blank" rel="noreferrer" className="mt-1 inline-block text-xs text-brand-600 hover:underline">
                  ATT&CK Reference
                </a>
              )}
            </div>
            <button className="text-xs text-slate-500 hover:text-slate-700" onClick={() => setSelectedTechnique(null)}>Close</button>
          </div>
          {selectedTechniqueDetails.findings.length === 0 ? (
            <p className="text-xs text-slate-400">No findings mapped to this technique in current scope.</p>
          ) : (
            <div className="max-h-60 space-y-2 overflow-y-auto">
              {selectedTechniqueDetails.findings.map(f => (
                <div key={f.id} className="rounded border border-slate-200 bg-slate-50 p-2 dark:border-slate-700 dark:bg-slate-800">
                  <div className="mb-1 flex items-center gap-2">
                    <span className={`rounded px-1.5 py-0 text-[10px] font-medium text-white ${SEV_COLORS[f.severity] || 'bg-slate-500'}`}>{f.severity}</span>
                    <span className="text-[10px] text-slate-500">scan #{f.scan_id}</span>
                    <span className="text-[10px] text-slate-500">{f.tool_source}</span>
                  </div>
                  <p className="text-xs text-slate-700 dark:text-slate-300">{f.finding}</p>
                  <p className="mt-0.5 text-[10px] text-slate-500">{f.category}</p>
                </div>
              ))}
            </div>
          )}
        </div>
      )}
    </div>
  );
}

function getMaxSeverity(severities: Record<string, number>): string {
  const order = ['Critical', 'High', 'Medium', 'Low', 'Info'];
  for (const s of order) if (severities[s]) return s;
  return 'Info';
}

function normalizeTacticKey(tactic: string): string {
  return tactic.trim().toLowerCase().replace(/\s+/g, ' ');
}

function normalizeTacticName(tactic: string): string {
  const normalized = normalizeTacticKey(tactic);
  return TACTIC_CANONICAL[normalized] || tactic;
}
