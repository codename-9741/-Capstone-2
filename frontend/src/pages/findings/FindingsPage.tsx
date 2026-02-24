import { useState, useEffect } from 'react';

const SEV_COLORS: Record<string, string> = {
  Critical: 'bg-red-500', High: 'bg-orange-500', Medium: 'bg-amber-400', Low: 'bg-emerald-500', Info: 'bg-blue-500',
};

const TOOL_COLORS: Record<string, string> = {
  native: 'bg-brand-600', nmap: 'bg-emerald-600', nikto: 'bg-orange-500', nuclei: 'bg-cyan-600',
  wapiti: 'bg-red-500', sslscan: 'bg-blue-500', whatweb: 'bg-amber-600', fierce: 'bg-pink-600', skipfish: 'bg-indigo-500',
};

export function FindingsPage() {
  const [findings, setFindings] = useState<any[]>([]);
  const [targets, setTargets] = useState<any[]>([]);
  const [scans, setScans] = useState<any[]>([]);
  const [severityFilter, setSeverityFilter] = useState('');
  const [targetFilter, setTargetFilter] = useState('');
  const [scanFilter, setScanFilter] = useState('');
  const [toolFilter, setToolFilter] = useState('');
  const [loading, setLoading] = useState(true);
  const [expandedId, setExpandedId] = useState<number | null>(null);

  useEffect(() => { loadData(); }, []);

  const loadData = async () => {
    setLoading(true);
    try {
      const [fRes, tRes, sRes] = await Promise.all([
        fetch('/api/findings'), fetch('/api/targets'), fetch('/api/scans'),
      ]);
      const f = await fRes.json(), t = await tRes.json(), s = await sRes.json();
      setFindings(f.data || []); setTargets(t.data || t || []); setScans(s.data || s || []);
    } catch (error) { console.error('Error loading data:', error); }
    finally { setLoading(false); }
  };

  const getTargetName = (scanId: number) => {
    const scan = scans.find((s: any) => s.id === scanId);
    if (!scan) return 'Unknown';
    const target = targets.find((t: any) => t.id === scan.target_id);
    return target?.domain || 'Unknown';
  };

  const filteredFindings = findings.filter((f) => {
    if (severityFilter && f.severity !== severityFilter) return false;
    if (scanFilter && f.scan_id !== parseInt(scanFilter)) return false;
    if (toolFilter && (f.tool_source || 'native') !== toolFilter) return false;
    if (targetFilter && getTargetName(f.scan_id) !== targetFilter) return false;
    return true;
  });

  const severityCounts = filteredFindings.reduce((acc: any, f) => { acc[f.severity] = (acc[f.severity] || 0) + 1; return acc; }, {});
  const toolCounts = findings.reduce((acc: any, f) => { const t = f.tool_source || 'native'; acc[t] = (acc[t] || 0) + 1; return acc; }, {});
  const uniqueTargets = [...new Set(findings.map((f) => getTargetName(f.scan_id)))];
  const uniqueScans = [...new Set(findings.map((f) => f.scan_id))];

  return (
    <div className="space-y-5">
      <div>
        <h1 className="text-2xl font-bold text-slate-900 dark:text-white">Findings</h1>
        <p className="text-sm text-slate-500">{filteredFindings.length} vulnerabilities discovered</p>
      </div>

      {/* Severity Filter */}
      <div>
        <p className="text-xs font-medium text-slate-400 mb-1.5">Severity</p>
        <div className="flex gap-1.5 flex-wrap">
          <button onClick={() => setSeverityFilter('')}
            className={`rounded-md px-3 py-1.5 text-xs font-medium transition-colors ${!severityFilter ? 'bg-brand-600 text-white' : 'bg-white border border-slate-200 text-slate-600 hover:bg-slate-50 dark:bg-slate-800 dark:border-slate-700 dark:text-slate-300'}`}>
            All ({findings.length})
          </button>
          {['Critical', 'High', 'Medium', 'Low', 'Info'].map((sev) => (
            <button key={sev} onClick={() => setSeverityFilter(sev)}
              className={`rounded-md px-3 py-1.5 text-xs font-medium transition-colors ${
                severityFilter === sev ? `${SEV_COLORS[sev]} text-white` : 'bg-white border border-slate-200 text-slate-600 hover:bg-slate-50 dark:bg-slate-800 dark:border-slate-700 dark:text-slate-300'
              }`}>
              {sev} ({severityCounts[sev] || 0})
            </button>
          ))}
        </div>
      </div>

      {/* Tool Filter */}
      <div>
        <p className="text-xs font-medium text-slate-400 mb-1.5">Tool Source</p>
        <div className="flex gap-1.5 flex-wrap">
          <button onClick={() => setToolFilter('')}
            className={`rounded-md px-3 py-1.5 text-xs font-medium transition-colors ${!toolFilter ? 'bg-brand-600 text-white' : 'bg-white border border-slate-200 text-slate-600 dark:bg-slate-800 dark:border-slate-700 dark:text-slate-300'}`}>
            All Tools
          </button>
          {Object.keys(toolCounts).sort().map((tool) => (
            <button key={tool} onClick={() => setToolFilter(tool)}
              className={`rounded-md px-3 py-1.5 text-xs font-medium transition-colors ${
                toolFilter === tool ? `${TOOL_COLORS[tool] || 'bg-slate-600'} text-white` : 'bg-white border border-slate-200 text-slate-600 dark:bg-slate-800 dark:border-slate-700 dark:text-slate-300'
              }`}>
              {tool} ({toolCounts[tool]})
            </button>
          ))}
        </div>
      </div>

      {/* Target & Scan selectors */}
      <div className="grid grid-cols-2 gap-4">
        <div>
          <p className="text-xs font-medium text-slate-400 mb-1.5">Target</p>
          <select value={targetFilter} onChange={(e) => setTargetFilter(e.target.value)} className="input">
            <option value="">All Targets</option>
            {uniqueTargets.map((t) => <option key={t} value={t}>{t}</option>)}
          </select>
        </div>
        <div>
          <p className="text-xs font-medium text-slate-400 mb-1.5">Scan</p>
          <select value={scanFilter} onChange={(e) => setScanFilter(e.target.value)} className="input">
            <option value="">All Scans</option>
            {uniqueScans.map((id) => <option key={id} value={id}>Scan #{id} - {getTargetName(id)}</option>)}
          </select>
        </div>
      </div>

      {/* Findings List */}
      {loading ? (
        <div className="text-center py-12 text-slate-400">Loading findings...</div>
      ) : filteredFindings.length === 0 ? (
        <div className="rounded-xl border border-slate-200 bg-white p-12 text-center dark:border-slate-800 dark:bg-slate-900">
          <p className="text-slate-400">No findings match your filters</p>
        </div>
      ) : (
        <div className="space-y-2">
          {filteredFindings.map((finding) => (
            <div
              key={finding.id}
              className="rounded-xl border border-slate-200 bg-white p-4 transition-colors hover:border-brand-300 cursor-pointer dark:border-slate-800 dark:bg-slate-900 dark:hover:border-brand-700"
              onClick={() => setExpandedId(expandedId === finding.id ? null : finding.id)}
            >
              <div className="flex items-start justify-between mb-1.5">
                <div className="flex items-center gap-2 flex-wrap">
                  <span className={`${SEV_COLORS[finding.severity] || 'bg-slate-500'} rounded-md px-2 py-0.5 text-xs font-medium text-white`}>
                    {finding.severity}
                  </span>
                  <span className={`${TOOL_COLORS[finding.tool_source || 'native'] || 'bg-slate-500'} rounded-md px-2 py-0.5 text-[10px] font-medium text-white`}>
                    {finding.tool_source || 'native'}
                  </span>
                  <span className="text-sm font-medium text-brand-600 dark:text-brand-400">{finding.category}</span>
                  <span className="text-xs text-slate-400">{getTargetName(finding.scan_id)}</span>
                </div>
                {finding.tool_count > 1 && (
                  <span className="rounded-md bg-emerald-100 px-2 py-0.5 text-[10px] font-medium text-emerald-700 dark:bg-emerald-900/30 dark:text-emerald-400">
                    {finding.tool_count} tools
                  </span>
                )}
              </div>

              <h3 className="text-sm font-semibold text-slate-900 dark:text-white mb-1">{finding.finding}</h3>

              {/* Framework tags */}
              <div className="flex gap-1.5 flex-wrap mb-1">
                {finding.mitre_attack_id && (
                  <a href={`https://attack.mitre.org/techniques/${finding.mitre_attack_id.replace('.', '/')}/`}
                    target="_blank" rel="noopener noreferrer"
                    className="rounded-md bg-red-50 border border-red-200 px-1.5 py-0.5 text-[10px] font-medium text-red-700 hover:bg-red-100 dark:bg-red-900/20 dark:border-red-800 dark:text-red-400"
                    onClick={(e) => e.stopPropagation()}>
                    {finding.mitre_attack_id} - {finding.mitre_tactic}
                  </a>
                )}
                {finding.owasp_category && (
                  <span className="rounded-md bg-orange-50 border border-orange-200 px-1.5 py-0.5 text-[10px] font-medium text-orange-700 dark:bg-orange-900/20 dark:border-orange-800 dark:text-orange-400">
                    {finding.owasp_category}
                  </span>
                )}
                {finding.kill_chain_phase && (
                  <span className="rounded-md bg-amber-50 border border-amber-200 px-1.5 py-0.5 text-[10px] font-medium text-amber-700 dark:bg-amber-900/20 dark:border-amber-800 dark:text-amber-400">
                    {finding.kill_chain_phase}
                  </span>
                )}
              </div>

              <p className="text-xs text-slate-400">Confidence: {finding.confidence}</p>

              {expandedId === finding.id && (
                <div className="mt-3 space-y-3 border-t border-slate-200 pt-3 dark:border-slate-800">
                  <div>
                    <p className="text-[10px] font-medium uppercase text-slate-400 mb-1">Remediation</p>
                    <div className="text-sm text-slate-700 bg-slate-50 p-3 rounded-lg dark:bg-slate-800 dark:text-slate-300">{finding.remediation}</div>
                  </div>
                  {finding.evidence && (
                    <div>
                      <p className="text-[10px] font-medium uppercase text-slate-400 mb-1">Evidence</p>
                      <pre className="p-3 bg-slate-950 rounded-lg text-xs text-slate-300 overflow-x-auto">{finding.evidence}</pre>
                    </div>
                  )}
                  {finding.http_method && (
                    <div className="flex gap-4 text-xs text-slate-400">
                      <span>Method: {finding.http_method}</span>
                      <span>Outcome: {finding.outcome}</span>
                    </div>
                  )}
                  <p className="text-[10px] text-slate-400">Discovered: {new Date(finding.created_at).toLocaleString()}</p>
                </div>
              )}
            </div>
          ))}
        </div>
      )}
    </div>
  );
}
