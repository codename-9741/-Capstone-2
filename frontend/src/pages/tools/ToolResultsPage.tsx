import { useState, useEffect, useRef, useCallback } from 'react';
import { toolExecutionApi, ToolExecution } from '../../api/scanApi';
import { Play, Square, RefreshCw, CheckCircle2, XCircle, Loader2, Terminal, ChevronDown, ChevronRight } from 'lucide-react';

// ─── Static metadata ────────────────────────────────────────────────────────

interface Target { id: number; domain: string; }

const TOOL_DESCRIPTIONS: Record<string, string> = {
  nmap: 'Network discovery and port scanning',
  nikto: 'Web server vulnerability scanner',
  nuclei: 'Template-based vulnerability scanner',
  wapiti: 'Web application vulnerability scanner',
  sslscan: 'SSL/TLS configuration analyzer',
  whatweb: 'Web technology fingerprinter',
  fierce: 'DNS reconnaissance tool',
  skipfish: 'Active web recon and fuzzer',
  sqlmap: 'Automated SQL injection testing',
  ffuf: 'Fast web content and API fuzzing',
  subfinder: 'Passive subdomain discovery',
  'testssl.sh': 'Deep TLS/SSL security testing',
  dalfox: 'XSS scanner and verification',
  gobuster: 'Directory and virtual host brute force',
  httpx: 'HTTP probing and tech detection',
  kr: 'Kiterunner API route discovery',
  amass: 'Passive asset and ASN intelligence',
  uncover: 'Passive internet-exposed host search',
  gau: 'Historical URL collection from archives',
  dnsx: 'DNS resolution and record enrichment',
  alterx: 'Subdomain permutation generation',
  crtsh: 'Certificate Transparency hostname lookup',
  metasploit: 'Metasploit auxiliary scanner modules',
  hydra: 'Online password auditing tool',
  masscan: 'High-speed asynchronous port scanner',
  zmap: 'Internet-scale single-port scanner',
  zaproxy: 'OWASP ZAP API discovery and scanning',
  arachni: 'Arachni web/API vulnerability scanner',
};

const TOOL_MODULES: Record<string, { id: string; label: string }[]> = {
  nmap: [
    { id: 'nmap_top1000', label: 'Top 1000 Ports' },
    { id: 'nmap_service_detection', label: 'Service Detection' },
    { id: 'nmap_vuln_scripts', label: 'Vuln Scripts' },
    { id: 'nmap_udp_top', label: 'UDP Top 20' },
    { id: 'nmap_tls_ciphers', label: 'TLS Ciphers' },
    { id: 'nmap_firewall_bypass', label: 'Firewall Bypass' },
  ],
  nikto: [
    { id: 'nikto_scan', label: 'Full Scan' },
    { id: 'nikto_outdated', label: 'Outdated Software' },
    { id: 'nikto_misconfig', label: 'Misconfigurations' },
  ],
  nuclei: [
    { id: 'nuclei_cves', label: 'CVE Templates' },
    { id: 'nuclei_misconfig', label: 'Misconfigurations' },
    { id: 'nuclei_exposed', label: 'Exposed Panels' },
    { id: 'nuclei_takeover', label: 'Subdomain Takeover' },
  ],
  wapiti: [
    { id: 'wapiti_sqli', label: 'SQL Injection' },
    { id: 'wapiti_xss', label: 'XSS' },
    { id: 'wapiti_ssrf', label: 'SSRF' },
    { id: 'wapiti_xxe', label: 'XXE' },
  ],
  sslscan: [
    { id: 'sslscan_ciphers', label: 'Cipher Suites' },
    { id: 'sslscan_protocols', label: 'Protocols' },
    { id: 'sslscan_certs', label: 'Certificates' },
  ],
  whatweb: [{ id: 'whatweb_fingerprint', label: 'Fingerprint' }],
  fierce: [{ id: 'fierce_dns_enum', label: 'DNS Enumeration' }],
  skipfish: [{ id: 'skipfish_recon', label: 'Recon Scan' }],
  sqlmap: [
    { id: 'sqlmap_detect', label: 'Detection (Fast)' },
    { id: 'sqlmap_deep', label: 'Deep Detection' },
  ],
  ffuf: [
    { id: 'ffuf_dirs', label: 'Directory Fuzzing' },
    { id: 'ffuf_api', label: 'API Route Fuzzing' },
  ],
  subfinder: [{ id: 'subfinder_passive', label: 'Passive Subdomain Enum' }],
  'testssl.sh': [
    { id: 'testssl_basic', label: 'TLS Baseline' },
    { id: 'testssl_vulns', label: 'TLS Vulnerability Checks' },
  ],
  dalfox: [
    { id: 'dalfox_url', label: 'URL Scan' },
    { id: 'dalfox_param', label: 'Parameter Focused Scan' },
  ],
  gobuster: [
    { id: 'gobuster_dir', label: 'Directory Bruteforce' },
    { id: 'gobuster_vhost', label: 'Virtual Host Bruteforce' },
  ],
  httpx: [
    { id: 'httpx_probe', label: 'Probe + Status/Title' },
    { id: 'httpx_tech', label: 'Technology Detection' },
  ],
  kr: [{ id: 'kiterunner_scan', label: 'API Route Scan' }],
  amass: [
    { id: 'amass_passive', label: 'Passive Enumeration' },
    { id: 'amass_intel', label: 'WHOIS / Intel' },
  ],
  uncover: [{ id: 'uncover_search', label: 'Passive Search' }],
  gau: [{ id: 'gau_urls', label: 'Historical URLs' }],
  dnsx: [{ id: 'dnsx_resolve', label: 'Resolve Records' }],
  alterx: [{ id: 'alterx_permute', label: 'Generate Permutations' }],
  crtsh: [{ id: 'crtsh_lookup', label: 'CT Hostname Lookup' }],
  metasploit: [
    { id: 'msf_http_version', label: 'HTTP Version Scanner' },
    { id: 'msf_ftp_version', label: 'FTP Version Scanner' },
  ],
  hydra: [
    { id: 'hydra_http_get', label: 'HTTP GET Auth Audit' },
    { id: 'hydra_ssh', label: 'SSH Auth Audit' },
  ],
  masscan: [
    { id: 'masscan_top100', label: 'Top 1-1024 Ports' },
    { id: 'masscan_web_ports', label: 'Common Web Ports' },
  ],
  zmap: [
    { id: 'zmap_http', label: 'HTTP Port 80' },
    { id: 'zmap_https', label: 'HTTPS Port 443' },
  ],
  zaproxy: [{ id: 'zap_quick', label: 'Quick Vulnerability Scan' }],
  arachni: [{ id: 'arachni_api', label: 'API Scan (XSS/Sqli Focus)' }],
};

// ─── Helpers ─────────────────────────────────────────────────────────────────

function formatDuration(start: string, end?: string): string {
  if (!start) return '-';
  const sec = Math.floor(((end ? new Date(end).getTime() : Date.now()) - new Date(start).getTime()) / 1000);
  return sec < 60 ? `${sec}s` : `${Math.floor(sec / 60)}m ${sec % 60}s`;
}

function statusBadge(status: string) {
  const map: Record<string, string> = {
    running: 'bg-blue-50 text-blue-700 dark:bg-blue-900/30 dark:text-blue-400',
    completed: 'bg-emerald-50 text-emerald-700 dark:bg-emerald-900/30 dark:text-emerald-400',
    failed: 'bg-red-50 text-red-700 dark:bg-red-900/30 dark:text-red-400',
    stopped: 'bg-amber-50 text-amber-700 dark:bg-amber-900/30 dark:text-amber-400',
  };
  return (
    <span className={`inline-flex items-center gap-1 rounded-md px-2 py-0.5 text-xs font-medium ${map[status] || 'bg-slate-100 text-slate-600'}`}>
      {status === 'running' && <span className="h-1.5 w-1.5 rounded-full bg-blue-500 animate-pulse" />}
      {status.charAt(0).toUpperCase() + status.slice(1)}
    </span>
  );
}

// ─── Selection state per tool ─────────────────────────────────────────────────

interface ToolSelection {
  enabled: boolean;
  moduleId: string;
  customArgs: string;
}

// ─── Main Component ───────────────────────────────────────────────────────────

export function ToolResultsPage() {
  // Data
  const [toolStatuses, setToolStatuses] = useState<{ name: string; installed: boolean; version: string }[]>([]);
  const [targets, setTargets] = useState<Target[]>([]);
  const [executions, setExecutions] = useState<ToolExecution[]>([]);
  const [loading, setLoading] = useState(true);

  // Session config
  const [selectedTargetId, setSelectedTargetId] = useState<number | ''>('');
  const [manualTarget, setManualTarget] = useState('');
  const [mode, setMode] = useState<'all' | 'custom'>('all');
  const [selections, setSelections] = useState<Record<string, ToolSelection>>({});

  // Session progress
  const [sessionExecs, setSessionExecs] = useState<ToolExecution[]>([]);
  const [isRunning, setIsRunning] = useState(false);
  const [sharedScanId, setSharedScanId] = useState<number | null>(null);

  // UI state
  const [activeExec, setActiveExec] = useState<ToolExecution | null>(null);
  const [consoleOpen, setConsoleOpen] = useState(true);
  const termRef = useRef<HTMLDivElement>(null);
  const pollRef = useRef<ReturnType<typeof setInterval> | null>(null);

  // ── Load initial data ────────────────────────────────────────────────────

  const loadData = useCallback(async (targetId?: number) => {
    try {
      const [toolRes, targetsRes, execRes] = await Promise.all([
        fetch('/api/tools/status').then((r) => r.json()),
        fetch('/api/targets').then((r) => r.json()),
        toolExecutionApi.list(targetId),
      ]);
      const statuses = toolRes.data || [];
      setToolStatuses(statuses);
      setTargets(targetsRes.data || []);
      setExecutions(execRes.data || []);

      // Init selections for all known tools
      const init: Record<string, ToolSelection> = {};
      for (const t of statuses) {
        const mods = TOOL_MODULES[t.name] || [];
        init[t.name] = { enabled: false, moduleId: mods[0]?.id || '', customArgs: '' };
      }
      setSelections((prev) => {
        // merge to preserve existing user choices
        const merged: Record<string, ToolSelection> = { ...init };
        for (const key of Object.keys(prev)) {
          if (key in merged) merged[key] = prev[key];
        }
        return merged;
      });
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    loadData();
  }, [loadData]);

  // ── Session polling ──────────────────────────────────────────────────────

  const stopPolling = useCallback(() => {
    if (pollRef.current) {
      clearInterval(pollRef.current);
      pollRef.current = null;
    }
  }, []);

  const startPolling = useCallback((execIds: number[]) => {
    stopPolling();
    pollRef.current = setInterval(async () => {
      const updated: ToolExecution[] = [];
      for (const id of execIds) {
        try {
          const res = await toolExecutionApi.get(id);
          if (res.success) updated.push(res.data);
        } catch { /* ignore */ }
      }
      if (updated.length) {
        setSessionExecs(updated);
        const activeOne = updated.find((e) => e.status === 'running');
        if (activeOne) setActiveExec(activeOne);
        else if (!activeExec || activeExec.status !== 'running') {
          setActiveExec(updated[updated.length - 1]);
        }
        const allDone = updated.every((e) => e.status !== 'running');
        if (allDone) {
          stopPolling();
          setIsRunning(false);
          // Refresh exec history
          loadData(selectedTargetId || undefined);
        }
      }
    }, 2500);
  }, [stopPolling, activeExec, loadData, selectedTargetId]);

  useEffect(() => () => stopPolling(), [stopPolling]);

  useEffect(() => {
    if (termRef.current) termRef.current.scrollTop = termRef.current.scrollHeight;
  }, [activeExec?.raw_output]);

  // ── Derived values ───────────────────────────────────────────────────────

  const resolvedTarget = selectedTargetId
    ? targets.find((t) => t.id === Number(selectedTargetId))?.domain || manualTarget
    : manualTarget;

  const installedTools = toolStatuses.filter((t) => t.installed);
  const selectedCount = Object.values(selections).filter((s) => s.enabled).length;

  const sessionRunning = sessionExecs.filter((e) => e.status === 'running').length;
  const sessionCompleted = sessionExecs.filter((e) => e.status === 'completed').length;
  const sessionFailed = sessionExecs.filter((e) => e.status === 'failed' || e.status === 'stopped').length;
  const sessionTotal = sessionExecs.length;

  // ── Actions ──────────────────────────────────────────────────────────────

  const handleScanAll = async () => {
    if (!resolvedTarget.trim()) return;
    setIsRunning(true);
    setSessionExecs([]);
    setActiveExec(null);
    setConsoleOpen(true);
    try {
      const res = await toolExecutionApi.scanAll(resolvedTarget.trim(), Number(selectedTargetId) || undefined);
      if (res.success && res.data?.length) {
        setSessionExecs(res.data);
        setSharedScanId(res.scan_id || null);
        setActiveExec(res.data[0]);
        startPolling(res.data.map((e) => e.id));
      } else {
        setIsRunning(false);
      }
    } catch {
      setIsRunning(false);
    }
  };

  const handleScanCustom = async () => {
    if (!resolvedTarget.trim()) return;
    const modules = Object.entries(selections)
      .filter(([, s]) => s.enabled)
      .map(([toolName, s]) => ({ tool_name: toolName, module_id: s.moduleId, custom_args: s.customArgs || undefined }));
    if (!modules.length) return;
    setIsRunning(true);
    setSessionExecs([]);
    setActiveExec(null);
    setConsoleOpen(true);
    try {
      const res = await toolExecutionApi.scanCustom(resolvedTarget.trim(), modules, Number(selectedTargetId) || undefined);
      if (res.success && res.data?.length) {
        setSessionExecs(res.data);
        setSharedScanId(res.scan_id || null);
        setActiveExec(res.data[0]);
        startPolling(res.data.map((e) => e.id));
      } else {
        setIsRunning(false);
      }
    } catch {
      setIsRunning(false);
    }
  };

  const handleStopAll = async () => {
    stopPolling();
    const running = sessionExecs.filter((e) => e.status === 'running');
    await Promise.allSettled(running.map((e) => toolExecutionApi.stop(e.id)));
    setIsRunning(false);
    loadData(Number(selectedTargetId) || undefined);
  };

  const handleTargetChange = (value: string) => {
    const numVal = Number(value);
    setSelectedTargetId(numVal || '');
    loadData(numVal || undefined);
  };

  const toggleTool = (name: string) => {
    setSelections((prev) => ({
      ...prev,
      [name]: { ...prev[name], enabled: !prev[name]?.enabled },
    }));
  };

  const selectAll = () => {
    setSelections((prev) => {
      const next = { ...prev };
      for (const t of installedTools) next[t.name] = { ...next[t.name], enabled: true };
      return next;
    });
  };

  const deselectAll = () => {
    setSelections((prev) => {
      const next = { ...prev };
      for (const t of installedTools) next[t.name] = { ...next[t.name], enabled: false };
      return next;
    });
  };

  // ── Render ───────────────────────────────────────────────────────────────

  if (loading) return <div className="py-12 text-center text-slate-400">Loading tools...</div>;

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-slate-900 dark:text-white">Tool Workbench</h1>
          <p className="text-sm text-slate-500">Select tools, configure parameters, and run scans against a target</p>
        </div>
        {sharedScanId && (
          <span className="rounded-lg bg-brand-50 px-3 py-1 text-xs font-mono text-brand-700 dark:bg-brand-900/20 dark:text-brand-300">
            Scan #{sharedScanId}
          </span>
        )}
      </div>

      {/* Target + Mode Config */}
      <div className="rounded-xl border border-slate-200 bg-white p-5 space-y-4 dark:border-slate-800 dark:bg-slate-900">
        <h2 className="text-xs font-semibold uppercase tracking-wide text-slate-400">Session Configuration</h2>

        <div className="grid grid-cols-2 gap-4">
          <div>
            <label className="block text-xs font-medium text-slate-500 mb-1">Select Existing Target</label>
            <select
              value={selectedTargetId}
              onChange={(e) => handleTargetChange(e.target.value)}
              className="input"
            >
              <option value="">— manual entry —</option>
              {targets.map((t) => (
                <option key={t.id} value={t.id}>{t.domain}</option>
              ))}
            </select>
          </div>
          <div>
            <label className="block text-xs font-medium text-slate-500 mb-1">
              {selectedTargetId ? 'Target (resolved)' : 'Target (manual)'}
            </label>
            {selectedTargetId ? (
              <div className="input bg-slate-50 dark:bg-slate-800/50 text-slate-600 dark:text-slate-400 font-mono text-sm">
                {resolvedTarget || '—'}
              </div>
            ) : (
              <input
                type="text"
                value={manualTarget}
                onChange={(e) => setManualTarget(e.target.value)}
                placeholder="e.g. example.com or https://example.com"
                className="input"
              />
            )}
          </div>
        </div>

        {/* Mode Tabs */}
        <div className="flex items-center gap-2">
          <button
            onClick={() => setMode('all')}
            className={`rounded-lg px-4 py-2 text-sm font-medium transition-colors ${
              mode === 'all'
                ? 'bg-brand-600 text-white'
                : 'bg-slate-100 text-slate-600 hover:bg-slate-200 dark:bg-slate-800 dark:text-slate-300'
            }`}
          >
            Scan All Installed Tools
          </button>
          <button
            onClick={() => setMode('custom')}
            className={`rounded-lg px-4 py-2 text-sm font-medium transition-colors ${
              mode === 'custom'
                ? 'bg-brand-600 text-white'
                : 'bg-slate-100 text-slate-600 hover:bg-slate-200 dark:bg-slate-800 dark:text-slate-300'
            }`}
          >
            Custom Selection
          </button>
        </div>

        {/* Action Buttons */}
        <div className="flex items-center gap-3">
          {mode === 'all' ? (
            <button
              onClick={handleScanAll}
              disabled={isRunning || !resolvedTarget.trim()}
              className="btn-primary flex items-center gap-2"
            >
              {isRunning ? <Loader2 className="h-4 w-4 animate-spin" /> : <Play className="h-4 w-4" />}
              {isRunning ? `Running (${sessionRunning} active)` : `Scan All ${installedTools.length} Tools`}
            </button>
          ) : (
            <button
              onClick={handleScanCustom}
              disabled={isRunning || !resolvedTarget.trim() || selectedCount === 0}
              className="btn-primary flex items-center gap-2"
            >
              {isRunning ? <Loader2 className="h-4 w-4 animate-spin" /> : <Play className="h-4 w-4" />}
              {isRunning ? `Running (${sessionRunning} active)` : `Run ${selectedCount} Selected`}
            </button>
          )}
          {isRunning && (
            <button onClick={handleStopAll} className="inline-flex items-center gap-2 rounded-lg bg-red-600 px-4 py-2 text-sm font-semibold text-white hover:bg-red-700 transition-colors">
              <Square className="h-4 w-4" /> Stop All
            </button>
          )}
          <button
            onClick={() => loadData(Number(selectedTargetId) || undefined)}
            disabled={isRunning}
            className="btn-secondary flex items-center gap-2"
          >
            <RefreshCw className="h-4 w-4" /> Refresh
          </button>
        </div>
      </div>

      {/* Live Progress Dashboard */}
      {sessionTotal > 0 && (
        <div className="rounded-xl border border-slate-200 bg-white dark:border-slate-800 dark:bg-slate-900 overflow-hidden">
          <button
            className="flex w-full items-center justify-between border-b border-slate-100 px-5 py-3 dark:border-slate-800"
            onClick={() => setConsoleOpen((v) => !v)}
          >
            <div className="flex items-center gap-4">
              <span className="text-xs font-semibold uppercase tracking-wide text-slate-500">Live Progress</span>
              {/* Counters */}
              <div className="flex items-center gap-3">
                <span className="flex items-center gap-1 text-xs font-medium text-slate-500">
                  <span className="h-2 w-2 rounded-full bg-slate-300 dark:bg-slate-600" /> Total: <span className="font-bold text-slate-700 dark:text-slate-200">{sessionTotal}</span>
                </span>
                <span className="flex items-center gap-1 text-xs font-medium text-blue-600">
                  <span className="h-2 w-2 rounded-full bg-blue-500 animate-pulse" /> Running: <span className="font-bold">{sessionRunning}</span>
                </span>
                <span className="flex items-center gap-1 text-xs font-medium text-emerald-600">
                  <CheckCircle2 className="h-3.5 w-3.5" /> Done: <span className="font-bold">{sessionCompleted}</span>
                </span>
                <span className="flex items-center gap-1 text-xs font-medium text-red-600">
                  <XCircle className="h-3.5 w-3.5" /> Failed: <span className="font-bold">{sessionFailed}</span>
                </span>
              </div>
              {/* Progress bar */}
              {sessionTotal > 0 && (
                <div className="w-32 h-1.5 rounded-full bg-slate-100 dark:bg-slate-800 overflow-hidden">
                  <div
                    className="h-full rounded-full bg-emerald-500 transition-all"
                    style={{ width: `${((sessionCompleted + sessionFailed) / sessionTotal) * 100}%` }}
                  />
                </div>
              )}
            </div>
            {consoleOpen ? <ChevronDown className="h-4 w-4 text-slate-400" /> : <ChevronRight className="h-4 w-4 text-slate-400" />}
          </button>

          {consoleOpen && (
            <div className="p-4 space-y-3">
              {/* Per-tool status list */}
              <div className="grid grid-cols-3 gap-2 max-h-48 overflow-y-auto pr-1">
                {sessionExecs.map((exec) => (
                  <button
                    key={exec.id}
                    onClick={() => setActiveExec(exec)}
                    className={`flex items-center gap-2 rounded-lg border px-3 py-2 text-left transition-colors ${
                      activeExec?.id === exec.id
                        ? 'border-brand-300 bg-brand-50 dark:border-brand-700 dark:bg-brand-900/20'
                        : 'border-slate-200 hover:bg-slate-50 dark:border-slate-800 dark:hover:bg-slate-800/50'
                    }`}
                  >
                    {exec.status === 'running' && <Loader2 className="h-3.5 w-3.5 shrink-0 animate-spin text-blue-500" />}
                    {exec.status === 'completed' && <CheckCircle2 className="h-3.5 w-3.5 shrink-0 text-emerald-500" />}
                    {(exec.status === 'failed' || exec.status === 'stopped') && <XCircle className="h-3.5 w-3.5 shrink-0 text-red-500" />}
                    <div className="min-w-0">
                      <p className="truncate text-[11px] font-bold uppercase text-slate-800 dark:text-slate-200">{exec.tool_name}</p>
                      <p className="truncate text-[10px] text-slate-400">{exec.module_id}</p>
                    </div>
                    {exec.finding_count > 0 && (
                      <span className="ml-auto shrink-0 rounded px-1 text-[10px] font-bold text-white bg-brand-600">{exec.finding_count}</span>
                    )}
                  </button>
                ))}
              </div>

              {/* Terminal output for selected execution */}
              {activeExec && (
                <div className="rounded-xl overflow-hidden border border-slate-200 dark:border-slate-800">
                  <div className="flex items-center gap-3 border-b border-slate-200 bg-slate-100 px-4 py-2 dark:border-slate-800 dark:bg-slate-800">
                    <Terminal className="h-4 w-4 text-slate-400" />
                    <span className="text-xs font-mono text-slate-500">
                      {activeExec.tool_name} {activeExec.module_id} — {activeExec.target}
                    </span>
                    {statusBadge(activeExec.status)}
                    <span className="ml-auto text-xs text-slate-400">{formatDuration(activeExec.started_at, activeExec.completed_at)}</span>
                  </div>
                  <div
                    ref={termRef}
                    className="bg-slate-950 p-4 font-mono text-xs text-slate-300 h-52 overflow-y-auto whitespace-pre-wrap"
                  >
                    {activeExec.raw_output || (activeExec.status === 'running' ? 'Waiting for output...' : 'No output')}
                    {activeExec.error_msg && <div className="text-red-400 mt-2">Error: {activeExec.error_msg}</div>}
                  </div>
                </div>
              )}
            </div>
          )}
        </div>
      )}

      {/* Custom Tool Selection Grid */}
      {mode === 'custom' && (
        <div className="rounded-xl border border-slate-200 bg-white dark:border-slate-800 dark:bg-slate-900 overflow-hidden">
          <div className="flex items-center justify-between border-b border-slate-100 px-5 py-3 dark:border-slate-800">
            <span className="text-xs font-semibold uppercase tracking-wide text-slate-500">
              Tool Selection — {selectedCount}/{installedTools.length} selected
            </span>
            <div className="flex items-center gap-2">
              <button onClick={selectAll} className="text-xs text-brand-600 hover:text-brand-700 font-medium">Select All</button>
              <span className="text-slate-300 dark:text-slate-700">|</span>
              <button onClick={deselectAll} className="text-xs text-slate-500 hover:text-slate-700 font-medium">Deselect All</button>
            </div>
          </div>
          <div className="p-4 grid grid-cols-2 gap-3">
            {toolStatuses.map((tool) => {
              const sel = selections[tool.name] || { enabled: false, moduleId: TOOL_MODULES[tool.name]?.[0]?.id || '', customArgs: '' };
              const modules = TOOL_MODULES[tool.name] || [];
              return (
                <div
                  key={tool.name}
                  className={`rounded-xl border p-4 transition-all ${
                    !tool.installed
                      ? 'border-slate-100 bg-slate-50 dark:border-slate-800 dark:bg-slate-900/50'
                      : sel.enabled
                      ? 'border-brand-400 bg-brand-50/60 dark:border-brand-700 dark:bg-brand-900/10'
                      : 'border-slate-200 dark:border-slate-800'
                  }`}
                >
                  <div className="flex items-start gap-3">
                    <input
                      type="checkbox"
                      checked={sel.enabled}
                      onChange={() => tool.installed && toggleTool(tool.name)}
                      disabled={!tool.installed}
                      className="mt-0.5 h-4 w-4 rounded border-slate-300 text-brand-600 focus:ring-brand-500 disabled:opacity-40 disabled:cursor-not-allowed"
                    />
                    <div className="flex-1 min-w-0">
                      <div className="flex items-center justify-between mb-1">
                        <p className={`text-xs font-bold uppercase ${tool.installed ? 'text-slate-900 dark:text-white' : 'text-slate-400 dark:text-slate-500'}`}>{tool.name}</p>
                        {tool.installed
                          ? <span className="text-[10px] text-slate-400 font-mono">{tool.version?.split(' ')[0] || ''}</span>
                          : <span className="rounded px-1.5 py-0.5 text-[9px] font-medium bg-slate-200 text-slate-500 dark:bg-slate-700 dark:text-slate-400">Not Installed</span>
                        }
                      </div>
                      <p className="text-[11px] text-slate-500 mb-2">{TOOL_DESCRIPTIONS[tool.name]}</p>
                      {sel.enabled && tool.installed && (
                        <div className="space-y-2">
                          <div>
                            <label className="block text-[10px] font-medium text-slate-400 mb-1">Module</label>
                            <select
                              value={sel.moduleId}
                              onChange={(e) => setSelections((prev) => ({ ...prev, [tool.name]: { ...prev[tool.name], moduleId: e.target.value } }))}
                              className="w-full rounded-md border border-slate-200 bg-white px-2 py-1 text-xs dark:border-slate-700 dark:bg-slate-800 dark:text-white"
                            >
                              {modules.map((m) => <option key={m.id} value={m.id}>{m.label}</option>)}
                            </select>
                          </div>
                          <div>
                            <label className="block text-[10px] font-medium text-slate-400 mb-1">Extra Args (optional)</label>
                            <input
                              type="text"
                              value={sel.customArgs}
                              onChange={(e) => setSelections((prev) => ({ ...prev, [tool.name]: { ...prev[tool.name], customArgs: e.target.value } }))}
                              placeholder="e.g. --timeout 30"
                              className="w-full rounded-md border border-slate-200 bg-white px-2 py-1 text-xs dark:border-slate-700 dark:bg-slate-800 dark:text-slate-300"
                            />
                          </div>
                        </div>
                      )}
                    </div>
                  </div>
                </div>
              );
            })}
            {toolStatuses.length === 0 && (
              <div className="col-span-2 py-8 text-center text-sm text-slate-400">
                Loading tool status...
              </div>
            )}
          </div>
        </div>
      )}

      {/* Tool status grid (Scan All mode) */}
      {mode === 'all' && (
        <div className="grid grid-cols-4 gap-3">
          {toolStatuses.map((tool) => (
            <div
              key={tool.name}
              className={`rounded-xl border p-4 ${
                tool.installed
                  ? 'border-slate-200 bg-white dark:border-slate-800 dark:bg-slate-900'
                  : 'border-slate-100 bg-slate-50 opacity-50 dark:border-slate-800 dark:bg-slate-900/50'
              }`}
            >
              <div className="flex items-center justify-between mb-1">
                <h3 className="text-xs font-bold uppercase tracking-wide text-slate-900 dark:text-white">{tool.name}</h3>
                <span className={`h-2 w-2 rounded-full ${tool.installed ? 'bg-emerald-500' : 'bg-slate-300 dark:bg-slate-600'}`} />
              </div>
              <p className="text-[11px] text-slate-400 leading-snug">{TOOL_DESCRIPTIONS[tool.name]}</p>
              {tool.installed && <p className="mt-1 text-[10px] font-mono text-slate-400 truncate">{tool.version?.split(' ')[0]}</p>}
            </div>
          ))}
        </div>
      )}

      {/* Execution History */}
      {executions.length > 0 && (
        <div className="rounded-xl border border-slate-200 bg-white dark:border-slate-800 dark:bg-slate-900 overflow-hidden">
          <div className="flex items-center justify-between border-b border-slate-200 px-5 py-3 dark:border-slate-800">
            <h3 className="text-xs font-semibold uppercase tracking-wide text-slate-500">
              Execution History {selectedTargetId ? `— Target #${selectedTargetId}` : '(All Targets)'}
            </h3>
            <span className="text-xs text-slate-400">{executions.length} runs</span>
          </div>
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead>
                <tr className="border-b border-slate-100 dark:border-slate-800 text-xs text-slate-400">
                  <th className="text-left px-4 py-2 font-medium">Tool</th>
                  <th className="text-left px-4 py-2 font-medium">Module</th>
                  <th className="text-left px-4 py-2 font-medium">Target</th>
                  <th className="text-left px-4 py-2 font-medium">Scan</th>
                  <th className="text-left px-4 py-2 font-medium">Status</th>
                  <th className="text-left px-4 py-2 font-medium">Findings</th>
                  <th className="text-left px-4 py-2 font-medium">Duration</th>
                  <th className="text-left px-4 py-2 font-medium">Date</th>
                </tr>
              </thead>
              <tbody>
                {executions.map((exec) => (
                  <tr
                    key={exec.id}
                    onClick={() => setActiveExec(exec)}
                    className={`border-b border-slate-100 cursor-pointer hover:bg-slate-50 transition-colors dark:border-slate-800/50 dark:hover:bg-slate-800/50 ${
                      activeExec?.id === exec.id ? 'bg-brand-50 dark:bg-brand-900/10' : ''
                    }`}
                  >
                    <td className="px-4 py-2.5 text-xs font-bold uppercase text-slate-900 dark:text-white">{exec.tool_name}</td>
                    <td className="px-4 py-2.5 text-xs text-slate-400">{exec.module_id}</td>
                    <td className="px-4 py-2.5 text-xs font-mono text-slate-500 max-w-[160px] truncate">{exec.target}</td>
                    <td className="px-4 py-2.5 text-xs font-mono text-slate-400">{exec.scan_id ? `#${exec.scan_id}` : '—'}</td>
                    <td className="px-4 py-2.5">{statusBadge(exec.status)}</td>
                    <td className="px-4 py-2.5 text-xs font-medium text-brand-600">{exec.finding_count || '—'}</td>
                    <td className="px-4 py-2.5 text-xs text-slate-400">{formatDuration(exec.started_at, exec.completed_at)}</td>
                    <td className="px-4 py-2.5 text-xs text-slate-400">{new Date(exec.created_at).toLocaleString()}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {/* Output viewer for history click */}
      {activeExec && !sessionExecs.find((e) => e.id === activeExec.id) && (
        <div className="rounded-xl border border-slate-200 bg-white dark:border-slate-800 dark:bg-slate-900 overflow-hidden">
          <div className="flex items-center gap-3 border-b border-slate-200 bg-slate-100 px-4 py-2 dark:border-slate-800 dark:bg-slate-800">
            <Terminal className="h-4 w-4 text-slate-400" />
            <span className="text-xs font-mono text-slate-500">{activeExec.tool_name} — {activeExec.target}</span>
            {statusBadge(activeExec.status)}
            <span className="ml-auto text-xs text-slate-400">{formatDuration(activeExec.started_at, activeExec.completed_at)}</span>
          </div>
          <div className="bg-slate-950 p-4 font-mono text-xs text-slate-300 max-h-72 overflow-y-auto whitespace-pre-wrap">
            {activeExec.raw_output || 'No output'}
            {activeExec.error_msg && <div className="text-red-400 mt-2">Error: {activeExec.error_msg}</div>}
          </div>
        </div>
      )}
    </div>
  );
}
