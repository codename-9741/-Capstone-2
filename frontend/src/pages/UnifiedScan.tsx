import { useEffect, useCallback, useRef, useState } from 'react';
import { activeScanApi } from '../api/scanApi';
import { Shield, Radio, Zap, XCircle, RotateCcw } from 'lucide-react';
import { useScanSessionStore, type ScanFinding } from '../stores/scanSessionStore';

// ─── Phase definitions ────────────────────────────────────────────────────────

interface PhaseGroup {
  label: string;
  ids: string[];
  modes: string[];
}

const PHASE_GROUPS: PhaseGroup[] = [
  {
    label: 'Core Security',
    ids: ['robots', 'headers', 'tls', 'cookies', 'cors', 'clickjacking', 'waf', 'websocket',
          'exposure', 'http_methods', 'sourcemaps', 'comments', 'backups', 'directory_listing',
          'admin_panels', 'api_docs', 'emails', 'fingerprinting', 'graphql'],
    modes: ['safe', 'normal', 'aggressive'],
  },
  {
    label: 'Web Vulnerabilities',
    ids: ['sqli', 'xss', 'csrf', 'xxe', 'ssrf', 'file_inclusion', 'path_traversal',
          'command_injection', 'ldap_injection', 'ssti', 'http_splitting', 'host_header_injection'],
    modes: ['normal', 'aggressive'],
  },
  {
    label: 'Auth & Sessions',
    ids: ['password_policy', 'rate_limiting', 'brute_force', 'session_fixation',
          'session_hijacking', 'oauth', 'jwt', 'api_key_exposure', 'default_creds',
          'password_reset', 'mfa_bypass'],
    modes: ['safe', 'normal', 'aggressive'],
  },
  {
    label: 'API Security',
    ids: ['rest_api', 'api_rate_limit', 'api_auth_bypass', 'mass_assignment',
          'api_version', 'excessive_data', 'api_cors'],
    modes: ['safe', 'normal', 'aggressive'],
  },
  {
    label: 'Business Logic',
    ids: ['price_manipulation', 'privilege_escalation', 'file_upload', 'unrestricted_upload',
          'idor', 'race_conditions', 'account_takeover', 'business_logic'],
    modes: ['safe', 'normal', 'aggressive'],
  },
  {
    label: 'Mobile / Crypto / Cloud',
    ids: ['mobile_app_links', 'app_config', 'cert_pinning', 'root_detection', 'app_hardening',
          'weak_ciphers', 'sslv3', 'tls_renegotiation', 'randomness', 'encryption_at_rest',
          'cloud_metadata', 's3_permissions', 'docker_exposure', 'k8s_exposure', 'cloud_provider'],
    modes: ['aggressive'],
  },
  {
    label: 'Compliance & Privacy',
    ids: ['gdpr', 'ccpa', 'pci_dss', 'hipaa', 'data_retention',
          'dom_clobbering', 'prototype_pollution', 'csp_bypass'],
    modes: ['safe', 'normal', 'aggressive'],
  },
  {
    label: 'Infrastructure',
    ids: ['load_balancer', 'cdn_bypass', 'dnssec', 'sri', 'security_monitoring'],
    modes: ['safe', 'normal', 'aggressive'],
  },
  {
    label: 'External — Passive Tools',
    ids: ['whatweb_fingerprint', 'sslscan_ciphers', 'sslscan_protocols', 'sslscan_certs',
          'fierce_dns_enum', 'amass_passive', 'amass_intel', 'gau_urls', 'dnsx_resolve',
          'crtsh_lookup', 'alterx_permute', 'uncover_search'],
    modes: ['safe', 'normal', 'aggressive'],
  },
  {
    label: 'External — Normal Tools',
    ids: ['nikto_scan', 'nikto_outdated', 'nikto_misconfig', 'nuclei_cves', 'nuclei_misconfig',
          'nuclei_exposed', 'nuclei_takeover', 'httpx_probe', 'httpx_tech',
          'subfinder_passive', 'gobuster_dir'],
    modes: ['normal', 'aggressive'],
  },
  {
    label: 'External — Aggressive Tools',
    ids: ['nmap_top1000', 'nmap_service_detection', 'nmap_vuln_scripts', 'nmap_udp_top',
          'nmap_tls_ciphers', 'nmap_firewall_bypass', 'network_port_exposure', 'tls_version_matrix',
          'http_method_override', 'host_header_injection_adv', 'open_redirect_adv',
          'subdomain_takeover', 'virtual_host_enum', 'directory_bruteforce',
          'credential_endpoint_discovery', 'wapiti_sqli', 'wapiti_xss', 'wapiti_ssrf',
          'wapiti_xxe', 'skipfish_recon', 'sqlmap_detect', 'sqlmap_deep',
          'ffuf_dirs', 'ffuf_api', 'testssl_basic', 'testssl_vulns',
          'dalfox_url', 'dalfox_param', 'gobuster_vhost', 'kiterunner_scan'],
    modes: ['aggressive'],
  },
];

// Generate fast_aggressive IDs (matches Go's fastAggressiveModuleIDs)
function fastAggressiveIDs(): string[] {
  const prefixes = [
    { prefix: 'fast_file', count: 30 },
    { prefix: 'fast_admin', count: 25 },
    { prefix: 'fast_api', count: 19 },
    { prefix: 'fast_cloud', count: 15 },
    { prefix: 'fast_auth', count: 10 },
  ];
  const ids: string[] = [];
  for (const { prefix, count } of prefixes) {
    for (let i = 1; i <= count; i++) {
      ids.push(`${prefix}_${String(i).padStart(3, '0')}`);
    }
  }
  return ids;
}

// Generate proto_method IDs (matches Go's protocolAggressiveModuleIDs)
function protoMethodIDs(): string[] {
  const ids: string[] = [];
  for (let i = 1; i <= 100; i++) {
    ids.push(`proto_method_${String(i).padStart(3, '0')}`);
  }
  return ids;
}

function allModuleIDsForMode(mode: string): string[] {
  const ids: string[] = [];
  for (const pg of PHASE_GROUPS) {
    if (pg.modes.includes(mode)) {
      ids.push(...pg.ids);
    }
  }
  if (mode === 'aggressive') {
    ids.push(...fastAggressiveIDs());
    ids.push(...protoMethodIDs());
  }
  return ids;
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

const SEV_COLORS: Record<string, string> = {
  Critical: 'bg-red-500',
  High: 'bg-orange-500',
  Medium: 'bg-amber-400',
  Low: 'bg-emerald-500',
  Info: 'bg-blue-500',
};

function statusColor(status: string): string {
  switch (status) {
    case 'running':   return 'bg-blue-500 animate-pulse';
    case 'completed': return 'bg-emerald-500';
    case 'failed':    return 'bg-red-500';
    case 'skipped':   return 'bg-amber-400';
    default:          return 'bg-slate-300 dark:bg-slate-600'; // pending
  }
}

function statusBadge(status: string): string {
  switch (status) {
    case 'running':   return 'bg-blue-100 text-blue-700 dark:bg-blue-900/30 dark:text-blue-400';
    case 'completed': return 'bg-emerald-100 text-emerald-700 dark:bg-emerald-900/30 dark:text-emerald-400';
    case 'failed':    return 'bg-red-100 text-red-700 dark:bg-red-900/30 dark:text-red-400';
    case 'skipped':   return 'bg-amber-100 text-amber-700 dark:bg-amber-900/30 dark:text-amber-400';
    default:          return 'bg-slate-100 text-slate-500 dark:bg-slate-800 dark:text-slate-400';
  }
}

const MODE_TIMEOUTS: Record<string, number> = {
  safe: 5,
  normal: 10,
  aggressive: 30,
};

// ─── Component ────────────────────────────────────────────────────────────────

export default function UnifiedScan() {
  const {
    domain, scanMode, scanType, isScanning, activeScanId,
    passiveScanStarted, passiveScanStartedAt, passiveScanCompleted,
    scanData, activeLogs, passiveLogs, findings,
    setDomain, setScanMode, setScanType, setIsScanning,
    setActiveScanId, setPassiveScanStarted, setPassiveScanStartedAt,
    setPassiveScanCompleted, setScanData, setFindings,
    setActiveLogs, setPassiveLogs, pushActiveLog, pushPassiveLog, resetSession,
  } = useScanSessionStore();

  const [moduleView, setModuleView] = useState<'overview' | 'modules'>('overview');
  const [timeoutMinutes, setTimeoutMinutes] = useState<number>(MODE_TIMEOUTS[scanMode] ?? 10);
  const [moduleStatuses, setModuleStatuses] = useState<Map<string, string>>(new Map());

  // Sync timeout default when mode changes
  useEffect(() => {
    setTimeoutMinutes(MODE_TIMEOUTS[scanMode] ?? 10);
  }, [scanMode]);

  // Refs to avoid stale closures in intervals
  const passiveScanCompletedRef = useRef(passiveScanCompleted);
  const activeScanIdRef         = useRef(activeScanId);
  const isScanningRef           = useRef(isScanning);
  useEffect(() => { passiveScanCompletedRef.current = passiveScanCompleted; }, [passiveScanCompleted]);
  useEffect(() => { activeScanIdRef.current = activeScanId; }, [activeScanId]);
  useEffect(() => { isScanningRef.current = isScanning; }, [isScanning]);

  const ts = () => new Date().toLocaleTimeString();
  const addActiveLog  = useCallback((msg: string) => pushActiveLog(`[${ts()}] ${msg}`), [pushActiveLog]);
  const addPassiveLog = useCallback((msg: string) => pushPassiveLog(`[${ts()}] ${msg}`), [pushPassiveLog]);

  // ── Module status polling ──────────────────────────────────────────────────

  useEffect(() => {
    if (!activeScanId || !isScanning) return;
    const interval = setInterval(async () => {
      try {
        const res = await activeScanApi.getModules(activeScanId);
        if (res.success && res.data) {
          setModuleStatuses((prev) => {
            const next = new Map(prev);
            for (const m of res.data) {
              next.set(m.id, m.status);
            }
            return next;
          });
        }
      } catch { /* ignore */ }
    }, 3000);
    return () => clearInterval(interval);
  }, [activeScanId, isScanning]);

  // ── Active scan status poll ────────────────────────────────────────────────

  useEffect(() => {
    if (!activeScanId || !isScanning) return;

    const interval = setInterval(async () => {
      try {
        const result = await activeScanApi.getScan(activeScanId);
        const data = result.data;
        setScanData(data);

        if (data.findings) {
          const newFindings = data.findings as ScanFinding[];
          const prev = useScanSessionStore.getState().findings;
          if (newFindings.length > prev.length) {
            newFindings.slice(prev.length).forEach((f) => {
              addActiveLog(`[${f.severity}] ${f.category}: ${f.finding}`);
            });
          }
          setFindings(newFindings);
        }

        const terminal = ['completed', 'failed', 'cancelled'];
        if (terminal.includes(data.status ?? '')) {
          clearInterval(interval);
          if (data.status === 'completed') {
            addActiveLog(`Scan completed. Findings: ${data.findings?.length || 0}`);
            addActiveLog(`Risk Score: ${data.risk_score}/100 (${data.risk_grade})`);
            if (passiveScanCompletedRef.current || !useScanSessionStore.getState().passiveScanStarted) {
              setIsScanning(false);
            }
          } else {
            addActiveLog(`Scan ended with status: ${(data.status ?? '').toUpperCase()}`);
            setIsScanning(false);
          }
        }
      } catch (error) {
        console.error('Error polling scan:', error);
      }
    }, 3000);

    return () => clearInterval(interval);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [activeScanId, isScanning]);

  // ── Passive scan poll ─────────────────────────────────────────────────────

  useEffect(() => {
    if (!isScanning || !passiveScanStarted || passiveScanCompleted || !passiveScanStartedAt) return;
    const elapsed = Date.now() - passiveScanStartedAt;
    const delay   = Math.max(0, 35000 - elapsed);
    const t = setTimeout(async () => {
      try {
        addPassiveLog('Checking passive scan results...');
        const res  = await fetch(`/api/intel/passive/${domain}`);
        const data = await res.json();
        if (data.status === 'success') {
          setPassiveScanCompleted(true);
          addPassiveLog('Passive scan completed.');
          addPassiveLog(`Intelligence sources: ${data.data.modules_succeeded}`);
          const st = useScanSessionStore.getState().scanData?.status;
          if (!st || st !== 'running') setIsScanning(false);
        }
      } catch (e) { console.error('Passive scan poll error:', e); }
    }, delay);
    return () => clearTimeout(t);
  }, [isScanning, passiveScanStarted, passiveScanCompleted, passiveScanStartedAt, domain]);

  // ── Recover latest scan on mount ─────────────────────────────────────────

  useEffect(() => {
    if (scanData || activeScanId) return;
    (async () => {
      try {
        const result = await activeScanApi.listScans();
        if (!result.success) return;
        const scans = result.data || [];
        if (scans.length === 0) return;
        const latest = scans[0];
        setScanData(latest);
        setFindings(latest.findings || []);
        if (latest.status === 'running' && latest.id) {
          addActiveLog(`Resuming active scan #${latest.id}`);
          setActiveScanId(latest.id);
          setIsScanning(true);
        }
      } catch (error) { console.error('Unable to recover latest scan:', error); }
    })();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  // ── Actions ───────────────────────────────────────────────────────────────

  const startScan = async () => {
    if (!domain) return;
    resetSession();
    setIsScanning(true);
    setActiveLogs([]); setPassiveLogs([]); setFindings([]); setScanData(null);
    setActiveScanId(null); setPassiveScanStarted(false); setPassiveScanStartedAt(null);
    setPassiveScanCompleted(false);

    // Pre-populate module statuses with "pending" for all expected modules
    const expectedIDs = allModuleIDsForMode(scanMode);
    const initial = new Map<string, string>();
    for (const id of expectedIDs) initial.set(id, 'pending');
    setModuleStatuses(initial);

    addActiveLog('NIGHTFALL TSUKUYOMI — Initializing scan');
    addActiveLog(`Target: ${domain}`);
    addActiveLog(`Mode: ${scanMode.toUpperCase()} | Timeout: ${timeoutMinutes}min | Modules: ${expectedIDs.length}`);
    addPassiveLog('NIGHTFALL TSUKUYOMI — Initializing PASSIVE scan');
    addPassiveLog(`Target: ${domain}`);

    try {
      if (scanType === 'active' || scanType === 'both') {
        addActiveLog(`Starting ACTIVE scan (${scanMode.toUpperCase()})...`);
        const result = await activeScanApi.createScan({ domain, mode: scanMode, timeoutMinutes });
        if (result.data?.id) {
          setActiveScanId(result.data.id);
          addActiveLog(`Active scan #${result.data.id} started`);
        } else {
          addActiveLog('Failed to start active scan — check backend logs');
          if (scanType === 'active') setIsScanning(false);
        }
      }

      if (scanType === 'passive' || scanType === 'both') {
        addPassiveLog('Starting PASSIVE intelligence gathering...');
        const passiveRes = await fetch('/api/intel/passive', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ domain }),
        });
        if (passiveRes.ok) {
          setPassiveScanStarted(true);
          setPassiveScanStartedAt(Date.now());
          setPassiveScanCompleted(false);
          addPassiveLog('Passive scan started');
          addPassiveLog('Gathering OSINT data (30-60 seconds)...');
        } else {
          addPassiveLog('Passive scan failed to start');
          if (scanType === 'passive') setIsScanning(false);
        }
      }
    } catch (error: any) {
      addActiveLog(`Error: ${error.message}`);
      addPassiveLog(`Error: ${error.message}`);
      setIsScanning(false);
    }
  };

  const cancelScan = async () => {
    if (activeScanId) {
      try {
        await activeScanApi.cancelScan(activeScanId);
        addActiveLog('Scan cancelled by user');
      } catch { /* ignore */ }
    }
    setIsScanning(false);
  };

  const resetUI = () => {
    resetSession();
    setActiveLogs([]); setPassiveLogs([]); setFindings([]); setScanData(null);
    setModuleStatuses(new Map());
  };

  // ── Derived ───────────────────────────────────────────────────────────────

  const scanTerminal  = scanData?.status && ['completed', 'failed', 'cancelled'].includes(scanData.status);
  const scanFailed    = scanData?.status === 'failed' || scanData?.status === 'cancelled';

  // Module stats derived from statuses map
  const statusCounts = { pending: 0, running: 0, completed: 0, failed: 0, skipped: 0 };
  moduleStatuses.forEach((s) => {
    const key = s as keyof typeof statusCounts;
    if (key in statusCounts) statusCounts[key]++;
  });
  const totalModules = moduleStatuses.size;
  const doneModules  = statusCounts.completed + statusCounts.failed + statusCounts.skipped;

  const moduleStatsRow = [
    { label: 'Total',     value: totalModules,             color: 'text-slate-900 dark:text-white' },
    { label: 'Pending',   value: statusCounts.pending,     color: 'text-slate-500' },
    { label: 'Running',   value: statusCounts.running,     color: 'text-blue-600' },
    { label: 'Done',      value: statusCounts.completed,   color: 'text-emerald-600' },
    { label: 'Failed',    value: statusCounts.failed,      color: 'text-red-600' },
    { label: 'Skipped',   value: statusCounts.skipped,     color: 'text-amber-600' },
  ];

  const reqStatsRow = [
    { label: 'Total Req.', value: scanData?.total_requests ?? 0 },
    { label: 'OK Req.',    value: scanData?.successful_requests ?? 0 },
    { label: 'Err Req.',   value: scanData?.errored_requests ?? 0 },
  ];

  // Visible phase groups for current mode
  const visibleGroups = PHASE_GROUPS.filter((pg) => pg.modes.includes(scanMode));

  // ── Render ────────────────────────────────────────────────────────────────

  return (
    <div className="space-y-6">

      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-slate-900 dark:text-white">Security Scanner</h1>
          <p className="text-sm text-slate-500">Vulnerability assessment and intelligence gathering</p>
        </div>
        {(scanData || activeLogs.length > 0) && !isScanning && (
          <button
            onClick={resetUI}
            className="inline-flex items-center gap-2 rounded-lg border border-slate-200 px-3 py-1.5 text-sm text-slate-500 hover:bg-slate-50 dark:border-slate-700 dark:hover:bg-slate-800"
          >
            <RotateCcw className="h-4 w-4" /> New Scan
          </button>
        )}
      </div>

      {/* Scan Controls */}
      <div className="rounded-xl border border-slate-200 bg-white p-6 space-y-4 dark:border-slate-800 dark:bg-slate-900">

        {/* Target */}
        <div>
          <label className="block text-xs font-medium text-slate-500 mb-1.5">Target Domain</label>
          <input
            type="text"
            placeholder="example.com"
            value={domain}
            onChange={(e) => setDomain(e.target.value)}
            className="input text-base py-2.5"
            disabled={isScanning}
          />
        </div>

        {/* Scan Type */}
        <div>
          <label className="block text-xs font-medium text-slate-500 mb-1.5">Scan Type</label>
          <div className="grid grid-cols-3 gap-2">
            {(['both', 'active', 'passive'] as const).map((type) => (
              <button
                key={type}
                onClick={() => setScanType(type)}
                disabled={isScanning}
                className={`flex items-center justify-center gap-2 rounded-lg px-4 py-2.5 text-sm font-medium transition-colors ${
                  scanType === type
                    ? 'bg-brand-600 text-white shadow-sm'
                    : 'border border-slate-200 bg-white text-slate-600 hover:bg-slate-50 dark:border-slate-700 dark:bg-slate-800 dark:text-slate-300'
                }`}
              >
                {type === 'active'  && <Shield className="h-4 w-4" />}
                {type === 'passive' && <Radio  className="h-4 w-4" />}
                {type === 'both'    && <Zap    className="h-4 w-4" />}
                {type === 'both' ? 'Full Scan' : type === 'active' ? 'Active Only' : 'Passive Only'}
              </button>
            ))}
          </div>
        </div>

        {/* Scan Mode + Timeout */}
        {(scanType === 'active' || scanType === 'both') && (
          <div className="grid grid-cols-1 gap-4 sm:grid-cols-2">
            <div>
              <label className="block text-xs font-medium text-slate-500 mb-1.5">Scan Mode</label>
              <div className="grid grid-cols-3 gap-2">
                {(['safe', 'normal', 'aggressive'] as const).map((mode) => (
                  <button
                    key={mode}
                    onClick={() => setScanMode(mode)}
                    disabled={isScanning}
                    className={`rounded-lg px-3 py-2 text-sm font-medium transition-colors ${
                      scanMode === mode
                        ? 'bg-slate-900 text-white dark:bg-white dark:text-slate-900'
                        : 'border border-slate-200 text-slate-600 hover:bg-slate-50 dark:border-slate-700 dark:text-slate-400'
                    }`}
                  >
                    {mode.charAt(0).toUpperCase() + mode.slice(1)}
                  </button>
                ))}
              </div>
              <p className="mt-1 text-[11px] text-slate-400">
                Safe: ~40 modules &nbsp;·&nbsp; Normal: ~70 &nbsp;·&nbsp; Aggressive: 315+
              </p>
            </div>
            <div>
              <label className="block text-xs font-medium text-slate-500 mb-1.5">
                Timeout (minutes)
              </label>
              <select
                value={timeoutMinutes}
                onChange={(e) => setTimeoutMinutes(Number(e.target.value))}
                disabled={isScanning}
                className="input py-2"
              >
                {[5, 10, 15, 20, 30, 45, 60].map((m) => (
                  <option key={m} value={m}>
                    {m} min{m === MODE_TIMEOUTS[scanMode] ? ' (default)' : ''}
                  </option>
                ))}
              </select>
              <p className="mt-1 text-[11px] text-slate-400">
                Scan will be killed after this duration.
              </p>
            </div>
          </div>
        )}

        {/* Start / Cancel */}
        <div className="flex items-center gap-3">
          <button
            onClick={startScan}
            disabled={isScanning || !domain}
            className="btn-primary flex-1 py-3 text-base"
          >
            {isScanning ? (
              <span className="flex items-center justify-center gap-2">
                <span className="h-2 w-2 rounded-full bg-white animate-pulse" />
                Scanning... {statusCounts.running > 0 ? `(${statusCounts.running} running)` : ''}
              </span>
            ) : 'Execute Scan'}
          </button>
          {isScanning && (
            <button
              onClick={cancelScan}
              className="inline-flex items-center gap-2 rounded-xl border border-red-200 bg-red-50 px-4 py-3 text-sm font-semibold text-red-700 hover:bg-red-100 dark:border-red-800 dark:bg-red-900/20 dark:text-red-400"
            >
              <XCircle className="h-4 w-4" /> Cancel
            </button>
          )}
        </div>
      </div>

      {/* Failed / Cancelled banner */}
      {scanFailed && (
        <div className="flex items-center gap-3 rounded-xl border border-red-200 bg-red-50 px-5 py-3 dark:border-red-800 dark:bg-red-900/20">
          <XCircle className="h-5 w-5 text-red-500" />
          <div>
            <p className="text-sm font-semibold text-red-700 dark:text-red-400">
              Scan {(scanData?.status ?? '').toUpperCase()}
            </p>
            <p className="text-xs text-red-600/80 dark:text-red-400/70">
              {scanData?.status === 'cancelled'
                ? 'Scan was cancelled by user.'
                : 'Scan failed — target may be unreachable, or connectivity is blocked. Check backend logs for details.'}
            </p>
          </div>
        </div>
      )}

      {/* View Toggle */}
      {(activeLogs.length > 0 || scanData || moduleStatuses.size > 0) && (
        <div className="flex gap-2">
          {(['overview', 'modules'] as const).map((v) => (
            <button
              key={v}
              onClick={() => setModuleView(v)}
              className={`rounded-lg px-3 py-1.5 text-xs font-medium transition-colors ${
                moduleView === v
                  ? 'bg-brand-600 text-white'
                  : 'border border-slate-200 text-slate-500 dark:border-slate-700'
              }`}
            >
              {v === 'overview' ? 'Overview' : `Module Matrix${totalModules > 0 ? ` (${totalModules})` : ''}`}
            </button>
          ))}
        </div>
      )}

      {/* ── Module Matrix ─────────────────────────────────────────────────── */}
      {moduleView === 'modules' && (
        <div className="rounded-xl border border-slate-200 bg-white p-5 dark:border-slate-800 dark:bg-slate-900 space-y-4">

          {/* Summary row */}
          <div className="flex items-center justify-between">
            <h3 className="text-sm font-semibold text-slate-900 dark:text-white">Module Matrix</h3>
            <div className="flex items-center gap-3">
              {isScanning && (
                <span className="flex items-center gap-1 text-xs text-blue-600">
                  <span className="h-1.5 w-1.5 rounded-full bg-blue-500 animate-pulse" /> Live
                </span>
              )}
              {scanData?.status && (
                <span className={`rounded-md px-2 py-0.5 text-xs font-medium ${statusBadge(scanData.status)}`}>
                  {scanData.status}
                </span>
              )}
            </div>
          </div>

          {/* Stats counters */}
          {totalModules > 0 && (
            <div className="grid grid-cols-6 gap-2">
              {moduleStatsRow.map(({ label, value, color }) => (
                <div key={label} className="rounded-lg bg-slate-50 p-2.5 dark:bg-slate-800 text-center">
                  <p className="text-[10px] font-medium uppercase text-slate-400">{label}</p>
                  <p className={`text-xl font-bold ${color}`}>{value}</p>
                </div>
              ))}
            </div>
          )}

          {/* Progress bar */}
          {totalModules > 0 && (
            <div>
              <div className="flex items-center justify-between mb-1">
                <span className="text-xs text-slate-400">Progress</span>
                <span className="text-xs font-medium text-slate-600 dark:text-slate-300">
                  {doneModules} / {totalModules}
                </span>
              </div>
              <div className="h-2 rounded-full bg-slate-100 dark:bg-slate-800 overflow-hidden">
                <div
                  className="h-full rounded-full bg-brand-500 transition-all duration-500"
                  style={{ width: `${(doneModules / Math.max(totalModules, 1)) * 100}%` }}
                />
              </div>
            </div>
          )}

          {/* Request stats */}
          {(scanData?.total_requests ?? 0) > 0 && (
            <div className="grid grid-cols-3 gap-2">
              {reqStatsRow.map(({ label, value }) => (
                <div key={label} className="rounded-lg bg-slate-50 p-2.5 dark:bg-slate-800">
                  <p className="text-[10px] font-medium uppercase text-slate-400">{label}</p>
                  <p className="text-lg font-bold text-slate-900 dark:text-white">{value}</p>
                </div>
              ))}
            </div>
          )}

          {/* Phase groups */}
          {totalModules === 0 && (
            <p className="text-xs text-slate-400 text-center py-4">
              Start a scan to see module statuses.
            </p>
          )}

          {totalModules > 0 && visibleGroups.map((pg) => {
            const groupModules = pg.ids.filter((id) => moduleStatuses.has(id));
            if (groupModules.length === 0) return null;
            return (
              <div key={pg.label}>
                <p className="text-[11px] font-semibold uppercase tracking-wide text-slate-400 mb-1.5">
                  {pg.label} ({groupModules.length})
                </p>
                <div className="flex flex-wrap gap-1.5">
                  {groupModules.map((id) => {
                    const st = moduleStatuses.get(id) ?? 'pending';
                    return (
                      <div
                        key={id}
                        title={`${id}: ${st}`}
                        className={`flex items-center gap-1 rounded-md px-2 py-0.5 text-[10px] font-mono border ${
                          st === 'running'   ? 'border-blue-300 bg-blue-50 text-blue-700 dark:border-blue-700 dark:bg-blue-900/20 dark:text-blue-400' :
                          st === 'completed' ? 'border-emerald-300 bg-emerald-50 text-emerald-700 dark:border-emerald-700 dark:bg-emerald-900/20 dark:text-emerald-400' :
                          st === 'failed'    ? 'border-red-300 bg-red-50 text-red-700 dark:border-red-700 dark:bg-red-900/20 dark:text-red-400' :
                          st === 'skipped'   ? 'border-amber-300 bg-amber-50 text-amber-700 dark:border-amber-700 dark:bg-amber-900/20 dark:text-amber-400' :
                          'border-slate-200 bg-slate-50 text-slate-500 dark:border-slate-700 dark:bg-slate-800 dark:text-slate-400'
                        }`}
                      >
                        <span className={`h-1.5 w-1.5 rounded-full flex-shrink-0 ${statusColor(st)}`} />
                        {id}
                      </div>
                    );
                  })}
                </div>
              </div>
            );
          })}

          {/* Fast Aggressive (100) */}
          {totalModules > 0 && scanMode === 'aggressive' && (() => {
            const fastIDs = fastAggressiveIDs().filter((id) => moduleStatuses.has(id));
            if (fastIDs.length === 0) return null;
            const counts = { pending: 0, running: 0, completed: 0, failed: 0, skipped: 0 };
            fastIDs.forEach((id) => {
              const s = (moduleStatuses.get(id) ?? 'pending') as keyof typeof counts;
              if (s in counts) counts[s]++;
            });
            return (
              <div key="fast-aggressive">
                <p className="text-[11px] font-semibold uppercase tracking-wide text-slate-400 mb-1.5">
                  Fast Aggressive — File / Admin / API / Cloud / Auth ({fastIDs.length})
                </p>
                <div className="flex flex-wrap gap-px">
                  {fastIDs.map((id) => (
                    <div
                      key={id}
                      title={`${id}: ${moduleStatuses.get(id) ?? 'pending'}`}
                      className={`h-3 w-3 rounded-sm ${statusColor(moduleStatuses.get(id) ?? 'pending')}`}
                    />
                  ))}
                </div>
                <div className="mt-1 flex gap-3 text-[10px] text-slate-400">
                  <span className="text-emerald-600">{counts.completed} done</span>
                  <span className="text-blue-600">{counts.running} running</span>
                  <span className="text-red-600">{counts.failed} failed</span>
                  <span className="text-amber-600">{counts.skipped} skipped</span>
                  <span>{counts.pending} pending</span>
                </div>
              </div>
            );
          })()}

          {/* Protocol Matrix (100) */}
          {totalModules > 0 && scanMode === 'aggressive' && (() => {
            const protoIDs = protoMethodIDs().filter((id) => moduleStatuses.has(id));
            if (protoIDs.length === 0) return null;
            const counts = { pending: 0, running: 0, completed: 0, failed: 0, skipped: 0 };
            protoIDs.forEach((id) => {
              const s = (moduleStatuses.get(id) ?? 'pending') as keyof typeof counts;
              if (s in counts) counts[s]++;
            });
            return (
              <div key="proto-matrix">
                <p className="text-[11px] font-semibold uppercase tracking-wide text-slate-400 mb-1.5">
                  Protocol Method Matrix — OPTIONS / TRACE / PUT / DELETE / PATCH ({protoIDs.length})
                </p>
                <div className="flex flex-wrap gap-px">
                  {protoIDs.map((id) => (
                    <div
                      key={id}
                      title={`${id}: ${moduleStatuses.get(id) ?? 'pending'}`}
                      className={`h-3 w-3 rounded-sm ${statusColor(moduleStatuses.get(id) ?? 'pending')}`}
                    />
                  ))}
                </div>
                <div className="mt-1 flex gap-3 text-[10px] text-slate-400">
                  <span className="text-emerald-600">{counts.completed} done</span>
                  <span className="text-blue-600">{counts.running} running</span>
                  <span className="text-red-600">{counts.failed} failed</span>
                  <span className="text-amber-600">{counts.skipped} skipped</span>
                  <span>{counts.pending} pending</span>
                </div>
              </div>
            );
          })()}

          {/* Legend */}
          <div className="flex flex-wrap gap-3 text-[10px]">
            {[
              { label: 'Pending',   cls: 'bg-slate-300 dark:bg-slate-600' },
              { label: 'Running',   cls: 'bg-blue-500' },
              { label: 'Completed', cls: 'bg-emerald-500' },
              { label: 'Failed',    cls: 'bg-red-500' },
              { label: 'Skipped',   cls: 'bg-amber-400' },
            ].map(({ label, cls }) => (
              <span key={label} className="flex items-center gap-1 text-slate-500">
                <span className={`h-2.5 w-2.5 rounded-sm ${cls}`} /> {label}
              </span>
            ))}
          </div>
        </div>
      )}

      {/* ── Overview panel ────────────────────────────────────────────────── */}
      {moduleView === 'overview' && (
        <>
          {/* Live Consoles */}
          {(activeLogs.length > 0 || passiveLogs.length > 0) && (
            <div className="grid grid-cols-1 gap-4 md:grid-cols-2">
              {(scanType === 'active' || scanType === 'both') && activeLogs.length > 0 && (
                <div className="rounded-xl border border-slate-200 bg-white dark:border-slate-800 dark:bg-slate-900 overflow-hidden">
                  <div className="flex items-center gap-2 border-b border-slate-200 px-4 py-2.5 dark:border-slate-800">
                    <h2 className="text-xs font-semibold uppercase tracking-wide text-slate-500">Active Console</h2>
                    <span className="text-[10px] text-slate-400">({activeLogs.length})</span>
                    {isScanning && !scanTerminal && (
                      <span className="ml-auto text-[10px] text-blue-500">live</span>
                    )}
                  </div>
                  <ConsoleView logs={activeLogs} />
                </div>
              )}
              {(scanType === 'passive' || scanType === 'both') && passiveLogs.length > 0 && (
                <div className="rounded-xl border border-slate-200 bg-white dark:border-slate-800 dark:bg-slate-900 overflow-hidden">
                  <div className="flex items-center gap-2 border-b border-slate-200 px-4 py-2.5 dark:border-slate-800">
                    <h2 className="text-xs font-semibold uppercase tracking-wide text-slate-500">Passive Console</h2>
                    <span className="text-[10px] text-slate-400">({passiveLogs.length})</span>
                    {isScanning && !passiveScanCompleted && (
                      <span className="ml-auto text-[10px] text-emerald-500">live</span>
                    )}
                  </div>
                  <ConsoleView logs={passiveLogs} />
                </div>
              )}
            </div>
          )}

          {/* Results Summary */}
          {scanData && (
            <div className="grid grid-cols-3 gap-4">
              <div className="rounded-xl border border-slate-200 bg-white p-4 dark:border-slate-800 dark:bg-slate-900">
                <p className="text-xs text-slate-400">Status</p>
                <p className={`text-xl font-bold ${
                  scanData.status === 'completed' ? 'text-emerald-600' :
                  scanData.status === 'running'   ? 'text-blue-600'   : 'text-red-600'
                }`}>{(scanData.status ?? 'unknown').toUpperCase()}</p>
              </div>
              <div className="rounded-xl border border-slate-200 bg-white p-4 dark:border-slate-800 dark:bg-slate-900">
                <p className="text-xs text-slate-400">Risk Score</p>
                <p className="text-xl font-bold text-slate-900 dark:text-white">{scanData.risk_score ?? 0}/100</p>
                {scanData.risk_grade && (
                  <span className={`mt-1 inline-block rounded-md px-2 py-0.5 text-xs font-medium text-white ${
                    scanData.risk_grade === 'HIGH' ? 'bg-red-500' :
                    scanData.risk_grade === 'MEDIUM' ? 'bg-amber-500' : 'bg-emerald-500'
                  }`}>{scanData.risk_grade}</span>
                )}
              </div>
              <div className="rounded-xl border border-slate-200 bg-white p-4 dark:border-slate-800 dark:bg-slate-900">
                <p className="text-xs text-slate-400">Total Findings</p>
                <p className="text-xl font-bold text-slate-900 dark:text-white">{findings.length}</p>
              </div>
            </div>
          )}

          {/* Findings Preview */}
          {findings.length > 0 && (
            <div className="rounded-xl border border-slate-200 bg-white p-6 dark:border-slate-800 dark:bg-slate-900">
              <h3 className="text-sm font-semibold text-slate-900 dark:text-white mb-4">
                Latest Findings ({findings.length})
              </h3>
              <div className="space-y-2 max-h-80 overflow-y-auto">
                {findings.slice(0, 20).map((finding: any, idx: number) => (
                  <div key={idx} className="rounded-lg border border-slate-200 p-3 dark:border-slate-800">
                    <div className="flex items-center gap-2 mb-1">
                      <span className={`rounded-md px-2 py-0.5 text-xs font-medium text-white ${SEV_COLORS[finding.severity] || 'bg-slate-500'}`}>
                        {finding.severity}
                      </span>
                      <span className="text-sm font-medium text-slate-900 dark:text-white">{finding.category}</span>
                    </div>
                    <p className="text-xs text-slate-500">{finding.finding}</p>
                  </div>
                ))}
              </div>
            </div>
          )}
        </>
      )}
    </div>
  );
}

// ─── Console sub-component (auto-scroll, plain text) ─────────────────────────

function ConsoleView({ logs }: { logs: string[] }) {
  const ref = useRef<HTMLDivElement>(null);
  useEffect(() => {
    if (ref.current) ref.current.scrollTop = ref.current.scrollHeight;
  }, [logs]);

  return (
    <div ref={ref} className="bg-slate-950 p-4 font-mono text-xs max-h-72 overflow-y-auto space-y-0.5">
      {logs.map((log, idx) => {
        const lower = log.toLowerCase();
        const cls =
          lower.includes('error') || lower.includes('failed') || lower.includes('cancelled')
            ? 'text-red-400'
            : lower.includes('completed') || lower.includes('risk score') || lower.includes('done')
            ? 'text-emerald-400'
            : 'text-slate-300';
        return <div key={idx} className={cls}>{log}</div>;
      })}
    </div>
  );
}
