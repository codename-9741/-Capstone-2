const API_BASE = '/api';

export interface ActiveScanRequest {
  domain: string;
  mode: 'safe' | 'normal' | 'aggressive';
  timeoutMinutes?: number;
}

export interface ModuleStatus {
  id: string;
  status: 'pending' | 'running' | 'completed' | 'failed' | 'skipped';
}

export interface ActiveScanResponse {
  status: string;
  success?: boolean;
  data: {
    id: number;
    target_id: number;
    scan_type: string;
    status: string;
    progress: number;
    started_at: string;
    completed_at?: string;
    findings?: Finding[];
    risk_score?: number;
    risk_grade?: string;
    enabled_modules?: number;
    attempted_modules?: number;
    completed_modules?: number;
    errored_modules?: number;
    successful_requests?: number;
    total_requests?: number;
    errored_requests?: number;
    opencti_export_status?: string;
    opencti_bundle_id?: string;
    opencti_error?: string;
  };
}

export interface Finding {
  id: number;
  severity: string;
  category: string;
  confidence: string;
  finding: string;
  remediation: string;
  evidence: string;
  http_method: string;
  outcome: string;
  tool_source: string;
  mitre_attack_id: string;
  mitre_tactic: string;
  mitre_technique: string;
  owasp_category: string;
  owasp_name: string;
  kill_chain_phase: string;
  correlation_id: string;
  correlated_with: string;
  tool_count: number;
}

export const activeScanApi = {
  createScan: async (request: ActiveScanRequest): Promise<ActiveScanResponse> => {
    console.log('Creating scan for:', request.domain);

    // Step 1: Create or get target
    const targetResponse = await fetch(`${API_BASE}/targets`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        domain: request.domain,
        display_name: request.domain
      }),
    });

    const targetData = await targetResponse.json();
    console.log('Target response:', targetData);

    const target = targetData;

    if (!target || !target.id) {
      throw new Error('Failed to create target');
    }

    console.log('Target ID:', target.id);

    // Step 2: Create scan
    const scanResponse = await fetch(`${API_BASE}/scans`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        target_id: target.id,
        scan_type: request.mode,
        timeout_minutes: request.timeoutMinutes ?? 0,
      }),
    });

    const scanData = await scanResponse.json();
    console.log('Scan created:', scanData);

    return scanData;
  },

  getScan: async (id: number): Promise<ActiveScanResponse> => {
    const response = await fetch(`${API_BASE}/scans/${id}`);
    return response.json();
  },

  listScans: async (): Promise<{ status: string; success?: boolean; data: any[] }> => {
    const response = await fetch(`${API_BASE}/scans`);
    return response.json();
  },

  exportToOpenCTI: async (scanId: number): Promise<{ success?: boolean; bundle_id?: string; error?: string }> => {
    const response = await fetch(`${API_BASE}/scans/${scanId}/export-opencti`, {
      method: 'POST',
    });
    return response.json();
  },

  cancelScan: async (scanId: number): Promise<{ success?: boolean }> => {
    const response = await fetch(`${API_BASE}/scans/${scanId}/cancel`, {
      method: 'POST',
    });
    return response.json();
  },

  getModules: async (scanId: number): Promise<{ success: boolean; data: ModuleStatus[] }> => {
    const response = await fetch(`${API_BASE}/scans/${scanId}/modules`);
    return response.json();
  },
};

// Tool Execution Workbench
export interface ToolExecution {
  id: number;
  target_id: number;
  scan_id: number;
  tool_name: string;
  module_id: string;
  target: string;
  command: string;
  custom_args: string;
  raw_output: string;
  status: string;
  exit_code: number;
  finding_count: number;
  error_msg: string;
  started_at: string;
  completed_at: string;
  created_at: string;
}

export const toolExecutionApi = {
  execute: async (req: { tool_name: string; module_id: string; target: string; custom_args?: string; target_id?: number; scan_id?: number }): Promise<{ success: boolean; data: ToolExecution }> => {
    const res = await fetch(`${API_BASE}/tools/execute`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(req) });
    return res.json();
  },
  get: async (id: number): Promise<{ success: boolean; data: ToolExecution }> => {
    const res = await fetch(`${API_BASE}/tools/executions/${id}`);
    return res.json();
  },
  list: async (targetId?: number): Promise<{ success: boolean; data: ToolExecution[] }> => {
    const qs = targetId ? `?target_id=${targetId}` : '';
    const res = await fetch(`${API_BASE}/tools/executions${qs}`);
    return res.json();
  },
  stop: async (id: number): Promise<{ success: boolean }> => {
    const res = await fetch(`${API_BASE}/tools/executions/${id}/stop`, { method: 'POST' });
    return res.json();
  },
  scanAll: async (target: string, targetId?: number): Promise<{ success: boolean; data: ToolExecution[]; total: number; scan_id: number }> => {
    const res = await fetch(`${API_BASE}/tools/scan-all`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ target, target_id: targetId }),
    });
    return res.json();
  },
  scanCustom: async (
    target: string,
    modules: { tool_name: string; module_id: string; custom_args?: string }[],
    targetId?: number,
  ): Promise<{ success: boolean; data: ToolExecution[]; total: number; scan_id: number }> => {
    const res = await fetch(`${API_BASE}/tools/scan-custom`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ target, modules, target_id: targetId }),
    });
    return res.json();
  },
};

export const passiveScanApi = {
  startScan: async (request: any) => {
    const response = await fetch(`${API_BASE}/intel/passive`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(request),
    });
    return response.json();
  },

  getResults: async (domain: string) => {
    const response = await fetch(`${API_BASE}/intel/passive/${domain}`);
    return response.json();
  },
};
