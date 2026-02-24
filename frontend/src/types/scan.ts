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

  // Enrichment fields
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

export interface Scan {
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
}

export interface ToolStatus {
  name: string;
  installed: boolean;
  version: string;
  path: string;
}
