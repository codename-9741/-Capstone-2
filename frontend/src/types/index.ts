export interface Target {
  id: number;
  domain: string;
  created_at: string;
  last_scanned_at: string | null;
}

export interface Scan {
  id: number;
  target_id: number;
  status: string;
  risk_score: number;
  started_at: string;
  completed_at: string | null;
}

export interface Finding {
  id: number;
  scan_id: number;
  severity: string;
  category: string;
  finding: string;
  remediation: string;
  evidence: string;
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
