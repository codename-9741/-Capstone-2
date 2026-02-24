import requests
import json
from typing import Dict, Any, List

API_BASE_URL = "http://localhost:8888/api/v1"

class NightfallAPI:
    def __init__(self, base_url: str = API_BASE_URL):
        self.base_url = base_url
        self.session = requests.Session()
        self.session.headers.update({
            'Content-Type': 'application/json'
        })
    
    def create_target(self, domain: str) -> Dict[str, Any]:
        """Create a new target"""
        try:
            response = self.session.post(
                f"{self.base_url}/targets",
                json={"domain": domain}
            )
            return response.json()
        except Exception as e:
            print(f"Failed to create target: {e}")
            return {}
    
    def create_scan(self, domain: str) -> Dict[str, Any]:
        """Create a new scan"""
        try:
            response = self.session.post(
                f"{self.base_url}/scans",
                json={"domain": domain}
            )
            return response.json()
        except Exception as e:
            print(f"Failed to create scan: {e}")
            return {}
    
    def update_scan_status(self, scan_id: int, status: str, risk_score: int = 0):
        """Update scan status and risk score"""
        try:
            response = self.session.put(
                f"{self.base_url}/scans/{scan_id}/status",
                json={"status": status, "risk_score": risk_score}
            )
            return response.json()
        except Exception as e:
            print(f"Failed to update scan: {e}")
            return {}
    
    def send_finding(self, scan_id: int, finding: Dict[str, Any]):
        """Send a finding to the API"""
        try:
            payload = {
                "scan_id": scan_id,
                "severity": finding.get("severity", "Info"),
                "category": finding.get("category", "Unknown"),
                "finding": finding.get("finding", ""),
                "remediation": finding.get("remediation", ""),
                "evidence": finding.get("evidence", "")
            }
            response = self.session.post(
                f"{self.base_url}/findings",
                json=payload
            )
            return response.json()
        except Exception as e:
            print(f"Failed to send finding: {e}")
            return {}
    
    def get_scan_findings(self, scan_id: int) -> List[Dict[str, Any]]:
        """Get all findings for a scan"""
        try:
            response = self.session.get(f"{self.base_url}/scans/{scan_id}/findings")
            return response.json().get('findings', [])
        except Exception as e:
            print(f"Failed to get findings: {e}")
            return []

# Global API client
api = NightfallAPI()
