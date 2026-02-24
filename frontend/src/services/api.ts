const API_BASE = '/api';

class ApiService {
  private async request(endpoint: string, options: RequestInit = {}) {
    const headers = {
      'Content-Type': 'application/json',
      ...options.headers,
    };

    try {
      const response = await fetch(`${API_BASE}${endpoint}`, {
        ...options,
        headers,
      });
      const data = await response.json();

      if (!response.ok) {
        throw new Error(data.error || 'API request failed');
      }

      return data;
    } catch (error) {
      console.error('API Error:', error);
      throw error;
    }
  }

  // Targets
  async createTarget(domain: string, display_name: string) {
    return this.request('/targets', {
      method: 'POST',
      body: JSON.stringify({ domain, display_name }),
    });
  }

  async listTargets() {
    return this.request('/targets');
  }

  async getTarget(id: number) {
    return this.request(`/targets/${id}`);
  }

  async deleteTarget(id: number) {
    return this.request(`/targets/${id}`, { method: 'DELETE' });
  }

  // Scans
  async createScan(target_id: number, scan_type: string) {
    return this.request('/scans', {
      method: 'POST',
      body: JSON.stringify({ target_id, scan_type }),
    });
  }

  async listScans() {
    return this.request('/scans');
  }

  async getScan(id: number) {
    return this.request(`/scans/${id}`);
  }

  // Findings
  async listFindings(params?: Record<string, string>) {
    const query = params ? '?' + new URLSearchParams(params).toString() : '';
    return this.request(`/findings${query}`);
  }

  async getFinding(id: number) {
    return this.request(`/findings/${id}`);
  }

  async updateFinding(id: number, updates: any) {
    return this.request(`/findings/${id}`, {
      method: 'PUT',
      body: JSON.stringify(updates),
    });
  }

  async getStats() {
    return this.request('/findings/stats');
  }
}

export const api = new ApiService();
