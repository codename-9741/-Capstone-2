const API_BASE = '/api';

const apiClient = {
  get: async (endpoint: string) => {
    const response = await fetch(`${API_BASE}${endpoint}`);
    return response.json();
  },
  
  post: async (endpoint: string, data: any) => {
    const response = await fetch(`${API_BASE}${endpoint}`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(data),
    });
    return response.json();
  },

  listScans: async () => {
    const response = await fetch(`${API_BASE}/scans`);
    return response.json();
  },
};

export default apiClient;
