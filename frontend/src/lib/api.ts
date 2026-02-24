import axios from 'axios';

const API_BASE_URL = '/api';

export const api = axios.create({
  baseURL: API_BASE_URL,
  headers: {
    'Content-Type': 'application/json',
  },
});

// API functions
export const scanAPI = {
  list: () => api.get('/scans'),
  get: (id: string) => api.get(`/scans/${id}`),
  create: (data: { domain: string }) => api.post('/scans', data),
};

export const targetAPI = {
  list: () => api.get('/targets'),
  create: (data: { domain: string }) => api.post('/targets', data),
};
