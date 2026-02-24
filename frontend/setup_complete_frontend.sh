#!/bin/bash

echo "🌙 Building Complete Nightfall Tsukuyomi Frontend..."

# 1. Create API Service
cat > src/services/api.ts << 'APIEOF'
const API_BASE = 'http://localhost:8080/api/v1';

class ApiService {
  private getToken(): string {
    return localStorage.getItem('access_token') || '';
  }

  private async request(endpoint: string, options: RequestInit = {}) {
    const token = this.getToken();
    const headers = {
      'Content-Type': 'application/json',
      ...(token && { Authorization: `Bearer ${token}` }),
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

  // Auth
  async login(email: string, password: string) {
    return this.request('/auth/login', {
      method: 'POST',
      body: JSON.stringify({ email, password }),
    });
  }

  async register(email: string, password: string, full_name: string) {
    return this.request('/auth/register', {
      method: 'POST',
      body: JSON.stringify({ email, password, full_name }),
    });
  }

  async getMe() {
    return this.request('/auth/me');
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
APIEOF

# 2. Create Auth Pages
mkdir -p src/pages/auth

cat > src/pages/auth/LoginPage.tsx << 'LOGINEOF'
import { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { api } from '../../services/api';

export function LoginPage() {
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(false);
  const navigate = useNavigate();

  const handleLogin = async (e: React.FormEvent) => {
    e.preventDefault();
    setError('');
    setLoading(true);

    try {
      const data = await api.login(email, password);
      localStorage.setItem('access_token', data.data.access_token);
      localStorage.setItem('user', JSON.stringify(data.data.user));
      navigate('/dashboard');
    } catch (err: any) {
      setError(err.message || 'Login failed');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="min-h-screen flex items-center justify-center bg-gradient-to-br from-slate-900 via-purple-900/20 to-slate-900">
      <div className="w-full max-w-md p-8">
        <div className="text-center mb-8">
          <div className="text-6xl mb-4">🌙</div>
          <h1 className="text-4xl font-black text-transparent bg-clip-text bg-gradient-to-r from-cyan-400 to-purple-400 mb-2">
            NIGHTFALL TSUKUYOMI
          </h1>
          <p className="text-slate-400">Security Intelligence Platform</p>
        </div>

        <div className="bg-gradient-to-br from-slate-800/50 to-slate-900/50 rounded-2xl p-8 border border-purple-500/30 shadow-2xl">
          <h2 className="text-2xl font-bold text-white mb-6">Sign In</h2>

          {error && (
            <div className="mb-4 p-3 bg-red-500/10 border border-red-500 rounded text-red-400 text-sm">
              {error}
            </div>
          )}

          <form onSubmit={handleLogin} className="space-y-4">
            <input
              type="email"
              value={email}
              onChange={(e) => setEmail(e.target.value)}
              className="w-full px-4 py-3 bg-slate-900/50 border border-purple-500/30 rounded text-white placeholder-slate-500 focus:outline-none focus:border-purple-500"
              placeholder="Email"
              required
            />

            <input
              type="password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              className="w-full px-4 py-3 bg-slate-900/50 border border-purple-500/30 rounded text-white placeholder-slate-500 focus:outline-none focus:border-purple-500"
              placeholder="Password"
              required
            />

            <button
              type="submit"
              disabled={loading}
              className="w-full py-3 bg-gradient-to-r from-purple-600 to-cyan-600 hover:from-purple-700 hover:to-cyan-700 text-white font-bold rounded transition disabled:opacity-50"
            >
              {loading ? 'Signing in...' : 'Sign In'}
            </button>
          </form>

          <div className="mt-6 text-center">
            <button
              onClick={() => navigate('/register')}
              className="text-cyan-400 hover:text-cyan-300 text-sm"
            >
              Create an account
            </button>
          </div>

          <div className="mt-4 p-3 bg-slate-800/30 rounded border border-cyan-500/20">
            <div className="text-xs text-slate-500">Demo:</div>
            <div className="text-sm text-cyan-400 font-mono">test@nightfall.local / password123</div>
          </div>
        </div>
      </div>
    </div>
  );
}
LOGINEOF

cat > src/pages/auth/RegisterPage.tsx << 'REGEOF'
import { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { api } from '../../services/api';

export function RegisterPage() {
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [fullName, setFullName] = useState('');
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(false);
  const navigate = useNavigate();

  const handleRegister = async (e: React.FormEvent) => {
    e.preventDefault();
    setError('');
    setLoading(true);

    try {
      await api.register(email, password, fullName);
      alert('Registration successful! Please login.');
      navigate('/login');
    } catch (err: any) {
      setError(err.message || 'Registration failed');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="min-h-screen flex items-center justify-center bg-gradient-to-br from-slate-900 via-purple-900/20 to-slate-900">
      <div className="w-full max-w-md p-8">
        <div className="text-center mb-8">
          <div className="text-6xl mb-4">🌙</div>
          <h1 className="text-4xl font-black text-transparent bg-clip-text bg-gradient-to-r from-cyan-400 to-purple-400 mb-2">
            NIGHTFALL TSUKUYOMI
          </h1>
          <p className="text-slate-400">Create Your Account</p>
        </div>

        <div className="bg-gradient-to-br from-slate-800/50 to-slate-900/50 rounded-2xl p-8 border border-purple-500/30 shadow-2xl">
          <h2 className="text-2xl font-bold text-white mb-6">Register</h2>

          {error && (
            <div className="mb-4 p-3 bg-red-500/10 border border-red-500 rounded text-red-400 text-sm">
              {error}
            </div>
          )}

          <form onSubmit={handleRegister} className="space-y-4">
            <input
              type="text"
              value={fullName}
              onChange={(e) => setFullName(e.target.value)}
              className="w-full px-4 py-3 bg-slate-900/50 border border-purple-500/30 rounded text-white placeholder-slate-500 focus:outline-none focus:border-purple-500"
              placeholder="Full Name"
              required
            />

            <input
              type="email"
              value={email}
              onChange={(e) => setEmail(e.target.value)}
              className="w-full px-4 py-3 bg-slate-900/50 border border-purple-500/30 rounded text-white placeholder-slate-500 focus:outline-none focus:border-purple-500"
              placeholder="Email"
              required
            />

            <input
              type="password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              className="w-full px-4 py-3 bg-slate-900/50 border border-purple-500/30 rounded text-white placeholder-slate-500 focus:outline-none focus:border-purple-500"
              placeholder="Password (min 8 characters)"
              minLength={8}
              required
            />

            <button
              type="submit"
              disabled={loading}
              className="w-full py-3 bg-gradient-to-r from-purple-600 to-cyan-600 hover:from-purple-700 hover:to-cyan-700 text-white font-bold rounded transition disabled:opacity-50"
            >
              {loading ? 'Creating account...' : 'Create Account'}
            </button>
          </form>

          <div className="mt-6 text-center">
            <button
              onClick={() => navigate('/login')}
              className="text-cyan-400 hover:text-cyan-300 text-sm"
            >
              Already have an account? Sign in
            </button>
          </div>
        </div>
      </div>
    </div>
  );
}
REGEOF

# 3. Update Findings Page with API
cat > src/pages/findings/FindingsPage.tsx << 'FINDEOF'
import { useEffect, useState } from 'react';
import { api } from '../../services/api';

interface Finding {
  id: number;
  severity: string;
  category: string;
  finding: string;
  remediation: string;
  evidence: string;
  status: string;
  created_at: string;
}

interface Stats {
  total: number;
  critical: number;
  high: number;
  medium: number;
  low: number;
  info: number;
}

export function FindingsPage() {
  const [findings, setFindings] = useState<Finding[]>([]);
  const [stats, setStats] = useState<Stats | null>(null);
  const [loading, setLoading] = useState(true);
  const [filter, setFilter] = useState('');

  useEffect(() => {
    fetchData();
  }, [filter]);

  const fetchData = async () => {
    try {
      const [findingsData, statsData] = await Promise.all([
        api.listFindings(filter ? { severity: filter } : {}),
        api.getStats(),
      ]);
      setFindings(findingsData.data || []);
      setStats(statsData.data);
      setLoading(false);
    } catch (error) {
      console.error('Error fetching findings:', error);
      setLoading(false);
    }
  };

  const getSeverityColor = (severity: string) => {
    const colors: Record<string, string> = {
      Critical: 'from-red-500 to-red-600',
      High: 'from-orange-500 to-orange-600',
      Medium: 'from-yellow-500 to-yellow-600',
      Low: 'from-green-500 to-green-600',
      Info: 'from-blue-500 to-blue-600',
    };
    return colors[severity] || 'from-gray-500 to-gray-600';
  };

  if (loading) {
    return (
      <div className="flex items-center justify-center h-full">
        <div className="text-2xl text-cyan-400">Loading findings...</div>
      </div>
    );
  }

  return (
    <div>
      <h1 className="text-4xl font-black text-transparent bg-clip-text bg-gradient-to-r from-cyan-400 to-purple-400 mb-2">
        🔍 Security Findings
      </h1>
      <p className="text-slate-400 mb-8">
        Comprehensive vulnerability analysis - {stats?.total || 0} total findings
      </p>

      {/* Stats Dashboard */}
      {stats && (
        <div className="grid grid-cols-5 gap-4 mb-8">
          {['Critical', 'High', 'Medium', 'Low', 'Info'].map((severity) => (
            <div
              key={severity}
              onClick={() => setFilter(filter === severity ? '' : severity)}
              className={`bg-gradient-to-br from-${severity.toLowerCase()}-900/50 to-${severity.toLowerCase()}-800/30 p-6 rounded-xl border cursor-pointer hover:border-${severity.toLowerCase()}-500 transition ${
                filter === severity ? 'border-' + severity.toLowerCase() + '-500' : 'border-' + severity.toLowerCase() + '-500/30'
              }`}
            >
              <div className={`text-3xl font-bold text-${severity.toLowerCase()}-400`}>
                {stats[severity.toLowerCase() as keyof Stats]}
              </div>
              <div className={`text-${severity.toLowerCase()}-300`}>{severity}</div>
            </div>
          ))}
        </div>
      )}

      {filter && (
        <button
          onClick={() => setFilter('')}
          className="mb-4 px-4 py-2 bg-purple-600 hover:bg-purple-700 rounded"
        >
          Clear Filter
        </button>
      )}

      {/* Findings List */}
      <div className="space-y-4">
        {findings.map((finding) => (
          <div
            key={finding.id}
            className="bg-gradient-to-br from-slate-800/50 to-slate-900/50 rounded-xl p-6 border border-purple-500/20 hover:border-purple-500/50 transition"
          >
            <div className="flex items-start justify-between mb-4">
              <div className="flex items-center gap-3">
                <span className={`px-3 py-1 rounded text-sm font-bold bg-gradient-to-r ${getSeverityColor(finding.severity)} text-white`}>
                  {finding.severity}
                </span>
                <span className="text-cyan-400 font-semibold">{finding.category}</span>
              </div>
              <span className="text-xs text-slate-500">
                {new Date(finding.created_at).toLocaleDateString()}
              </span>
            </div>

            <h3 className="text-xl font-bold text-white mb-2">{finding.finding}</h3>

            <div className="mb-3">
              <div className="text-sm text-slate-400 mb-1">Remediation:</div>
              <div className="text-slate-300">{finding.remediation}</div>
            </div>

            {finding.evidence && (
              <div className="mt-3 p-3 bg-black/30 rounded border-l-4 border-cyan-500">
                <div className="text-xs text-slate-500 mb-1">Evidence:</div>
                <div className="text-sm text-slate-400">{finding.evidence}</div>
              </div>
            )}
          </div>
        ))}
      </div>

      {findings.length === 0 && (
        <div className="text-center py-12 text-slate-400">No findings found</div>
      )}
    </div>
  );
}
FINDEOF

# 4. Create Complete App.tsx with all routes
cat > src/App.tsx << 'APPEOF'
import { BrowserRouter as Router, Routes, Route, Navigate } from 'react-router-dom';
import { Layout } from './components/layout/Layout';
import { LoginPage } from './pages/auth/LoginPage';
import { RegisterPage } from './pages/auth/RegisterPage';
import UnifiedScan from './pages/UnifiedScan';
import Dashboard from './pages/Dashboard';
import { FindingsPage } from './pages/findings/FindingsPage';
import { PassiveIntelPage } from './pages/passive-intel/PassiveIntelPage';
import { ActiveScansPage } from './pages/active-scans/ActiveScansPage';
import { CvePage } from './pages/cve/CvePage';
import { OwaspPage } from './pages/owasp/OwaspPage';
import './App.css';

function ProtectedRoute({ children }: { children: React.ReactNode }) {
  const token = localStorage.getItem('access_token');
  return token ? <>{children}</> : <Navigate to="/login" replace />;
}

function App() {
  return (
    <Router>
      <Routes>
        {/* Public Routes */}
        <Route path="/login" element={<LoginPage />} />
        <Route path="/register" element={<RegisterPage />} />

        {/* Protected Routes with Layout */}
        <Route
          path="/*"
          element={
            <ProtectedRoute>
              <Layout>
                <Routes>
                  <Route path="/" element={<Dashboard />} />
                  <Route path="/dashboard" element={<Dashboard />} />
                  <Route path="/scan" element={<UnifiedScan />} />
                  <Route path="/findings" element={<FindingsPage />} />
                  <Route path="/passive-intel" element={<PassiveIntelPage />} />
                  <Route path="/active-scans" element={<ActiveScansPage />} />
                  <Route path="/cve" element={<CvePage />} />
                  <Route path="/owasp" element={<OwaspPage />} />
                </Routes>
              </Layout>
            </ProtectedRoute>
          }
        />
      </Routes>
    </Router>
  );
}

export default App;
APPEOF

echo "✅ Complete frontend structure created!"
echo "📁 Files created:"
echo "  - src/services/api.ts (Centralized API service)"
echo "  - src/pages/auth/LoginPage.tsx"
echo "  - src/pages/auth/RegisterPage.tsx"
echo "  - src/pages/findings/FindingsPage.tsx (with API integration)"
echo "  - src/App.tsx (Complete routing)"
