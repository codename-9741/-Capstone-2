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
