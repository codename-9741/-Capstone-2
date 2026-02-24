import { useState } from 'react';

export function LoginPage() {
  const [email, setEmail] = useState('test@nightfall.local');
  const [password, setPassword] = useState('password123');
  const [error, setError] = useState('');

  const handleLogin = async (e: React.FormEvent) => {
    e.preventDefault();
    setError('');

    try {
      const response = await fetch('/api/auth/login', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ email, password }),
      });

      const data = await response.json();

      if (data.data && data.data.access_token) {
        localStorage.setItem('token', data.data.access_token);
        localStorage.setItem('user', JSON.stringify(data.data.user));
        window.location.href = '/';
      } else {
        setError('Login failed');
      }
    } catch (err) {
      setError('Connection failed');
    }
  };

  return (
    <div className="min-h-screen bg-gradient-to-br from-slate-900 via-purple-900/20 to-slate-900 flex items-center justify-center">
      <div className="bg-slate-800 p-8 rounded-xl border border-purple-500/30 w-full max-w-md">
        <h1 className="text-3xl font-bold text-white mb-2">🌙 Nightfall</h1>
        <p className="text-slate-400 mb-6">Security Platform</p>

        {error && (
          <div className="bg-red-500/20 border border-red-500 text-red-300 px-4 py-2 rounded mb-4">
            {error}
          </div>
        )}

        <form onSubmit={handleLogin} className="space-y-4">
          <div>
            <label className="block text-sm text-slate-300 mb-2">Email</label>
            <input
              type="email"
              value={email}
              onChange={(e) => setEmail(e.target.value)}
              className="w-full px-4 py-3 bg-slate-900 border border-slate-700 rounded text-white"
              required
            />
          </div>

          <div>
            <label className="block text-sm text-slate-300 mb-2">Password</label>
            <input
              type="password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              className="w-full px-4 py-3 bg-slate-900 border border-slate-700 rounded text-white"
              required
            />
          </div>

          <button
            type="submit"
            className="w-full bg-purple-600 hover:bg-purple-700 text-white py-3 rounded font-bold"
          >
            Login
          </button>
        </form>

        <p className="text-xs text-slate-500 mt-4">
          Demo: test@nightfall.local / password123
        </p>
      </div>
    </div>
  );
}
