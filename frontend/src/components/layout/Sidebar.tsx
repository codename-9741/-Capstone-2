import { useNavigate, useLocation } from 'react-router-dom';
import {
  LayoutDashboard,
  Radar,
  AlertTriangle,
  Wrench,
  Shield,
  FileText,
  Settings,
  Crosshair,
  Target,
  Bug,
  Link,
  Activity,
} from 'lucide-react';

const navItems = [
  { path: '/', icon: LayoutDashboard, label: 'Dashboard' },
  { path: '/scan', icon: Radar, label: 'Discover' },
  { path: '/findings', icon: AlertTriangle, label: 'Findings' },
  { path: '/tools', icon: Wrench, label: 'Tools' },
  { path: '/passive-intel', icon: Shield, label: 'Tech Stack' },
  { path: '/mitre', icon: Target, label: 'MITRE' },
  { path: '/owasp', icon: Bug, label: 'OWASP' },
  { path: '/killchain', icon: Link, label: 'Kill Chain' },
  { path: '/cve', icon: Activity, label: 'CVE' },
  { path: '/breach', icon: Crosshair, label: 'Breach Sim' },
  { path: '/reports', icon: FileText, label: 'Reports' },
  { path: '/settings', icon: Settings, label: 'Settings' },
];

export const Sidebar = () => {
  const navigate = useNavigate();
  const location = useLocation();

  const isActive = (path: string) => location.pathname === path;

  return (
    <div className="fixed inset-y-0 left-0 z-50 flex h-screen w-16 flex-col items-center border-r border-slate-200 bg-white py-4 dark:border-slate-800 dark:bg-slate-950">
      {/* Logo */}
      <div className="mb-4 flex h-14 w-14 items-center justify-center rounded-2xl overflow-hidden ring-2 ring-brand-500/30 shadow-lg shadow-brand-500/20">
        <img src="/logo.png" alt="Nightfall" className="h-full w-full object-cover" />
      </div>

      {/* Nav */}
      <nav className="flex flex-1 flex-col items-center gap-1 overflow-y-auto">
        {navItems.map((item) => {
          const Icon = item.icon;
          const active = isActive(item.path);
          return (
            <button
              key={item.path}
              title={item.label}
              onClick={() => navigate(item.path)}
              className={`group relative flex h-10 w-10 items-center justify-center rounded-lg transition-colors ${
                active
                  ? 'bg-brand-50 text-brand-600 dark:bg-brand-900/30 dark:text-brand-400'
                  : 'text-slate-400 hover:bg-slate-100 hover:text-slate-600 dark:hover:bg-slate-800 dark:hover:text-slate-300'
              }`}
            >
              <Icon className="h-5 w-5" strokeWidth={active ? 2.2 : 1.8} />
              <span className="pointer-events-none absolute left-14 z-50 whitespace-nowrap rounded-md bg-slate-900 px-2 py-1 text-xs font-medium text-white opacity-0 shadow-lg transition-opacity group-hover:opacity-100 dark:bg-slate-700">
                {item.label}
              </span>
            </button>
          );
        })}
      </nav>

      {/* Status dot */}
      <div className="flex flex-col items-center gap-1 text-[10px] text-slate-400">
        <div className="h-2 w-2 rounded-full bg-emerald-500" />
      </div>
    </div>
  );
};
