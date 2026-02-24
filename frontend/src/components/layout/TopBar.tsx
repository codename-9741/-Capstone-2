import { Moon, Sun, Settings, User } from 'lucide-react';
import { useNavigate } from 'react-router-dom';
import { useTheme } from '../../hooks/useTheme';

export const TopBar = () => {
  const navigate = useNavigate();
  const { dark, toggle } = useTheme();

  return (
    <div className="flex h-14 items-center justify-between border-b border-slate-200 bg-white px-6 dark:border-slate-800 dark:bg-slate-950">
      <p className="text-xs font-medium uppercase tracking-widest text-slate-400">
        Security Intelligence Platform
      </p>
      <div className="flex items-center gap-3">
        <button
          onClick={toggle}
          className="flex h-8 w-8 items-center justify-center rounded-lg text-slate-400 hover:bg-slate-100 hover:text-slate-600 transition-colors dark:hover:bg-slate-800 dark:hover:text-slate-300"
          title={dark ? 'Light mode' : 'Dark mode'}
        >
          {dark ? <Sun className="h-4 w-4" /> : <Moon className="h-4 w-4" />}
        </button>
        <button
          onClick={() => navigate('/settings')}
          className="flex h-8 w-8 items-center justify-center rounded-lg text-slate-400 hover:bg-slate-100 hover:text-slate-600 transition-colors dark:hover:bg-slate-800 dark:hover:text-slate-300"
        >
          <Settings className="h-4 w-4" />
        </button>
        <div className="ml-2 flex items-center gap-2 border-l border-slate-200 pl-4 dark:border-slate-800">
          <div className="text-right">
            <div className="text-sm font-semibold text-slate-900 dark:text-white">Nightfall</div>
            <div className="text-[10px] text-slate-400">Analyst</div>
          </div>
          <div className="flex h-8 w-8 items-center justify-center rounded-lg bg-brand-600 text-white">
            <User className="h-4 w-4" />
          </div>
        </div>
      </div>
    </div>
  );
};
