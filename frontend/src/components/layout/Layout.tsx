import { Sidebar } from './Sidebar';
import { TopBar } from './TopBar';

interface LayoutProps {
  children: React.ReactNode;
}

export function Layout({ children }: LayoutProps) {
  return (
    <div className="flex min-h-screen bg-slate-50 dark:bg-slate-950">
      <Sidebar />
      <div className="flex flex-1 flex-col overflow-hidden pl-16">
        <TopBar />
        <main className="flex-1 overflow-y-auto bg-slate-50 p-6 dark:bg-slate-950">
          {children}
        </main>
      </div>
    </div>
  );
}
