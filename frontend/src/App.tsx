import { BrowserRouter, Routes, Route, Navigate } from 'react-router-dom';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { Layout } from './components/layout/Layout';
import { Dashboard } from './pages/Dashboard';
import { FindingsPage } from './pages/findings/FindingsPage';
import { PassiveIntelPage } from './pages/passive-intel';
import { ToolResultsPage } from './pages/tools/ToolResultsPage';
import { MitrePage } from './pages/mitre/MitrePage';
import { OwaspPage } from './pages/owasp/OwaspPage';
import { KillChainPage } from './pages/killchain/KillChainPage';
import { CvePage } from './pages/cve/CvePage';
import { BreachSimulationPage } from './pages/breach/BreachSimulationPage';
import { ReportsPage } from './pages/reports/ReportsPage';
import { SettingsPage } from './pages/settings/SettingsPage';
import UnifiedScan from './pages/UnifiedScan';

const queryClient = new QueryClient();

function App() {
  return (
    <QueryClientProvider client={queryClient}>
      <BrowserRouter>
        <Routes>
          <Route path="/" element={<Layout><Dashboard /></Layout>} />
          <Route path="/scan" element={<Layout><UnifiedScan /></Layout>} />
          <Route path="/findings" element={<Layout><FindingsPage /></Layout>} />
          <Route path="/tools" element={<Layout><ToolResultsPage /></Layout>} />
          <Route path="/passive-intel" element={<Layout><PassiveIntelPage /></Layout>} />
          <Route path="/mitre" element={<Layout><MitrePage /></Layout>} />
          <Route path="/owasp" element={<Layout><OwaspPage /></Layout>} />
          <Route path="/killchain" element={<Layout><KillChainPage /></Layout>} />
          <Route path="/cve" element={<Layout><CvePage /></Layout>} />
          <Route path="/breach" element={<Layout><BreachSimulationPage /></Layout>} />
          <Route path="/reports" element={<Layout><ReportsPage /></Layout>} />
          <Route path="/settings" element={<Layout><SettingsPage /></Layout>} />
          <Route path="*" element={<Navigate to="/" replace />} />
        </Routes>
      </BrowserRouter>
    </QueryClientProvider>
  );
}

export default App;
