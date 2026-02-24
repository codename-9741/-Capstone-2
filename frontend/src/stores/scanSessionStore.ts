import { create } from 'zustand';
import { persist } from 'zustand/middleware';

export type ScanMode = 'safe' | 'normal' | 'aggressive';
export type ScanType = 'active' | 'passive' | 'both';

export interface ScanFinding {
  severity: string;
  category: string;
  finding: string;
  remediation?: string;
  outcome?: string;
  http_method?: string;
  confidence?: string;
  evidence?: string;
  score?: number;
  occurrences?: number;
}

export interface ScanData {
  id?: number;
  status?: string;
  risk_score?: number;
  risk_grade?: string;
  findings?: ScanFinding[];
  enabled_modules?: number;
  attempted_modules?: number;
  completed_modules?: number;
  errored_modules?: number;
  total_requests?: number;
  successful_requests?: number;
  errored_requests?: number;
}

interface ScanSessionState {
  domain: string;
  scanMode: ScanMode;
  scanType: ScanType;
  isScanning: boolean;

  activeScanId: number | null;
  passiveScanStarted: boolean;
  passiveScanStartedAt: number | null;
  passiveScanCompleted: boolean;

  scanData: ScanData | null;
  findings: ScanFinding[];

  activeLogs: string[];
  passiveLogs: string[];

  setDomain: (domain: string) => void;
  setScanMode: (mode: ScanMode) => void;
  setScanType: (type: ScanType) => void;
  setIsScanning: (v: boolean) => void;

  setActiveScanId: (id: number | null) => void;
  setPassiveScanStarted: (v: boolean) => void;
  setPassiveScanStartedAt: (ts: number | null) => void;
  setPassiveScanCompleted: (v: boolean) => void;

  setScanData: (data: ScanData | null) => void;
  setFindings: (findings: ScanFinding[]) => void;

  setActiveLogs: (logs: string[]) => void;
  setPassiveLogs: (logs: string[]) => void;
  pushActiveLog: (log: string) => void;
  pushPassiveLog: (log: string) => void;

  resetSession: () => void;
}

const initialState = {
  domain: '',
  scanMode: 'safe' as ScanMode,
  scanType: 'both' as ScanType,
  isScanning: false,
  activeScanId: null as number | null,
  passiveScanStarted: false,
  passiveScanStartedAt: null as number | null,
  passiveScanCompleted: false,
  scanData: null as ScanData | null,
  findings: [] as ScanFinding[],
  activeLogs: [] as string[],
  passiveLogs: [] as string[],
};

export const useScanSessionStore = create<ScanSessionState>()(
  persist(
    (set) => ({
      ...initialState,

      setDomain: (domain) => set({ domain }),
      setScanMode: (scanMode) => set({ scanMode }),
      setScanType: (scanType) => set({ scanType }),
      setIsScanning: (isScanning) => set({ isScanning }),

      setActiveScanId: (activeScanId) => set({ activeScanId }),
      setPassiveScanStarted: (passiveScanStarted) => set({ passiveScanStarted }),
      setPassiveScanStartedAt: (passiveScanStartedAt) => set({ passiveScanStartedAt }),
      setPassiveScanCompleted: (passiveScanCompleted) => set({ passiveScanCompleted }),

      setScanData: (scanData) => set({ scanData }),
      setFindings: (findings) => set({ findings }),

      setActiveLogs: (activeLogs) => set({ activeLogs }),
      setPassiveLogs: (passiveLogs) => set({ passiveLogs }),
      pushActiveLog: (log) => set((s) => ({ activeLogs: [...s.activeLogs, log] })),
      pushPassiveLog: (log) => set((s) => ({ passiveLogs: [...s.passiveLogs, log] })),

      resetSession: () =>
        set({
          isScanning: false,
          activeScanId: null,
          passiveScanStarted: false,
          passiveScanStartedAt: null,
          passiveScanCompleted: false,
          scanData: null,
          findings: [],
          activeLogs: [],
          passiveLogs: [],
        }),
    }),
    {
      name: 'nightfall.scanSession.v1',
      version: 1,
    }
  )
);

