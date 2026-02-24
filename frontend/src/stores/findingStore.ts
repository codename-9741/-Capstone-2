import { create } from 'zustand';

interface Finding {
  id: number;
  severity: string;
  category: string;
  finding: string;
  remediation: string;
  status: string;
  created_at: string;
}

interface FindingStore {
  findings: Finding[];
  isLoading: boolean;
  filters: {
    severity?: string;
    status?: string;
    page: number;
  };
  fetchFindings: () => Promise<void>;
  setFilters: (filters: any) => void;
}

export const useFindingStore = create<FindingStore>((set, get) => ({
  findings: [],
  isLoading: false,
  filters: { page: 1 },

  fetchFindings: async () => {
    set({ isLoading: true });
    const { filters } = get();

    const params = new URLSearchParams();
    if (filters.severity) params.append('severity', filters.severity);
    if (filters.status) params.append('status', filters.status);
    params.append('page', filters.page.toString());

    try {
      const response = await fetch(`/api/findings?${params}`);
      const data = await response.json();
      set({ findings: data.data || [], isLoading: false });
    } catch (error) {
      console.error('Error fetching findings:', error);
      set({ isLoading: false });
    }
  },

  setFilters: (newFilters) => {
    set((state) => ({ filters: { ...state.filters, ...newFilters } }));
  },
}));
