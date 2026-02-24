import { useState } from 'react';
import { useMutation, useQueryClient } from '@tanstack/react-query';
import { motion, AnimatePresence } from 'framer-motion';
import { PlayCircle, X } from 'lucide-react';
import { API_URL } from '../config';

export function ScanButton() {
  const [domain, setDomain] = useState('');
  const [isOpen, setIsOpen] = useState(false);
  const queryClient = useQueryClient();

  const createScan = useMutation({
    mutationFn: async (domain: string) => {
      const res = await fetch(`${API_URL}/api/v1/scans`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ domain }),
      });
      return res.json();
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['scans'] });
      setDomain('');
      setIsOpen(false);
    },
  });

  return (
    <>
      <button
        onClick={() => setIsOpen(true)}
        className="flex items-center gap-2 px-4 py-2 bg-indigo-600 hover:bg-indigo-500 text-white rounded font-semibold transition-colors"
      >
        <PlayCircle className="w-4 h-4" strokeWidth={2} />
        New Scan
      </button>

      <AnimatePresence>
        {isOpen && (
          <>
            {/* Backdrop */}
            <motion.div
              initial={{ opacity: 0 }}
              animate={{ opacity: 1 }}
              exit={{ opacity: 0 }}
              onClick={() => setIsOpen(false)}
              className="fixed inset-0 bg-black/50 backdrop-blur-sm z-50"
            />

            {/* Modal */}
            <motion.div
              initial={{ opacity: 0, scale: 0.95, y: 20 }}
              animate={{ opacity: 1, scale: 1, y: 0 }}
              exit={{ opacity: 0, scale: 0.95, y: 20 }}
              className="fixed left-1/2 top-1/2 -translate-x-1/2 -translate-y-1/2 w-[480px] bg-[#1a1d29] rounded-lg border border-[#2a2d3a] shadow-2xl z-50"
            >
              {/* Header */}
              <div className="flex items-center justify-between p-6 border-b border-[#2a2d3a]">
                <h3 className="text-lg font-semibold text-white">Start New Scan</h3>
                <button
                  onClick={() => setIsOpen(false)}
                  className="p-1 hover:bg-[#252836] rounded transition-colors"
                >
                  <X className="w-5 h-5 text-slate-500" />
                </button>
              </div>

              {/* Body */}
              <div className="p-6">
                <label className="block text-sm font-medium text-slate-400 mb-2">
                  Target Domain
                </label>
                <input
                  type="text"
                  value={domain}
                  onChange={(e) => setDomain(e.target.value)}
                  placeholder="example.com"
                  className="w-full px-4 py-2.5 bg-[#252836] border border-[#2a2d3a] rounded text-white placeholder-slate-600 focus:border-indigo-500 focus:outline-none transition-colors"
                  onKeyPress={(e) => e.key === 'Enter' && domain && createScan.mutate(domain)}
                  autoFocus
                />
                <p className="text-xs text-slate-600 mt-2">
                  Enter a domain without protocol (e.g., example.com)
                </p>
              </div>

              {/* Footer */}
              <div className="flex gap-2 p-6 border-t border-[#2a2d3a]">
                <button
                  onClick={() => setIsOpen(false)}
                  className="flex-1 px-4 py-2 bg-[#252836] hover:bg-[#2a2d3a] text-slate-300 rounded font-medium transition-colors"
                >
                  Cancel
                </button>
                <button
                  onClick={() => domain && createScan.mutate(domain)}
                  disabled={!domain || createScan.isPending}
                  className="flex-1 px-4 py-2 bg-indigo-600 hover:bg-indigo-500 text-white rounded font-semibold transition-colors disabled:opacity-50 disabled:cursor-not-allowed"
                >
                  {createScan.isPending ? 'Starting...' : 'Start Scan'}
                </button>
              </div>
            </motion.div>
          </>
        )}
      </AnimatePresence>
    </>
  );
}
