import { useQuery } from '@tanstack/react-query';
import { motion } from 'framer-motion';
import { Activity, Clock, CheckCircle, XCircle } from 'lucide-react';
import { API_URL } from '../../config';

interface Scan {
  id: number;
  target_id: number;
  status: string;
  risk_score: number;
  started_at: string;
  completed_at: string | null;
}

export function ActiveScansPage() {
  const { data: scansData } = useQuery({
    queryKey: ['scans'],
    queryFn: async () => {
      const res = await fetch(`${API_URL}/api/v1/scans`);
      return res.json();
    },
    refetchInterval: 2000,
  });

  const { data: targetsData } = useQuery({
    queryKey: ['targets'],
    queryFn: async () => {
      const res = await fetch(`${API_URL}/api/v1/targets`);
      return res.json();
    },
  });

  const scans: Scan[] = scansData?.scans || [];
  const targets = targetsData?.targets || [];
  
  const activeScans = scans.filter(s => 
    s.status === 'running' || s.status === 'passive_recon'
  );

  const getTargetDomain = (targetId: number) => {
    const target = targets.find((t: any) => t.id === targetId);
    return target?.domain || 'Unknown';
  };

  const getStatusIcon = (status: string) => {
    if (status === 'completed') return <CheckCircle className="w-4 h-4" />;
    if (status === 'running' || status === 'passive_recon') return <Activity className="w-4 h-4" />;
    if (status === 'failed') return <XCircle className="w-4 h-4" />;
    return <Clock className="w-4 h-4" />;
  };

  const getStatusColor = (status: string) => {
    if (status === 'completed') return 'text-green-500 bg-green-500/10 border-green-500/20';
    if (status === 'running' || status === 'passive_recon') return 'text-yellow-500 bg-yellow-500/10 border-yellow-500/20';
    if (status === 'failed') return 'text-red-500 bg-red-500/10 border-red-500/20';
    return 'text-slate-500 bg-slate-500/10 border-slate-500/20';
  };

  return (
    <div className="p-8">
      {/* Header */}
      <div className="mb-8">
        <div className="flex items-center gap-3 mb-2">
          <Activity className="w-8 h-8 text-indigo-500" strokeWidth={2} />
          <h1 className="text-2xl font-bold text-white">Active Scans</h1>
        </div>
        <p className="text-sm text-slate-500">Real-time scan monitoring and progress tracking</p>
      </div>

      {/* Running Scans */}
      {activeScans.length > 0 && (
        <div className="mb-8">
          <div className="flex items-center gap-2 mb-4">
            <Activity className="w-5 h-5 text-green-500" />
            <h2 className="text-lg font-semibold text-white">
              Running Now ({activeScans.length})
            </h2>
          </div>
          
          <div className="grid gap-4">
            {activeScans.map((scan) => (
              <motion.div
                key={scan.id}
                initial={{ opacity: 0, y: 20 }}
                animate={{ opacity: 1, y: 0 }}
                className="bg-[#1a1d29] rounded-lg p-6 border border-[#2a2d3a]"
              >
                <div className="flex items-center justify-between mb-4">
                  <div>
                    <div className="text-base font-semibold text-white mb-1">
                      Scan #{scan.id} · {getTargetDomain(scan.target_id)}
                    </div>
                    <div className="text-xs text-slate-500">
                      Started {new Date(scan.started_at).toLocaleString()}
                    </div>
                  </div>
                  <div className={`flex items-center gap-2 px-3 py-1.5 rounded border text-sm font-medium ${getStatusColor(scan.status)}`}>
                    {getStatusIcon(scan.status)}
                    {scan.status === 'passive_recon' ? 'Passive Recon' : 'Active Scan'}
                  </div>
                </div>

                {/* Progress Bar */}
                <div className="mb-4">
                  <div className="flex justify-between text-xs text-slate-500 mb-2">
                    <span>Progress</span>
                    <span>{scan.status === 'passive_recon' ? '30%' : '80%'}</span>
                  </div>
                  <div className="h-1.5 bg-[#252836] rounded-full overflow-hidden">
                    <motion.div
                      initial={{ width: 0 }}
                      animate={{ width: scan.status === 'passive_recon' ? '30%' : '80%' }}
                      className="h-full bg-gradient-to-r from-indigo-500 to-purple-600"
                      transition={{ duration: 0.5 }}
                    />
                  </div>
                </div>

                {/* Phases */}
                <div className="grid grid-cols-3 gap-2">
                  <div className={`px-3 py-2 rounded text-center text-xs font-medium border ${
                    scan.status === 'passive_recon' || scan.status === 'running' || scan.status === 'completed'
                      ? 'bg-green-500/10 border-green-500/20 text-green-500'
                      : 'bg-[#252836] border-[#2a2d3a] text-slate-600'
                  }`}>
                    Passive Recon {(scan.status === 'running' || scan.status === 'completed') && '✓'}
                  </div>
                  <div className={`px-3 py-2 rounded text-center text-xs font-medium border ${
                    scan.status === 'running' || scan.status === 'completed'
                      ? 'bg-yellow-500/10 border-yellow-500/20 text-yellow-500'
                      : 'bg-[#252836] border-[#2a2d3a] text-slate-600'
                  }`}>
                    Active Scan {scan.status === 'completed' && '✓'}
                  </div>
                  <div className={`px-3 py-2 rounded text-center text-xs font-medium border ${
                    scan.status === 'completed'
                      ? 'bg-green-500/10 border-green-500/20 text-green-500'
                      : 'bg-[#252836] border-[#2a2d3a] text-slate-600'
                  }`}>
                    Analysis {scan.status === 'completed' && '✓'}
                  </div>
                </div>
              </motion.div>
            ))}
          </div>
        </div>
      )}

      {/* All Scans Table */}
      <div>
        <div className="flex items-center gap-2 mb-4">
          <Clock className="w-5 h-5 text-slate-500" />
          <h2 className="text-lg font-semibold text-white">
            All Scans ({scans.length})
          </h2>
        </div>
        
        <div className="bg-[#1a1d29] rounded-lg border border-[#2a2d3a] overflow-hidden">
          <table className="w-full">
            <thead className="bg-[#252836] border-b border-[#2a2d3a]">
              <tr>
                <th className="px-4 py-3 text-left text-[10px] font-semibold text-slate-500 uppercase tracking-wider">
                  ID
                </th>
                <th className="px-4 py-3 text-left text-[10px] font-semibold text-slate-500 uppercase tracking-wider">
                  Target
                </th>
                <th className="px-4 py-3 text-left text-[10px] font-semibold text-slate-500 uppercase tracking-wider">
                  Status
                </th>
                <th className="px-4 py-3 text-left text-[10px] font-semibold text-slate-500 uppercase tracking-wider">
                  Risk Score
                </th>
                <th className="px-4 py-3 text-left text-[10px] font-semibold text-slate-500 uppercase tracking-wider">
                  Started
                </th>
                <th className="px-4 py-3 text-left text-[10px] font-semibold text-slate-500 uppercase tracking-wider">
                  Duration
                </th>
              </tr>
            </thead>
            <tbody className="divide-y divide-[#2a2d3a]">
              {scans.map((scan) => (
                <motion.tr
                  key={scan.id}
                  whileHover={{ backgroundColor: 'rgba(37, 40, 54, 0.5)' }}
                  className="transition-colors cursor-pointer"
                >
                  <td className="px-4 py-3 whitespace-nowrap text-sm font-semibold text-white">
                    #{scan.id}
                  </td>
                  <td className="px-4 py-3 whitespace-nowrap text-sm text-slate-300">
                    {getTargetDomain(scan.target_id)}
                  </td>
                  <td className="px-4 py-3 whitespace-nowrap">
                    <span className={`inline-flex items-center gap-1.5 px-2 py-1 rounded text-xs font-medium border ${getStatusColor(scan.status)}`}>
                      {getStatusIcon(scan.status)}
                      {scan.status}
                    </span>
                  </td>
                  <td className="px-4 py-3 whitespace-nowrap text-sm">
                    <span className={`font-semibold ${
                      scan.risk_score >= 70 ? 'text-red-500' :
                      scan.risk_score >= 40 ? 'text-yellow-500' :
                      'text-green-500'
                    }`}>
                      {scan.risk_score}/100
                    </span>
                  </td>
                  <td className="px-4 py-3 whitespace-nowrap text-xs text-slate-500">
                    {new Date(scan.started_at).toLocaleString()}
                  </td>
                  <td className="px-4 py-3 whitespace-nowrap text-xs text-slate-500">
                    {scan.completed_at ? (
                      `${Math.round((new Date(scan.completed_at).getTime() - new Date(scan.started_at).getTime()) / 1000)}s`
                    ) : (
                      <span className="text-yellow-500 font-medium">Running...</span>
                    )}
                  </td>
                </motion.tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}
