import { useQuery } from '@tanstack/react-query';
import { motion } from 'framer-motion';
import { Globe, Server, Wrench, AlertCircle } from 'lucide-react';
import { API_URL } from '../config';

interface Intelligence {
  id: number;
  scan_id: number;
  target: string;
  subdomains: string;
  dns_records: string;
  technologies: string;
  created_at: string;
}

export function IntelligencePanel({ scanId }: { scanId: number }) {
  const { data, isLoading, error } = useQuery({
    queryKey: ['intelligence', scanId],
    queryFn: async () => {
      const res = await fetch(`${API_URL}/api/v1/scans/${scanId}/intelligence`);
      if (!res.ok) return null;
      return res.json() as Promise<Intelligence>;
    },
    refetchInterval: 3000,
  });

  if (isLoading) {
    return (
      <div className="space-y-4">
        {[1, 2, 3].map((i) => (
          <div key={i} className="bg-[#1a1d29] rounded-lg p-6 border border-[#2a2d3a] animate-pulse">
            <div className="h-4 bg-[#252836] rounded w-1/3 mb-4" />
            <div className="space-y-2">
              <div className="h-3 bg-[#252836] rounded" />
              <div className="h-3 bg-[#252836] rounded w-5/6" />
            </div>
          </div>
        ))}
      </div>
    );
  }

  if (error || !data) {
    return (
      <div className="bg-[#1a1d29] rounded-lg p-12 border border-[#2a2d3a] text-center">
        <AlertCircle className="w-12 h-12 text-slate-700 mx-auto mb-4" />
        <p className="text-slate-400">
          Passive reconnaissance in progress... Check back in a few moments.
        </p>
      </div>
    );
  }

  let dnsRecords: any = {};
  let technologies: any[] = [];
  let subdomains: any[] = [];

  try {
    dnsRecords = data.dns_records ? JSON.parse(data.dns_records) : {};
  } catch (e) {}

  try {
    technologies = data.technologies ? JSON.parse(data.technologies) : [];
    if (!Array.isArray(technologies)) technologies = [];
  } catch (e) {}

  try {
    if (data.subdomains && data.subdomains !== 'null') {
      subdomains = JSON.parse(data.subdomains);
      if (!Array.isArray(subdomains)) subdomains = [];
    }
  } catch (e) {}

  const hasDns = dnsRecords && Object.keys(dnsRecords).length > 0;
  const hasTech = Array.isArray(technologies) && technologies.length > 0;
  const hasSubs = Array.isArray(subdomains) && subdomains.length > 0;

  return (
    <motion.div
      initial={{ opacity: 0, y: 20 }}
      animate={{ opacity: 1, y: 0 }}
      className="space-y-4"
    >
      {/* DNS Intelligence */}
      {hasDns && (
        <div className="bg-[#1a1d29] rounded-lg p-6 border border-[#2a2d3a]">
          <div className="flex items-center gap-2 mb-4">
            <Globe className="w-5 h-5 text-indigo-500" strokeWidth={2} />
            <h3 className="text-base font-semibold text-white">DNS Intelligence</h3>
          </div>
          <div className="grid grid-cols-2 gap-3">
            {Object.entries(dnsRecords).map(([type, records]: [string, any]) => (
              <div key={type} className="bg-[#252836] rounded p-3 border border-[#2a2d3a]">
                <div className="text-xs font-semibold text-indigo-400 mb-2 uppercase tracking-wider">
                  {type}
                </div>
                <div className="text-xs text-slate-400 space-y-1 max-h-24 overflow-y-auto">
                  {Array.isArray(records) ? (
                    records.slice(0, 3).map((record, i) => (
                      <div key={i} className="truncate font-mono">{record}</div>
                    ))
                  ) : (
                    <div className="truncate font-mono">{String(records)}</div>
                  )}
                  {Array.isArray(records) && records.length > 3 && (
                    <div className="text-slate-600 text-[10px]">+{records.length - 3} more</div>
                  )}
                </div>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Technologies */}
      {hasTech && (
        <div className="bg-[#1a1d29] rounded-lg p-6 border border-[#2a2d3a]">
          <div className="flex items-center gap-2 mb-4">
            <Wrench className="w-5 h-5 text-indigo-500" strokeWidth={2} />
            <h3 className="text-base font-semibold text-white">Technologies Detected</h3>
          </div>
          <div className="flex flex-wrap gap-2">
            {technologies.map((tech: any, i: number) => (
              <div
                key={i}
                className="bg-indigo-500/10 border border-indigo-500/20 rounded px-3 py-2"
              >
                <div className="text-sm font-semibold text-indigo-400">
                  {tech.name || 'Unknown'}
                </div>
                {tech.version && (
                  <div className="text-xs text-slate-500">v{tech.version}</div>
                )}
                <div className="text-[10px] text-slate-600 uppercase tracking-wider">
                  {tech.source || 'N/A'}
                </div>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Subdomains */}
      {hasSubs && (
        <div className="bg-[#1a1d29] rounded-lg p-6 border border-[#2a2d3a]">
          <div className="flex items-center gap-2 mb-4">
            <Server className="w-5 h-5 text-indigo-500" strokeWidth={2} />
            <h3 className="text-base font-semibold text-white">
              Subdomains ({subdomains.length})
            </h3>
          </div>
          <div className="grid grid-cols-2 gap-2 max-h-48 overflow-y-auto">
            {subdomains.map((subdomain: string, i: number) => (
              <div
                key={i}
                className="text-xs text-slate-400 bg-[#252836] rounded px-3 py-2 font-mono truncate border border-[#2a2d3a]"
              >
                {subdomain}
              </div>
            ))}
          </div>
        </div>
      )}

      {/* No Data */}
      {!hasDns && !hasTech && !hasSubs && (
        <div className="bg-[#1a1d29] rounded-lg p-12 border border-[#2a2d3a] text-center">
          <AlertCircle className="w-12 h-12 text-slate-700 mx-auto mb-4" />
          <p className="text-slate-400 mb-1">No intelligence data available</p>
          <p className="text-sm text-slate-600">Target: {data.target}</p>
        </div>
      )}
    </motion.div>
  );
}
