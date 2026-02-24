import { useState, useEffect, useCallback, useRef } from 'react';

export interface ScanProgress {
  scan_id: number;
  status: string;
  progress: number;
  message: string;
  current_step: string;
  timestamp: string;
}

export interface ScanFinding {
  scan_id: number;
  severity: string;
  category: string;
  finding: string;
}

export interface ScanComplete {
  scan_id: number;
  risk_score: number;
  risk_grade: string;
  timestamp: string;
}

export function useScanStream(scanId: number | null) {
  const [isConnected, setIsConnected] = useState(false);
  const [progress, setProgress] = useState<ScanProgress | null>(null);
  const [findings, setFindings] = useState<ScanFinding[]>([]);
  const [complete, setComplete] = useState<ScanComplete | null>(null);
  const wsRef = useRef<WebSocket | null>(null);

  const connect = useCallback(() => {
    if (!scanId) return;

    const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
    const ws = new WebSocket(`${protocol}//${window.location.host}/ws/scans/${scanId}/stream`);
    
    ws.onopen = () => {
      console.log('[WebSocket] Connected to scan stream');
      setIsConnected(true);
    };

    ws.onmessage = (event) => {
      try {
        const data = JSON.parse(event.data);
        
        switch (data.type) {
          case 'scan_progress':
            setProgress(data);
            break;
          case 'scan_finding':
            setFindings(prev => [...prev, data]);
            break;
          case 'scan_complete':
            setComplete(data);
            setIsConnected(false);
            break;
        }
      } catch (error) {
        console.error('[WebSocket] Parse error:', error);
      }
    };

    ws.onerror = (error) => {
      console.error('[WebSocket] Error:', error);
    };

    ws.onclose = () => {
      console.log('[WebSocket] Disconnected');
      setIsConnected(false);
    };

    wsRef.current = ws;
  }, [scanId]);

  useEffect(() => {
    if (scanId) {
      connect();
    }

    return () => {
      if (wsRef.current) {
        wsRef.current.close();
      }
    };
  }, [scanId, connect]);

  return {
    isConnected,
    progress,
    findings,
    complete,
  };
}
