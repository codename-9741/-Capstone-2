export function CvePage() {
  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-bold text-slate-900 dark:text-white">CVE Intelligence</h1>
        <p className="text-sm text-slate-500">Common Vulnerabilities and Exposures database</p>
      </div>
      <div className="rounded-xl border border-slate-200 bg-white p-12 text-center dark:border-slate-800 dark:bg-slate-900">
        <p className="text-lg font-medium text-slate-400">CVE correlation coming soon</p>
        <p className="text-sm text-slate-400 mt-2">Scan findings will be correlated with CVE entries</p>
      </div>
    </div>
  );
}
