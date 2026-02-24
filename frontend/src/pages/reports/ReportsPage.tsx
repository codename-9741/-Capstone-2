export function ReportsPage() {
  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-bold text-slate-900 dark:text-white">Report Studio</h1>
        <p className="text-sm text-slate-500">
          Aggregate findings into templated reports for executive briefings and compliance
        </p>
      </div>

      <div className="grid gap-4 sm:grid-cols-3">
        {['Executive Brief', 'Compliance Pack', 'Custom PDF'].map((label) => (
          <div key={label} className="rounded-xl border border-slate-200 bg-white p-6 dark:border-slate-800 dark:bg-slate-900">
            <p className="text-sm font-semibold text-slate-900 dark:text-white">{label}</p>
            <p className="text-xs text-slate-400 mt-2">Coming soon</p>
          </div>
        ))}
      </div>
    </div>
  );
}
