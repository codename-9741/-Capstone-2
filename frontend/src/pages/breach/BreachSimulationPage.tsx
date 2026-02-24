export function BreachSimulationPage() {
  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-bold text-slate-900 dark:text-white">Breach Attack Simulation</h1>
        <p className="text-sm text-slate-500">
          Visualize attack scenarios mapped from your findings
        </p>
      </div>

      <div className="rounded-xl border border-slate-200 bg-white p-6 dark:border-slate-800 dark:bg-slate-900">
        <div className="flex items-center justify-between mb-4">
          <h2 className="text-sm font-semibold text-slate-900 dark:text-white">Simulation List</h2>
          <button className="btn-primary text-xs">Create Exercise</button>
        </div>
        <div className="grid gap-4 md:grid-cols-2">
          {[1, 2].map((item) => (
            <div key={item} className="rounded-lg border border-slate-200 bg-slate-50 p-4 dark:border-slate-700 dark:bg-slate-800">
              <h3 className="text-sm font-semibold text-slate-900 dark:text-white">Scenario {item}</h3>
              <p className="text-xs text-slate-500 mt-2">Placeholder for simulation description</p>
              <span className="mt-3 inline-block rounded-md bg-amber-50 px-2 py-0.5 text-[10px] font-medium text-amber-700 dark:bg-amber-900/20 dark:text-amber-400">
                Draft
              </span>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}
