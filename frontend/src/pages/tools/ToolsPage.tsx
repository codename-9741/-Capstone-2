export function ToolsPage() {
  return (
    <div className="app-card">
      <h1 className="text-2xl font-bold text-slate-900">Tools Workspace</h1>
      <p className="text-sm text-slate-500 mt-2">
        Placeholder module — you can expand this area with tool creation, orchestration, or other utilities later.
      </p>
      <div className="mt-6 grid gap-4 sm:grid-cols-2">
        {[1, 2].map((box) => (
          <div key={box} className="rounded-2xl border border-slate-200 bg-slate-50 p-4">
            <p className="text-xs uppercase tracking-[0.4em] text-slate-400">Widget {box}</p>
            <p className="mt-3 text-sm text-slate-500">Awaiting your workflow design.</p>
          </div>
        ))}
      </div>
    </div>
  );
}
