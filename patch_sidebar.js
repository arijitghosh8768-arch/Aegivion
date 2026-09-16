const fs = require('fs');
const file = 'packages/frontend/components/topology/topology-panels.tsx';
let content = fs.readFileSync(file, 'utf8');

if (!content.includes('useQuery')) {
  content = content.replace('import { useMemo, useState } from "react";', 'import { useMemo, useState } from "react";\nimport { useQuery } from "@tanstack/react-query";\nimport { fetchApi } from "@/lib/api-client";');
}

const oldSidebarStart = content.indexOf('export function ConnectedCloudsSidebar');
const oldSidebarEnd = content.indexOf('export function BottomPanel()');
const oldSidebar = content.slice(oldSidebarStart, oldSidebarEnd);

const newSidebar = `export function ConnectedCloudsSidebar({
  connected,
  onConnect,
  onDisconnect,
}: {
  connected: ProviderId[];
  onConnect: (p: ProviderId) => void;
  onDisconnect: (p: ProviderId) => void;
}) {
  const available = (Object.keys(PROVIDER_META) as ProviderId[]).filter((p) => !connected.includes(p));

  const { data: cloudAccountsRes } = useQuery({ queryKey: ['cloud-accounts'], queryFn: () => fetchApi('/v1/cloud-accounts') });
  const { data: findingsRes } = useQuery({ queryKey: ['findings'], queryFn: () => fetchApi('/v1/findings') });
  const { data: topologyRes } = useQuery({ queryKey: ['topology'], queryFn: () => fetchApi('/v1/topology') });
  
  const liveAccounts = cloudAccountsRes?.data || [];
  const liveFindings = findingsRes?.findings || [];
  const liveNodes = topologyRes?.nodes || [];

  const totalAssets = liveNodes.length;

  const healthFor = (p: ProviderId) => {
    const pFindings = liveFindings.filter((f: any) => f.cloud_provider?.toLowerCase() === p);
    if (!pFindings.length && !liveAccounts.find((a: any) => a.provider?.toLowerCase() === p)) return 0;
    if (!pFindings.length) return 100;
    
    const score = 100 - pFindings.reduce((acc: number, f: any) => {
        return acc + (f.severity?.toLowerCase() === 'critical' ? 5 : f.severity?.toLowerCase() === 'high' ? 2 : 1);
    }, 0);
    return Math.max(0, Math.min(100, score));
  };
  const scoreColor = (v: number) => (v >= 80 ? '#22c55e' : v >= 60 ? '#f59e0b' : '#ef4444');

  return (
    <div className="space-y-4 rounded-2xl border border-border bg-card p-4 shadow-soft xl:sticky xl:top-4 xl:self-start">
      <div>
        <h3 className="flex items-center gap-1.5 text-[13px] font-bold tracking-tight">
          <Layers className="h-4 w-4 text-primary" /> Connected Clouds
        </h3>
        <p className="mt-0.5 text-[11px] text-muted-foreground">
          {connected.length} of 3 providers — {totalAssets.toLocaleString()} assets
        </p>
      </div>

      <div className="space-y-2.5">
        {connected.map((p) => {
          const meta = PROVIDER_META[p];
          const providerNodes = liveNodes.filter((n: any) => n.provider === p);
          const providerFindings = liveFindings.filter((f: any) => f.cloud_provider?.toLowerCase() === p);
          const critical = providerFindings.filter((f: any) => f.severity?.toLowerCase() === 'critical').length;
          
          return (
            <motion.div
              key={p}
              layout
              initial={{ opacity: 0, x: 12 }}
              animate={{ opacity: 1, x: 0 }}
              exit={{ opacity: 0, x: 12 }}
              className="rounded-xl border border-border bg-muted/30 p-3"
            >
              <div className="flex items-center gap-2.5">
                <ProviderMark provider={p} size={30} />
                <div className="min-w-0 flex-1">
                  <div className="truncate text-[12.5px] font-semibold">{meta.name}</div>
                  <div className="flex items-center gap-1 text-[10.5px] font-medium text-success">
                    <span className="relative flex h-1.5 w-1.5">
                      <span className="absolute h-full w-full animate-ping rounded-full bg-success opacity-60" />
                      <span className="relative h-1.5 w-1.5 rounded-full bg-success" />
                    </span>
                    Connected
                  </div>
                </div>
                <button
                  onClick={() => onDisconnect(p)}
                  className="flex h-7 w-7 cursor-pointer items-center justify-center rounded-lg text-muted-foreground transition hover:bg-destructive/10 hover:text-destructive"
                  aria-label={\`Disconnect \${meta.name}\`}
                >
                  <X className="h-3.5 w-3.5" />
                </button>
              </div>
              <div className="mt-2.5 grid grid-cols-3 gap-1.5 text-center">
                <div className="rounded-lg bg-card px-1 py-1.5">
                  <div className="text-[12px] font-bold tabular-nums">{providerNodes.length.toLocaleString()}</div>
                  <div className="text-[9px] text-muted-foreground">Assets</div>
                </div>
                <div className={cn("rounded-lg bg-card px-1 py-1.5", critical > 0 && "ring-1 ring-destructive/25")}>
                  <div className={cn("text-[12px] font-bold tabular-nums", critical > 0 && "text-destructive")}>
                    {critical}
                  </div>
                  <div className="text-[9px] text-muted-foreground">Critical</div>
                </div>
                <div className="rounded-lg bg-card px-1 py-1.5">
                  <div className="text-[12px] font-bold tabular-nums">{providerFindings.length.toLocaleString()}</div>
                  <div className="text-[9px] text-muted-foreground">Findings</div>
                </div>
              </div>
              <div className="mt-2.5">
                <div className="mb-1 flex items-center justify-between text-[10px]">
                  <span className="text-muted-foreground">Security Score</span>
                  <span className="font-bold tabular-nums" style={{ color: scoreColor(healthFor(p)) }}>
                    {healthFor(p)}/100
                  </span>
                </div>
                <div className="h-1.5 overflow-hidden rounded-full bg-muted">
                  <motion.div
                    className="h-full rounded-full"
                    style={{ background: scoreColor(healthFor(p)) }}
                    initial={{ width: 0 }}
                    animate={{ width: \`\${healthFor(p)}%\` }}
                    transition={{ duration: 1, delay: 0.2 }}
                  />
                </div>
              </div>
            </motion.div>
          );
        })}
      </div>

      {available.length > 0 && (
        <div className="pt-2">
          <p className="mb-2 text-[10px] font-medium uppercase tracking-wider text-muted-foreground">
            Available to connect
          </p>
          <div className="space-y-1.5">
            {available.map((p) => {
              const meta = PROVIDER_META[p];
              return (
                <button
                  key={p}
                  onClick={() => onConnect(p)}
                  className="flex w-full items-center justify-between rounded-lg border border-border bg-card p-2 text-left transition hover:bg-muted/50"
                >
                  <div className="flex items-center gap-2">
                    <ProviderMark provider={p} size={20} />
                    <span className="text-[12px] font-medium">{meta.name}</span>
                  </div>
                  <Plus className="h-3.5 w-3.5 text-muted-foreground" />
                </button>
              );
            })}
          </div>
        </div>
      )}
    </div>
  );
}
`;

content = content.replace(oldSidebar, newSidebar);
fs.writeFileSync(file, content, 'utf8');
