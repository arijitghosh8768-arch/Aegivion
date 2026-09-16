"use client";

import { useMemo, useState } from "react";
import { AnimatePresence, motion } from "framer-motion";
import {
  Plug2,
  Search,
  Loader2,
  Check,
  CheckCircle2,
  XCircle,
  RefreshCw,
  Clock,
  Activity,
  Trash2,
  Unplug,
  ShieldCheck,
  ArrowRight,
  AlertTriangle,
  KeyRound,
  TestTube2,
  History,
  Send,
} from "lucide-react";
import { PageHeader } from "@/components/shared/page-header";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Switch } from "@/components/ui/switch";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Badge } from "@/components/ui/badge";
import { Progress } from "@/components/ui/progress";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import { useIntegrationsStore, INTEGRATION_DEFS, type IntegrationDefinition } from "@/lib/integrations-store";
import { toast } from "@/lib/toast";
import { cn } from "@/lib/utils";

const CATEGORIES = ["all", "communication", "devops", "ticketing", "siem", "notifications", "cloud"] as const;

const STATUS_META: Record<string, { label: string; dot: string; cls: string }> = {
  connected: { label: "Connected", dot: "bg-success", cls: "text-success border-success/25 bg-success/10" },
  attention: { label: "Needs attention", dot: "bg-warning", cls: "text-warning border-warning/25 bg-warning/10" },
  error: { label: "Connection failed", dot: "bg-destructive", cls: "text-destructive border-destructive/25 bg-destructive/10" },
  disconnected: { label: "Disconnected", dot: "bg-muted-foreground/60", cls: "text-muted-foreground border-border bg-muted/40" },
};

function IconBadge({ def, size = 9 }: { def: IntegrationDefinition; size?: number }) {
  return (
    <span
      className="flex shrink-0 items-center justify-center rounded-xl font-bold text-white shadow-soft"
      style={{ background: def.color, width: size * 4, height: size * 4, fontSize: size * 1.4 }}
    >
      {def.name.slice(0, 1).toUpperCase()}
      {def.name.length > 1 && def.name.slice(1, 2).toLowerCase()}
    </span>
  );
}

export default function IntegrationsPage() {
  const items = useIntegrationsStore((s) => s.items);
  const [query, setQuery] = useState("");
  const [cat, setCat] = useState<(typeof CATEGORIES)[number]>("all");
  const [active, setActive] = useState<IntegrationDefinition | null>(null);
  const [flow, setFlow] = useState<"config" | "oauth" | "disconnect" | null>(null);

  const filtered = useMemo(
    () =>
      INTEGRATION_DEFS.filter(
        (d) =>
          (cat === "all" || d.category === cat) &&
          (query === "" || d.name.toLowerCase().includes(query.toLowerCase()) || d.description.toLowerCase().includes(query.toLowerCase()))
      ),
    [query, cat]
  );

  const connectedCount = INTEGRATION_DEFS.filter((d) => items[d.id]?.status === "connected").length;

  return (
    <div className="mx-auto max-w-[1280px]">
      <PageHeader
        title="Integrations"
        description="Connect Aegivion to your workflow — alerts, ticketing, SIEM and CI/CD."
      >
        <div className="flex items-center gap-3">
          <div className="hidden items-center gap-2 rounded-full border border-border bg-card px-3.5 py-1.5 text-sm font-semibold sm:flex">
            <span className="h-2 w-2 rounded-full bg-success" /> {connectedCount} active
          </div>
          <Badge variant="soft" className="gap-1.5">
            <ShieldCheck className="h-3.5 w-3.5 text-primary" /> Secrets encrypted at rest
          </Badge>
        </div>
      </PageHeader>

      {/* Toolbar */}
      <div className="mb-5 flex flex-wrap items-center gap-3">
        <div className="relative min-w-[220px] flex-1">
          <Search className="absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-muted-foreground" />
          <Input
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            placeholder="Search 20 integrations…"
            className="pl-9"
          />
        </div>
        <div className="flex flex-wrap gap-1.5">
          {CATEGORIES.map((c) => (
            <button
              key={c}
              onClick={() => setCat(c)}
              className={cn(
                "cursor-pointer rounded-full border px-3 py-1.5 text-sm font-semibold capitalize transition",
                cat === c
                  ? "border-primary/40 bg-primary/10 text-primary"
                  : "border-border bg-card text-muted-foreground hover:border-primary/30 hover:text-foreground"
              )}
            >
              {c}
            </button>
          ))}
        </div>
      </div>

      {/* Catalog */}
      <div className="grid gap-4 sm:grid-cols-2 xl:grid-cols-3">
        {filtered.map((def, i) => {
          const state = items[def.id];
          const meta = STATUS_META[state.status];
          return (
            <motion.div
              key={def.id}
              initial={{ opacity: 0, y: 14 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ delay: i * 0.04 }}
              className="card-hover group flex flex-col rounded-2xl border border-border bg-card p-4 shadow-soft"
            >
              <div className="flex items-start gap-3">
                <IconBadge def={def} />
                <div className="min-w-0 flex-1">
                  <div className="flex items-center gap-2">
                    <h3 className="truncate text-[14px] font-bold">{def.name}</h3>
                    <span className={cn("rounded-full border px-2 py-0.5 text-[9.5px] font-bold", meta.cls)}>{meta.label}</span>
                  </div>
                  <p className="mt-0.5 line-clamp-2 text-xs leading-snug text-muted-foreground">{def.description}</p>
                </div>
              </div>

              <div className="mt-2.5 flex flex-wrap gap-1">
                {def.features.slice(0, 3).map((f) => (
                  <span key={f} className="rounded-md bg-muted/60 px-1.5 py-0.5 text-[10px] font-medium text-muted-foreground">
                    {f}
                  </span>
                ))}
              </div>

              {state.status === "connected" ? (
                <div className="mt-3 space-y-2 border-t border-border/60 pt-3">
                  <div className="flex items-center justify-between text-[10.5px] text-muted-foreground">
                    <span className="flex items-center gap-1">
                      <Clock className="h-3 w-3" /> Last sync {state.lastSync}
                    </span>
                    <span className="flex items-center gap-1">
                      <RefreshCw className="h-3 w-3" /> Next {state.nextSync}
                    </span>
                  </div>
                  <div className="flex items-center gap-2">
                    <Progress value={state.health} className="flex-1" indicatorClassName={state.health >= 98 ? "bg-success" : "bg-warning"} />
                    <span className="text-[10px] font-bold tabular-nums text-muted-foreground">{state.health}%</span>
                  </div>
                </div>
              ) : (
                <div className="mt-3 flex-1" />
              )}

              <div className="mt-3 flex gap-2 border-t border-border/60 pt-3">
                {state.status === "connected" ? (
                  <>
                    <Button size="sm" variant="outline" className="flex-1" onClick={() => { setActive(def); setFlow("config"); }}>
                      Configure
                    </Button>
                    <Button size="sm" variant="outline" className="flex-1" onClick={() => { setActive(def); setFlow("disconnect"); }}>
                      <Unplug className="h-3.5 w-3.5" /> Disconnect
                    </Button>
                  </>
                ) : (
                  <Button size="sm" variant="gradient" className="flex-1" onClick={() => { setActive(def); setFlow("oauth"); }}>
                    <Plug2 className="h-3.5 w-3.5" /> Connect
                  </Button>
                )}
                <Button size="sm" variant="ghost" onClick={() => { setActive(def); setFlow("config"); }}>
                  <History className="h-3.5 w-3.5" />
                </Button>
              </div>
            </motion.div>
          );
        })}
      </div>

      {filtered.length === 0 && (
        <div className="rounded-2xl border border-dashed border-border py-14 text-center">
          <Plug2 className="mx-auto h-8 w-8 text-muted-foreground/50" />
          <p className="mt-2 text-[13px] font-semibold">No integrations match</p>
          <p className="text-sm text-muted-foreground">Try a different search or category.</p>
        </div>
      )}

      {/* Modals */}
      <AnimatePresence>
        {active && flow === "oauth" && <OAuthFlow def={active} onDone={(cfg) => { useIntegrationsStore.getState().connect(active.id, cfg); toast("success", `${active.name} connected`, "OAuth handshake complete — alerts will start flowing."); setFlow(null); setActive(null); }} onClose={() => setFlow(null)} />}
        {active && flow === "config" && <ConfigDialog def={active} onClose={() => setFlow(null)} />}
        {active && flow === "disconnect" && <DisconnectDialog def={active} onClose={() => setFlow(null)} />}
      </AnimatePresence>
    </div>
  );
}

/* ------------------------------------------------------------------ */
/* OAuth connect flow                                                 */
/* ------------------------------------------------------------------ */

function OAuthFlow({ def, onDone, onClose }: { def: IntegrationDefinition; onDone: (cfg: Record<string, string>) => void; onClose: () => void }) {
  const [step, setStep] = useState(0);
  const [authorizing, setAuthorizing] = useState(false);
  const [workspace, setWorkspace] = useState("Acme Corp");

  const startAuth = () => {
    setAuthorizing(true);
    setTimeout(() => {
      setAuthorizing(false);
      setStep(2);
    }, 1800);
  };

  return (
    <Dialog open onOpenChange={(o) => !o && onClose()}>
      <DialogContent className="sm:max-w-md">
        <DialogHeader>
          <DialogTitle className="flex items-center gap-2.5">
            <IconBadge def={def} size={6} /> Connect {def.name}
          </DialogTitle>
          <DialogDescription>Authorize Aegivion to access your {def.name} account.</DialogDescription>
        </DialogHeader>

        {step === 0 && (
          <div className="space-y-4">
            <div className="rounded-xl border border-border bg-muted/30 p-4">
              <div className="text-[12px] font-semibold">Select workspace</div>
              <div className="mt-2 space-y-1.5">
                {["Acme Corp", "Acme Labs"].map((w) => (
                  <button
                    key={w}
                    onClick={() => setWorkspace(w)}
                    className={cn(
                      "flex w-full cursor-pointer items-center gap-2.5 rounded-lg border px-3 py-2.5 text-left text-[12.5px] font-medium transition",
                      workspace === w ? "border-primary/40 bg-primary/10 text-primary" : "border-border bg-card hover:bg-muted/50"
                    )}
                  >
                    <span className="flex h-7 w-7 items-center justify-center rounded-lg" style={{ background: def.color }} />
                    {w}
                    {workspace === w && <Check className="ml-auto h-4 w-4" />}
                  </button>
                ))}
              </div>
            </div>
            <div className="rounded-xl border border-border/60 p-4">
              <div className="text-[12px] font-semibold">Aegivion will be able to:</div>
              <ul className="mt-2 space-y-1.5">
                {def.features.map((f) => (
                  <li key={f} className="flex items-center gap-2 text-sm text-muted-foreground">
                    <Check className="h-3.5 w-3.5 text-success" /> {f}
                  </li>
                ))}
                <li className="flex items-center gap-2 text-sm text-muted-foreground">
                  <ShieldCheck className="h-3.5 w-3.5 text-primary" /> Read-only security telemetry
                </li>
              </ul>
            </div>
          </div>
        )}

        {step === 1 && (
          <div className="flex flex-col items-center py-8">
            <motion.div
              animate={{ scale: [1, 1.08, 1] }}
              transition={{ repeat: Infinity, duration: 1.2 }}
              className="flex h-16 w-16 items-center justify-center rounded-2xl" style={{ background: def.color }}
            >
              <Loader2 className="h-7 w-7 animate-spin text-white" />
            </motion.div>
            <p className="mt-4 text-[13px] font-semibold">Redirecting to {def.name}…</p>
            <p className="text-xs text-muted-foreground">Completing OAuth 2.0 authorization code flow</p>
          </div>
        )}

        {step === 2 && (
          <motion.div initial={{ opacity: 0, scale: 0.95 }} animate={{ opacity: 1, scale: 1 }} className="flex flex-col items-center py-6">
            <motion.div
              initial={{ scale: 0 }}
              animate={{ scale: 1 }}
              transition={{ type: "spring", stiffness: 300, damping: 18 }}
              className="flex h-16 w-16 items-center justify-center rounded-full bg-success/15"
            >
              <CheckCircle2 className="h-8 w-8 text-success" />
            </motion.div>
            <p className="mt-4 text-[14px] font-bold">Authorization complete</p>
            <p className="mt-1 text-center text-sm text-muted-foreground">
              {workspace} granted access · OAuth tokens encrypted and stored securely.
            </p>
          </motion.div>
        )}

        <DialogFooter>
          {step === 0 && (
            <>
              <Button variant="outline" onClick={onClose}>Cancel</Button>
              <Button variant="gradient" onClick={() => setStep(1)}>
                Continue to {def.name} <ArrowRight className="h-4 w-4" />
              </Button>
            </>
          )}
          {step === 1 && <Button variant="gradient" disabled={!authorizing} onClick={startAuth}><Loader2 className="h-4 w-4 animate-spin" /> Authorizing…</Button>}
          {step === 2 && (
            <Button variant="gradient" onClick={() => onDone({ workspace })}>
              <Check className="h-4 w-4" /> Finish & Connect
            </Button>
          )}
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}

/* ------------------------------------------------------------------ */
/* Config dialog                                                      */
/* ------------------------------------------------------------------ */

const CONFIG_FIELDS: Record<string, { key: string; label: string; type: "text" | "select" | "toggle"; options?: string[] }[]> = {
  slack: [
    { key: "channel", label: "Alert channel", type: "text" },
    { key: "severity", label: "Severity filter", type: "select", options: ["Critical + High", "Critical only", "All severities"] },
    { key: "mentions", label: "Mention users (comma-separated)", type: "text" },
    { key: "dailySummary", label: "Send daily summary", type: "toggle" },
    { key: "criticalAlerts", label: "Send critical alerts", type: "toggle" },
    { key: "weeklyReports", label: "Send weekly reports", type: "toggle" },
  ],
  github: [
    { key: "repository", label: "Repository", type: "text" },
    { key: "branch", label: "Branch", type: "text" },
    { key: "secretScanning", label: "Secret scanning", type: "toggle" },
    { key: "dependabot", label: "Dependabot sync", type: "toggle" },
    { key: "codeScanning", label: "Code scanning", type: "toggle" },
    { key: "actions", label: "Auto actions", type: "select", options: ["Create issue", "Open PR", "Push Terraform fix", "Generate report"] },
  ],
  jira: [
    { key: "project", label: "Project", type: "text" },
    { key: "issueType", label: "Issue type", type: "select", options: ["Bug", "Task", "Story", "Epic"] },
    { key: "priority", label: "Priority mapping", type: "select", options: ["Critical→Highest", "Critical→High", "Default mapping"] },
    { key: "assignee", label: "Assign to", type: "text" },
    { key: "autoCreate", label: "Auto-create tickets", type: "toggle" },
    { key: "autoClose", label: "Auto-close on remediation", type: "toggle" },
  ],
  pagerduty: [
    { key: "routingKey", label: "Routing key", type: "text" },
    { key: "escalation", label: "Escalation policy", type: "text" },
    { key: "sevCritical", label: "Critical → Page", type: "toggle" },
    { key: "sevHigh", label: "High → Page", type: "toggle" },
    { key: "sevMedium", label: "Medium → Email", type: "toggle" },
  ],
  smtp: [
    { key: "provider", label: "Provider", type: "select", options: ["SMTP", "Office365", "Gmail", "Amazon SES"] },
    { key: "host", label: "SMTP host", type: "text" },
    { key: "port", label: "Port", type: "text" },
    { key: "from", label: "From address", type: "text" },
  ],
  webhook: [
    { key: "url", label: "Webhook URL", type: "text" },
    { key: "auth", label: "Authentication", type: "select", options: ["None", "Bearer token", "Basic auth", "API key header"] },
    { key: "retry", label: "Retry policy", type: "select", options: ["3 retries · exponential", "5 retries · exponential", "No retries"] },
  ],
};

function ConfigDialog({ def, onClose }: { def: IntegrationDefinition; onClose: () => void }) {
  const item = useIntegrationsStore((s) => s.items[def.id]);
  const updateConfig = useIntegrationsStore((s) => s.updateConfig);
  const addLog = useIntegrationsStore((s) => s.addLog);
  const testConnection = useIntegrationsStore((s) => s.testConnection);
  const [tab, setTab] = useState<"config" | "test" | "logs">("config");
  const [values, setValues] = useState<Record<string, string | boolean>>(item.config);
  const [testing, setTesting] = useState(false);
  const [tested, setTested] = useState<boolean | null>(null);

  const fields = CONFIG_FIELDS[def.id] ?? [];

  const save = () => {
    updateConfig(def.id, values);
    addLog(def.id, "Configuration saved", "info");
    toast("success", `${def.name} configuration saved`, "Notification rules are now active.");
    onClose();
  };

  const test = async () => {
    setTesting(true);
    setTested(null);
    const ok = await testConnection(def.id);
    setTesting(false);
    setTested(ok);
  };

  const canConfigure = item.status === "connected";

  return (
    <Dialog open onOpenChange={(o) => !o && onClose()}>
      <DialogContent className="sm:max-w-xl">
        <DialogHeader>
          <DialogTitle className="flex items-center gap-2.5">
            <IconBadge def={def} size={6} /> {def.name} configuration
          </DialogTitle>
          <DialogDescription>
            {canConfigure ? (
              <>
                Connected · last sync {item.lastSync} · health {item.health}%
              </>
            ) : (
              "Connect first to configure this integration."
            )}
          </DialogDescription>
        </DialogHeader>

        <div className="flex gap-1.5 rounded-xl bg-muted/50 p-1">
          {(["config", "test", "logs"] as const).map((t) => (
            <button
              key={t}
              onClick={() => setTab(t)}
              className={cn(
                "flex flex-1 cursor-pointer items-center justify-center gap-1.5 rounded-lg py-1.5 text-sm font-semibold capitalize transition",
                tab === t ? "bg-card text-foreground shadow-soft" : "text-muted-foreground hover:text-foreground"
              )}
            >
              {t === "test" ? <TestTube2 className="h-3.5 w-3.5" /> : t === "logs" ? <Activity className="h-3.5 w-3.5" /> : <KeyRound className="h-3.5 w-3.5" />}
              {t}
            </button>
          ))}
        </div>

        {tab === "config" && (
          <div className="grid gap-3.5 sm:grid-cols-2">
            {fields.map((f) => (
              <div key={f.key} className={cn("space-y-1.5", f.type === "toggle" && "flex items-center justify-between gap-3 sm:col-span-2 rounded-xl border border-border/60 px-3.5 py-2.5")}>
                {f.type === "toggle" ? (
                  <>
                    <Label className="text-[12.5px] font-medium">{f.label}</Label>
                    <Switch
                      checked={Boolean(values[f.key])}
                      disabled={!canConfigure}
                      onCheckedChange={(v) => setValues((s) => ({ ...s, [f.key]: v }))}
                    />
                  </>
                ) : f.type === "select" ? (
                  <>
                    <Label className="text-[12.5px] font-medium">{f.label}</Label>
                    <Select
                      value={String(values[f.key] ?? f.options?.[0])}
                      onValueChange={(v) => setValues((s) => ({ ...s, [f.key]: v }))}
                    >
                      <SelectTrigger disabled={!canConfigure}>
                        <SelectValue />
                      </SelectTrigger>
                      <SelectContent>
                        {f.options?.map((o) => (
                          <SelectItem key={o} value={o}>{o}</SelectItem>
                        ))}
                      </SelectContent>
                    </Select>
                  </>
                ) : (
                  <>
                    <Label className="text-[12.5px] font-medium">{f.label}</Label>
                    <Input
                      value={String(values[f.key] ?? "")}
                      disabled={!canConfigure}
                      onChange={(e) => setValues((s) => ({ ...s, [f.key]: e.target.value }))}
                    />
                  </>
                )}
              </div>
            ))}
            {fields.length === 0 && (
              <p className="text-[12px] text-muted-foreground">This integration has no additional configuration.</p>
            )}
          </div>
        )}

        {tab === "test" && (
          <div className="flex flex-col items-center py-4">
            <Button variant={tested === false ? "destructive" : "outline"} onClick={test} disabled={testing || !canConfigure}>
              {testing ? <Loader2 className="h-4 w-4 animate-spin" /> : <TestTube2 className="h-4 w-4" />}
              {testing ? "Testing connection…" : "Test connection"}
            </Button>
            {tested !== null && (
              <motion.div initial={{ opacity: 0, y: 6 }} animate={{ opacity: 1, y: 0 }} className="mt-3 flex items-center gap-2 text-[12.5px] font-semibold">
                {tested ? (
                  <>
                    <CheckCircle2 className="h-4 w-4 text-success" /> Connection successful
                  </>
                ) : (
                  <>
                    <XCircle className="h-4 w-4 text-destructive" /> Authentication failed
                  </>
                )}
              </motion.div>
            )}
            <p className="mt-3 text-center text-xs leading-relaxed text-muted-foreground">
              Validates credentials, endpoint reachability and permission scope against {def.name}.
            </p>
          </div>
        )}

        {tab === "logs" && (
          <div className="max-h-56 space-y-1.5 overflow-y-auto">
            {item.logs.length === 0 && (
              <p className="py-6 text-center text-[12px] text-muted-foreground">No activity yet for this integration.</p>
            )}
            {item.logs.map((l) => (
              <div key={l.id} className="flex items-center gap-2.5 rounded-lg border border-border/50 px-3 py-2">
                <span className={cn("h-1.5 w-1.5 shrink-0 rounded-full", l.kind === "success" ? "bg-success" : l.kind === "error" ? "bg-destructive" : l.kind === "warning" ? "bg-warning" : "bg-info")} />
                <span className="w-10 shrink-0 text-[10.5px] font-semibold tabular-nums text-muted-foreground">{l.time}</span>
                <span className="text-sm">{l.message}</span>
              </div>
            ))}
          </div>
        )}

        <DialogFooter>
          <Button variant="outline" onClick={onClose}>Cancel</Button>
          {tab === "config" && (
            <>
              {(def.id === "slack" || def.id === "pagerduty" || def.id === "smtp" || def.id === "webhook") && (
                <Button variant="outline" onClick={async () => { await test(); toast("success", `Test ${def.id === "slack" ? "notification" : def.id === "pagerduty" ? "incident" : "message"} sent`, "Check the target channel to confirm delivery."); }} disabled={testing || !canConfigure}>
                  {testing ? <Loader2 className="h-4 w-4 animate-spin" /> : <Send className="h-4 w-4" />}
                  {def.id === "pagerduty" ? "Test incident" : "Send test notification"}
                </Button>
              )}
              <Button variant="gradient" onClick={save} disabled={!canConfigure}>
                <Check className="h-4 w-4" /> Save
              </Button>
            </>
          )}
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}

/* ------------------------------------------------------------------ */
/* Disconnect dialog                                                  */
/* ------------------------------------------------------------------ */

function DisconnectDialog({ def, onClose }: { def: IntegrationDefinition; onClose: () => void }) {
  const disconnect = useIntegrationsStore((s) => s.disconnect);
  const [working, setWorking] = useState(false);

  const run = () => {
    setWorking(true);
    setTimeout(() => {
      disconnect(def.id);
      toast("info", `${def.name} disconnected`, "OAuth tokens revoked and cached secrets cleared.");
      onClose();
    }, 900);
  };

  return (
    <Dialog open onOpenChange={(o) => !o && onClose()}>
      <DialogContent className="sm:max-w-sm">
        <DialogHeader>
          <DialogTitle className="flex items-center gap-2.5 text-destructive">
            <AlertTriangle className="h-5 w-5" /> Disconnect {def.name}?
          </DialogTitle>
          <DialogDescription>
            Aegivion will stop sending alerts and syncing findings to {def.name}. OAuth tokens will be revoked and
            cached credentials removed.
          </DialogDescription>
        </DialogHeader>
        <div className="rounded-xl border border-border/60 bg-muted/30 p-3 text-sm text-muted-foreground">
          Dashboard, Detection Engine and Settings will reflect the disconnected status instantly.
        </div>
        <DialogFooter>
          <Button variant="outline" onClick={onClose} disabled={working}>Cancel</Button>
          <Button variant="destructive" onClick={run} disabled={working}>
            {working ? <Loader2 className="h-4 w-4 animate-spin" /> : <Trash2 className="h-4 w-4" />}
            {working ? "Disconnecting…" : "Disconnect"}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}
