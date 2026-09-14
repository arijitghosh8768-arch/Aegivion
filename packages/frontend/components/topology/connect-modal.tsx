"use client";

import { useState } from "react";
import { motion } from "framer-motion";
import { ShieldCheck, Loader2, CheckCircle2 } from "lucide-react";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { PROVIDER_META } from "@/lib/data/providers";
import { cn } from "@/lib/utils";
import type { ProviderId } from "@/lib/types";

interface Props {
  provider: ProviderId | null;
  onClose: () => void;
  onConnect: (p: ProviderId) => void;
}

type TestState = "idle" | "testing" | "ok" | "fail";

export function ConnectModal({ provider, onClose, onConnect }: Props) {
  const [name, setName] = useState("");
  const [authMethod, setAuthMethod] = useState<"role" | "keys">("role");
  const [region, setRegion] = useState("us-east-1");
  const [accessKey, setAccessKey] = useState("");
  const [secretKey, setSecretKey] = useState("");
  const [sessionToken, setSessionToken] = useState("");
  const [tenantId, setTenantId] = useState("");
  const [subscriptionId, setSubscriptionId] = useState("");
  const [clientId, setClientId] = useState("");
  const [clientSecret, setClientSecret] = useState("");
  const [projectId, setProjectId] = useState("");
  const [saJson, setSaJson] = useState("");
  const [test, setTest] = useState<TestState>("idle");
  const [connecting, setConnecting] = useState(false);

  const open = provider !== null;

  const reset = () => {
    setName("");
    setAuthMethod("role");
    setAccessKey("");
    setSecretKey("");
    setSessionToken("");
    setTenantId("");
    setSubscriptionId("");
    setClientId("");
    setClientSecret("");
    setProjectId("");
    setSaJson("");
    setTest("idle");
    setConnecting(false);
  };

  const handleClose = () => {
    if (connecting) return;
    reset();
    onClose();
  };

  const runTest = () => {
    if (connecting) return;
    setTest("testing");
    setTimeout(() => setTest("ok"), 1400);
  };

  const doConnect = () => {
    if (connecting || test !== "ok") return;
    setConnecting(true);
    setTimeout(() => {
      if (provider) onConnect(provider);
      reset();
      onClose();
    }, 1100);
  };

  const nameValid = name.trim().length >= 2;

  const awsValid = authMethod === "role" ? nameValid : nameValid && accessKey.trim().length > 8 && secretKey.trim().length > 8;
  const azureValid = nameValid && tenantId.trim().length > 4 && subscriptionId.trim().length > 4 && clientId.trim().length > 4 && clientSecret.trim().length > 4;
  const gcpValid = nameValid && projectId.trim().length > 2 && saJson.trim().length > 10;

  const valid = provider === "aws" ? awsValid : provider === "azure" ? azureValid : gcpValid;

  return (
    <Dialog open={open} onOpenChange={(o) => !o && handleClose()}>
      <DialogContent className="max-h-[90dvh] overflow-y-auto sm:max-w-lg">
        <DialogHeader>
          <DialogTitle className="flex items-center gap-2.5">
            {provider && (
              <span
                className="flex h-8 w-8 items-center justify-center rounded-xl text-[13px] font-bold"
                style={{ background: PROVIDER_META[provider].soft, color: PROVIDER_META[provider].color }}
              >
                {PROVIDER_META[provider].short}
              </span>
            )}
            Connect {provider ? PROVIDER_META[provider].name : ""}
          </DialogTitle>
          <DialogDescription>
            Grant Aegivion read-only access. Your credentials are encrypted with KMS and never stored in plain text.
          </DialogDescription>
        </DialogHeader>

        <div className="space-y-4 py-1">
          {/* Connection name */}
          <div className="space-y-1.5">
            <Label htmlFor="conn-name">Connection Name</Label>
            <Input
              id="conn-name"
              placeholder={provider === "aws" ? "AWS Production" : provider === "azure" ? "Azure Production" : "GCP Production"}
              value={name}
              onChange={(e) => setName(e.target.value)}
            />
          </div>

          {/* AWS auth method */}
          {provider === "aws" && (
            <>
              <div className="space-y-2">
                <Label>Authentication Method</Label>
                <div className="grid grid-cols-2 gap-2">
                  {(
                    [
                      { id: "role", title: "IAM Role", desc: "Recommended" },
                      { id: "keys", title: "Access Keys", desc: "Legacy" },
                    ] as const
                  ).map((m) => (
                    <button
                      key={m.id}
                      onClick={() => setAuthMethod(m.id)}
                      className={cn(
                        "flex cursor-pointer flex-col items-start gap-0.5 rounded-xl border px-3 py-2.5 text-left transition",
                        authMethod === m.id
                          ? "border-primary/40 bg-primary/5"
                          : "border-border bg-muted/30 hover:border-primary/30"
                      )}
                    >
                      <span className="flex items-center gap-2 text-[12.5px] font-semibold">
                        <span
                          className={cn(
                            "flex h-3.5 w-3.5 items-center justify-center rounded-full border-2",
                            authMethod === m.id ? "border-primary" : "border-muted-foreground/40"
                          )}
                        >
                          {authMethod === m.id && <span className="h-1.5 w-1.5 rounded-full bg-primary" />}
                        </span>
                        {m.title}
                      </span>
                      <span className="pl-[18px] text-[10.5px] text-muted-foreground">{m.desc}</span>
                    </button>
                  ))}
                </div>
              </div>

              {authMethod === "keys" && (
                <>
                  <div className="space-y-1.5">
                    <Label htmlFor="region">Region</Label>
                    <Input id="region" value={region} onChange={(e) => setRegion(e.target.value)} />
                  </div>
                  <div className="space-y-1.5">
                    <Label htmlFor="access-key">Access Key</Label>
                    <Input id="access-key" type="password" value={accessKey} onChange={(e) => setAccessKey(e.target.value)} placeholder="AKIA…" />
                  </div>
                  <div className="space-y-1.5">
                    <Label htmlFor="secret-key">Secret Key</Label>
                    <Input id="secret-key" type="password" value={secretKey} onChange={(e) => setSecretKey(e.target.value)} placeholder="••••••••••••" />
                  </div>
                  <div className="space-y-1.5">
                    <Label htmlFor="session-token">Session Token <span className="font-normal text-muted-foreground">(optional)</span></Label>
                    <Input id="session-token" type="password" value={sessionToken} onChange={(e) => setSessionToken(e.target.value)} />
                  </div>
                </>
              )}
            </>
          )}

          {/* Azure fields */}
          {provider === "azure" && (
            <>
              <div className="space-y-1.5">
                <Label htmlFor="tenant-id">Tenant ID</Label>
                <Input id="tenant-id" value={tenantId} onChange={(e) => setTenantId(e.target.value)} placeholder="00000000-0000-0000-0000-000000000000" />
              </div>
              <div className="space-y-1.5">
                <Label htmlFor="sub-id">Subscription ID</Label>
                <Input id="sub-id" value={subscriptionId} onChange={(e) => setSubscriptionId(e.target.value)} placeholder="00000000-0000-0000-0000-000000000000" />
              </div>
              <div className="space-y-1.5">
                <Label htmlFor="client-id">Client ID</Label>
                <Input id="client-id" value={clientId} onChange={(e) => setClientId(e.target.value)} placeholder="00000000-0000-0000-0000-000000000000" />
              </div>
              <div className="space-y-1.5">
                <Label htmlFor="client-secret">Client Secret</Label>
                <Input id="client-secret" type="password" value={clientSecret} onChange={(e) => setClientSecret(e.target.value)} />
              </div>
            </>
          )}

          {/* GCP fields */}
          {provider === "gcp" && (
            <>
              <div className="space-y-1.5">
                <Label htmlFor="project-id">Project ID</Label>
                <Input id="project-id" value={projectId} onChange={(e) => setProjectId(e.target.value)} placeholder="my-gcp-project" />
              </div>
              <div className="space-y-1.5">
                <Label htmlFor="sa-json">Service Account JSON</Label>
                <textarea
                  id="sa-json"
                  value={saJson}
                  onChange={(e) => setSaJson(e.target.value)}
                  placeholder='{"type": "service_account", "project_id": "…", "private_key": "…"}'
                  className="code-block min-h-[110px] w-full resize-y rounded-xl border border-input bg-muted/40 px-3 py-2.5 text-[11.5px] outline-none transition focus:border-primary/50 focus:ring-2 focus:ring-ring/40"
                />
              </div>
            </>
          )}

          {/* Test result */}
          {test === "testing" && (
            <div className="flex items-center gap-2 rounded-xl border border-border bg-muted/40 px-3 py-2.5 text-[12px] text-muted-foreground">
              <Loader2 className="h-4 w-4 animate-spin text-primary" /> Testing connection…
            </div>
          )}
          {test === "ok" && (
            <motion.div
              initial={{ opacity: 0, y: 4 }}
              animate={{ opacity: 1, y: 0 }}
              className="flex items-center gap-2 rounded-xl border border-success/25 bg-success/10 px-3 py-2.5 text-[12px] font-semibold text-success"
            >
              <CheckCircle2 className="h-4 w-4" /> Connection successful — read-only role verified.
            </motion.div>
          )}
        </div>

        {/* security note */}
        <div className="flex items-start gap-2 rounded-xl border border-primary/15 bg-primary/5 px-3.5 py-3">
          <ShieldCheck className="mt-0.5 h-4 w-4 shrink-0 text-primary" />
          <p className="text-[11.5px] leading-relaxed text-muted-foreground">
            Aegivion requires <span className="font-semibold text-foreground">read-only permissions only</span>.
            Remediation flows use your existing CI/CD identity.
          </p>
        </div>

        <div className="flex flex-wrap items-center justify-end gap-2 pt-1">
          <Button variant="ghost" onClick={handleClose} disabled={connecting}>
            Cancel
          </Button>
          <Button variant="outline" onClick={runTest} disabled={connecting || !valid || test === "testing"}>
            {test === "testing" ? (
              <>
                <Loader2 className="h-4 w-4 animate-spin" /> Testing…
              </>
            ) : provider === "gcp" ? (
              "Validate"
            ) : (
              "Test Connection"
            )}
          </Button>
          <Button variant="gradient" onClick={doConnect} disabled={connecting || test !== "ok"}>
            {connecting ? (
              <>
                <Loader2 className="h-4 w-4 animate-spin" /> Connecting…
              </>
            ) : (
              <>
                Connect {provider ? (provider === "azure" ? "Azure" : provider === "gcp" ? "GCP" : "AWS") : ""}
              </>
            )}
          </Button>
        </div>
      </DialogContent>
    </Dialog>
  );
}
