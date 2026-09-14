"use client";

import { useRef, useState } from "react";
import Link from "next/link";
import { AnimatePresence, motion } from "framer-motion";
import {
  User,
  Building2,
  Bell,
  Users,
  List,
  ShieldCheck,
  Cloud,
  Plug2,
  Palette,
  KeyRound,
  Loader2,
  Check,
  ArrowRight,
  Camera,
  X,
  MonitorSmartphone,
  Smartphone,
  LogOut,
  Moon,
  Sun,
} from "lucide-react";
import { PageHeader } from "@/components/shared/page-header";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Switch } from "@/components/ui/switch";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Badge } from "@/components/ui/badge";
import { Avatar, AvatarFallback, AvatarImage } from "@/components/ui/avatar";
import { useAppStore, DEFAULT_PROFILE } from "@/lib/store";
import { useIntegrationsStore, INTEGRATION_DEFS } from "@/lib/integrations-store";
import { toast } from "@/lib/toast";
import { cn } from "@/lib/utils";

type SectionId = "profile" | "organization" | "users" | "notifications" | "security" | "audit" | "cloud" | "appearance" | "integrations";

const NAV: { id: SectionId; label: string; icon: React.ComponentType<{ className?: string }> }[] = [
  { id: "profile", label: "Profile", icon: User },
  { id: "organization", label: "Organization", icon: Building2 },
  { id: "users", label: "Users & Roles", icon: Users },
  { id: "notifications", label: "Notifications", icon: Bell },
  { id: "security", label: "Security", icon: ShieldCheck },
  { id: "audit", label: "Audit Log", icon: List },
  { id: "cloud", label: "Cloud Preferences", icon: Cloud },
  { id: "appearance", label: "Appearance", icon: Palette },
  { id: "integrations", label: "Integrations", icon: Plug2 },
];

export default function SettingsPage() {
  const [active, setActive] = useState<SectionId>("profile");

  return (
    <div className="mx-auto max-w-[1280px]">
      <PageHeader
        title="Settings"
        description="Manage your workspace, profile, integrations and security preferences."
      />

      <div className="grid gap-5 lg:grid-cols-[220px_1fr] xl:grid-cols-[220px_1fr_280px]">
        {/* Section nav */}
        <nav className="h-fit rounded-2xl border border-border bg-card p-2 shadow-soft">
          <div className="mb-1 px-2.5 pb-2 pt-1 text-[9.5px] font-semibold uppercase tracking-[0.16em] text-muted-foreground">
            Manage workspace
          </div>
          {NAV.map((n) => {
            const Icon = n.icon;
            const isActive = active === n.id;
            const external = n.id === "appearance" || n.id === "integrations";
            return (
              <div key={n.id}>
                {external ? (
                  <Link
                    href={n.id === "appearance" ? "/settings/appearance" : "/settings/integrations"}
                    className="group relative flex items-center gap-2.5 rounded-xl px-2.5 py-2 text-[12.5px] font-medium text-muted-foreground transition hover:bg-muted/70 hover:text-foreground"
                  >
                    <Icon className="h-4 w-4" />
                    {n.label}
                    <ArrowRight className="ml-auto h-3.5 w-3.5 opacity-0 transition group-hover:opacity-60" />
                  </Link>
                ) : (
                  <button
                    onClick={() => setActive(n.id)}
                    className={cn(
                      "relative flex w-full cursor-pointer items-center gap-2.5 rounded-xl px-2.5 py-2 text-[12.5px] font-medium transition",
                      isActive ? "text-primary" : "text-muted-foreground hover:bg-muted/70 hover:text-foreground"
                    )}
                  >
                    {isActive && (
                      <motion.span
                        layoutId="settings-nav-pill"
                        className="absolute inset-0 rounded-xl border border-primary/15 bg-primary/10"
                        transition={{ type: "spring", stiffness: 400, damping: 32 }}
                      />
                    )}
                    <Icon className={cn("relative z-10 h-4 w-4", isActive && "text-primary")} />
                    <span className="relative z-10">{n.label}</span>
                  </button>
                )}
              </div>
            );
          })}
        </nav>

        {/* Main section */}
        <div className="min-w-0">
          <AnimatePresence mode="wait">
            <motion.div
              key={active}
              initial={{ opacity: 0, y: 10 }}
              animate={{ opacity: 1, y: 0 }}
              exit={{ opacity: 0, y: -6 }}
              transition={{ duration: 0.25 }}
              className="space-y-5"
            >
              {active === "profile" && <ProfileSection />}
              {active === "organization" && <OrganizationSection />}
              {active === "users" && <UsersSection />}
              {active === "notifications" && <NotificationsSection />}
              {active === "security" && <SecuritySection />}
              {active === "audit" && <AuditSection />}
              {active === "cloud" && <CloudSection />}
            </motion.div>
          </AnimatePresence>
        </div>

        {/* Right rail */}
        <div className="space-y-4">
          <IntegrationsCard />
          <AppearanceCard />
        </div>
      </div>
    </div>
  );
}

/* ------------------------------------------------------------------ */
/* Profile                                                            */
/* ------------------------------------------------------------------ */

function ProfileSection() {
  const user = useAppStore((s) => s.user);
  const updateUser = useAppStore((s) => s.updateUser);
  const p = user ?? DEFAULT_PROFILE;

  const [form, setForm] = useState({
    name: p?.name ?? "Admin User",
    username: p?.username ?? "admin",
    email: p?.email ?? "admin@acme.com",
    phone: p?.phone ?? "+1 (555) 010-2030",
    company: p?.company ?? "Acme Corp",
    jobRole: p?.jobRole ?? "Security Architect",
    department: p?.department ?? "Platform Security",
    country: p?.country ?? "United States",
    timezone: p?.timezone ?? "America/New_York",
    language: p?.language ?? "English (US)",
  });
  const [avatar, setAvatar] = useState(p?.avatar ?? "");
  const [errors, setErrors] = useState<Record<string, string>>({});
  const [saving, setSaving] = useState(false);
  const [saved, setSaved] = useState(false);
  const fileRef = useRef<HTMLInputElement>(null);

  const dirty =
    JSON.stringify(form) !==
      JSON.stringify({
        name: p?.name,
        username: p?.username,
        email: p?.email,
        phone: p?.phone,
        company: p?.company,
        jobRole: p?.jobRole,
        department: p?.department,
        country: p?.country,
        timezone: p?.timezone,
        language: p?.language,
      }) ||
    avatar !== (p?.avatar ?? "");

  const set = (k: keyof typeof form) => (e: React.ChangeEvent<HTMLInputElement>) =>
    setForm((f) => ({ ...f, [k]: e.target.value }));

  const uploadAvatar = (file: File) => {
    if (file.size > 2 * 1024 * 1024) {
      toast("error", "Image too large", "Please choose an image under 2 MB.");
      return;
    }
    if (!file.type.startsWith("image/")) {
      toast("error", "Invalid file type", "Please choose an image file.");
      return;
    }
    const reader = new FileReader();
    reader.onload = () => setAvatar(String(reader.result));
    reader.readAsDataURL(file);
  };

  const validate = () => {
    const e: Record<string, string> = {};
    if (!form.name.trim()) e.name = "Full name is required";
    else if (form.name.trim().length < 3) e.name = "Name must be at least 3 characters";
    if (!form.username.trim()) e.username = "Username is required";
    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(form.email)) e.email = "Enter a valid work email";
    if (form.phone && !/^[+\d][\d\s\-()]{6,}$/.test(form.phone)) e.phone = "Enter a valid phone number";
    setErrors(e);
    return Object.keys(e).length === 0;
  };

  const save = () => {
    if (!validate()) return;
    setSaving(true);
    setTimeout(() => {
      updateUser({ ...form, avatar });
      setSaving(false);
      setSaved(true);
      toast("success", "Profile saved", "Your changes are live across Aegivion instantly.");
      setTimeout(() => setSaved(false), 2000);
    }, 900);
  };

  return (
    <SectionShell icon={User} title="Profile" subtitle="This information appears across Aegivion — sidebar, top bar, reports and AI copilot.">
      {/* Avatar + name/email */}
      <div className="flex items-center gap-4">
        <div className="relative shrink-0">
          <Avatar className="h-16 w-16">
            {avatar && <AvatarImage src={avatar} alt={form.name} />}
            <AvatarFallback className="bg-brand-gradient text-lg">{form.name.slice(0, 2).toUpperCase()}</AvatarFallback>
          </Avatar>
          <button
            onClick={() => fileRef.current?.click()}
            className="absolute -bottom-1 -right-1 flex h-6 w-6 cursor-pointer items-center justify-center rounded-full border-2 border-card bg-primary text-white shadow-soft transition hover:bg-primary-soft"
            aria-label="Upload profile picture"
          >
            <Camera className="h-3 w-3" />
          </button>
          <input
            ref={fileRef}
            type="file"
            accept="image/*"
            className="hidden"
            onChange={(e) => {
              if (e.target.files?.[0]) uploadAvatar(e.target.files[0]);
              e.target.value = "";
            }}
          />
        </div>
        <div className="min-w-0 flex-1">
          <div className="text-[14.5px] font-bold">{form.name}</div>
          <div className="text-[11.5px] text-muted-foreground">@{form.username}</div>
          <div className="mt-1.5 flex gap-2">
            {avatar && (
              <Button variant="outline" size="sm" onClick={() => setAvatar("")}>
                <X className="h-3.5 w-3.5" /> Remove
              </Button>
            )}
            <Button variant="outline" size="sm" onClick={() => fileRef.current?.click()}>
              <Camera className="h-3.5 w-3.5" /> Change photo
            </Button>
          </div>
        </div>
      </div>

      <div className="mt-5 grid gap-3.5 sm:grid-cols-2">
        <Field label="Full name" error={errors.name}>
          <Input value={form.name} onChange={set("name")} />
        </Field>
        <Field label="Username" error={errors.username}>
          <Input value={form.username} onChange={set("username")} />
        </Field>
        <Field label="Work email" error={errors.email}>
          <Input value={form.email} onChange={set("email")} />
        </Field>
        <Field label="Phone number" error={errors.phone}>
          <Input value={form.phone} onChange={set("phone")} placeholder="+1 (555) 000-0000" />
        </Field>
        <Field label="Organization">
          <Input value={form.company} onChange={set("company")} />
        </Field>
        <Field label="Job role">
          <Input value={form.jobRole} onChange={set("jobRole")} />
        </Field>
        <Field label="Department">
          <Input value={form.department} onChange={set("department")} />
        </Field>
        <Field label="Country">
          <Input value={form.country} onChange={set("country")} />
        </Field>
        <Field label="Timezone">
          <Input value={form.timezone} onChange={set("timezone")} />
        </Field>
        <Field label="Language">
          <Input value={form.language} onChange={set("language")} />
        </Field>
      </div>

      <div className="mt-5 flex items-center justify-end gap-2 border-t border-border/60 pt-4">
        <span className="mr-auto text-[11.5px] text-muted-foreground">
          {dirty ? (
            <span className="flex items-center gap-1.5 font-medium text-warning">
              <span className="h-1.5 w-1.5 rounded-full bg-warning" /> Unsaved changes
            </span>
          ) : (
            "All changes saved"
          )}
        </span>
        <Button variant="outline" size="sm" onClick={() => setSaved(false)} disabled={!dirty || saving}>
          Cancel
        </Button>
        <Button variant="gradient" size="sm" onClick={save} disabled={!dirty || saving}>
          {saving ? (
            <>
              <Loader2 className="h-3.5 w-3.5 animate-spin" /> Saving…
            </>
          ) : saved ? (
            <>
              <Check className="h-3.5 w-3.5" /> Saved
            </>
          ) : (
            "Save changes"
          )}
        </Button>
      </div>
    </SectionShell>
  );
}

/* ------------------------------------------------------------------ */
/* Organization                                                       */
/* ------------------------------------------------------------------ */

function OrganizationSection() {
  const org = useAppStore((s) => s.org);
  const setOrg = useAppStore((s) => s.setOrg);
  const [draft, setDraft] = useState(org);
  const [saving, setSaving] = useState(false);
  const dirty = JSON.stringify(draft) !== JSON.stringify(org);

  const save = async () => {
    setSaving(true);
    try {
      const res = await fetch("http://localhost:8000/api/v1/orgs/org-1/settings", {
        method: "PATCH",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          security_policy: {
            require_exception_approval: draft.requireExceptionApproval,
            auto_suppress_non_prod: draft.autoSuppressNonProd,
          },
          enabled_cloud_providers: [draft.primaryCloud],
        })
      });
      if (res.ok) {
        setOrg(draft);
        toast("success", "Organization saved", "Workspace settings updated across the platform.");
      } else {
        toast("error", "Error saving settings", "Please try again later.");
      }
    } catch (e) {
      toast("error", "Error saving settings", "Network error occurred.");
    } finally {
      setSaving(false);
    }
  };

  return (
    <SectionShell icon={Building2} title="Organization" subtitle="Workspace identity, logo and compliance scope.">
      <div className="grid gap-3.5 sm:grid-cols-2">
        <Field label="Workspace name">
          <Input value={draft.workspaceName} onChange={(e) => setDraft((d) => ({ ...d, workspaceName: e.target.value }))} />
        </Field>
        <Field label="Company name">
          <Input value={draft.companyName} onChange={(e) => setDraft((d) => ({ ...d, companyName: e.target.value }))} />
        </Field>
        <Field label="Primary cloud">
          <Select value={draft.primaryCloud} onValueChange={(v) => setDraft((d) => ({ ...d, primaryCloud: v as "aws" | "azure" | "gcp" }))}>
            <SelectTrigger>
              <SelectValue />
            </SelectTrigger>
            <SelectContent>
              <SelectItem value="aws">Amazon Web Services</SelectItem>
              <SelectItem value="azure">Microsoft Azure</SelectItem>
              <SelectItem value="gcp">Google Cloud</SelectItem>
            </SelectContent>
          </Select>
        </Field>
        <Field label="Default region">
          <Input value={draft.region} onChange={(e) => setDraft((d) => ({ ...d, region: e.target.value }))} />
        </Field>
        <div className="sm:col-span-2 space-y-4 pt-4 mt-2 border-t border-border/60">
          <h4 className="text-[13px] font-medium">Security Policies</h4>
          <div className="flex items-center justify-between gap-4 rounded-xl border border-border/60 px-4 py-3">
            <div>
              <div className="text-[13px] font-medium">Require Exception Approvals</div>
              <div className="text-[11.5px] text-muted-foreground">Require separate approval for exceptions on Critical/High findings</div>
            </div>
            <Switch checked={draft.requireExceptionApproval ?? false} onCheckedChange={(v) => setDraft((d) => ({ ...d, requireExceptionApproval: v }))} />
          </div>
          <div className="flex items-center justify-between gap-4 rounded-xl border border-border/60 px-4 py-3">
            <div>
              <div className="text-[13px] font-medium">Auto-suppress non-production</div>
              <div className="text-[11.5px] text-muted-foreground">Automatically suppress Low/Info findings in non-prod environments</div>
            </div>
            <Switch checked={draft.autoSuppressNonProd ?? false} onCheckedChange={(v) => setDraft((d) => ({ ...d, autoSuppressNonProd: v }))} />
          </div>
        </div>
      </div>
      <div className="mt-5 flex justify-end gap-2 border-t border-border/60 pt-4">
        <Button variant="outline" size="sm" disabled={!dirty || saving}>
          Cancel
        </Button>
        <Button variant="gradient" size="sm" onClick={save} disabled={!dirty || saving}>
          {saving ? <Loader2 className="h-3.5 w-3.5 animate-spin" /> : <Check className="h-3.5 w-3.5" />} Save changes
        </Button>
      </div>
    </SectionShell>
  );
}

/* ------------------------------------------------------------------ */
/* Notifications                                                      */
/* ------------------------------------------------------------------ */

function NotificationsSection() {
  const prefs = useAppStore((s) => s.notifPrefs);
  const setPrefs = useAppStore((s) => s.setNotifPrefs);
  const [draft, setDraft] = useState(prefs);

  const rows: { key: keyof typeof draft; label: string; desc: string }[] = [
    { key: "emailAlerts", label: "Email alerts", desc: "Send security emails to your inbox" },
    { key: "criticalFindings", label: "Critical findings", desc: "Page you immediately for critical & high severity" },
    { key: "dailySummary", label: "Daily summary", desc: "Posture summary every day at 08:00" },
    { key: "weeklyReport", label: "Weekly report", desc: "Full security report every Monday" },
    { key: "cloudConnectionAlerts", label: "Cloud connection alerts", desc: "Notify when a cloud account disconnects" },
    { key: "aiRecommendations", label: "AI recommendations", desc: "Aegivion AI suggestions in your feed" },
    { key: "browserNotifications", label: "Browser notifications", desc: "In-app toast alerts while working" },
  ];

  return (
    <SectionShell icon={Bell} title="Notifications" subtitle="Choose how Aegivion reaches you.">
      <div className="space-y-2">
        {rows.map((r) => (
          <div
            key={r.key}
            className="flex items-center justify-between gap-4 rounded-xl border border-border/60 px-4 py-3 transition hover:bg-muted/40"
          >
            <div>
              <div className="text-[13px] font-medium">{r.label}</div>
              <div className="text-[11.5px] text-muted-foreground">{r.desc}</div>
            </div>
            <Switch checked={draft[r.key]} onCheckedChange={(v) => setDraft((d) => ({ ...d, [r.key]: v }))} />
          </div>
        ))}
      </div>
      <div className="mt-5 flex justify-end gap-2 border-t border-border/60 pt-4">
        <Button variant="outline" size="sm" onClick={() => setDraft(prefs)} disabled={JSON.stringify(draft) === JSON.stringify(prefs)}>
          Reset
        </Button>
        <Button
          variant="gradient"
          size="sm"
          disabled={JSON.stringify(draft) === JSON.stringify(prefs)}
          onClick={() => {
            setPrefs(draft);
            toast("success", "Notification preferences saved");
          }}
        >
          <Check className="h-3.5 w-3.5" /> Save preferences
        </Button>
      </div>
    </SectionShell>
  );
}

/* ------------------------------------------------------------------ */
/* Security                                                           */
/* ------------------------------------------------------------------ */

function SecuritySection() {
  const [mfa, setMfa] = useState(true);
  const [recoveryEmail, setRecoveryEmail] = useState("security@acme.com");
  const [recoveryPhone, setRecoveryPhone] = useState("+1 (555) 010-2030");

  return (
    <SectionShell icon={ShieldCheck} title="Security" subtitle="Password, MFA, sessions and API tokens.">
      <div className="space-y-2.5">
        <div className="flex items-center justify-between gap-4 rounded-xl border border-border/60 px-4 py-3">
          <div>
            <div className="text-[13px] font-medium">Change password</div>
            <div className="text-[11.5px] text-muted-foreground">Last changed 34 days ago</div>
          </div>
          <Button variant="outline" size="sm" onClick={() => toast("info", "Password reset email sent")}>
            <KeyRound className="h-3.5 w-3.5" /> Change
          </Button>
        </div>

        <div className="flex items-center justify-between gap-4 rounded-xl border border-border/60 px-4 py-3">
          <div>
            <div className="text-[13px] font-medium">Two-factor authentication (MFA)</div>
            <div className="text-[11.5px] text-muted-foreground">Required for all admin roles</div>
          </div>
          <Switch checked={mfa} onCheckedChange={(v) => { setMfa(v); toast(v ? "success" : "info", v ? "MFA enabled" : "MFA disabled"); }} />
        </div>

        <div className="grid gap-3.5 sm:grid-cols-2">
          <Field label="Recovery email">
            <Input value={recoveryEmail} onChange={(e) => setRecoveryEmail(e.target.value)} />
          </Field>
          <Field label="Recovery phone">
            <Input value={recoveryPhone} onChange={(e) => setRecoveryPhone(e.target.value)} />
          </Field>
        </div>

        <div className="rounded-xl border border-border/60 p-4">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-2.5">
              <span className="flex h-8 w-8 items-center justify-center rounded-lg bg-success/10 text-success">
                <MonitorSmartphone className="h-4 w-4" />
              </span>
              <div>
                <div className="text-[13px] font-medium">Active sessions</div>
                <div className="text-[11.5px] text-muted-foreground">Windows · Chrome · New York — this device</div>
              </div>
              <Badge variant="success" className="ml-2">Current</Badge>
            </div>
          </div>
          <div className="mt-3 flex items-center justify-between rounded-lg bg-muted/40 px-3 py-2.5">
            <div className="flex items-center gap-2 text-[12px] text-muted-foreground">
              <Smartphone className="h-3.5 w-3.5" /> iPhone 15 · Safari · 2h ago
            </div>
            <Button variant="ghost" size="sm" className="text-destructive hover:text-destructive" onClick={() => toast("success", "Session revoked")}>
              Revoke
            </Button>
          </div>
          <Button variant="destructive" size="sm" className="mt-3" onClick={() => toast("warning", "All other sessions signed out")}>
            <LogOut className="h-3.5 w-3.5" /> Logout all devices
          </Button>
        </div>

        <div className="flex items-center justify-between gap-4 rounded-xl border border-border/60 px-4 py-3">
          <div>
            <div className="text-[13px] font-medium">API tokens</div>
            <div className="text-[11.5px] text-muted-foreground">ak_aeg_7f3a…9c21 · last used 2h ago</div>
          </div>
          <Button variant="outline" size="sm" onClick={() => toast("success", "API token rotated", "The previous token was revoked.")}>
            <KeyRound className="h-3.5 w-3.5" /> Rotate
          </Button>
        </div>
      </div>
    </SectionShell>
  );
}

/* ------------------------------------------------------------------ */
/* Cloud preferences                                                  */
/* ------------------------------------------------------------------ */

function CloudSection() {
  const prefs = useAppStore((s) => s.cloudPrefs);
  const setPrefs = useAppStore((s) => s.setCloudPrefs);
  const [draft, setDraft] = useState(prefs);
  const dirty = JSON.stringify(draft) !== JSON.stringify(prefs);

  return (
    <SectionShell icon={Cloud} title="Cloud Preferences" subtitle="Defaults used by scanning, topology and AI analysis.">
      <div className="grid gap-3.5 sm:grid-cols-2">
        <Field label="Default cloud">
          <Select value={draft.defaultCloud} onValueChange={(v) => setDraft((d) => ({ ...d, defaultCloud: v as "aws" | "azure" | "gcp" }))}>
            <SelectTrigger>
              <SelectValue />
            </SelectTrigger>
            <SelectContent>
              <SelectItem value="aws">Amazon Web Services</SelectItem>
              <SelectItem value="azure">Microsoft Azure</SelectItem>
              <SelectItem value="gcp">Google Cloud</SelectItem>
            </SelectContent>
          </Select>
        </Field>
        <Field label="Default region">
          <Select value={draft.defaultRegion} onValueChange={(v) => setDraft((d) => ({ ...d, defaultRegion: v }))}>
            <SelectTrigger>
              <SelectValue />
            </SelectTrigger>
            <SelectContent>
              <SelectItem value="us-east-1 (N. Virginia)">us-east-1 (N. Virginia)</SelectItem>
              <SelectItem value="us-west-2 (Oregon)">us-west-2 (Oregon)</SelectItem>
              <SelectItem value="eu-west-1 (Ireland)">eu-west-1 (Ireland)</SelectItem>
              <SelectItem value="ap-south-1 (Mumbai)">ap-south-1 (Mumbai)</SelectItem>
            </SelectContent>
          </Select>
        </Field>
        <Field label="Preferred dashboard">
          <Select value={draft.preferredDashboard} onValueChange={(v) => setDraft((d) => ({ ...d, preferredDashboard: v }))}>
            <SelectTrigger>
              <SelectValue />
            </SelectTrigger>
            <SelectContent>
              <SelectItem value="Command Center">Command Center</SelectItem>
              <SelectItem value="Cloud Topology">Cloud Topology</SelectItem>
              <SelectItem value="Detection Engine">Detection Engine</SelectItem>
              <SelectItem value="Threat Correlation">Threat Correlation</SelectItem>
            </SelectContent>
          </Select>
        </Field>
        <div className="space-y-1">
          <Label>Scanning behavior</Label>
          <div className="flex h-9 items-center gap-4 rounded-xl border border-border/60 bg-card/50 px-3">
            <label className="flex cursor-pointer items-center gap-1.5 text-[11.5px] font-medium">
              <input type="checkbox" className="accent-[#6d5df6]" checked={draft.autoRefresh} onChange={(e) => setDraft((d) => ({ ...d, autoRefresh: e.target.checked }))} /> Auto refresh
            </label>
            <label className="flex cursor-pointer items-center gap-1.5 text-[11.5px] font-medium">
              <input type="checkbox" className="accent-[#6d5df6]" checked={draft.autoScan} onChange={(e) => setDraft((d) => ({ ...d, autoScan: e.target.checked }))} /> Auto scan
            </label>
          </div>
        </div>
      </div>
      <div className="mt-5 flex justify-end gap-2 border-t border-border/60 pt-4">
        <Button variant="outline" size="sm" onClick={() => setDraft(prefs)} disabled={!dirty}>
          Cancel
        </Button>
        <Button
          variant="gradient"
          size="sm"
          disabled={!dirty}
          onClick={() => {
            setPrefs(draft);
            toast("success", "Cloud preferences saved");
          }}
        >
          <Check className="h-3.5 w-3.5" /> Save preferences
        </Button>
      </div>
    </SectionShell>
  );
}

/* ------------------------------------------------------------------ */
/* Right rail cards                                                   */
/* ------------------------------------------------------------------ */

function IntegrationsCard() {
  const items = useIntegrationsStore((s) => s.items);
  const connected = INTEGRATION_DEFS.filter((d) => items[d.id]?.status === "connected");

  return (
    <div className="rounded-2xl border border-border bg-card p-4 shadow-soft">
      <div className="flex items-center justify-between">
        <h3 className="flex items-center gap-2 text-[13px] font-semibold">
          <Plug2 className="h-4 w-4 text-primary" /> Integrations
        </h3>
        <Link href="/settings/integrations" className="flex items-center gap-0.5 text-[11px] font-semibold text-primary transition hover:gap-1.5">
          Manage <ArrowRight className="h-3 w-3" />
        </Link>
      </div>
      <div className="mt-3 space-y-2">
        {connected.slice(0, 4).map((d) => (
          <div key={d.id} className="flex items-center gap-2.5 rounded-xl border border-border/60 px-3 py-2.5">
            <span className="h-2 w-2 shrink-0 rounded-full bg-success" />
            <div className="min-w-0 flex-1">
              <div className="truncate text-[12.5px] font-semibold">{d.name}</div>
              <div className="truncate text-[10.5px] text-muted-foreground">{d.features[0]}</div>
            </div>
            <Link href="/settings/integrations" className="rounded-lg border border-border px-2.5 py-1 text-[10.5px] font-semibold text-muted-foreground transition hover:border-primary/40 hover:text-foreground">
              Configure
            </Link>
          </div>
        ))}
        {connected.length === 0 && (
          <div className="rounded-xl border border-dashed border-border px-3 py-4 text-center text-[11.5px] text-muted-foreground">
            No integrations connected yet.
          </div>
        )}
      </div>
      <div className="mt-3 border-t border-border/60 pt-2.5 text-[11px] text-muted-foreground">
        {connected.length}/{INTEGRATION_DEFS.length} integrations active
      </div>
    </div>
  );
}

function AppearanceCard() {
  const appearance = useAppStore((s) => s.appearance);
  const setAppearance = useAppStore((s) => s.setAppearance);

  return (
    <div className="rounded-2xl border border-border bg-card p-4 shadow-soft">
      <div className="flex items-center justify-between">
        <h3 className="flex items-center gap-2 text-[13px] font-semibold">
          <Palette className="h-4 w-4 text-primary" /> Appearance
        </h3>
        <Link href="/settings/appearance" className="flex items-center gap-0.5 text-[11px] font-semibold text-primary transition hover:gap-1.5">
          Customize <ArrowRight className="h-3 w-3" />
        </Link>
      </div>
      <div className="mt-3 space-y-2.5">
        <div>
          <div className="mb-1.5 text-[10.5px] font-semibold uppercase tracking-wide text-muted-foreground">Theme mode</div>
          <div className="flex gap-1.5">
            {(["system", "light", "dark"] as const).map((m) => (
              <button
                key={m}
                onClick={() => setAppearance({ themeMode: m })}
                className={cn(
                  "flex h-8 flex-1 cursor-pointer items-center justify-center gap-1 rounded-lg border text-[11px] font-semibold capitalize transition",
                  appearance.themeMode === m
                    ? "border-primary/40 bg-primary/10 text-primary"
                    : "border-border bg-muted/40 text-muted-foreground hover:text-foreground"
                )}
              >
                {m === "dark" ? <Moon className="h-3 w-3" /> : m === "light" ? <Sun className="h-3 w-3" /> : <MonitorSmartphone className="h-3 w-3" />}
                {m}
              </button>
            ))}
          </div>
        </div>
        <div>
          <div className="mb-1.5 text-[10.5px] font-semibold uppercase tracking-wide text-muted-foreground">Accent color</div>
          <div className="flex gap-2">
            {(["purple", "blue", "emerald", "indigo"] as const).map((a) => (
              <button
                key={a}
                onClick={() => setAppearance({ accent: a })}
                aria-label={`Accent ${a}`}
                className={cn(
                  "h-7 w-7 cursor-pointer rounded-full border-2 transition",
                  appearance.accent === a ? "scale-110 border-foreground" : "border-transparent hover:scale-105"
                )}
                style={{ background: ACCENTS[a] }}
              />
            ))}
          </div>
        </div>
      </div>
    </div>
  );
}

/* ------------------------------------------------------------------ */
/* Shared                                                             */
/* ------------------------------------------------------------------ */

const ACCENTS = {
  purple: "#6d5df6",
  blue: "#3b82f6",
  emerald: "#10b981",
  indigo: "#4f46e5",
};

function SectionShell({
  icon: Icon,
  title,
  subtitle,
  children,
}: {
  icon: React.ComponentType<{ className?: string }>;
  title: string;
  subtitle?: string;
  children: React.ReactNode;
}) {
  return (
    <section className="rounded-2xl border border-border bg-card p-5 shadow-soft">
      <div className="mb-5 flex items-center gap-2.5">
        <span className="flex h-8 w-8 items-center justify-center rounded-xl bg-primary/10">
          <Icon className="h-4 w-4 text-primary" />
        </span>
        <div>
          <h3 className="text-[15px] font-bold leading-tight">{title}</h3>
          {subtitle && <p className="mt-0.5 text-[11px] text-muted-foreground">{subtitle}</p>}
        </div>
      </div>
      {children}
    </section>
  );
}

function Field({
  label,
  error,
  className,
  children,
}: {
  label: string;
  error?: string;
  className?: string;
  children: React.ReactNode;
}) {
  return (
    <div className={cn("space-y-1.5", className)}>
      <Label className="text-[12.5px] font-medium">{label}</Label>
      {children}
      {error && <p className="text-[11px] font-medium text-destructive">{error}</p>}
    </div>
  );
}

/* ------------------------------------------------------------------ */
/* Users & Roles                                                      */
/* ------------------------------------------------------------------ */

function UsersSection() {
  const users = [
    { id: 1, name: "Admin User", email: "admin@aegivion.internal", role: "Super Admin", status: "Active" },
    { id: 2, name: "Security Analyst", email: "analyst@aegivion.internal", role: "Analyst", status: "Active" },
    { id: 3, name: "Engineering Lead", email: "eng@aegivion.internal", role: "Viewer", status: "Invited" },
  ];

  return (
    <SectionShell icon={Users} title="Users & Roles" subtitle="Manage workspace access and role permissions.">
      <div className="flex justify-end mb-4">
        <Button variant="outline" size="sm">Invite User</Button>
      </div>
      <div className="space-y-2">
        {users.map(u => (
          <div key={u.id} className="flex items-center justify-between gap-4 rounded-xl border border-border/60 px-4 py-3">
            <div className="flex items-center gap-3">
              <Avatar className="h-8 w-8">
                <AvatarFallback className="text-[10px] bg-primary/10 text-primary">{u.name.slice(0,2).toUpperCase()}</AvatarFallback>
              </Avatar>
              <div>
                <div className="text-[13px] font-medium">{u.name}</div>
                <div className="text-[11.5px] text-muted-foreground">{u.email}</div>
              </div>
            </div>
            <div className="flex items-center gap-4">
              <Badge variant="outline" className="text-[10px] font-mono">{u.role}</Badge>
              <Badge variant={u.status === 'Active' ? 'success' : 'outline'} className="text-[10px]">{u.status}</Badge>
              <Button variant="ghost" size="sm" className="h-6 px-2 text-xs">Edit</Button>
            </div>
          </div>
        ))}
      </div>
    </SectionShell>
  );
}

/* ------------------------------------------------------------------ */
/* Audit Log                                                          */
/* ------------------------------------------------------------------ */

function AuditSection() {
  const logs = [
    { id: 1, action: "User Login", user: "Admin User", time: "2 mins ago", details: "Successful login from New York" },
    { id: 2, action: "Security Policy Updated", user: "Admin User", time: "1 hr ago", details: "require_exception_approval set to True" },
    { id: 3, action: "Exception Approved", user: "Security Analyst", time: "2 hrs ago", details: "Approved exception EX-1042 for finding F-99" },
    { id: 4, action: "Cloud Account Added", user: "Admin User", time: "1 day ago", details: "AWS Production (123456789012) linked" },
  ];

  return (
    <SectionShell icon={List} title="Audit Log" subtitle="Comprehensive immutable record of actions taken in the workspace.">
      <div className="flex gap-2 mb-4">
        <Input placeholder="Search audit logs..." className="h-8 text-xs" />
        <Button variant="outline" size="sm" className="h-8">Filter</Button>
      </div>
      <div className="rounded-xl border border-border/60 overflow-hidden">
        <table className="w-full text-left text-[12px]">
          <thead className="bg-muted/40 text-muted-foreground border-b border-border/60">
            <tr>
              <th className="px-4 py-2 font-medium">Action</th>
              <th className="px-4 py-2 font-medium">User</th>
              <th className="px-4 py-2 font-medium">Time</th>
              <th className="px-4 py-2 font-medium">Details</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-border/60">
            {logs.map(log => (
              <tr key={log.id} className="hover:bg-muted/20 transition-colors">
                <td className="px-4 py-2.5 font-medium">{log.action}</td>
                <td className="px-4 py-2.5 text-muted-foreground">{log.user}</td>
                <td className="px-4 py-2.5 text-muted-foreground">{log.time}</td>
                <td className="px-4 py-2.5 text-muted-foreground font-mono text-[10px]">{log.details}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </SectionShell>
  );
}
