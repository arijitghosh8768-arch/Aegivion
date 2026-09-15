"use client";

import { useEffect, useState } from "react";
import { useAppStore } from "@/lib/store";
import { useRouter } from "next/navigation";
import { fetchApi } from "@/lib/api-client";
import { motion } from "framer-motion";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Plus, Building2, Users, Loader2 } from "lucide-react";

export default function SuperAdminPage() {
  const router = useRouter();
  const user = useAppStore((s) => s.user);
  
  const [orgs, setOrgs] = useState<any[]>([]);
  const [loading, setLoading] = useState(true);
  const [creatingOrg, setCreatingOrg] = useState(false);
  const [orgName, setOrgName] = useState("");
  
  const [creatingAdmin, setCreatingAdmin] = useState(false);
  const [adminEmail, setAdminEmail] = useState("");
  const [adminPassword, setAdminPassword] = useState("");
  const [selectedOrgId, setSelectedOrgId] = useState("");

  useEffect(() => {
    // Basic protection - if not superadmin, bounce them
    if (user && user.role !== "superadmin" && user.role !== "Super Admin") {
      router.push("/");
    } else if (user) {
      fetchOrgs();
    }
  }, [user]);

  const fetchOrgs = async () => {
    setLoading(true);
    try {
      const res = await fetchApi("/v1/admin/orgs");
      if (res) {
        setOrgs(res.data || []);
      }
    } catch (e) {
      console.error(e);
    } finally {
      setLoading(false);
    }
  };

  const handleCreateOrg = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!orgName) return;
    setCreatingOrg(true);
    try {
      const res = await fetchApi("/v1/admin/orgs", {
        method: "POST",
        body: JSON.stringify({ name: orgName })
      });
      if (res) {
        setOrgName("");
        fetchOrgs();
      }
    } finally {
      setCreatingOrg(false);
    }
  };

  const handleCreateAdmin = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!adminEmail || !adminPassword || !selectedOrgId) return;
    setCreatingAdmin(true);
    try {
      const res = await fetchApi("/v1/admin/users", {
        method: "POST",
        body: JSON.stringify({ 
          email: adminEmail, 
          password: adminPassword, 
          org_id: selectedOrgId,
          role: "admin"
        })
      });
      if (res) {
        setAdminEmail("");
        setAdminPassword("");
        alert("Org Admin created successfully!");
      } else {
        alert("Failed to create user");
      }
    } finally {
      setCreatingAdmin(false);
    }
  };

  if (!user || loading) return <div className="flex h-screen items-center justify-center"><Loader2 className="h-8 w-8 animate-spin" /></div>;

  return (
    <div className="flex flex-col gap-6 p-8 max-w-6xl mx-auto">
      <div>
        <h1 className="text-3xl font-bold tracking-tight">Super Admin Control Panel</h1>
        <p className="text-muted-foreground mt-1">Manage global organizations and provision Org Admins.</p>
      </div>

      <div className="grid gap-6 md:grid-cols-2">
        {/* Create Organization */}
        <div className="rounded-xl border bg-card p-6 shadow-sm">
          <div className="flex items-center gap-3 mb-4">
            <Building2 className="h-5 w-5 text-primary" />
            <h2 className="text-xl font-semibold">Create Organization</h2>
          </div>
          <form onSubmit={handleCreateOrg} className="space-y-4">
            <div className="space-y-1.5">
              <Label htmlFor="orgName">Organization Name</Label>
              <Input
                id="orgName"
                placeholder="Acme Corp"
                value={orgName}
                onChange={(e) => setOrgName(e.target.value)}
              />
            </div>
            <Button type="submit" disabled={creatingOrg || !orgName}>
              {creatingOrg ? <Loader2 className="mr-2 h-4 w-4 animate-spin" /> : <Plus className="mr-2 h-4 w-4" />}
              Create Organization
            </Button>
          </form>
        </div>

        {/* Create Org Admin */}
        <div className="rounded-xl border bg-card p-6 shadow-sm">
          <div className="flex items-center gap-3 mb-4">
            <Users className="h-5 w-5 text-primary" />
            <h2 className="text-xl font-semibold">Provision Org Admin</h2>
          </div>
          <form onSubmit={handleCreateAdmin} className="space-y-4">
            <div className="space-y-1.5">
              <Label htmlFor="orgSelect">Assign to Organization</Label>
              <select
                id="orgSelect"
                className="flex h-10 w-full items-center justify-between rounded-md border border-input bg-background px-3 py-2 text-sm ring-offset-background placeholder:text-muted-foreground focus:outline-none focus:ring-2 focus:ring-ring focus:ring-offset-2 disabled:cursor-not-allowed disabled:opacity-50"
                value={selectedOrgId}
                onChange={(e) => setSelectedOrgId(e.target.value)}
              >
                <option value="" disabled>Select an Organization...</option>
                {orgs.map((o) => (
                  <option key={o.id} value={o.id}>{o.name || o.id}</option>
                ))}
              </select>
            </div>
            <div className="space-y-1.5">
              <Label htmlFor="adminEmail">Admin Email (Login ID)</Label>
              <Input
                id="adminEmail"
                type="email"
                placeholder="admin@company.com"
                value={adminEmail}
                onChange={(e) => setAdminEmail(e.target.value)}
              />
            </div>
            <div className="space-y-1.5">
              <Label htmlFor="adminPassword">Initial Password</Label>
              <Input
                id="adminPassword"
                type="text"
                placeholder="SuperSecret123!"
                value={adminPassword}
                onChange={(e) => setAdminPassword(e.target.value)}
              />
            </div>
            <Button type="submit" disabled={creatingAdmin || !adminEmail || !adminPassword || !selectedOrgId}>
              {creatingAdmin ? <Loader2 className="mr-2 h-4 w-4 animate-spin" /> : <Plus className="mr-2 h-4 w-4" />}
              Create Org Admin
            </Button>
          </form>
        </div>
      </div>

      {/* Orgs List */}
      <div className="rounded-xl border bg-card shadow-sm mt-4">
        <div className="p-6 border-b">
          <h2 className="text-xl font-semibold">Registered Organizations</h2>
        </div>
        <div className="p-0">
          <table className="w-full text-sm text-left">
            <thead className="bg-muted/50 border-b">
              <tr>
                <th className="px-6 py-3 font-medium text-muted-foreground">ID</th>
                <th className="px-6 py-3 font-medium text-muted-foreground">Name</th>
                <th className="px-6 py-3 font-medium text-muted-foreground">Created At</th>
              </tr>
            </thead>
            <tbody>
              {orgs.length === 0 ? (
                <tr>
                  <td colSpan={3} className="px-6 py-8 text-center text-muted-foreground">
                    No organizations found. Create one above.
                  </td>
                </tr>
              ) : (
                orgs.map((org) => (
                  <tr key={org.id} className="border-b last:border-0 hover:bg-muted/20">
                    <td className="px-6 py-4 font-mono text-xs">{org.id}</td>
                    <td className="px-6 py-4 font-medium">{org.name || "Unnamed Organization"}</td>
                    <td className="px-6 py-4 text-muted-foreground">{new Date(org.created_at || Date.now()).toLocaleDateString()}</td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}
