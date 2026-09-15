"use client";

import { useEffect, useState } from "react";
import { useAppStore } from "@/lib/store";
import { useRouter } from "next/navigation";
import { fetchApi } from "@/lib/api-client";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Plus, Users, Loader2, Trash2 } from "lucide-react";

export default function TeamPage() {
  const router = useRouter();
  const user = useAppStore((s) => s.user);
  
  const [invites, setInvites] = useState<any[]>([]);
  const [loading, setLoading] = useState(true);
  const [inviting, setInviting] = useState(false);
  const [email, setEmail] = useState("");
  const [role, setRole] = useState("viewer");
  
  // Super Admin org selection
  const [orgs, setOrgs] = useState<any[]>([]);
  const [targetOrg, setTargetOrg] = useState<string>("");

  const isSuperAdmin = user?.role?.toLowerCase().replace(/\s/g, "") === "superadmin";

  useEffect(() => {
    // Only admins can view this page
    if (user && user.role !== "admin" && user.role !== "superadmin" && user.role !== "super admin") {
      router.push("/");
    } else if (user && user.company) {
      if (isSuperAdmin) {
        fetchOrgs();
      }
      // If super admin hasn't selected an org yet, use their company as default
      if (!targetOrg) {
        setTargetOrg(user.company);
      }
      fetchInvites(targetOrg || user.company);
    }
  }, [user, targetOrg]);

  const fetchOrgs = async () => {
    try {
      const res = await fetchApi<any>("/v1/admin/orgs");
      if (res && res.data) {
        setOrgs(res.data);
      }
    } catch (e) {
      console.error("Failed to fetch orgs:", e);
    }
  };

  const fetchInvites = async (orgId: string) => {
    if (!orgId) return;
    setLoading(true);
    try {
      const res = await fetchApi<any>(`/v1/orgs/${orgId}/invitations`);
      if (res) {
        setInvites(res.data || []);
      }
    } catch (e) {
      console.error(e);
    } finally {
      setLoading(false);
    }
  };

  const handleInvite = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!email) return;
    
    const orgId = targetOrg || user?.company;
    if (!orgId) return;

    setInviting(true);
    try {
      const res = await fetchApi(`/v1/orgs/${orgId}/invitations`, {
        method: "POST",
        body: JSON.stringify({ email, role })
      });
      if (res) {
        setEmail("");
        fetchInvites(orgId);
      } else {
        alert("Failed to invite user");
      }
    } finally {
      setInviting(false);
    }
  };

  const handleRevoke = async (id: string) => {
    if (!confirm("Are you sure you want to revoke this invitation?")) return;
    
    try {
      const res = await fetchApi(`/v1/invitations/${id}`, {
        method: "DELETE",
      });
      if (res) {
        fetchInvites(targetOrg || user?.company || "");
      }
    } catch (e) {
      console.error(e);
    }
  };

  if (!user || loading) return <div className="flex h-[calc(100vh-100px)] items-center justify-center"><Loader2 className="h-8 w-8 animate-spin" /></div>;

  return (
    <div className="flex flex-col gap-6 p-6 max-w-5xl mx-auto">
      <div>
        <h1 className="text-3xl font-bold tracking-tight">Team Management</h1>
        <p className="text-muted-foreground mt-1">Manage your organization's employee allowlist.</p>
      </div>

      <div className="grid gap-6 md:grid-cols-3">
        {/* Invite Form */}
        <div className="md:col-span-1 rounded-xl border bg-card p-6 shadow-sm h-fit">
          <div className="flex items-center gap-3 mb-4">
            <Users className="h-5 w-5 text-primary" />
            <h2 className="text-xl font-semibold">Add Employee</h2>
          </div>
          <form onSubmit={handleInvite} className="space-y-4">
            <div className="space-y-1.5">
              <Label htmlFor="email">Employee Email</Label>
              <Input
                id="email"
                type="email"
                placeholder="john@company.com"
                value={email}
                onChange={(e) => setEmail(e.target.value)}
              />
            </div>
            
            {isSuperAdmin && (
              <div className="space-y-1.5">
                <Label htmlFor="orgSelect">Target Organization</Label>
                <select
                  id="orgSelect"
                  className="flex h-10 w-full items-center justify-between rounded-md border border-input bg-background px-3 py-2 text-sm ring-offset-background placeholder:text-muted-foreground focus:outline-none focus:ring-2 focus:ring-ring focus:ring-offset-2 disabled:cursor-not-allowed disabled:opacity-50"
                  value={targetOrg}
                  onChange={(e) => setTargetOrg(e.target.value)}
                >
                  {orgs.map(org => (
                    <option key={org.id} value={org.id}>{org.name}</option>
                  ))}
                  {!orgs.find(o => o.id === user.company) && (
                    <option value={user.company}>My Organization</option>
                  )}
                </select>
              </div>
            )}

            <div className="space-y-1.5">
              <Label htmlFor="roleSelect">Role</Label>
              <select
                id="roleSelect"
                className="flex h-10 w-full items-center justify-between rounded-md border border-input bg-background px-3 py-2 text-sm ring-offset-background placeholder:text-muted-foreground focus:outline-none focus:ring-2 focus:ring-ring focus:ring-offset-2 disabled:cursor-not-allowed disabled:opacity-50"
                value={role}
                onChange={(e) => setRole(e.target.value)}
              >
                <option value="viewer">Viewer</option>
                <option value="analyst">Security Analyst</option>
                <option value="admin">Admin</option>
              </select>
            </div>
            <Button type="submit" disabled={inviting || !email} className="w-full">
              {inviting ? <Loader2 className="mr-2 h-4 w-4 animate-spin" /> : <Plus className="mr-2 h-4 w-4" />}
              Add to Allowlist
            </Button>
          </form>
          <div className="mt-4 text-xs text-muted-foreground p-3 bg-muted/50 rounded-lg">
            <strong>Note:</strong> Employees must log in using Google OAuth. If their email is not on this list, they will be blocked.
          </div>
        </div>

        {/* Userlist */}
        <div className="md:col-span-2 rounded-xl border bg-card shadow-sm">
          <div className="p-6 border-b flex justify-between items-center">
            <h2 className="text-xl font-semibold">Employee Allowlist</h2>
            {isSuperAdmin && (
              <span className="text-xs text-muted-foreground">Showing: {orgs.find(o => o.id === targetOrg)?.name || "Current Org"}</span>
            )}
          </div>
          <div className="p-0">
            <table className="w-full text-sm text-left">
              <thead className="bg-muted/50 border-b">
                <tr>
                  <th className="px-6 py-3 font-medium text-muted-foreground">Email</th>
                  <th className="px-6 py-3 font-medium text-muted-foreground">Role</th>
                  <th className="px-6 py-3 font-medium text-muted-foreground">Status</th>
                  <th className="px-6 py-3 font-medium text-muted-foreground text-right">Actions</th>
                </tr>
              </thead>
              <tbody>
                {invites.length === 0 ? (
                  <tr>
                    <td colSpan={4} className="px-6 py-8 text-center text-muted-foreground">
                      No employees on the allowlist yet. Add one to the left.
                    </td>
                  </tr>
                ) : (
                  invites.map((inv) => (
                    <tr key={inv.id} className="border-b last:border-0 hover:bg-muted/20">
                      <td className="px-6 py-4 font-medium">{inv.email}</td>
                      <td className="px-6 py-4 capitalize">{inv.role_id || inv.role || "viewer"}</td>
                      <td className="px-6 py-4">
                        <span className={`inline-flex items-center px-2 py-1 rounded-full text-xs font-medium ${inv.status === 'PENDING' ? 'bg-yellow-100 text-yellow-800 dark:bg-yellow-900/30 dark:text-yellow-500' : inv.status === 'ACCEPTED' ? 'bg-green-100 text-green-800 dark:bg-green-900/30 dark:text-green-500' : 'bg-red-100 text-red-800 dark:bg-red-900/30 dark:text-red-500'}`}>
                          {inv.status || "PENDING"}
                        </span>
                      </td>
                      <td className="px-6 py-4 text-right">
                        {(!inv.status || inv.status === 'PENDING') && (
                          <Button variant="ghost" size="sm" onClick={() => handleRevoke(inv.id)} className="text-destructive hover:text-destructive hover:bg-destructive/10">
                            <Trash2 className="h-4 w-4" />
                          </Button>
                        )}
                      </td>
                    </tr>
                  ))
                )}
              </tbody>
            </table>
          </div>
        </div>
      </div>
    </div>
  );
}
