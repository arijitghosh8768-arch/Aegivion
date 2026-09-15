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

  useEffect(() => {
    // Only admins can view this page
    if (user && user.role !== "admin" && user.role !== "superadmin") {
      router.push("/");
    } else if (user && user.company) {
      fetchInvites();
    }
  }, [user]);

  const fetchInvites = async () => {
    setLoading(true);
    try {
      const res = await fetchApi<any>(`/v1/orgs/${user?.company}/invitations`);
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
    setInviting(true);
    try {
      const res = await fetchApi(`/v1/orgs/${user?.company}/invitations`, {
        method: "POST",
        body: JSON.stringify({ email, role })
      });
      if (res) {
        setEmail("");
        fetchInvites();
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
        fetchInvites();
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
          <div className="p-6 border-b">
            <h2 className="text-xl font-semibold">Employee Allowlist</h2>
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
                      <td className="px-6 py-4 capitalize">{inv.role_id}</td>
                      <td className="px-6 py-4">
                        <span className={`inline-flex items-center px-2 py-1 rounded-full text-xs font-medium ${inv.status === 'PENDING' ? 'bg-yellow-100 text-yellow-800 dark:bg-yellow-900/30 dark:text-yellow-500' : inv.status === 'ACCEPTED' ? 'bg-green-100 text-green-800 dark:bg-green-900/30 dark:text-green-500' : 'bg-red-100 text-red-800 dark:bg-red-900/30 dark:text-red-500'}`}>
                          {inv.status}
                        </span>
                      </td>
                      <td className="px-6 py-4 text-right">
                        {inv.status === 'PENDING' && (
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
