
import re

with open("temp_admin.tsx", "r", encoding="utf-8") as f:
    content = f.read()

# Add lucide icon
content = content.replace("Plus, Building2, Users, Loader2", "Plus, Building2, Users, Loader2, Trash2")

# Add delete handlers
delete_handlers = """
  const handleDeleteOrg = async (id: string) => {
    if (!window.confirm("Are you sure you want to delete this organization?")) return;
    try {
      const res = await fetchApi(`/v1/admin/orgs/${id}`, { method: "DELETE" });
      if (res) {
        fetchOrgs();
      }
    } catch (e) {
      console.error(e);
    }
  };

  const handleDeleteAdmin = async (id: string) => {
    if (!window.confirm("Are you sure you want to delete this admin user?")) return;
    try {
      const res = await fetchApi(`/v1/admin/users/${id}`, { method: "DELETE" });
      if (res) {
        fetchAdmins();
      }
    } catch (e) {
      console.error(e);
    }
  };
"""

content = content.replace("const handleCreateOrg", delete_handlers + "\n  const handleCreateOrg")

# Update orgs table header
content = content.replace(
    """<th className="px-6 py-3 font-medium text-muted-foreground">Created At</th>
              </tr>""",
    """<th className="px-6 py-3 font-medium text-muted-foreground">Created At</th>
                <th className="px-6 py-3 font-medium text-muted-foreground text-right">Actions</th>
              </tr>"""
)

# Update orgs table row
content = content.replace(
    """<td className="px-6 py-4 text-muted-foreground">{new Date(org.created_at || Date.now()).toLocaleDateString()}</td>
                  </tr>""",
    """<td className="px-6 py-4 text-muted-foreground">{new Date(org.created_at || Date.now()).toLocaleDateString()}</td>
                    <td className="px-6 py-4 text-right">
                      <Button variant="ghost" size="sm" className="text-destructive hover:text-destructive hover:bg-destructive/10" onClick={() => handleDeleteOrg(org.id)}>
                        <Trash2 className="h-4 w-4" />
                      </Button>
                    </td>
                  </tr>"""
)

content = content.replace("colSpan={3}", "colSpan={4}")

# Update admins table header
content = content.replace(
    """<th className="px-6 py-3 font-medium text-muted-foreground">Created At</th>
              </tr>
            </thead>
            <tbody>
              {admins.length === 0 ? (
                <tr>
                  <td colSpan={4}""",
    """<th className="px-6 py-3 font-medium text-muted-foreground">Created At</th>
                <th className="px-6 py-3 font-medium text-muted-foreground text-right">Actions</th>
              </tr>
            </thead>
            <tbody>
              {admins.length === 0 ? (
                <tr>
                  <td colSpan={4}"""
)

# The earlier replace might not match if it was colSpan={3}, let me do it generically
content = re.sub(
    r"<th className=\"px-6 py-3 font-medium text-muted-foreground\">Created At</th>\s*</tr>\s*</thead>\s*<tbody>\s*\{\s*admins.length === 0 \? \(\s*<tr>\s*<td colSpan=\{3\}",
    """<th className="px-6 py-3 font-medium text-muted-foreground">Created At</th>
                <th className="px-6 py-3 font-medium text-muted-foreground text-right">Actions</th>
              </tr>
            </thead>
            <tbody>
              {admins.length === 0 ? (
                <tr>
                  <td colSpan={4}""",
    content
)

# Update admins table row
content = content.replace(
    """<td className="px-6 py-4 text-muted-foreground">{admin.created_at ? new Date(admin.created_at).toLocaleDateString() : "N/A"}</td>
                  </tr>""",
    """<td className="px-6 py-4 text-muted-foreground">{admin.created_at ? new Date(admin.created_at).toLocaleDateString() : "N/A"}</td>
                    <td className="px-6 py-4 text-right">
                      <Button variant="ghost" size="sm" className="text-destructive hover:text-destructive hover:bg-destructive/10" onClick={() => handleDeleteAdmin(admin.id)}>
                        <Trash2 className="h-4 w-4" />
                      </Button>
                    </td>
                  </tr>"""
)

with open("packages/frontend/app/(dashboard)/admin/page.tsx", "w", encoding="utf-8") as f:
    f.write(content)

print("Patched!")

