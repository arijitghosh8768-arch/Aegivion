import React, { useState } from 'react';
import { createRoute } from '@tanstack/react-router';
import { Route as rootRoute } from './__root';
import { Plus, Key, Copy, Trash2 } from 'lucide-react';

export const Route = createRoute({
  getParentRoute: () => rootRoute,
  path: '/settings',
  component: SettingsPage,
});

function SettingsPage() {
  const [activeSubTab, setActiveSubTab] = useState('Users');
  const tabs = ['Users', 'Roles', 'Organization', 'API keys', 'Integrations'];

  const [orgName, setOrgName] = useState('Aegivion Global');
  const [orgDomain, setOrgDomain] = useState('aegivion.io');
  const [enforceSSO, setEnforceSSO] = useState(true);

  // Integrations states
  const [slackEnabled, setSlackEnabled] = useState(true);
  const [jiraEnabled, setJiraEnabled] = useState(true);
  const [pagerDutyEnabled, setPagerDutyEnabled] = useState(false);
  const [splunkEnabled, setSplunkEnabled] = useState(false);

  const users = [
    { name: 'Rana Okafor', email: 'rana@aegivion.io', role: 'Security Lead', status: 'Active', statusColor: 'bg-blue-500/10 text-blue-400 border-blue-500/20' },
    { name: 'Mikael Lindqvist', email: 'mikael@aegivion.io', role: 'Cloud Engineer', status: 'Active', statusColor: 'bg-blue-500/10 text-blue-400 border-blue-500/20' },
    { name: 'Sana Bhatt', email: 'sana@aegivion.io', role: 'Analyst', status: 'Active', statusColor: 'bg-blue-500/10 text-blue-400 border-blue-500/20' },
    { name: 'Jorge Alvarez', email: 'jorge@aegivion.io', role: 'Compliance', status: 'Pending', statusColor: 'bg-gray-500/10 text-gray-400 border-gray-500/20' }
  ];

  const roles = [
    { title: 'Owner', desc: 'Full administrative control', members: '1 members' },
    { title: 'Security Lead', desc: 'Manage findings, incidents, reports', members: '3 members' },
    { title: 'Analyst', desc: 'Read findings, comment, triage', members: '8 members' },
    { title: 'Auditor', desc: 'Read-only compliance evidence', members: '2 members' }
  ];

  const apiKeys = [
    { name: 'CI pipeline', key: 'aeg_live_9fzc...', meta: 'Created Feb 12, 2026 · last used 4 min ago' },
    { name: 'SIEM forwarder', key: 'aeg_live_31ab...', meta: 'Created Jan 04, 2026 · last used 1 h ago' }
  ];

  const integrations = [
    { id: 'slack', title: 'Slack', desc: 'Route critical findings to #sec-alerts', val: slackEnabled, setter: setSlackEnabled },
    { id: 'jira', title: 'Jira', desc: 'Create issues from findings', val: jiraEnabled, setter: setJiraEnabled },
    { id: 'pagerduty', title: 'PagerDuty', desc: 'Page on-call for critical incidents', val: pagerDutyEnabled, setter: setPagerDutyEnabled },
    { id: 'splunk', title: 'Splunk', desc: 'Forward events to your SIEM', val: splunkEnabled, setter: setSplunkEnabled }
  ];

  return (
    <div className="space-y-6 text-gray-200 pb-10">
      {/* Header bar */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 border-b border-gray-800 pb-5">
        <div>
          <h1 className="text-2xl font-bold text-white tracking-tight">Settings</h1>
          <p className="text-gray-400 text-sm mt-1">Workspace administration and integrations.</p>
        </div>
      </div>

      {/* Sub tabs navigation */}
      <div className="flex border border-gray-800 bg-[#0d1326]/60 w-fit p-1 rounded-xl gap-1">
        {tabs.map((t) => (
          <button
            key={t}
            onClick={() => setActiveSubTab(t)}
            className={`px-4 py-1.5 rounded-lg text-xs font-semibold transition ${
              activeSubTab === t 
                ? 'bg-[#121a36] text-white border border-gray-800' 
                : 'text-gray-400 hover:text-white'
            }`}
          >
            {t}
          </button>
        ))}
      </div>

      {/* Users view */}
      {activeSubTab === 'Users' && (
        <div className="bg-[#0e1428] border border-gray-800 rounded-xl p-5 space-y-4">
          <div className="flex justify-between items-center">
            <div>
              <h3 className="text-sm font-semibold text-white">Users</h3>
              <p className="text-xs text-gray-500">People with access to this workspace</p>
            </div>
            <button className="px-4 py-2 bg-blue-600 hover:bg-blue-500 text-white rounded-lg text-xs font-semibold transition flex items-center gap-1.5">
              <Plus size={14} />
              Invite
            </button>
          </div>

          <div className="overflow-x-auto pt-2">
            <table className="w-full text-left text-xs text-gray-300">
              <thead className="bg-[#0d1326] text-gray-400 uppercase text-[10px] tracking-wider font-semibold border-b border-gray-800">
                <tr>
                  <th className="px-6 py-4">Member</th>
                  <th className="px-6 py-4">Role</th>
                  <th className="px-6 py-4">Status</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-gray-800/65">
                {users.map((u, idx) => (
                  <tr key={idx} className="hover:bg-gray-800/10 transition">
                    <td className="px-6 py-4 flex items-center gap-3">
                      <div className="w-8 h-8 rounded-full bg-blue-600/20 text-blue-400 flex items-center justify-center font-bold text-xs">
                        {u.name.split(' ').map(n => n[0]).join('')}
                      </div>
                      <div>
                        <div className="font-semibold text-white text-sm">{u.name}</div>
                        <div className="text-[10px] text-gray-500">{u.email}</div>
                      </div>
                    </td>
                    <td className="px-6 py-4 text-gray-400 font-medium">{u.role}</td>
                    <td className="px-6 py-4">
                      <span className={`px-2.5 py-0.5 border text-[10px] font-semibold rounded ${u.statusColor}`}>
                        {u.status}
                      </span>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {/* Roles view */}
      {activeSubTab === 'Roles' && (
        <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
          {roles.map((r, idx) => (
            <div key={idx} className="bg-[#0e1428] border border-gray-800 rounded-xl p-5 flex flex-col justify-between h-36">
              <div>
                <h3 className="font-bold text-white text-sm">{r.title}</h3>
                <p className="text-xs text-gray-500 mt-2">{r.desc}</p>
              </div>
              <span className="w-fit px-3 py-1 bg-[#121a36] border border-gray-800 text-[10px] font-semibold text-gray-400 rounded-full">
                {r.members}
              </span>
            </div>
          ))}
        </div>
      )}

      {/* Organization view */}
      {activeSubTab === 'Organization' && (
        <div className="bg-[#0e1428] border border-gray-800 rounded-xl p-6 space-y-6 max-w-2xl">
          <div>
            <h3 className="font-bold text-white text-base">Organization</h3>
            <p className="text-xs text-gray-500 mt-1">Workspace identity and defaults</p>
          </div>

          <div className="space-y-4">
            <div className="space-y-1">
              <label className="text-xs text-gray-400 font-medium">Organization name</label>
              <input
                type="text"
                value={orgName}
                onChange={(e) => setOrgName(e.target.value)}
                className="w-full bg-[#0d1326] border border-gray-800 rounded-lg px-3 py-2.5 text-xs text-white focus:outline-none focus:border-gray-700 transition"
              />
            </div>

            <div className="space-y-1">
              <label className="text-xs text-gray-400 font-medium">Primary domain</label>
              <input
                type="text"
                value={orgDomain}
                onChange={(e) => setOrgDomain(e.target.value)}
                className="w-full bg-[#0d1326] border border-gray-800 rounded-lg px-3 py-2.5 text-xs text-white focus:outline-none focus:border-gray-700 transition"
              />
            </div>

            <div className="flex items-center justify-between pt-4 border-t border-gray-800/80">
              <div>
                <h4 className="text-xs font-semibold text-white">Enforce SSO</h4>
                <p className="text-[10px] text-gray-550 mt-0.5">Require SAML sign-in for all members</p>
              </div>
              <button
                type="button"
                onClick={() => setEnforceSSO(!enforceSSO)}
                className={`relative inline-flex h-5 w-9 shrink-0 cursor-pointer rounded-full border-2 border-transparent transition-colors duration-200 ease-in-out focus:outline-none ${
                  enforceSSO ? 'bg-blue-600' : 'bg-gray-800'
                }`}
              >
                <span
                  className={`pointer-events-none inline-block h-4.5 w-4.5 transform rounded-full bg-white shadow ring-0 transition duration-200 ease-in-out ${
                    enforceSSO ? 'translate-x-4' : 'translate-x-0'
                  }`}
                />
              </button>
            </div>
          </div>

          <button className="px-5 py-2.5 bg-blue-600 hover:bg-blue-500 text-white rounded-lg text-xs font-semibold shadow-lg shadow-blue-500/10 transition duration-200">
            Save changes
          </button>
        </div>
      )}

      {/* API keys view */}
      {activeSubTab === 'API keys' && (
        <div className="bg-[#0e1428] border border-gray-800 rounded-xl p-5 space-y-4">
          <div className="flex justify-between items-center pb-2 border-b border-gray-800/60">
            <div>
              <h3 className="font-bold text-white text-base">API keys</h3>
              <p className="text-xs text-gray-500 mt-1">Programmatic access to the Aegivion API</p>
            </div>
            <button className="px-4 py-2 bg-blue-600 hover:bg-blue-500 text-white rounded-lg text-xs font-semibold transition flex items-center gap-1.5">
              <Key size={14} />
              Create key
            </button>
          </div>

          <div className="divide-y divide-gray-800/80">
            {apiKeys.map((k, idx) => (
              <div key={idx} className="py-4 flex items-center justify-between gap-4">
                <div className="space-y-1">
                  <h4 className="font-semibold text-white text-xs">{k.name}</h4>
                  <div className="font-mono text-[11px] text-gray-400">{k.key}</div>
                  <div className="text-[10px] text-gray-500">{k.meta}</div>
                </div>
                <div className="flex items-center gap-2">
                  <button className="p-2 bg-[#0b0f19] border border-gray-800 text-gray-400 hover:text-white rounded-lg transition">
                    <Copy size={13} />
                  </button>
                  <button className="p-2 bg-[#0b0f19] border border-gray-800 text-gray-400 hover:text-red-400 rounded-lg transition">
                    <Trash2 size={13} />
                  </button>
                </div>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Integrations view */}
      {activeSubTab === 'Integrations' && (
        <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
          {integrations.map((i) => (
            <div key={i.id} className="bg-[#0e1428] border border-gray-800 rounded-xl p-5 flex justify-between items-center h-28">
              <div>
                <h3 className="font-bold text-white text-sm">{i.title}</h3>
                <p className="text-xs text-gray-500 mt-2">{i.desc}</p>
              </div>
              <button
                type="button"
                onClick={() => i.setter(!i.val)}
                className={`relative inline-flex h-5 w-9 shrink-0 cursor-pointer rounded-full border-2 border-transparent transition-colors duration-200 ease-in-out focus:outline-none ${
                  i.val ? 'bg-blue-600' : 'bg-gray-800'
                }`}
              >
                <span
                  className={`pointer-events-none inline-block h-4.5 w-4.5 transform rounded-full bg-white shadow ring-0 transition duration-200 ease-in-out ${
                    i.val ? 'translate-x-4' : 'translate-x-0'
                  }`}
                />
              </button>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}
