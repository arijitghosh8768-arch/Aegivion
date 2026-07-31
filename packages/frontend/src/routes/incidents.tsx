import React, { useState } from 'react';
import { createRoute } from '@tanstack/react-router';
import { Route as rootRoute } from './__root';
import { ShieldAlert, User, CheckCircle, RefreshCw } from 'lucide-react';

export const Route = createRoute({
  getParentRoute: () => rootRoute,
  path: '/incidents',
  component: IncidentsPage,
});

function IncidentsPage() {
  const [selectedIncidentIdx, setSelectedIncidentIdx] = useState(0);

  const incidents = [
    {
      id: 'INC-238',
      title: 'Public exposure of customer export bucket',
      sub: '3 findings · opened 2h ago',
      severity: 'Critical',
      severityColor: 'bg-red-500/20 text-red-400 border-red-500/30',
      status: 'Investigating',
      statusColor: 'bg-blue-500/10 text-blue-400 border-blue-500/20',
      owner: 'R. Okafor',
      timeline: [
        { title: 'Incident opened from finding AEG-1041', time: '2h ago' },
        { title: 'Assigned to Rana Okafor', time: '1h 40m ago' },
        { title: 'Bucket policy snapshot captured for evidence', time: '1h 05m ago' },
        { title: 'Public access block enabled in staging', time: '40m ago' },
        { title: 'Awaiting change approval for production', time: '12m ago' }
      ]
    },
    {
      id: 'INC-236',
      title: 'Unrestricted SSH ingress across production',
      sub: '2 findings · opened 6h ago',
      severity: 'Critical',
      severityColor: 'bg-red-500/20 text-red-400 border-red-500/30',
      status: 'Contained',
      statusColor: 'bg-indigo-500/10 text-indigo-400 border-indigo-500/20',
      owner: 'J. Doe',
      timeline: [
        { title: 'Incident triggered by port 22 open rule violation', time: '6h ago' },
        { title: 'Assigned to security triage team', time: '5h 30m ago' },
        { title: 'Temporary firewall ingress block applied', time: '4h ago' }
      ]
    },
    {
      id: 'INC-231',
      title: 'Stale administrator credentials in CI',
      sub: '4 findings · opened 1d ago',
      severity: 'High',
      severityColor: 'bg-orange-500/20 text-orange-400 border-orange-500/30',
      status: 'Triage',
      statusColor: 'bg-red-500/10 text-red-400 border-red-500/20',
      owner: 'A. Patel',
      timeline: [
        { title: 'Credential age audit threshold exceeded', time: '1d ago' },
        { title: 'Notification sent to CI owner', time: '20h ago' }
      ]
    },
    {
      id: 'INC-229',
      title: 'Anomalous IAM role assumption from new region',
      sub: '1 finding · opened 1d ago',
      severity: 'High',
      severityColor: 'bg-orange-500/20 text-orange-400 border-orange-500/30',
      status: 'Investigating',
      statusColor: 'bg-blue-500/10 text-blue-400 border-blue-500/20',
      owner: 'R. Okafor',
      timeline: [
        { title: 'Anomalous API logs flagged in CloudTrail', time: '1d ago' },
        { title: 'Assigned to Rana Okafor', time: '22h ago' }
      ]
    },
    {
      id: 'INC-224',
      title: 'Unencrypted reporting database',
      sub: '2 findings · opened 3d ago',
      severity: 'Medium',
      severityColor: 'bg-yellow-500/20 text-yellow-400 border-yellow-500/30',
      status: 'Contained',
      statusColor: 'bg-indigo-500/10 text-indigo-400 border-indigo-500/20',
      owner: 'M. Chen',
      timeline: [
        { title: 'Database resource encryption status check failed', time: '3d ago' },
        { title: 'Remediation plan approved', time: '2d ago' }
      ]
    },
    {
      id: 'INC-217',
      title: 'Build cache retention gap',
      sub: '1 finding · opened 6d ago',
      severity: 'Low',
      severityColor: 'bg-blue-500/20 text-blue-400 border-blue-500/30',
      status: 'Resolved',
      statusColor: 'bg-green-500/10 text-green-400 border-green-500/20',
      owner: 'S. Miller',
      timeline: [
        { title: 'Vulnerability scan complete', time: '6d ago' },
        { title: 'Retention policy patched via CLI', time: '5d ago' },
        { title: 'Closed incident', time: '5d ago' }
      ]
    }
  ];

  const activeInc = incidents[selectedIncidentIdx];

  return (
    <div className="space-y-6 text-gray-200">
      {/* Header bar */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 border-b border-gray-800 pb-5">
        <div>
          <h1 className="text-2xl font-bold text-white tracking-tight">Incidents</h1>
          <p className="text-gray-400 text-sm mt-1">6 active investigations across the estate.</p>
        </div>
        <button className="px-4 py-2 bg-blue-600 hover:bg-blue-500 text-white rounded-lg text-sm transition flex items-center gap-2">
          <ShieldAlert size={16} />
          Declare incident
        </button>
      </div>

      {/* Split Screen Master-Detail */}
      <div className="grid grid-cols-1 lg:grid-cols-5 gap-6">
        {/* Left: Incident Queue */}
        <div className="lg:col-span-3 bg-[#0e1428] border border-gray-800 rounded-xl p-5 flex flex-col gap-4">
          <div>
            <h2 className="text-sm font-bold text-white">Incident queue</h2>
            <p className="text-xs text-gray-500">Select an incident to review the response timeline</p>
          </div>
          
          <div className="space-y-2 overflow-y-auto max-h-[500px] pr-1">
            {incidents.map((inc, idx) => (
              <div 
                key={inc.id}
                onClick={() => setSelectedIncidentIdx(idx)}
                className={`p-4 border rounded-xl cursor-pointer transition flex items-center justify-between gap-4 ${
                  selectedIncidentIdx === idx 
                    ? 'bg-blue-600/5 border-blue-500/40' 
                    : 'bg-[#0b0f19]/40 border-gray-800 hover:bg-gray-850'
                }`}
              >
                <div>
                  <h3 className="font-semibold text-sm text-white">{inc.title}</h3>
                  <div className="text-[10px] text-gray-500 font-mono mt-1">
                    {inc.id} &middot; {inc.sub}
                  </div>
                </div>
                <div className="flex gap-2">
                  <span className={`px-2 py-0.5 border text-[9px] font-bold rounded ${inc.severityColor}`}>
                    {inc.severity}
                  </span>
                  <span className={`px-2 py-0.5 border text-[9px] font-semibold rounded ${inc.statusColor}`}>
                    {inc.status}
                  </span>
                </div>
              </div>
            ))}
          </div>
        </div>

        {/* Right: Incident Details */}
        <div className="lg:col-span-2 bg-[#0e1428] border border-gray-800 rounded-xl p-5 flex flex-col justify-between h-[590px]">
          <div className="space-y-6">
            <div>
              <h3 className="text-base font-bold text-white leading-snug">{activeInc.title}</h3>
              <span className="text-xs text-gray-500 font-mono">{activeInc.id}</span>
            </div>

            {/* Owner Section */}
            <div className="flex items-center justify-between p-3 bg-[#0b0f19]/55 rounded-lg border border-gray-800">
              <div className="flex items-center gap-3">
                <div className="w-8 h-8 rounded-full bg-blue-600/20 text-blue-400 flex items-center justify-center font-bold text-xs">
                  {activeInc.owner.split(' ').map(n => n[0]).join('')}
                </div>
                <div>
                  <h4 className="text-xs font-semibold text-white">{activeInc.owner}</h4>
                  <span className="text-[10px] text-gray-500">Incident owner</span>
                </div>
              </div>
              <button className="px-3 py-1.5 border border-gray-800 bg-[#0d1326] text-gray-300 rounded text-[10px] hover:text-white transition">
                Reassign
              </button>
            </div>

            {/* Timeline */}
            <div className="space-y-4">
              <h4 className="text-xs font-bold text-gray-400 uppercase tracking-wider">Resolution timeline</h4>
              <div className="relative border-l-2 border-gray-800 pl-4 space-y-5 ml-2">
                {activeInc.timeline.map((step, idx) => (
                  <div key={idx} className="relative">
                    <span className="absolute -left-[21px] top-1.5 w-2 h-2 rounded-full bg-blue-500"></span>
                    <p className="text-xs text-gray-300 font-medium leading-relaxed">{step.title}</p>
                    <span className="text-[10px] text-gray-500 block mt-0.5">{step.time}</span>
                  </div>
                ))}
              </div>
            </div>
          </div>

          {/* Footer Action Controls */}
          <div className="grid grid-cols-2 gap-3 pt-4 border-t border-gray-800/80">
            <button className="w-full py-2 bg-blue-600 hover:bg-blue-500 text-white rounded-lg text-xs font-semibold transition">
              Mark contained
            </button>
            <button className="w-full py-2 bg-gray-800 hover:bg-gray-700 text-white border border-gray-750 rounded-lg text-xs font-semibold transition">
              Close Incident
            </button>
          </div>
        </div>
      </div>
    </div>
  );
}
