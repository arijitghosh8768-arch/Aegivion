import React, { useState } from 'react';
import { useMutation, useQueryClient } from '@tanstack/react-query';
import { api } from '@/lib/api';
import { UserCheck, ShieldAlert, FileText, Send, Calendar, ShieldCheck, Clock } from 'lucide-react';

interface Note {
  id: string;
  author: string;
  content: string;
  created_at: string;
}

interface TimelineEvent {
  timestamp: string;
  title: string;
  description: string;
}

interface AnalystActionsProps {
  findingId: string;
  currentStatus: string;
  currentAssignee?: string | null;
  timeline: TimelineEvent[];
  notes: Note[];
  onUpdate?: () => void;
}

export function AnalystActions({ 
  findingId, 
  currentStatus, 
  currentAssignee,
  timeline = [],
  notes = [],
  onUpdate
}: AnalystActionsProps) {
  const queryClient = useQueryClient();
  const [newNote, setNewNote] = useState('');
  const [selectedStatus, setSelectedStatus] = useState(currentStatus);
  const [selectedAssignee, setSelectedAssignee] = useState(currentAssignee || '');
  
  // Suppression Form modal state
  const [showSuppressModal, setShowSuppressModal] = useState(false);
  const [suppressReason, setSuppressReason] = useState('');
  const [suppressDays, setSuppressDays] = useState(30);

  // Update status mutation
  const updateStatusMutation = useMutation({
    mutationFn: async (status: string) => {
      const response = await api.patch(`/v1/findings/${findingId}/status`, { status });
      return response.data;
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['finding', findingId] });
      queryClient.invalidateQueries({ queryKey: ['findings'] });
      if (onUpdate) onUpdate();
    }
  });

  // Suppression mutation (M2 exception logging)
  const suppressMutation = useMutation({
    mutationFn: async () => {
      const response = await api.post(`/v1/history/findings/${findingId}/suppress?reason=${encodeURIComponent(suppressReason)}&days=${suppressDays}`);
      return response.data;
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['finding', findingId] });
      queryClient.invalidateQueries({ queryKey: ['findings'] });
      setShowSuppressModal(false);
      if (onUpdate) onUpdate();
    }
  });

  // Assign user mutation
  const assignUserMutation = useMutation({
    mutationFn: async (userId: string) => {
      const response = await api.patch(`/v1/findings/${findingId}/assign`, { user_id: userId });
      return response.data;
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['finding', findingId] });
      queryClient.invalidateQueries({ queryKey: ['findings'] });
      if (onUpdate) onUpdate();
    }
  });

  // Add note mutation
  const addNoteMutation = useMutation({
    mutationFn: async (content: string) => {
      const response = await api.post(`/v1/findings/${findingId}/notes`, { content });
      return response.data;
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['finding', findingId] });
      queryClient.invalidateQueries({ queryKey: ['findings'] });
      setNewNote('');
      if (onUpdate) onUpdate();
    }
  });

  const handleStatusChange = (e: React.ChangeEvent<HTMLSelectElement>) => {
    const val = e.target.value;
    setSelectedStatus(val);
    updateStatusMutation.mutate(val);
  };

  const handleAssigneeChange = (e: React.ChangeEvent<HTMLSelectElement>) => {
    const val = e.target.value;
    setSelectedAssignee(val);
    assignUserMutation.mutate(val);
  };

  const handleAddNote = (e: React.FormEvent) => {
    e.preventDefault();
    if (!newNote.trim()) return;
    addNoteMutation.mutate(newNote);
  };

  const statusOptions = [
    { value: 'open', label: 'Open' },
    { value: 'investigating', label: 'Investigating' },
    { value: 'mitigated', label: 'Mitigated' },
    { value: 'resolved', label: 'Resolved' },
    { value: 'suppressed', label: 'Suppressed' },
    { value: 'accepted_risk', label: 'Accepted Risk' }
  ];

  const assigneeOptions = [
    { value: '', label: 'Unassigned' },
    { value: 'analyst1', label: 'Security Analyst 1' },
    { value: 'analyst2', label: 'Security Analyst 2' },
    { value: 'secops', label: 'SecOps Team' }
  ];

  return (
    <div className="space-y-6">
      {/* Lifecycle Status & Suppress Button */}
      <div className="p-4 bg-[#0e1428] border border-gray-800 rounded-xl space-y-3">
        <h4 className="text-[10px] font-bold text-gray-500 uppercase tracking-wider flex items-center gap-1.5">
          <ShieldAlert size={12} className="text-blue-400" />
          Lifecycle Status
        </h4>
        <div className="flex flex-col gap-2">
          <select
            value={selectedStatus}
            onChange={handleStatusChange}
            className="w-full px-3 py-2 bg-[#0b0f19] border border-gray-850 rounded-lg text-xs text-gray-300 focus:outline-none focus:border-blue-500"
          >
            {statusOptions.map(opt => (
              <option key={opt.value} value={opt.value}>{opt.label}</option>
            ))}
          </select>
          {selectedStatus !== 'suppressed' ? (
            <button
              type="button"
              onClick={() => setShowSuppressModal(true)}
              className="w-full py-1.5 bg-yellow-600/10 hover:bg-yellow-600/20 text-yellow-400 border border-yellow-500/20 hover:text-white rounded-lg text-xs font-semibold transition"
            >
              Suppress Finding
            </button>
          ) : (
            <div className="p-2.5 bg-yellow-950/20 border border-yellow-900/30 text-[10px] text-yellow-400 rounded-lg flex items-center gap-1.5">
              <Clock size={12} />
              <span>Finding temporarily suppressed under rule exception policies.</span>
            </div>
          )}
        </div>
      </div>

      {/* Assignment Control */}
      <div className="p-4 bg-[#0e1428] border border-gray-800 rounded-xl space-y-3">
        <h4 className="text-[10px] font-bold text-gray-500 uppercase tracking-wider flex items-center gap-1.5">
          <UserCheck size={12} className="text-green-400" />
          Assignee
        </h4>
        <select
          value={selectedAssignee}
          onChange={handleAssigneeChange}
          className="w-full px-3 py-2 bg-[#0b0f19] border border-gray-850 rounded-lg text-xs text-gray-300 focus:outline-none focus:border-blue-500"
        >
          {assigneeOptions.map(opt => (
            <option key={opt.value} value={opt.value}>{opt.label}</option>
          ))}
        </select>
      </div>

      {/* Notes Form */}
      <div className="p-4 bg-[#0e1428] border border-gray-800 rounded-xl space-y-3">
        <h4 className="text-[10px] font-bold text-gray-500 uppercase tracking-wider flex items-center gap-1.5">
          <FileText size={12} className="text-yellow-400" />
          Analyst Notes
        </h4>
        <form onSubmit={handleAddNote} className="space-y-2">
          <textarea
            value={newNote}
            onChange={(e) => setNewNote(e.target.value)}
            placeholder="Add investigation logs..."
            rows={3}
            className="w-full px-3 py-2 bg-[#0b0f19] border border-gray-850 rounded-lg text-xs text-gray-350 focus:outline-none focus:border-blue-500 resize-none"
          />
          <button
            type="submit"
            disabled={!newNote.trim()}
            className="w-full py-2 bg-blue-600 hover:bg-blue-500 disabled:bg-gray-800 disabled:text-gray-500 text-white rounded-lg text-xs font-semibold transition flex items-center justify-center gap-1"
          >
            <Send size={12} />
            Post Note
          </button>
        </form>

        {notes && notes.length > 0 && (
          <div className="pt-3 border-t border-gray-800/60 space-y-2.5 max-h-48 overflow-y-auto">
            {notes.map((note) => (
              <div key={note.id} className="p-2.5 bg-[#0b0f19] border border-gray-850/60 rounded-lg text-[11px] space-y-1">
                <div className="flex justify-between font-semibold text-gray-400">
                  <span>{note.author}</span>
                  <span className="text-[9px] font-normal text-gray-500">
                    {new Date(note.created_at).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })}
                  </span>
                </div>
                <p className="text-gray-300 leading-normal">{note.content}</p>
              </div>
            ))}
          </div>
        )}
      </div>

      {/* Expiry Suppression Modal */}
      {showSuppressModal && (
        <div className="fixed inset-0 bg-black/60 backdrop-blur-sm flex items-center justify-center p-4 z-50">
          <div className="bg-[#0e1428] border border-gray-850 rounded-xl p-6 max-w-sm w-full space-y-4">
            <div>
              <h3 className="font-bold text-white text-sm">Temporary Rule Exception</h3>
              <p className="text-[10px] text-gray-500 mt-1">Specify authorization details to suppress this finding from active postures.</p>
            </div>
            
            <div className="space-y-3">
              <div>
                <label className="text-[9px] font-bold text-gray-500 uppercase tracking-wider block mb-1.5">Suppression Reason</label>
                <textarea
                  value={suppressReason}
                  onChange={(e) => setSuppressReason(e.target.value)}
                  placeholder="Migration test window, temporary security exception..."
                  rows={3}
                  className="w-full px-3 py-2 bg-[#0b0f19] border border-gray-850 rounded-lg text-xs text-white focus:outline-none focus:border-blue-500"
                />
              </div>

              <div>
                <label className="text-[9px] font-bold text-gray-500 uppercase tracking-wider block mb-1.5">Expiration Timeframe</label>
                <select
                  value={suppressDays}
                  onChange={(e) => setSuppressDays(Number(e.target.value))}
                  className="w-full px-3 py-2 bg-[#0b0f19] border border-gray-850 rounded-lg text-xs text-gray-300 focus:outline-none focus:border-blue-500"
                >
                  <option value={7}>7 Days</option>
                  <option value={30}>30 Days</option>
                  <option value={90}>90 Days</option>
                </select>
              </div>
            </div>

            <div className="flex justify-end gap-2 border-t border-gray-800 pt-3">
              <button
                type="button"
                onClick={() => setShowSuppressModal(false)}
                className="px-3.5 py-1.5 border border-gray-800 hover:bg-gray-850 text-gray-300 rounded text-[10px] font-semibold transition"
              >
                Cancel
              </button>
              <button
                type="button"
                onClick={() => suppressMutation.mutate()}
                disabled={!suppressReason.trim() || suppressMutation.isPending}
                className="px-3.5 py-1.5 bg-yellow-600 hover:bg-yellow-500 disabled:bg-gray-800 disabled:text-gray-500 text-white rounded text-[10px] font-semibold transition"
              >
                Suppress
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
