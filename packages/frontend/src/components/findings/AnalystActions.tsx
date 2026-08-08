import React, { useState } from 'react';
import { useMutation, useQueryClient } from '@tanstack/react-query';
import { api } from '@/lib/api';
import { UserCheck, ShieldAlert, FileText, Send, Calendar } from 'lucide-react';

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
      {/* Status Control */}
      <div className="p-4 bg-[#0e1428] border border-gray-800 rounded-xl space-y-3">
        <h4 className="text-[10px] font-bold text-gray-500 uppercase tracking-wider flex items-center gap-1.5">
          <ShieldAlert size={12} className="text-blue-400" />
          Lifecycle Status
        </h4>
        <div className="flex gap-2">
          <select
            value={selectedStatus}
            onChange={handleStatusChange}
            className="flex-1 px-3 py-2 bg-[#0b0f19] border border-gray-850 rounded-lg text-xs text-gray-300 focus:outline-none focus:border-blue-500"
          >
            {statusOptions.map(opt => (
              <option key={opt.value} value={opt.value}>{opt.label}</option>
            ))}
          </select>
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
            className="w-full px-3 py-2 bg-[#0b0f19] border border-gray-850 rounded-lg text-xs text-gray-305 focus:outline-none focus:border-blue-500 resize-none"
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

        {/* Notes list */}
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

      {/* Activity Timeline */}
      {timeline && timeline.length > 0 && (
        <div className="p-4 bg-[#0e1428] border border-gray-800 rounded-xl space-y-3">
          <h4 className="text-[10px] font-bold text-gray-500 uppercase tracking-wider flex items-center gap-1.5">
            <Calendar size={12} className="text-purple-400" />
            Activity Timeline
          </h4>
          <div className="space-y-3.5 pl-2 relative border-l border-gray-800 mt-2">
            {timeline.map((event, idx) => (
              <div key={idx} className="relative pl-4 text-[11px]">
                <div className="absolute -left-[5px] top-1.5 w-2.5 h-2.5 bg-gray-800 border border-blue-500 rounded-full" />
                <div className="flex justify-between font-semibold text-gray-350">
                  <span>{event.title}</span>
                  <span className="text-[9px] font-normal text-gray-500">
                    {new Date(event.timestamp).toLocaleDateString([], { month: 'short', day: 'numeric' })}
                  </span>
                </div>
                <p className="text-gray-400 mt-0.5 leading-normal">{event.description}</p>
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}
