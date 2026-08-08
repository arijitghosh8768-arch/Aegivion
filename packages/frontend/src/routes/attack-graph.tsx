import React, { useState } from 'react';
import { createRoute } from '@tanstack/react-router';
import { Route as rootRoute } from './__root';
import { useQuery } from '@tanstack/react-query';
import { api } from '@/lib/api';
import { 
  GitCommit, 
  RotateCw, 
  Search, 
  SlidersHorizontal, 
  AlertTriangle,
  Info,
  Shield,
  Layers,
  HelpCircle,
  Brain,
  Compass,
  FileText,
  TrendingUp,
  X
} from 'lucide-react';

export const Route = createRoute({
  getParentRoute: () => rootRoute,
  path: '/attack-graph',
  component: AttackGraphPage,
});

interface GraphNode {
  id: string;
  type: string;
  label: string;
}

interface GraphEdge {
  source: string;
  target: string;
  type: string;
  evidence: Record<string, any>;
}

interface AttackPath {
  path_id: string;
  nodes: string[];
  edges: string[];
  risk_score: number;
  confidence: string;
  evidence: Array<Record<string, any>>;
}

interface Explanation {
  summary: string;
  entry_point: string;
  path_steps: Array<{ step: number, description: string, evidence_refs: string[] }>;
  potential_scenario: string;
  potential_impact: string;
  uncertainty: string[];
  recommendations: string[];
}

function AttackGraphPage() {
  const [selectedPathId, setSelectedPathId] = useState<string | null>(null);
  const [selectedNodeId, setSelectedNodeId] = useState<string | null>(null);
  const [selectedEdge, setSelectedEdge] = useState<GraphEdge | null>(null);
  const [minRisk, setMinRisk] = useState<number>(50);

  // Query attack graph data
  const { data, isLoading, isError, refetch } = useQuery({
    queryKey: ['attack-graph'],
    queryFn: async () => {
      const res = await api.get('/v1/attack-graph');
      return res.data as { nodes: GraphNode[], edges: GraphEdge[], paths: AttackPath[] };
    }
  });

  // Query explanation for selected path
  const { data: explanation, isLoading: explanationLoading } = useQuery<Explanation>({
    queryKey: ['attack-path-explanation', selectedPathId],
    queryFn: async () => {
      const res = await api.post(`/v1/attack-graph/paths/${selectedPathId}/explain`);
      return res.data;
    },
    enabled: !!selectedPathId
  });

  const nodes = data?.nodes || [];
  const edges = data?.edges || [];
  const paths = data?.paths || [];

  const filteredPaths = paths.filter(p => p.risk_score >= minRisk);
  const activePath = paths.find(p => p.path_id === selectedPathId);

  const getEdgeStyle = (edge: GraphEdge) => {
    if (!activePath) return 'stroke-gray-700 opacity-60';
    const srcIndex = activePath.nodes.indexOf(edge.source);
    const tgtIndex = activePath.nodes.indexOf(edge.target);
    if (srcIndex !== -1 && tgtIndex !== -1 && Math.abs(srcIndex - tgtIndex) === 1) {
      return 'stroke-red-500 stroke-[3px] animate-pulse';
    }
    return 'stroke-gray-800 opacity-20';
  };

  const getNodeStyle = (node: GraphNode) => {
    const isSelected = selectedNodeId === node.id;
    const isExposed = node.id === 'INTERNET';
    const isTarget = node.type === 'S3_BUCKET';
    
    let border = 'border-gray-800 bg-[#0b0f19]';
    if (isSelected) border = 'border-blue-500 ring-2 ring-blue-500/20 bg-blue-950/20';
    else if (isExposed) border = 'border-orange-500/50 bg-orange-950/10 text-orange-400';
    else if (isTarget) border = 'border-red-500/50 bg-red-950/10 text-red-400';

    return `p-3 rounded-lg border text-center transition cursor-pointer ${border}`;
  };

  return (
    <div className="space-y-6 text-gray-200 pb-16">
      {/* Header */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 border-b border-gray-800 pb-5">
        <div>
          <h1 className="text-2xl font-bold text-white tracking-tight flex items-center gap-2">
            <Compass size={22} className="text-blue-500" />
            Attack Path Graph
          </h1>
          <p className="text-gray-400 text-sm mt-1">
            Map relationship chains and isolate potential security routes toward sensitive resources.
          </p>
        </div>
        <button 
          onClick={() => refetch()}
          className="px-4 py-2 bg-blue-600/10 border border-blue-500/20 text-blue-400 hover:text-white hover:bg-blue-600 rounded-lg text-xs font-semibold transition flex items-center gap-1.5"
        >
          <RotateCw size={14} className={isLoading ? 'animate-spin' : ''} />
          Recalculate Paths
        </button>
      </div>

      {/* Warning of partial scan coverage */}
      <div className="p-4 bg-yellow-950/20 border border-yellow-900/30 rounded-xl flex items-start gap-3">
        <AlertTriangle className="text-yellow-500 shrink-0 w-4 h-4 mt-0.5" />
        <div>
          <h4 className="text-[11px] font-bold text-yellow-400">Partial Graph Coverage</h4>
          <p className="text-[10px] text-gray-400 mt-0.5">
            IAM collection has incomplete permissions. Hidden trust links or access policies might be omitted from these paths.
          </p>
        </div>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-4 gap-6">
        
        {/* Left Side: Paths Queue & Controls */}
        <div className="lg:col-span-1 space-y-4">
          <div className="bg-[#0e1428] border border-gray-850 p-4 rounded-xl space-y-4">
            <div className="flex items-center justify-between">
              <span className="text-xs font-bold text-white uppercase tracking-wider text-gray-400">Risk Threshold</span>
              <span className="text-xs font-bold text-red-400">{minRisk}+ Risk</span>
            </div>
            <input 
              type="range" 
              min="0" 
              max="100" 
              value={minRisk} 
              onChange={(e) => setMinRisk(Number(e.target.value))}
              className="w-full h-1 bg-gray-800 rounded-lg appearance-none cursor-pointer accent-blue-500" 
            />

            <div className="border-t border-gray-800/80 pt-4 space-y-2">
              <span className="text-[10px] font-bold text-gray-500 uppercase tracking-wider block">Potential Paths ({filteredPaths.length})</span>
              {filteredPaths.length === 0 ? (
                <p className="text-[11px] text-gray-550 py-3">No paths match current risk criteria.</p>
              ) : (
                <div className="space-y-1.5 max-h-[300px] overflow-y-auto pr-1">
                  {filteredPaths.map((p) => (
                    <button
                      key={p.path_id}
                      onClick={() => {
                        setSelectedPathId(p.path_id === selectedPathId ? null : p.path_id);
                        setSelectedNodeId(null);
                        setSelectedEdge(null);
                      }}
                      className={`w-full p-2.5 text-left border rounded-lg text-xs transition block ${
                        selectedPathId === p.path_id 
                          ? 'bg-blue-600/10 border-blue-500/40 text-white' 
                          : 'bg-[#0b0f19]/35 border-gray-850 text-gray-400 hover:text-white'
                      }`}
                    >
                      <div className="flex items-center justify-between">
                        <span className="font-bold font-mono">{p.path_id}</span>
                        <span className="text-[10px] font-bold text-red-400">{p.risk_score}/100</span>
                      </div>
                      <p className="text-[10px] text-gray-500 mt-1 truncate">
                        {p.nodes.join(' ➔ ')}
                      </p>
                    </button>
                  ))}
                </div>
              )}
            </div>
          </div>
        </div>

        {/* Center: Graph Canvas Area */}
        <div className="lg:col-span-2 bg-[#0e1428] border border-gray-850 rounded-xl p-5 relative min-h-[450px] flex flex-col justify-between">
          <div className="flex items-center justify-between border-b border-gray-800/60 pb-3">
            <span className="text-xs font-bold text-white uppercase tracking-wider text-gray-400">Security Graph Viewer</span>
            <div className="flex items-center gap-1.5 text-[10px] text-gray-500">
              <span className="w-2.5 h-2.5 rounded bg-orange-500/20 border border-orange-500/40" /> Ingress
              <span className="w-2.5 h-2.5 rounded bg-red-500/20 border border-red-500/40 ml-2" /> Target
            </div>
          </div>

          {/* Simple Dynamic Flow Layout */}
          {isLoading ? (
            <div className="flex items-center justify-center py-24">
              <RotateCw className="w-8 h-8 text-blue-500 animate-spin" />
            </div>
          ) : (
            <div className="flex flex-col items-center justify-center space-y-8 py-8 w-full">
              {nodes.map((node) => (
                <div 
                  key={node.id} 
                  onClick={() => {
                    setSelectedNodeId(node.id === selectedNodeId ? null : node.id);
                    setSelectedEdge(null);
                  }}
                  className={`${getNodeStyle(node)} w-64`}
                >
                  <span className="text-xs font-bold text-white block">{node.label}</span>
                  <span className="text-[9px] text-gray-500 font-mono block mt-0.5">{node.type}</span>
                </div>
              ))}
            </div>
          )}

          <div className="text-[10px] text-gray-500 border-t border-gray-800/60 pt-3">
            Click nodes above to inspect target asset metrics or configuration profiles.
          </div>
        </div>

        {/* Right Side: Drawer/Inspector */}
        <div className="lg:col-span-1">
          <div className="bg-[#0e1428] border border-gray-850 rounded-xl p-5 min-h-[450px]">
            
            {/* 1. Path Detail Active */}
            {activePath && (
              <div className="space-y-6 text-xs">
                <div className="flex items-center justify-between border-b border-gray-800 pb-3">
                  <h3 className="font-bold text-white uppercase tracking-wider text-gray-400">Path Inspector</h3>
                  <button onClick={() => setSelectedPathId(null)} className="text-gray-500 hover:text-white">
                    <X size={14} />
                  </button>
                </div>

                <div className="space-y-1">
                  <span className="text-[10px] text-gray-500 font-mono uppercase">{activePath.path_id}</span>
                  <div className="flex items-center gap-2">
                    <span className="text-red-400 font-bold text-sm">{activePath.risk_score}/100 Risk</span>
                    <span className="px-1.5 py-0.5 bg-blue-950/20 border border-blue-900/30 text-blue-400 text-[9px] font-bold rounded">
                      {activePath.confidence} CONFIDENCE
                    </span>
                  </div>
                </div>

                {/* AI Explanation Tab Panel */}
                <div className="border-t border-gray-800 pt-4 space-y-4">
                  <span className="text-[10px] font-bold text-white uppercase tracking-wider text-gray-400 flex items-center gap-1">
                    <Brain size={12} className="text-blue-400" /> AI Path Analysis
                  </span>
                  
                  {explanationLoading ? (
                    <div className="flex items-center gap-2 py-4 text-gray-500">
                      <RotateCw size={12} className="animate-spin" />
                      <span>Generating steps...</span>
                    </div>
                  ) : explanation ? (
                    <div className="space-y-4">
                      <div>
                        <span className="font-semibold text-white block">Logical Path Summary</span>
                        <p className="text-gray-400 text-[11px] mt-0.5 leading-normal">{explanation.summary}</p>
                      </div>
                      <div>
                        <span className="font-semibold text-white block">Conditional Scenario</span>
                        <p className="text-gray-300 text-[11px] font-medium mt-0.5 leading-normal">{explanation.potential_scenario}</p>
                      </div>
                      <div>
                        <span className="font-semibold text-white block">Uncertainty</span>
                        <ul className="list-disc pl-4 space-y-1 text-gray-400 text-[10px] mt-1">
                          {explanation.uncertainty.map((un, idx) => (
                            <li key={idx}>{un}</li>
                          ))}
                        </ul>
                      </div>
                    </div>
                  ) : (
                    <p className="text-gray-500">Explanation details unavailable.</p>
                  )}
                </div>
              </div>
            )}

            {/* 2. Node Inspector Active */}
            {!activePath && selectedNodeId && (
              <div className="space-y-4 text-xs">
                <div className="flex items-center justify-between border-b border-gray-800 pb-3">
                  <h3 className="font-bold text-white uppercase tracking-wider text-gray-400">Node Profile</h3>
                  <button onClick={() => setSelectedNodeId(null)} className="text-gray-500 hover:text-white">
                    <X size={14} />
                  </button>
                </div>

                <div>
                  <span className="text-[10px] text-gray-500 font-mono">{selectedNodeId}</span>
                  <h4 className="font-bold text-white text-sm mt-1">
                    {nodes.find(n => n.id === selectedNodeId)?.label || 'Cloud Asset'}
                  </h4>
                </div>

                <div className="space-y-2 border-t border-gray-800 pt-4">
                  <div className="flex justify-between">
                    <span className="text-gray-500">Type</span>
                    <span className="text-gray-300 font-mono uppercase">{nodes.find(n => n.id === selectedNodeId)?.type}</span>
                  </div>
                  <div className="flex justify-between">
                    <span className="text-gray-500">State</span>
                    <span className="text-green-400 font-semibold">Active</span>
                  </div>
                </div>
              </div>
            )}

            {/* 3. Empty Selection State */}
            {!activePath && !selectedNodeId && (
              <div className="flex flex-col items-center justify-center min-h-[300px] text-center space-y-2">
                <Layers className="text-gray-600 w-8 h-8" />
                <span className="text-xs font-bold text-gray-400">Select Node or Path</span>
                <p className="text-[10px] text-gray-550 max-w-xs leading-normal">
                  Select a threat path from the queue or click on a node in the graph viewer to inspect configuration details.
                </p>
              </div>
            )}
          </div>
        </div>

      </div>
    </div>
  );
}
