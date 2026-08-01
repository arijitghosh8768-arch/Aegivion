import React, { useState, useEffect } from 'react';
import { 
  Shield, 
  LayoutDashboard, 
  Terminal, 
  BrainCircuit, 
  Settings as SettingsIcon, 
  Menu, 
  X,
  AlertTriangle,
  CheckCircle,
  Database,
  ExternalLink,
  ChevronRight,
  BarChart3
} from 'lucide-react';

// Mock findings matching findings_schema.json
const mockFindings = [
  {
    finding_id: "finding-001",
    title: "S3 Bucket Public Access Enabled",
    severity: "High",
    resource_id: "arn:aws:s3:::aegivion-public-assets",
    resource_type: "aws_s3_bucket",
    cloud_provider: "AWS",
    description: "The S3 bucket 'aegivion-public-assets' is configured to allow public access. Anyone on the internet can read or write to it.",
    remediation: "Enable 'Block all public access' settings in S3 console or Terraform configuration."
  },
  {
    finding_id: "finding-002",
    title: "SSH Port Open to Internet",
    severity: "Critical",
    resource_id: "/subscriptions/sub-123/resourceGroups/aegivion-rg/providers/Microsoft.Compute/virtualMachines/aegivion-vm-01",
    resource_type: "azure_virtual_machine",
    cloud_provider: "Azure",
    description: "Port 22 (SSH) is open to the public internet (0.0.0.0/0). This allows unauthorized access attempts to the virtual machine.",
    remediation: "Restrict SSH access in the Network Security Group to trusted IP ranges or enable Just-In-Time access."
  },
  {
    finding_id: "finding-003",
    title: "Kubernetes Private Nodes Disabled",
    severity: "Medium",
    resource_id: "projects/aegivion-prod/zones/us-central1-a/clusters/aegivion-k8s-cluster",
    resource_type: "gcp_kubernetes_cluster",
    cloud_provider: "GCP",
    description: "Kubernetes cluster nodes are allocated public IPs. Nodes should reside in a private subnet to reduce attack surface.",
    remediation: "Recreate or configure the cluster with enable_private_nodes set to true."
  }
];

export default function App() {
  const [activeTab, setActiveTab] = useState('dashboard');
  const [sidebarOpen, setSidebarOpen] = useState(false);
  const [selectedFinding, setSelectedFinding] = useState<typeof mockFindings[0] | null>(null);
  const [aiAnalysis, setAiAnalysis] = useState<string>('');
  const [isAnalyzing, setIsAnalyzing] = useState(false);
  const [findingsList, setFindingsList] = useState<any[]>([]);
  const [assetsList, setAssetsList] = useState<any[]>([]);
  const [scanning, setScanning] = useState(false);

  const API_URL = import.meta.env.VITE_API_URL || 'http://localhost:8000';
  const WS_URL = API_URL.replace(/^http/, 'ws');

  const fetchFindings = async () => {
    try {
      const res = await fetch(`${API_URL}/api/v1/findings`);
      const data = await res.json();
      if (data && data.findings) {
        setFindingsList(data.findings);
      }
    } catch (err) {
      console.error('Failed to fetch findings:', err);
    }
  };

  const fetchAssets = async () => {
    try {
      const res = await fetch(`${API_URL}/api/v1/findings/assets`);
      const data = await res.json();
      if (data && data.assets) {
        setAssetsList(data.assets);
      }
    } catch (err) {
      console.error('Failed to fetch assets:', err);
    }
  };

  const handleTriggerScan = async () => {
    setScanning(true);
    try {
      const res = await fetch(`${API_URL}/api/v1/findings/scan`, {
        method: 'POST',
      });
      const data = await res.json();
      if (data && data.success) {
        fetchFindings();
        fetchAssets();
      }
    } catch (err) {
      console.error('Failed to trigger scan:', err);
    } finally {
      setScanning(false);
    }
  };

  useEffect(() => {
    fetchFindings();
    fetchAssets();
    
    // Establish real-time WebSocket connection to the backend service
    const socket = new WebSocket(`${WS_URL}/ws/dashboard?user_id=u-1234`);
    
    socket.onmessage = (event) => {
      try {
        const payload = JSON.parse(event.data);
        if (payload.type === 'new_finding') {
          setFindingsList((prev) => [payload.data, ...prev]);
        }
      } catch (err) {
        console.error('Failed to parse WS message:', err);
      }
    };

    return () => socket.close();
  }, []);



  const requestAiRemediation = (finding: typeof mockFindings[0]) => {
    setIsAnalyzing(true);
    setAiAnalysis('');
    setTimeout(() => {
      setAiAnalysis(`### Aegivion AI Remediation Guide
      
**Risk Assessment:**
This finding indicates that the resource is exposed to public network access. Attackers can scan, enumerate, or exploit service vulnerabilities on this interface.

**Step-by-Step Fix:**
1. Open the Cloud console and locate the resource ID: \`${finding.resource_id}\`.
2. Disable public access and restrict ingress to authorized internal networks.

**Terraform Prevention Snippet:**
\`\`\`hcl
# Hardened Configuration
resource "${finding.resource_type}_secure" "main" {
  name = "${finding.resource_id.split('/').pop()}"
  public_access = false
  # Block public incoming connections
}
\`\`\``);
      setIsAnalyzing(false);
    }, 1000);
  };

  const tabs = [
    { id: 'dashboard', name: 'Dashboard', icon: LayoutDashboard },
    { id: 'analytics', name: 'Analytics', icon: BarChart3 },
    { id: 'security', name: 'Security Rules', icon: Shield },
    { id: 'ai', name: 'AI Assistant', icon: BrainCircuit },
    { id: 'settings', name: 'Settings', icon: SettingsIcon },
  ];

  return (
    <div className="flex h-screen bg-[#0b0f19] text-gray-100 font-sans overflow-hidden">
      
      {/* Mobile Sidebar Toggle */}
      <button 
        className="lg:hidden absolute top-4 left-4 z-50 p-2 rounded-lg bg-gray-800 border border-gray-700 text-white"
        onClick={() => setSidebarOpen(!sidebarOpen)}
      >
        {sidebarOpen ? <X size={20} /> : <Menu size={20} />}
      </button>

      {/* Sidebar */}
      <aside className={`
        fixed inset-y-0 left-0 z-40 w-64 bg-[#0d1326] border-r border-gray-850 transform transition-transform duration-300 ease-in-out lg:translate-x-0 lg:static lg:flex lg:flex-col
        ${sidebarOpen ? 'translate-x-0' : '-translate-x-full'}
      `}>
        <div className="h-16 flex items-center px-6 gap-3 border-b border-gray-800">
          <Shield className="w-8 h-8 text-blue-500 animate-pulse" />
          <span className="text-xl font-bold tracking-wider bg-gradient-to-r from-blue-400 to-indigo-500 bg-clip-text text-transparent">AEGIVION</span>
        </div>
        
        <nav className="flex-1 px-4 py-6 space-y-2">
          {tabs.map((tab) => {
            const Icon = tab.icon;
            return (
              <button
                key={tab.id}
                onClick={() => {
                  setActiveTab(tab.id);
                  setSidebarOpen(false);
                }}
                className={`w-full flex items-center gap-3 px-4 py-3 rounded-lg text-sm font-medium transition-all duration-200 ${
                  activeTab === tab.id 
                    ? 'bg-blue-600/10 text-blue-400 border-l-4 border-blue-500' 
                    : 'text-gray-400 hover:bg-gray-800/50 hover:text-white'
                }`}
              >
                <Icon size={18} />
                {tab.name}
              </button>
            );
          })}
        </nav>

        <div className="p-4 border-t border-gray-800">
          <div className="flex items-center gap-2 text-xs text-gray-500">
            <span className="w-2 h-2 rounded-full bg-green-500 animate-ping"></span>
            <span>Local Services: Up & Running</span>
          </div>
        </div>
      </aside>

      {/* Main Content Area */}
      <main className="flex-1 flex flex-col overflow-y-auto relative p-6 lg:p-10">
        <header className="mb-8 flex items-center justify-between">
          <div>
            <h1 className="text-3xl font-extrabold tracking-tight bg-gradient-to-r from-white to-gray-400 bg-clip-text text-transparent">
              {tabs.find(t => t.id === activeTab)?.name}
            </h1>
            <p className="text-gray-400 mt-1">Aegivion Cloud Security & Vulnerability Intelligence Platform</p>
          </div>
          {activeTab === 'dashboard' && (
            <button
              onClick={handleTriggerScan}
              disabled={scanning}
              className="px-5 py-2.5 bg-gradient-to-r from-blue-600 to-indigo-600 hover:from-blue-500 hover:to-indigo-500 disabled:opacity-50 disabled:cursor-not-allowed text-white rounded-lg text-sm font-semibold shadow-lg shadow-blue-500/20 transition-all duration-200 flex items-center gap-2"
            >
              {scanning ? (
                <>
                  <span className="w-4 h-4 border-2 border-white/30 border-t-white rounded-full animate-spin"></span>
                  Scanning...
                </>
              ) : (
                'Trigger Cloud Scan'
              )}
            </button>
          )}
        </header>

        {activeTab === 'dashboard' && (
          <div className="space-y-6">
            {/* Stats Cards */}
            <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
              <div className="bg-gradient-to-br from-[#121a36] to-[#0e1428] border border-red-500/20 rounded-xl p-6 relative overflow-hidden">
                <div className="flex items-center justify-between">
                  <span className="text-gray-400 text-sm font-medium">Critical/High Findings</span>
                  <AlertTriangle className="text-red-500" size={24} />
                </div>
                <div className="mt-4">
                  <span className="text-3xl font-bold text-red-500">
                    {findingsList.filter(f => f.severity === 'Critical' || f.severity === 'High').length}
                  </span>
                  <span className="text-xs text-gray-500 ml-2">requires immediate attention</span>
                </div>
              </div>

              <div className="bg-gradient-to-br from-[#121a36] to-[#0e1428] border border-blue-500/20 rounded-xl p-6">
                <div className="flex items-center justify-between">
                  <span className="text-gray-400 text-sm font-medium">Scanned Resources</span>
                  <Database className="text-blue-400" size={24} />
                </div>
                <div className="mt-4">
                  <span className="text-3xl font-bold text-blue-400">{assetsList.length}</span>
                  <span className="text-xs text-gray-500 ml-2">across AWS provider</span>
                </div>
              </div>

              <div className="bg-gradient-to-br from-[#121a36] to-[#0e1428] border border-green-500/20 rounded-xl p-6">
                <div className="flex items-center justify-between">
                  <span className="text-gray-400 text-sm font-medium">Security Score</span>
                  <CheckCircle className="text-green-500" size={24} />
                </div>
                <div className="mt-4">
                  <span className="text-3xl font-bold text-green-500">
                    {Math.max(10, 100 - findingsList.length * 10)}%
                  </span>
                  <span className="text-xs text-gray-500 ml-2">healthy state</span>
                </div>
              </div>
            </div>

            {/* Findings List */}
            <div className="bg-[#0e1428] border border-gray-800 rounded-xl p-6">
              <h2 className="text-lg font-bold mb-4">Latest Vulnerability Findings</h2>
              <div className="divide-y divide-gray-800">
                {findingsList.map((finding) => (
                  <div key={finding.finding_id} className="py-4 flex flex-col md:flex-row md:items-center justify-between gap-4">
                    <div className="space-y-1">
                      <div className="flex items-center gap-2">
                        <span className={`px-2 py-0.5 rounded text-xs font-semibold ${
                          finding.severity === 'Critical' ? 'bg-red-500/20 text-red-400 border border-red-500/30' :
                          finding.severity === 'High' ? 'bg-orange-500/20 text-orange-400 border border-orange-500/30' :
                          'bg-yellow-500/20 text-yellow-400 border border-yellow-500/30'
                        }`}>
                          {finding.severity}
                        </span>
                        <span className="text-xs text-gray-400 font-mono">{finding.cloud_provider}</span>
                      </div>
                      <h3 className="font-semibold text-white">{finding.title}</h3>
                      <p className="text-xs text-gray-400 font-mono">{finding.resource_id}</p>
                    </div>
                    <button 
                      onClick={() => {
                        setSelectedFinding(finding);
                        setActiveTab('ai');
                        requestAiRemediation(finding);
                      }}
                      className="px-4 py-2 bg-blue-600 hover:bg-blue-500 text-white rounded-lg text-sm transition-colors flex items-center gap-2 self-start md:self-auto"
                    >
                      AI Remediation <ChevronRight size={14} />
                    </button>
                  </div>
                ))}
              </div>
            </div>
          </div>
        )}

        {activeTab === 'analytics' && (
          <div className="space-y-6">
            <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
              {/* Doughnut Severity Chart */}
              <div className="bg-[#0e1428] border border-gray-800 rounded-xl p-6">
                <h3 className="text-lg font-bold mb-4">Vulnerability Severity Distribution</h3>
                <div className="flex items-center justify-around h-64">
                  <svg className="w-48 h-48 transform -rotate-90" viewBox="0 0 100 100">
                    {/* Circle slices representing Critical: 30%, High: 45%, Medium: 25% */}
                    <circle cx="50" cy="50" r="40" fill="transparent" stroke="#ef4444" strokeWidth="20" strokeDasharray="18.84 251.2" strokeDashoffset="0"></circle>
                    <circle cx="50" cy="50" r="40" fill="transparent" stroke="#f97316" strokeWidth="20" strokeDasharray="113.04 251.2" strokeDashoffset="-18.84"></circle>
                    <circle cx="50" cy="50" r="40" fill="transparent" stroke="#eab308" strokeWidth="20" strokeDasharray="119.32 251.2" strokeDashoffset="-131.88"></circle>
                    <circle cx="50" cy="50" r="30" fill="#0e1428"></circle>
                  </svg>
                  <div className="space-y-2">
                    <div className="flex items-center gap-2">
                      <span className="w-3.5 h-3.5 rounded bg-red-500"></span>
                      <span className="text-sm font-medium text-gray-300">Critical (1)</span>
                    </div>
                    <div className="flex items-center gap-2">
                      <span className="w-3.5 h-3.5 rounded bg-orange-500"></span>
                      <span className="text-sm font-medium text-gray-300">High (1)</span>
                    </div>
                    <div className="flex items-center gap-2">
                      <span className="w-3.5 h-3.5 rounded bg-yellow-500"></span>
                      <span className="text-sm font-medium text-gray-300">Medium (1)</span>
                    </div>
                  </div>
                </div>
              </div>

              {/* Compliance Line Trend Chart */}
              <div className="bg-[#0e1428] border border-gray-800 rounded-xl p-6">
                <h3 className="text-lg font-bold mb-4">Security Compliance Trend (Last 6 Months)</h3>
                <div className="h-64 flex items-end">
                  <svg className="w-full h-full" viewBox="0 0 500 200">
                    {/* Gridlines */}
                    <line x1="50" y1="30" x2="450" y2="30" stroke="#1f2937" strokeWidth="1"></line>
                    <line x1="50" y1="80" x2="450" y2="80" stroke="#1f2937" strokeWidth="1"></line>
                    <line x1="50" y1="130" x2="450" y2="130" stroke="#1f2937" strokeWidth="1"></line>
                    <line x1="50" y1="180" x2="450" y2="180" stroke="#1f2937" strokeWidth="1"></line>

                    {/* Gradient Area path */}
                    <path d="M 50 180 L 50 140 L 130 110 L 210 130 L 290 90 L 370 70 L 450 50 L 450 180 Z" fill="url(#blue-grad)" opacity="0.15"></path>
                    
                    {/* Line path */}
                    <path d="M 50 140 L 130 110 L 210 130 L 290 90 L 370 70 L 450 50" fill="none" stroke="#3b82f6" strokeWidth="3"></path>

                    {/* Dots */}
                    <circle cx="50" cy="140" r="4" fill="#60a5fa"></circle>
                    <circle cx="130" cy="110" r="4" fill="#60a5fa"></circle>
                    <circle cx="210" cy="130" r="4" fill="#60a5fa"></circle>
                    <circle cx="290" cy="90" r="4" fill="#60a5fa"></circle>
                    <circle cx="370" cy="70" r="4" fill="#60a5fa"></circle>
                    <circle cx="450" cy="50" r="4" fill="#60a5fa"></circle>

                    {/* Labels */}
                    <text x="50" y="198" fill="#9ca3af" fontSize="11" textAnchor="middle">Feb</text>
                    <text x="130" y="198" fill="#9ca3af" fontSize="11" textAnchor="middle">Mar</text>
                    <text x="210" y="198" fill="#9ca3af" fontSize="11" textAnchor="middle">Apr</text>
                    <text x="290" y="198" fill="#9ca3af" fontSize="11" textAnchor="middle">May</text>
                    <text x="370" y="198" fill="#9ca3af" fontSize="11" textAnchor="middle">Jun</text>
                    <text x="450" y="198" fill="#9ca3af" fontSize="11" textAnchor="middle">Jul</text>

                    <defs>
                      <linearGradient id="blue-grad" x1="0%" y1="0%" x2="0%" y2="100%">
                        <stop offset="0%" stopColor="#3b82f6"></stop>
                        <stop offset="100%" stopColor="#3b82f6" stopOpacity="0"></stop>
                      </linearGradient>
                    </defs>
                  </svg>
                </div>
              </div>
            </div>

            {/* Compliance Matrix Bar Chart */}
            <div className="bg-[#0e1428] border border-gray-800 rounded-xl p-6">
              <h3 className="text-lg font-bold mb-4">Framework Alignment Integrity</h3>
              <div className="space-y-4">
                <div>
                  <div className="flex justify-between text-sm mb-1">
                    <span>CIS AWS Foundations v2.0</span>
                    <span className="font-semibold">68%</span>
                  </div>
                  <div className="w-full bg-gray-850 h-2.5 rounded-full overflow-hidden">
                    <div className="bg-blue-500 h-full rounded-full" style={{ width: '68%' }}></div>
                  </div>
                </div>
                <div>
                  <div className="flex justify-between text-sm mb-1">
                    <span>SOC 2 Type II</span>
                    <span className="font-semibold">82%</span>
                  </div>
                  <div className="w-full bg-gray-850 h-2.5 rounded-full overflow-hidden">
                    <div className="bg-emerald-500 h-full rounded-full" style={{ width: '82%' }}></div>
                  </div>
                </div>
                <div>
                  <div className="flex justify-between text-sm mb-1">
                    <span>PCI DSS v4.0</span>
                    <span className="font-semibold">45%</span>
                  </div>
                  <div className="w-full bg-gray-850 h-2.5 rounded-full overflow-hidden">
                    <div className="bg-amber-500 h-full rounded-full" style={{ width: '45%' }}></div>
                  </div>
                </div>
              </div>
            </div>
          </div>
        )}

        {activeTab === 'security' && (
          <div className="bg-[#0e1428] border border-gray-800 rounded-xl p-6 space-y-6">
            <div>
              <h2 className="text-lg font-bold">Scanning Rules Engine</h2>
              <p className="text-gray-400 text-sm mt-1">Configure automated compliance and threat intelligence rules.</p>
            </div>
            
            <div className="space-y-4">
              <div className="p-4 border border-gray-800 rounded-lg flex items-center justify-between">
                <div>
                  <h3 className="font-semibold">aws_s3_bucket_public_access</h3>
                  <p className="text-xs text-gray-400">Verifies if S3 buckets allow public reading or writing</p>
                </div>
                <span className="px-2 py-1 bg-green-500/10 text-green-400 border border-green-500/20 text-xs rounded font-medium">Active</span>
              </div>

              <div className="p-4 border border-gray-800 rounded-lg flex items-center justify-between">
                <div>
                  <h3 className="font-semibold">azure_vm_ssh_open</h3>
                  <p className="text-xs text-gray-400">Verifies NSG rules don't permit incoming port 22 access to all</p>
                </div>
                <span className="px-2 py-1 bg-green-500/10 text-green-400 border border-green-500/20 text-xs rounded font-medium">Active</span>
              </div>
            </div>
          </div>
        )}

        {activeTab === 'ai' && (
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
            <div className="bg-[#0e1428] border border-gray-800 rounded-xl p-6 flex flex-col h-[500px]">
              <h2 className="text-lg font-bold mb-4">Select Vulnerability to Analyze</h2>
              <div className="flex-1 overflow-y-auto space-y-3 pr-2">
                {findingsList.map((finding) => (
                  <div 
                    key={finding.finding_id} 
                    onClick={() => {
                      setSelectedFinding(finding);
                      requestAiRemediation(finding);
                    }}
                    className={`p-4 border rounded-lg cursor-pointer transition-all duration-200 ${
                      selectedFinding?.finding_id === finding.finding_id 
                        ? 'border-blue-500 bg-blue-600/5' 
                        : 'border-gray-800 hover:border-gray-700 bg-gray-900/40'
                    }`}
                  >
                    <div className="flex justify-between items-center mb-1">
                      <span className="font-semibold text-sm">{finding.title}</span>
                      <span className="text-xs font-semibold text-orange-400">{finding.severity}</span>
                    </div>
                    <span className="text-xs text-gray-500 font-mono block truncate">{finding.resource_id}</span>
                  </div>
                ))}
              </div>
            </div>

            <div className="bg-[#0e1428] border border-gray-800 rounded-xl p-6 flex flex-col h-[500px]">
              <h2 className="text-lg font-bold mb-4">AI Copilot Remediation</h2>
              <div className="flex-1 bg-gray-950/60 rounded-lg p-4 font-mono text-xs overflow-y-auto border border-gray-800">
                {isAnalyzing ? (
                  <div className="flex items-center justify-center h-full gap-2">
                    <span className="w-2.5 h-2.5 bg-blue-500 rounded-full animate-bounce"></span>
                    <span className="w-2.5 h-2.5 bg-blue-500 rounded-full animate-bounce delay-100"></span>
                    <span className="w-2.5 h-2.5 bg-blue-500 rounded-full animate-bounce delay-200"></span>
                    <span className="text-gray-400 ml-2">Generating secure fix...</span>
                  </div>
                ) : selectedFinding ? (
                  <div className="whitespace-pre-line leading-relaxed">
                    {aiAnalysis}
                  </div>
                ) : (
                  <div className="flex flex-col items-center justify-center h-full text-gray-500">
                    <BrainCircuit size={48} className="mb-2 text-gray-600" />
                    <span>Select a vulnerability to see AI-generated remediation</span>
                  </div>
                )}
              </div>
            </div>
          </div>
        )}

        {activeTab === 'settings' && (
          <div className="bg-[#0e1428] border border-gray-800 rounded-xl p-6 space-y-6">
            <h2 className="text-lg font-bold">Workspace Configuration</h2>
            
            <div className="space-y-4 max-w-xl">
              <div>
                <label className="block text-xs font-semibold uppercase tracking-wider text-gray-400 mb-2">LLM Provider</label>
                <select className="w-full bg-[#121a36] border border-gray-800 rounded-lg p-2.5 text-sm text-gray-200 focus:outline-none focus:border-blue-500">
                  <option value="gemini">Google Gemini 3.5 Flash (Recommended)</option>
                  <option value="openai">OpenAI GPT-4o</option>
                  <option value="azure">Azure OpenAI</option>
                </select>
              </div>

              <div>
                <label className="block text-xs font-semibold uppercase tracking-wider text-gray-400 mb-2">Vector Database Location</label>
                <input 
                  type="text" 
                  value="http://localhost:6333" 
                  readOnly 
                  className="w-full bg-[#121a36] border border-gray-800 rounded-lg p-2.5 text-sm text-gray-400 cursor-not-allowed"
                />
              </div>
            </div>
          </div>
        )}
      </main>
    </div>
  );
}
