import React, { useState } from 'react';
import { createRoute } from '@tanstack/react-router';
import { Route as rootRoute } from './__root';
import { Send, BrainCircuit, Sparkles, MessageSquare } from 'lucide-react';

export const Route = createRoute({
  getParentRoute: () => rootRoute,
  path: '/ai-assistant',
  component: AIAssistantPage,
});

function AIAssistantPage() {
  const [messages, setMessages] = useState([
    { sender: 'ai', text: 'I have indexed 12,847 assets and 1,510 findings across 9 accounts. Ask me anything about your posture.' }
  ]);
  const [inputValue, setInputValue] = useState('');
  const [loading, setLoading] = useState(false);

  const recommendations = [
    { title: 'Close public read on customer-exports before anything else', desc: 'Removes the single largest data-breach path in the estate (4,102 PII objects).', impact: 'Critical', confidence: 97 },
    { title: 'Replace legacy-ci-user with OIDC-federated role', desc: 'Eliminates standing admin credentials used by no active workload.', impact: 'High', confidence: 91 },
    { title: 'Enable TDE across Azure managed databases', desc: 'Clears two failing SOC 2 and ISO encryption controls at once.', impact: 'Medium', confidence: 86 }
  ];

  const prompts = [
    'Which buckets expose PII?',
    'Show me identity risk in prod',
    'Draft the INC-238 exec summary'
  ];

  const suggestions = [
    'What are my top 3 risks right now?',
    'Which findings block SOC 2 certification?',
    'Summarise incident INC-238 for the executive team.',
    'Which IAM identities have unused admin access?'
  ];

  const handleSend = (text: string) => {
    if (!text.trim()) return;
    setMessages(prev => [...prev, { sender: 'user', text }]);
    setInputValue('');
    setLoading(true);

    setTimeout(() => {
      let reply = "I've checked the security graph. Let me know if you need specific CLI scripts or Terraform files to address this.";
      if (text.includes('top 3 risks')) {
        reply = "Your top 3 risks are:\n1. Public exposure of S3 bucket 'customer-exports'\n2. Security group 'sg-public-ssh' allowing port 22 access from 0.0.0.0/0\n3. Stale credentials for IAM user 'legacy-ci-user'.";
      } else if (text.includes('SOC 2')) {
        reply = "Failing SOC 2 controls are cc6.1 (logical access controls) and cc6.6 (encryption at rest). Resolving public port access and database encryption will clear these blockers.";
      } else if (text.includes('INC-238')) {
        reply = "Summary for INC-238:\nCritical incident triggered by public exposure of 'customer-exports' S3 bucket. Incident has been assigned to Rana Okafor. Public access blocks have been validated in staging; awaiting final change approval for production deployment.";
      } else if (text.includes('IAM')) {
        reply = "IAM user 'legacy-ci-user' holds administrative credentials that have not been rotated in 90+ days and are unused. Recommend replacing with a short-lived OIDC federation token.";
      }
      setMessages(prev => [...prev, { sender: 'ai', text: reply }]);
      setLoading(false);
    }, 1000);
  };

  return (
    <div className="space-y-6 text-gray-200 pb-10">
      <div>
        <h1 className="text-2xl font-bold text-white tracking-tight">AI assistant</h1>
        <p className="text-gray-400 text-sm mt-1">Conversational analysis over your live security graph.</p>
      </div>

      {/* Main Grid split */}
      <div className="grid grid-cols-1 lg:grid-cols-5 gap-6">
        {/* Left: Chat Console */}
        <div className="lg:col-span-3 bg-[#0e1428] border border-gray-800 rounded-xl p-5 flex flex-col justify-between h-[600px]">
          <div>
            <h2 className="text-sm font-bold text-white flex items-center gap-2">
              <Sparkles size={16} className="text-blue-400" />
              Aegivion Copilot
            </h2>
            <p className="text-xs text-gray-500 mt-0.5">Answers cite live findings and asset relationships</p>
          </div>

          {/* Conversation list */}
          <div className="flex-1 overflow-y-auto my-4 space-y-4 pr-1">
            {messages.map((m, idx) => (
              <div 
                key={idx} 
                className={`flex gap-3 text-xs leading-relaxed max-w-[85%] ${
                  m.sender === 'user' ? 'ml-auto flex-row-reverse' : ''
                }`}
              >
                <div className={`w-7 h-7 rounded-full shrink-0 flex items-center justify-center font-bold text-[10px] ${
                  m.sender === 'ai' 
                    ? 'bg-blue-600/20 text-blue-400' 
                    : 'bg-gray-800 text-gray-300'
                }`}>
                  {m.sender === 'ai' ? 'CO' : 'US'}
                </div>
                <div className={`p-3 rounded-lg whitespace-pre-line ${
                  m.sender === 'ai' 
                    ? 'bg-[#0b0f19]/65 border border-gray-850 text-gray-200' 
                    : 'bg-blue-600 text-white'
                }`}>
                  {m.text}
                </div>
              </div>
            ))}
            {loading && (
              <div className="flex gap-3 text-xs text-gray-400">
                <div className="w-7 h-7 rounded-full bg-blue-600/20 text-blue-400 flex items-center justify-center font-bold text-[10px]">CO</div>
                <div className="p-3 bg-[#0b0f19]/65 border border-gray-850 rounded-lg animate-pulse">Thinking...</div>
              </div>
            )}
          </div>

          {/* Input & suggestions area */}
          <div className="space-y-4 pt-4 border-t border-gray-800/85">
            {/* Suggestions pills */}
            <div className="flex flex-wrap gap-2">
              {suggestions.map((sug, idx) => (
                <button
                  key={idx}
                  onClick={() => handleSend(sug)}
                  className="px-3 py-1.5 bg-[#0b0f19] border border-gray-800 hover:border-gray-700 text-gray-400 hover:text-white rounded-full text-[10px] transition text-left"
                >
                  {sug}
                </button>
              ))}
            </div>

            {/* Field */}
            <form 
              onSubmit={(e) => {
                e.preventDefault();
                handleSend(inputValue);
              }}
              className="relative"
            >
              <input
                type="text"
                placeholder="Ask about risks, assets or compliance..."
                value={inputValue}
                onChange={(e) => setInputValue(e.target.value)}
                className="w-full bg-[#0b0f19] border border-gray-800 rounded-lg pl-4 pr-12 py-3 text-xs text-white focus:outline-none focus:border-gray-700 transition"
              />
              <button 
                type="submit"
                className="absolute right-2.5 top-2 p-1.5 bg-blue-600 hover:bg-blue-500 rounded text-white transition"
              >
                <Send size={14} />
              </button>
            </form>
          </div>
        </div>

        {/* Right: Recommendation + Prompt History */}
        <div className="lg:col-span-2 space-y-6 flex flex-col">
          {/* Recommendation panel */}
          <div className="bg-[#0e1428] border border-gray-800 rounded-xl p-5 space-y-4">
            <div>
              <h3 className="text-sm font-semibold text-white">Recommendation panel</h3>
              <p className="text-xs text-gray-500">Risk summary, impact and confidence</p>
            </div>
            
            <div className="space-y-4">
              {recommendations.map((rec, idx) => (
                <div key={idx} className="space-y-2 border-b border-gray-800/60 pb-3 last:border-0 last:pb-0">
                  <div className="flex justify-between items-start gap-2 text-xs">
                    <h4 className="font-semibold text-gray-200 leading-snug hover:text-blue-400 cursor-pointer transition">{rec.title}</h4>
                    <span className="text-[10px] font-bold text-gray-400 uppercase tracking-wider">{rec.impact}</span>
                  </div>
                  <p className="text-[10px] text-gray-500 leading-relaxed">{rec.desc}</p>
                  <div>
                    <div className="flex justify-between text-[9px] text-gray-500 mb-1">
                      <span>Confidence</span>
                      <span>{rec.confidence}%</span>
                    </div>
                    <div className="w-full bg-gray-850 h-1 rounded-full overflow-hidden">
                      <div className="bg-blue-500 h-full rounded-full" style={{ width: `${rec.confidence}%` }}></div>
                    </div>
                  </div>
                </div>
              ))}
            </div>
          </div>

          {/* Prompt History */}
          <div className="bg-[#0e1428] border border-gray-800 rounded-xl p-5 flex-1 space-y-4">
            <div>
              <h3 className="text-sm font-semibold text-white">Prompt history</h3>
            </div>
            <div className="space-y-3">
              {prompts.map((p, idx) => (
                <button
                  key={idx}
                  onClick={() => handleSend(p)}
                  className="w-full text-left text-xs text-gray-400 hover:text-white flex items-center gap-2 py-1.5 border-b border-gray-800/50 last:border-0 transition"
                >
                  <MessageSquare size={13} className="text-gray-600" />
                  {p}
                </button>
              ))}
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}
