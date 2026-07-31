"use client";

import { useState } from "react";
import { Send, Bot, User, Sparkles } from "lucide-react";

interface Message {
  role: "user" | "ai";
  content: string;
}

export default function AIAssistantPage() {
  const [messages, setMessages] = useState<Message[]>([
    { role: "ai", content: "Hello! I am the Aegivion AI Assistant. Ask me about your cloud security posture, findings, or compliance." }
  ]);
  const [input, setInput] = useState("");

  const handleSend = () => {
    if (!input.trim()) return;
    setMessages((prev) => [...prev, { role: "user", content: input }]);
    
    setTimeout(() => {
      setMessages((prev) => [...prev, { 
        role: "ai", 
        content: `Based on your current posture, I recommend addressing the 3 critical IAM misconfigurations in your AWS account. Would you like me to generate a remediation script?` 
      }]);
    }, 1000);
    
    setInput("");
  };

  return (
    <div className="h-[calc(100vh-8rem)] flex flex-col">
      <div className="flex-1 flex flex-col bg-[#1E293B] border border-slate-700 rounded-lg overflow-hidden">
        <div className="p-4 border-b border-slate-700">
          <h2 className="flex items-center gap-2 text-lg font-bold text-white">
            <Sparkles className="h-5 w-5 text-blue-500" />
            Aegivion AI Assistant
          </h2>
        </div>
        
        <div className="flex-1 overflow-y-auto p-6 space-y-6">
          {messages.map((msg, i) => (
            <div key={i} className={`flex gap-3 ${msg.role === "user" ? "justify-end" : "justify-start"}`}>
              {msg.role === "ai" && <div className="h-8 w-8 rounded-full bg-blue-600/20 flex items-center justify-center flex-shrink-0"><Bot className="h-4 w-4 text-blue-500" /></div>}
              <div className={`max-w-[80%] rounded-lg p-3 text-sm ${msg.role === "user" ? "bg-blue-600 text-white" : "bg-[#0F172A] border border-slate-700 text-slate-100"}`}>
                {msg.content}
              </div>
              {msg.role === "user" && <div className="h-8 w-8 rounded-full bg-slate-700 flex items-center justify-center flex-shrink-0"><User className="h-4 w-4 text-white" /></div>}
            </div>
          ))}
        </div>

        <div className="p-4 border-t border-slate-700 bg-[#0F172A]">
          <div className="flex gap-2">
            <input 
              placeholder="Ask about findings, compliance, or remediation..." 
              value={input} 
              onChange={(e) => setInput(e.target.value)}
              onKeyDown={(e) => e.key === "Enter" && handleSend()}
              className="flex-1 bg-[#1E293B] border border-slate-700 text-slate-100 placeholder-slate-400 rounded px-3 py-2 text-sm focus:outline-none"
            />
            <button onClick={handleSend} className="p-2.5 bg-blue-600 hover:bg-blue-500 text-white rounded flex items-center justify-center">
              <Send className="h-4 w-4" />
            </button>
          </div>
        </div>
      </div>
    </div>
  );
}
