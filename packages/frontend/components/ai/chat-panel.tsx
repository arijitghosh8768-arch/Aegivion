"use client";

import { useState, useRef, useEffect } from "react";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Card, CardHeader, CardTitle, CardContent, CardFooter } from "@/components/ui/card";
import { Send, Loader2, Bot, User } from "lucide-react";
import { GroundedMessage } from "./grounded-message";

interface Message {
  id: string;
  role: "user" | "assistant";
  content: string;
  observed?: string[];
  inferred?: string[];
  unknown?: string[];
  declined?: boolean;
}

interface ChatPanelProps {
  findingId?: string;
  assetId?: string;
}

export function ChatPanel({ findingId, assetId }: ChatPanelProps) {
  const [messages, setMessages] = useState<Message[]>([
    {
      id: "intro",
      role: "assistant",
      content: "I am Aegivion AI. I can answer questions grounded in the context of this finding and asset.",
    }
  ]);
  const [input, setInput] = useState("");
  const [isLoading, setIsLoading] = useState(false);
  const scrollRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    if (scrollRef.current) {
      scrollRef.current.scrollTop = scrollRef.current.scrollHeight;
    }
  }, [messages]);

  const handleSend = async () => {
    if (!input.trim()) return;
    
    const userMsg: Message = { id: Date.now().toString(), role: "user", content: input };
    setMessages(prev => [...prev, userMsg]);
    setInput("");
    setIsLoading(true);

    try {
      // In a real implementation this would fetch from /v1/ai/chat
      // We simulate the fetch here for UI demo purposes if backend isn't connected
      const res = await fetch("http://localhost:8000/v1/ai/chat", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          message: input,
          finding_id: findingId,
          asset_id: assetId,
          history: messages.slice(1).map(m => ({ role: m.role, content: m.content }))
        })
      });

      if (res.ok) {
        const data = await res.json();
        setMessages(prev => [...prev, {
          id: Date.now().toString(),
          role: "assistant",
          content: data.response,
          observed: data.observed,
          inferred: data.inferred,
          unknown: data.unknown,
          declined: data.declined
        }]);
      } else {
        throw new Error("Failed to connect");
      }
    } catch (e) {
      // Fallback dummy response for testing without backend
      setTimeout(() => {
        const isOffTopic = input.toLowerCase().includes("who is");
        setMessages(prev => [...prev, {
          id: Date.now().toString(),
          role: "assistant",
          content: isOffTopic ? "I do not have evidence or context to answer that question." : "Based on the evidence, this configuration is risky.",
          declined: isOffTopic,
          observed: isOffTopic ? [] : ["Port 22 is open to 0.0.0.0/0."],
          inferred: isOffTopic ? [] : ["This increases remote-access exposure."],
          unknown: isOffTopic ? [] : ["Actual exploitation has not been observed."]
        }]);
        setIsLoading(false);
      }, 800);
    } finally {
      setIsLoading(false);
    }
  };

  return (
    <Card className="flex flex-col h-[500px] shadow-lg border-border">
      <CardHeader className="py-3 px-4 border-b bg-muted/20">
        <CardTitle className="text-sm flex items-center gap-2">
          <Bot className="h-4 w-4 text-primary" />
          Aegivion Context Chat
        </CardTitle>
      </CardHeader>
      
      <CardContent className="flex-1 overflow-y-auto p-4 space-y-4" ref={scrollRef}>
        {messages.map((msg) => (
          <div key={msg.id} className={`flex gap-3 ${msg.role === "user" ? "justify-end" : "justify-start"}`}>
            {msg.role === "assistant" && (
              <div className="h-8 w-8 rounded-full bg-primary/10 flex items-center justify-center shrink-0">
                <Bot className="h-4 w-4 text-primary" />
              </div>
            )}
            
            <div className={`max-w-[85%] ${msg.role === "user" ? "bg-primary text-primary-foreground rounded-2xl rounded-tr-sm px-4 py-2" : ""}`}>
              {msg.role === "user" ? (
                <div className="text-sm">{msg.content}</div>
              ) : (
                <GroundedMessage 
                  content={msg.content} 
                  observed={msg.observed} 
                  inferred={msg.inferred} 
                  unknown={msg.unknown} 
                  declined={msg.declined} 
                />
              )}
            </div>
            
            {msg.role === "user" && (
              <div className="h-8 w-8 rounded-full bg-muted flex items-center justify-center shrink-0">
                <User className="h-4 w-4 text-muted-foreground" />
              </div>
            )}
          </div>
        ))}
        {isLoading && (
          <div className="flex gap-3 justify-start items-center text-muted-foreground">
             <div className="h-8 w-8 rounded-full bg-primary/10 flex items-center justify-center shrink-0">
                <Bot className="h-4 w-4 text-primary" />
             </div>
             <Loader2 className="h-4 w-4 animate-spin" />
             <span className="text-xs">Analyzing context...</span>
          </div>
        )}
      </CardContent>
      
      <CardFooter className="p-3 border-t bg-card">
        <form className="flex w-full gap-2" onSubmit={(e) => { e.preventDefault(); handleSend(); }}>
          <Input 
            placeholder="Ask about this finding..." 
            value={input} 
            onChange={(e) => setInput(e.target.value)} 
            disabled={isLoading}
            className="flex-1"
          />
          <Button type="submit" size="icon" disabled={isLoading || !input.trim()}>
            <Send className="h-4 w-4" />
          </Button>
        </form>
      </CardFooter>
    </Card>
  );
}
