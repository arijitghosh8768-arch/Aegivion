from typing import Dict, Any, List, Optional
import inspect

class AttackPathReasonerService:
    """Attack path reasoner explaining security traversal vectors with strict grounding controls"""

    def __init__(self, llm_provider=None):
        self.llm_provider = llm_provider

    async def explain_path(self, path_id: str, nodes: List[str], edges: List[str], evidence: List[Dict]) -> Dict[str, Any]:
        """Explain the logical security path steps and potential impact conditional scenarios"""
        
        prompt = self._build_prompt(path_id, nodes, edges, evidence)
        
        # Build safe fallback
        fallback = {
            "path_id": path_id,
            "summary": f"Potential lateral traversal path detected from Internet entry point to target resource {nodes[-1]}.",
            "entry_point": f"Access initiated via public node connection to {nodes[1]}.",
            "path_steps": [
                {
                    "step": 1,
                    "description": f"Connection established from Internet entry to public {nodes[1]} workload.",
                    "evidence_refs": ["edge:EXPOSED_TO"]
                },
                {
                    "step": 2,
                    "description": f"Privilege escalation vector through associated role permissions allowing access to target {nodes[-1]}.",
                    "evidence_refs": ["edge:CAN_ACCESS"]
                }
            ],
            "potential_scenario": f"If an adversary compromises the public workload {nodes[1]}, they could potentially use role credentials to perform read operations on {nodes[-1]}.",
            "potential_impact": "Read or write access to target data stores or compute profiles.",
            "uncertainty": [
                "No active exploitation has been observed on any graph node.",
                "Workload compromise status is currently unknown."
            ],
            "recommendations": [
                "Restrict inbound ingress port configurations on public security group.",
                "Restrict associated IAM policy resource statements to specific resource ARNs rather than wildcard stars."
            ]
        }

        if not self.llm_provider:
            return fallback

        try:
            res = self.llm_provider.generate(prompt)
            if inspect.iscoroutine(res):
                response_text = await res
            elif inspect.iscoroutinefunction(self.llm_provider.generate):
                response_text = await self.llm_provider.generate(prompt)
            else:
                response_text = res
            
            if hasattr(response_text, 'content'):
                text = response_text.content
            else:
                text = str(response_text)
                
            validated = self._validate_and_sanitize(text, fallback)
            return validated
        except Exception:
            return fallback

    def _build_prompt(self, path_id: str, nodes: List[str], edges: List[str], evidence: List[Dict]) -> str:
        return f"""
        Explain the following potential cloud security attack path:
        PATH ID: {path_id}
        NODES: {nodes}
        EDGES: {edges}
        EVIDENCE: {evidence}
        
        Strict rules for explanation:
        1. Keep explanations conditional (use "could", "potentially").
        2. DO NOT state that a breach, exploit, or compromise has occurred.
        3. Expose evidence references (e.g. edge:EXPOSED_TO).
        4. Detail what remains unknown.
        
        Return a JSON matching this exact structure:
        {{
            "summary": "...",
            "entry_point": "...",
            "path_steps": [
                {{"step": 1, "description": "...", "evidence_refs": ["..."]}}
            ],
            "potential_scenario": "...",
            "potential_impact": "...",
            "uncertainty": ["..."],
            "recommendations": ["..."]
        }}
        """

    def _validate_and_sanitize(self, response_text: str, fallback: Dict) -> Dict:
        import json
        try:
            if "{" in response_text:
                json_str = response_text[response_text.find("{"):response_text.rfind("}")+1]
                data = json.loads(json_str)
            else:
                return fallback
        except Exception:
            return fallback

        # Grounding: reject absolute statements about exploitation/compromise
        prohibited_phrases = ["compromised", "breached", "attacker exploited", "stole credentials"]
        
        # Verify potential scenario is conditional
        scenario = data.get("potential_scenario", "").lower()
        has_conditional = any(word in scenario for word in ["could", "potentially", "if", "might", "would"])
        
        for k in ["summary", "potential_scenario", "potential_impact"]:
            text_val = data.get(k, "").lower()
            if any(phrase in text_val for phrase in prohibited_phrases) or (k == "potential_scenario" and not has_conditional):
                data[k] = fallback[k]
                
        if not data.get("uncertainty") or len(data["uncertainty"]) == 0:
            data["uncertainty"] = fallback["uncertainty"]

        return data
