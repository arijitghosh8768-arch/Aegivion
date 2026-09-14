import json
from typing import Dict, Any, List
import re

class SemanticChunker:
    """Simulates a semantic chunker with configurable token size and overlap"""
    def __init__(self, chunk_size=300, overlap_percent=0.15):
        self.chunk_size = chunk_size
        self.overlap = int(chunk_size * overlap_percent)
        
    def chunk_document(self, text: str) -> List[str]:
        # Approximate tokenization by words for simulation
        words = text.split()
        chunks = []
        start = 0
        while start < len(words):
            end = start + self.chunk_size
            chunk = " ".join(words[start:end])
            chunks.append(chunk)
            if end >= len(words):
                break
            start += (self.chunk_size - self.overlap)
        return chunks

class SecurityKnowledgeRetriever:
    """
    Retrieves semantic security knowledge based on finding context
    using chunked index simulation.
    """
    def __init__(self, knowledge_base_path: str = "packages/ai/knowledge_base/sample_entries.json"):
        self.knowledge_base_path = knowledge_base_path
        self.chunker = SemanticChunker(chunk_size=300, overlap_percent=0.15)
        self.index = []
        self._load_knowledge_base()

    def _load_knowledge_base(self):
        try:
            with open(self.knowledge_base_path, 'r') as f:
                raw_docs = json.load(f)
                
            # Build vector-like index using chunks
            for doc in raw_docs:
                content = doc.get("content", "")
                chunks = self.chunker.chunk_document(content)
                for c in chunks:
                    self.index.append({
                        "title": doc.get("title", "Document"),
                        "content": c,
                        "tags": doc.get("tags", [])
                    })
        except Exception:
            self.index = []

    def _simulate_vector_search(self, query_terms: List[str], top_k: int = 3) -> List[Dict]:
        """Simulates vector retrieval using simple term overlap scoring."""
        scored_chunks = []
        for chunk in self.index:
            score = sum(1 for term in query_terms if term.lower() in chunk["content"].lower() or term.lower() in str(chunk["tags"]).lower())
            if score > 0:
                scored_chunks.append((score, chunk))
                
        scored_chunks.sort(key=lambda x: x[0], reverse=True)
        return [c for _, c in scored_chunks[:top_k]]

    def retrieve_security_knowledge(self, finding_id: str, provider: str, finding_type: str, finding_metadata: Dict = None) -> Dict[str, Any]:
        # Build a semantic query
        query_terms = [provider, finding_type]
        if finding_metadata:
            if finding_metadata.get("mitre_technique"):
                query_terms.append(finding_metadata["mitre_technique"])
            if finding_metadata.get("cve_id"):
                query_terms.append(finding_metadata["cve_id"])
                
        # Simulate top-k vector retrieval
        relevant_entries = self._simulate_vector_search(query_terms, top_k=3)
        
        # Inject dynamic Threat Intel (e.g., KEV, explicit MITRE) if not in base index
        if finding_metadata:
            mitre_id = finding_metadata.get('mitre_technique')
            if mitre_id and not any(mitre_id in str(e) for e in relevant_entries):
                relevant_entries.append({
                    "title": f"MITRE ATT&CK: {mitre_id}",
                    "content": f"The technique {mitre_id} involves adversaries exploring the environment. Security controls should monitor for anomalous behavior mapped to {mitre_id}.",
                    "tags": ["mitre", mitre_id]
                })
                
            has_kev = finding_metadata.get('has_cisa_kev', False)
            if has_kev:
                relevant_entries.append({
                    "title": "CISA KEV Alert",
                    "content": "This vulnerability is listed in the CISA Known Exploited Vulnerabilities catalog. It has been observed in active exploitation campaigns in the wild. Remediation should be prioritized.",
                    "tags": ["kev", "cisa", "active_exploitation"]
                })
        
        return {
            "finding_id": finding_id,
            "provider": provider,
            "relevant_knowledge": relevant_entries
        }

# Usage instance
rag_retriever = SecurityKnowledgeRetriever()
