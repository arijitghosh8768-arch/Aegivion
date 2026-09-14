from typing import List, Dict, Any

class RagSkeleton:
    """
    Skeleton for the Multi-Cloud Retrieval-Augmented Generation (RAG) engine.
    This will be fully built out in Week 12 to query a vector store (e.g. pgvector).
    """
    
    def __init__(self):
        # In the future, this will initialize the vector DB connection and embedding model
        self.mock_db = []
        
    def embed_and_store(self, document_id: str, content: str, metadata: Dict[str, Any]):
        """
        Mocks the embedding of a document (like a security rule or best practice)
        and storing it into the vector database.
        """
        # Week 12: Call embedding API and insert into pgvector
        self.mock_db.append({
            "id": document_id,
            "content": content,
            "metadata": metadata
        })
        print(f"Stored document {document_id} into RAG skeleton.")
        
    def _is_prompt_injection(self, text: str) -> bool:
        """
        Hardening: Simple heuristic check for prompt injection attempts.
        """
        suspicious_patterns = [
            "ignore previous instructions",
            "system prompt",
            "you are now",
            "override instructions"
        ]
        text_lower = text.lower()
        return any(pattern in text_lower for pattern in suspicious_patterns)
        
    def retrieve_context(self, query: str, top_k: int = 3) -> List[Dict[str, Any]]:
        """
        Mocks the retrieval of relevant context based on semantic similarity to the query.
        """
        if self._is_prompt_injection(query):
            print("WARNING: Prompt injection attempt detected. Rejecting query.")
            raise ValueError("Invalid query: suspicious patterns detected.")
            
        # Week 12: Embed query, perform nearest-neighbor search, return context
        print(f"Retrieving top {top_k} documents for query: '{query}'")
        return self.mock_db[:top_k]

# Initialize a global instance for the AI engine to use later
rag_engine = RagSkeleton()
