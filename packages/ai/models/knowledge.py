import enum
from app.database.base import BaseModel

class KnowledgeCategory(str, enum.Enum):
    SECURITY_BEST_PRACTICE = "security_best_practice"
    COMPLIANCE = "compliance"
    THREAT = "threat"
    REMEDIATION = "remediation"
    ARCHITECTURE = "architecture"
    GENERAL = "general"

class KnowledgeBase(BaseModel):
    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.title = kwargs.get("title")
        self.content = kwargs.get("content")
        self.category = kwargs.get("category") or KnowledgeCategory.GENERAL
        self.tags = kwargs.get("tags") or []
        self.embedding = kwargs.get("embedding")
        self.source = kwargs.get("source")
        self.author = kwargs.get("author")
        self.references = kwargs.get("references") or []
        self.related_findings = kwargs.get("related_findings") or []
        self.version = kwargs.get("version") or 1
        self.previous_version_id = kwargs.get("previous_version_id")

    def dict(self):
        res = super().dict()
        res.update({
            "title": self.title,
            "content": self.content,
            "category": self.category,
            "tags": self.tags,
            "embedding": self.embedding,
            "source": self.source,
            "author": self.author,
            "references": self.references,
            "related_findings": self.related_findings,
            "version": self.version,
            "previous_version_id": str(self.previous_version_id) if self.previous_version_id else None
        })
        return res

class Conversation(BaseModel):
    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.user_id = kwargs.get("user_id")
        self.title = kwargs.get("title")
        self.messages = kwargs.get("messages") or []
        self.context = kwargs.get("context") or {}
        self.tokens_used = kwargs.get("tokens_used") or 0
        self.response_time_ms = kwargs.get("response_time_ms") or 0

    def dict(self):
        res = super().dict()
        res.update({
            "user_id": str(self.user_id) if self.user_id else None,
            "title": self.title,
            "messages": self.messages,
            "context": self.context,
            "tokens_used": self.tokens_used,
            "response_time_ms": self.response_time_ms
        })
        return res

