from sqlalchemy import Column, String, ForeignKey
from sqlalchemy.orm import relationship
from sqlalchemy.dialects.postgresql import UUID
from app.database.base import BaseModel

class Role(BaseModel):
    __tablename__ = 'roles'

    name = Column(String(100), nullable=False)
    description = Column(String(255), nullable=True)
    organization_id = Column(UUID(as_uuid=True), ForeignKey("organizations.id", ondelete="CASCADE"), nullable=True)

    users = relationship("User", back_populates="role")
    organization = relationship("Organization", back_populates="roles")

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.name = kwargs.get("name")
        self.description = kwargs.get("description")
        self.organization_id = kwargs.get("organization_id")
