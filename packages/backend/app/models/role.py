from sqlalchemy import Column, String, ForeignKey
from sqlalchemy.orm import relationship
from sqlalchemy.dialects.postgresql import UUID
from app.database.base import BaseModel

class Role(BaseModel):
    __tablename__ = 'roles'

    name = Column(String, unique=True, nullable=False, index=True)
    description = Column(String, nullable=True)
    organization_id = Column(UUID(as_uuid=True), ForeignKey("organizations.id", ondelete="CASCADE"), nullable=True)

    users = relationship("User", back_populates="role")
    organization = relationship("Organization", back_populates="roles")
