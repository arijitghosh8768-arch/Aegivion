from pydantic import BaseModel
from typing import Optional

class OrganizationType(BaseModel):
    id: int
    name: str
    description: Optional[str] = None
