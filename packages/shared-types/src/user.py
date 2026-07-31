from pydantic import BaseModel, EmailStr
from typing import Optional, List

class UserType(BaseModel):
    id: int
    email: str
    organization_id: Optional[int] = None
    roles: List[str] = []
