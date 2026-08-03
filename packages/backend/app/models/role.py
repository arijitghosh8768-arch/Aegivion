from app.database.base import BaseModel

class Role(BaseModel):
    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.name = kwargs.get("name")
        self.description = kwargs.get("description")
        self.organization_id = kwargs.get("organization_id")

    def dict(self):
        res = super().dict()
        res.update({
            "name": self.name,
            "description": self.description,
            "organization_id": str(self.organization_id) if self.organization_id else None
        })
        return res

