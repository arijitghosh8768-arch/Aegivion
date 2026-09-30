from datetime import datetime, timezone

class Clock:
    _instance = None
    
    @classmethod
    def get_instance(cls):
        if cls._instance is None:
            cls._instance = SystemClock()
        return cls._instance
        
    @classmethod
    def set_instance(cls, clock):
        cls._instance = clock
        
    def now(self) -> datetime:
        raise NotImplementedError

class SystemClock(Clock):
    def now(self) -> datetime:
        return datetime.now(timezone.utc)

class FrozenClock(Clock):
    def __init__(self, dt: datetime):
        self._dt = dt
        
    def now(self) -> datetime:
        return self._dt
        
    def advance(self, seconds: float):
        from datetime import timedelta
        self._dt += timedelta(seconds=seconds)
