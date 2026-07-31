from fastapi import WebSocket
from typing import Dict, Set, Any
import json

class ConnectionManager:
    def __init__(self):
        # Maps user_id to a set of active WebSockets
        self.active_connections: Dict[str, Set[WebSocket]] = {}
        
    async def connect(self, websocket: WebSocket, user_id: str):
        await websocket.accept()
        if user_id not in self.active_connections:
            self.active_connections[user_id] = set()
        self.active_connections[user_id].add(websocket)
        
    def disconnect(self, websocket: WebSocket, user_id: str):
        if user_id in self.active_connections:
            self.active_connections[user_id].discard(websocket)
            if not self.active_connections[user_id]:
                del self.active_connections[user_id]
            
    async def broadcast_finding(self, finding: Dict[str, Any]):
        """Broadcast new finding to all active users"""
        message = {
            "type": "new_finding",
            "data": finding
        }
        message_str = json.dumps(message)
        for user_id, connections in self.active_connections.items():
            for connection in list(connections):
                try:
                    await connection.send_text(message_str)
                except Exception:
                    # Connection might be stale, discard it
                    self.disconnect(connection, user_id)

# Singleton manager
ws_manager = ConnectionManager()
