from locust import HttpUser, task, between

class AegivionUser(HttpUser):
    wait_time = between(1, 3)
    
    def on_start(self):
        """Simulate loading dashboard"""
        pass
    
    @task(3)
    def view_dashboard(self):
        self.client.get("/")
    
    @task(2)
    def check_health(self):
        self.client.get("/health")
