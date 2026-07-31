export async function getFrontendHealth() {
  return {
    status: 'ok',
    service: 'frontend',
    timestamp: new Date().toISOString()
  };
}
