export interface User {
  id: string;
  email: string;
  name: string;
  role: 'admin' | 'analyst' | 'viewer';
  organization_id: string;
  created_at: string;
}

export interface Finding {
  id: string;
  rule_id: string;
  severity: 'critical' | 'high' | 'medium' | 'low' | 'info';
  resource_id: string;
  resource_type: string;
  message: string;
  remediation: string;
  status: 'open' | 'in_progress' | 'resolved' | 'suppressed';
  created_at: string;
}

export interface APIResponse<T = any> {
  success: boolean;
  data?: T;
  error?: string;
  timestamp: string;
  request_id: string;
}
