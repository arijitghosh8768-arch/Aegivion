export class APIError extends Error {
  constructor(public status: number, message: string) {
    super(message);
    this.name = "APIError";
  }
}

export async function fetchApi<T>(
  endpoint: string,
  options: RequestInit = {}
): Promise<T> {
  const baseUrl = process.env.NEXT_PUBLIC_API_URL || "https://aegivion.onrender.com";
  const url = `${baseUrl}/api${endpoint}`;

  // Use a JWT token if it exists in local storage
  const token = typeof window !== "undefined" ? localStorage.getItem("aegivion_token") : null;

  const headers = new Headers(options.headers);
  headers.set("Content-Type", "application/json");
  if (token) {
    headers.set("Authorization", `Bearer ${token}`);
  }

  const response = await fetch(url, {
    ...options,
    headers,
  });

  if (!response.ok) {
    let message = "An error occurred while fetching the data.";
    try {
      const errorData = await response.json();
      message = errorData.message || message;
    } catch (e) {
      // JSON parsing failed
    }
    
    // Auto logout on 401
    if (response.status === 401 && typeof window !== "undefined") {
      localStorage.removeItem("aegivion_token");
      window.location.href = "/login";
    }

    throw new APIError(response.status, message);
  }

  // Handle empty responses (like 204 No Content)
  if (response.status === 204) {
    return {} as T;
  }

  return response.json();
}

export interface RemediationPlanAction {
  id: string;
  action_type: string;
  status: string;
  parameters: Record<string, any>;
  aws_request_id?: string;
}

export interface RemediationPlanItem {
  id: string;
  organization_id: string;
  finding_id?: string;
  resource_id: string;
  status: "PENDING_APPROVAL" | "APPROVED" | "EXECUTING" | "EXECUTED" | "VERIFIED" | "FAILED" | "FAILED_VERIFICATION" | "ROLLED_BACK" | "EXPIRED" | "REJECTED";
  expires_at?: string;
  created_at?: string;
  action_type: string;
  actions: RemediationPlanAction[];
}

export async function getRemediationPlans(): Promise<{ success: boolean; data: RemediationPlanItem[] }> {
  return fetchApi("/v1/remediation/plans");
}

export async function approveRemediationPlan(planId: string): Promise<any> {
  return fetchApi(`/v1/remediation/plans/${planId}/approve`, {
    method: "POST",
  });
}

export async function rejectRemediationPlan(planId: string, reason = "Rejected by operator"): Promise<any> {
  return fetchApi(`/v1/remediation/plans/${planId}/reject`, {
    method: "POST",
    body: JSON.stringify({ reason }),
  });
}

export async function executeRemediationPlan(planId: string): Promise<any> {
  return fetchApi(`/v1/remediation/plans/${planId}/execute`, {
    method: "POST",
  });
}

export async function rollbackRemediationPlan(planId: string, reason = "Rolled back by operator"): Promise<any> {
  return fetchApi(`/v1/remediation/plans/${planId}/rollback`, {
    method: "POST",
    body: JSON.stringify({ reason }),
  });
}
