export class APIError extends Error {
  constructor(public status: number, message: string) {
    super(message);
    this.name = "APIError";
  }
}

let refreshPromise: Promise<string | null> | null = null;

async function refreshAccessToken(): Promise<string | null> {
  if (typeof window === "undefined") return null;
  const refreshToken = localStorage.getItem("aegivion_refresh_token");
  if (!refreshToken) return null;

  const baseUrl = process.env.NEXT_PUBLIC_API_URL || "https://aegivion.onrender.com";
  try {
    const res = await fetch(`${baseUrl}/api/v1/auth/refresh`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ refresh_token: refreshToken }),
    });

    if (!res.ok) {
      localStorage.removeItem("aegivion_token");
      localStorage.removeItem("aegivion_refresh_token");
      return null;
    }

    const data = await res.json();
    const newToken = data.token || data.access_token;
    if (newToken) {
      localStorage.setItem("aegivion_token", newToken);
      if (data.refresh_token) {
        localStorage.setItem("aegivion_refresh_token", data.refresh_token);
      }
      return newToken;
    }
  } catch (err) {
    localStorage.removeItem("aegivion_token");
    localStorage.removeItem("aegivion_refresh_token");
  }
  return null;
}

export async function fetchApi<T>(
  endpoint: string,
  options: RequestInit = {}
): Promise<T> {
  const baseUrl = process.env.NEXT_PUBLIC_API_URL || "https://aegivion.onrender.com";
  const url = `${baseUrl}/api${endpoint}`;

  // Use a JWT token if it exists in local storage
  let token = typeof window !== "undefined" ? localStorage.getItem("aegivion_token") : null;

  const headers = new Headers(options.headers);
  headers.set("Content-Type", "application/json");
  if (token) {
    headers.set("Authorization", `Bearer ${token}`);
  }

  let response = await fetch(url, {
    ...options,
    headers,
  });

  // Handle 401 with Token Refresh Interceptor (except for auth endpoints)
  if (response.status === 401 && !endpoint.includes("/auth/login") && !endpoint.includes("/auth/refresh") && typeof window !== "undefined") {
    if (!refreshPromise) {
      refreshPromise = refreshAccessToken().finally(() => {
        refreshPromise = null;
      });
    }

    const newToken = await refreshPromise;
    if (newToken) {
      headers.set("Authorization", `Bearer ${newToken}`);
      response = await fetch(url, {
        ...options,
        headers,
      });
    } else {
      localStorage.removeItem("aegivion_token");
      localStorage.removeItem("aegivion_refresh_token");
      window.location.href = "/login";
    }
  }

  if (!response.ok) {
    let message = "An error occurred while fetching the data.";
    try {
      const errorData = await response.json();
      message = (typeof errorData.detail === "string" ? errorData.detail : errorData.message) || message;
    } catch (e) {
      // JSON parsing failed
    }
    
    // Auto logout on 401 if refresh failed or not attempted
    if (response.status === 401 && typeof window !== "undefined" && !endpoint.includes("/auth/login")) {
      localStorage.removeItem("aegivion_token");
      localStorage.removeItem("aegivion_refresh_token");
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
