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
