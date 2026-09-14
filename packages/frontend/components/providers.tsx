"use client";

import { useState } from "react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { ThemeProvider } from "next-themes";
import { Toaster } from "@/components/shared/toaster";
import { useAppearanceStyles } from "@/lib/use-appearance";
import { GoogleOAuthProvider } from "@react-oauth/google";

function AppearanceApplier() {
  useAppearanceStyles();
  return null;
}

export function Providers({ children }: { children: React.ReactNode }) {
  const [queryClient] = useState(
    () =>
      new QueryClient({
        defaultOptions: {
          queries: { staleTime: 30_000, refetchOnWindowFocus: false, retry: 1 },
        },
      })
  );

  const googleClientId = process.env.NEXT_PUBLIC_GOOGLE_CLIENT_ID || "placeholder-client-id.apps.googleusercontent.com";

  return (
    <ThemeProvider attribute="class" defaultTheme="light" enableSystem disableTransitionOnChange>
      <GoogleOAuthProvider clientId={googleClientId}>
        <AppearanceApplier />
        <QueryClientProvider client={queryClient}>{children}</QueryClientProvider>
        <Toaster />
      </GoogleOAuthProvider>
    </ThemeProvider>
  );
}
