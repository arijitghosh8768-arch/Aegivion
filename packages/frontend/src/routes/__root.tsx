import React from 'react';
import { createRootRoute, Outlet, useLocation, useNavigate } from '@tanstack/react-router';
import DashboardLayout from '@/components/dashboard-layout';
import { useAuthStore } from '@/store/auth-store';

export const Route = createRootRoute({
  component: RootComponent,
});

function RootComponent() {
  const location = useLocation();
  const navigate = useNavigate();
  const isAuthenticated = useAuthStore((state: any) => state.isAuthenticated);
  const [isHydrated, setIsHydrated] = React.useState(false);

  React.useEffect(() => {
    const unsub = useAuthStore.persist.onFinishHydration(() => {
      setIsHydrated(true);
    });
    
    if (useAuthStore.persist.hasHydrated()) {
      setIsHydrated(true);
    }
    
    return () => unsub();
  }, []);

  const isLoginPage = location.pathname === '/login';

  React.useEffect(() => {
    if (isHydrated && !isAuthenticated && !isLoginPage) {
      navigate({ to: '/login' });
    }
  }, [isHydrated, isAuthenticated, isLoginPage, navigate]);

  // If loading login page, don't wrap with DashboardLayout
  if (isLoginPage) {
    return <Outlet />;
  }

  // If not hydrated yet, show a loader
  if (!isHydrated) {
    return (
      <div className="h-screen w-screen bg-[#0b0f19] flex items-center justify-center text-gray-400">
        Loading session...
      </div>
    );
  }

  // If not authenticated and not on login page, wait for redirect
  if (!isAuthenticated) {
    return (
      <div className="h-screen w-screen bg-[#0b0f19] flex items-center justify-center text-gray-400">
        Redirecting to login...
      </div>
    );
  }

  return (
    <DashboardLayout>
      <Outlet />
    </DashboardLayout>
  );
}
