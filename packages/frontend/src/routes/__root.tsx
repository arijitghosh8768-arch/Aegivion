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

  const isLoginPage = location.pathname === '/login';

  React.useEffect(() => {
    if (!isAuthenticated && !isLoginPage) {
      navigate({ to: '/login' });
    }
  }, [isAuthenticated, isLoginPage, navigate]);

  // If loading login page, don't wrap with DashboardLayout
  if (isLoginPage) {
    return <Outlet />;
  }

  // If not authenticated and not on login page, wait for redirect (show skeleton/loader if desired)
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
