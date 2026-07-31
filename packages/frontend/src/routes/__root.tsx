import React from 'react';
import { createRootRoute, Outlet } from '@tanstack/react-router';
import DashboardLayout from '@/components/dashboard-layout';

export const Route = createRootRoute({
  component: () => (
    <DashboardLayout>
      <Outlet />
    </DashboardLayout>
  ),
});
