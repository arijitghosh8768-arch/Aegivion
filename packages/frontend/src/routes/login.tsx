import React from 'react';
import { createRoute } from '@tanstack/react-router';
import { Route as rootRoute } from './__root';

export const Route = createRoute({
  getParentRoute: () => rootRoute,
  path: '/login',
  component: LoginPage,
});

function LoginPage() {
  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-3xl font-extrabold tracking-tight">Login</h1>
        <p className="text-gray-400 mt-1">Access Aegivion Security Center</p>
      </div>

      <div className="bg-[#0e1428] border border-gray-800 rounded-xl p-6 max-w-md">
        <p className="text-sm text-gray-500">Log in screen template.</p>
      </div>
    </div>
  );
}
