import { createRouter } from '@tanstack/react-router';
import { Route as rootRoute } from './routes/__root';
import { Route as indexRoute } from './routes/index';
import { Route as findingsRoute } from './routes/findings';
import { Route as assetsRoute } from './routes/assets';
import { Route as aiAssistantRoute } from './routes/ai-assistant';
import { Route as cloudAccountsRoute } from './routes/cloud-accounts';
import { Route as complianceRoute } from './routes/compliance';
import { Route as settingsRoute } from './routes/settings';
import { Route as reportsRoute } from './routes/reports';
import { Route as incidentsRoute } from './routes/incidents';

const routeTree = rootRoute.addChildren([
  indexRoute,
  findingsRoute,
  assetsRoute,
  aiAssistantRoute,
  cloudAccountsRoute,
  complianceRoute,
  settingsRoute,
  reportsRoute,
  incidentsRoute,
]);

export const router = createRouter({ routeTree });

declare module '@tanstack/react-router' {
  interface Register {
    router: typeof router;
  }
}
