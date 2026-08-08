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
import { Route as remediationRoute } from './routes/remediation';
import { Route as riskRoute } from './routes/risk';
import { Route as identitiesRoute } from './routes/identities';
import { Route as findingsDetailRoute } from './routes/findings.$findingId';
import { Route as incidentsDetailRoute } from './routes/incidents.$incidentId';
import { Route as attackGraphRoute } from './routes/attack-graph';
import { Route as cloudAccountsScanRoute } from './routes/cloud-accounts.$accountId.scan';
import { Route as loginRoute } from './routes/login';

const routeTree = rootRoute.addChildren([
  indexRoute,
  loginRoute,
  findingsRoute,
  findingsDetailRoute,
  assetsRoute,
  aiAssistantRoute,
  cloudAccountsRoute,
  cloudAccountsScanRoute,
  complianceRoute,
  settingsRoute,
  reportsRoute,
  incidentsRoute,
  incidentsDetailRoute,
  attackGraphRoute,
  remediationRoute,
  riskRoute,
  identitiesRoute,
]);

export const router = createRouter({ routeTree });

declare module '@tanstack/react-router' {
  interface Register {
    router: typeof router;
  }
}
