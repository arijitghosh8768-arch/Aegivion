import Link from "next/link";
import { Shield, ArrowLeft } from "lucide-react";
import { Button } from "@/components/ui/button";

export default function PrivacyPolicyPage() {
  return (
    <div className="min-h-screen bg-background text-foreground">
      {/* Navigation Header */}
      <header className="sticky top-0 z-50 border-b border-border/60 bg-background/80 backdrop-blur-md">
        <div className="mx-auto flex h-16 max-w-5xl items-center justify-between px-6">
          <Link href="/" className="flex items-center gap-2.5">
            <span className="flex h-9 w-9 items-center justify-center rounded-xl bg-brand-gradient shadow-soft">
              <Shield className="h-5 w-5 text-white" />
            </span>
            <span className="text-[17px] font-bold tracking-tight">
              Aegivion<span className="text-gradient">.</span>
            </span>
          </Link>
          <Link href="/">
            <Button variant="outline" size="sm" className="gap-2">
              <ArrowLeft className="h-4 w-4" /> Back to Dashboard
            </Button>
          </Link>
        </div>
      </header>

      {/* Main Content */}
      <main className="mx-auto max-w-3xl px-6 py-12 md:py-16">
        <div className="space-y-4">
          <span className="inline-block rounded-full bg-brand-purple/10 px-3 py-1 text-xs font-semibold uppercase tracking-wider text-brand-purple">
            Legal & Compliance
          </span>
          <h1 className="text-3xl font-extrabold tracking-tight md:text-4xl">
            Privacy Policy
          </h1>
          <p className="text-sm text-muted-foreground">
            Effective Date: November 9, 2026 · Last Updated: November 2026
          </p>
        </div>

        <hr className="my-8 border-border/60" />

        <article className="prose prose-invert max-w-none space-y-8 text-sm leading-relaxed text-muted-foreground">
          <section className="space-y-3">
            <h2 className="text-lg font-bold text-foreground">1. Introduction</h2>
            <p>
              Aegivion Security Inc. (&quot;Aegivion&quot;, &quot;we&quot;, &quot;our&quot;, or &quot;us&quot;) provides an autonomous
              cloud security copilot platform. We are committed to protecting your organizational data, cloud infrastructure
              credentials, and user privacy in strict accordance with industry best practices, SOC 2 Type II, ISO 27001,
              and global privacy frameworks including GDPR and CCPA.
            </p>
          </section>

          <section className="space-y-3">
            <h2 className="text-lg font-bold text-foreground">2. Cloud Account Scanning & Data Collection</h2>
            <p>
              When you connect cloud service provider accounts (e.g., AWS, Azure, Google Cloud Platform):
            </p>
            <ul className="list-disc space-y-1.5 pl-5">
              <li>
                <strong>Read-Only Metadata & Topology:</strong> We scan resource configurations, network security group rules,
                IAM roles, and cloud asset metadata necessary to generate real-time Digital Twin models and threat correlations.
              </li>
              <li>
                <strong>No Payload Data Access:</strong> Aegivion never accesses, inspects, or copies user application payloads,
                database row contents, customer files, or proprietary business data stored within your cloud resources.
              </li>
              <li>
                <strong>Temporary In-Memory Evaluation:</strong> Telemetry collected for attack simulation and risk analysis is
                processed ephemerally in encrypted memory pipelines.
              </li>
            </ul>
          </section>

          <section className="space-y-3">
            <h2 className="text-lg font-bold text-foreground">3. Multi-Tenant Data Isolation</h2>
            <p>
              Tenant isolation is enforced cryptographically and at the architectural level:
            </p>
            <ul className="list-disc space-y-1.5 pl-5">
              <li>
                <strong>Database Partitioning:</strong> All customer records are segregated by organization ID with database-level
                row access control policies and Casbin RBAC enforcement.
              </li>
              <li>
                <strong>Credentials & Token Encryption:</strong> Cloud connection secrets, STS AssumeRole sessions, and API tokens
                are encrypted at rest using AES-256-GCM and HSM-backed key rotation mechanisms.
              </li>
            </ul>
          </section>

          <section className="space-y-3">
            <h2 className="text-lg font-bold text-foreground">4. AI Grounding & LLM Data Protection</h2>
            <p>
              Aegivion AI Copilot utilizes enterprise-grade model providers (Anthropic Claude, OpenAI, and Google Gemini).
              Your cloud architecture metadata and security findings are never submitted to public training sets or used
              by upstream foundation model providers to train AI models. All API communications leverage zero-retention contracts.
            </p>
          </section>

          <section className="space-y-3">
            <h2 className="text-lg font-bold text-foreground">5. Data Retention & Account Deletion</h2>
            <p>
              We maintain security findings, audit traces, and snapshots according to your chosen plan retention window (14 to 90 days).
              Upon account or organization termination:
            </p>
            <ul className="list-disc space-y-1.5 pl-5">
              <li>All connected cloud integrations and access tokens are immediately revoked.</li>
              <li>Historical snapshots, telemetry, and digital twins are cryptographically wiped within 30 days.</li>
              <li>Organizations can request an immediate hard-delete by contacting <code className="text-foreground">privacy@aegivion.com</code>.</li>
            </ul>
          </section>

          <section className="space-y-3">
            <h2 className="text-lg font-bold text-foreground">6. Security Certifications & Contact</h2>
            <p>
              If you have any questions regarding our privacy practices, security posture, or data handling policies,
              please reach out to our Data Protection Officer at:
            </p>
            <div className="rounded-xl border border-border/60 bg-card p-4 text-xs font-mono text-foreground">
              Aegivion Security Inc. — Data Protection Office<br />
              Email: security@aegivion.com · privacy@aegivion.com
            </div>
          </section>
        </article>
      </main>

      {/* Footer */}
      <footer className="border-t border-border/60 py-8 text-center text-xs text-muted-foreground">
        <div className="mx-auto flex max-w-5xl flex-col items-center justify-between gap-4 px-6 md:flex-row">
          <p>© 2026 Aegivion Security Inc. All rights reserved.</p>
          <div className="flex gap-6">
            <Link href="/privacy" className="hover:text-foreground">Privacy Policy</Link>
            <Link href="/terms" className="hover:text-foreground">Terms of Service</Link>
            <Link href="/login" className="hover:text-foreground">Sign In</Link>
          </div>
        </div>
      </footer>
    </div>
  );
}
