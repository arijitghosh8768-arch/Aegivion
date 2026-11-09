import Link from "next/link";
import { Shield, ArrowLeft } from "lucide-react";
import { Button } from "@/components/ui/button";

export default function TermsOfServicePage() {
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
          <span className="inline-block rounded-full bg-brand-blue/10 px-3 py-1 text-xs font-semibold uppercase tracking-wider text-brand-blue">
            Terms & Agreement
          </span>
          <h1 className="text-3xl font-extrabold tracking-tight md:text-4xl">
            Terms of Service
          </h1>
          <p className="text-sm text-muted-foreground">
            Effective Date: November 9, 2026 · Last Updated: November 2026
          </p>
        </div>

        <hr className="my-8 border-border/60" />

        <article className="prose prose-invert max-w-none space-y-8 text-sm leading-relaxed text-muted-foreground">
          <section className="space-y-3">
            <h2 className="text-lg font-bold text-foreground">1. Acceptance of Terms</h2>
            <p>
              By signing up, accessing, or using the Aegivion platform, application programming interfaces (APIs),
              or cloud remediation tools (&quot;Services&quot;), you agree to be bound by these Terms of Service.
              If you represent an enterprise or legal entity, you represent and warrant that you possess the requisite authority
              to bind that organization to these terms.
            </p>
          </section>

          <section className="space-y-3">
            <h2 className="text-lg font-bold text-foreground">2. Authorized Cloud Access & Scopes</h2>
            <p>
              In order to provide autonomous security posture management, digital twin visualization, and remediation:
            </p>
            <ul className="list-disc space-y-1.5 pl-5">
              <li>
                <strong>Client Authorization:</strong> You grant Aegivion explicit authorization to connect to your specified cloud environments
                (AWS cross-account IAM roles, Azure service principals, GCP service accounts) to retrieve metadata and discover configuration state.
              </li>
              <li>
                <strong>Credential Integrity:</strong> You agree not to provide unauthorized, compromised, or third-party credentials.
              </li>
              <li>
                <strong>Least-Privilege Principle:</strong> You are encouraged to configure cloud roles strictly adhering to Aegivion&apos;s
                documented least-privilege policies.
              </li>
            </ul>
          </section>

          <section className="space-y-3">
            <h2 className="text-lg font-bold text-foreground">3. Autonomous Remediation & Safe Rollback</h2>
            <p>
              Aegivion provides both manual approval workflows and autonomous threat remediation capabilities (such as revoking
              over-permissive security groups, disabling compromised access keys, and closing public S3 buckets):
            </p>
            <ul className="list-disc space-y-1.5 pl-5">
              <li>
                <strong>Verification & Rollback:</strong> Every automated action is accompanied by state tracking and an automated rollback
                manifest. You retain ultimate control over whether actions execute autonomously or require interactive two-man approval.
              </li>
              <li>
                <strong>Operational Testing:</strong> You are responsible for validating that automated remediation actions match your organizational
                change management policies in staging before enabling production autonomous execution.
              </li>
            </ul>
          </section>

          <section className="space-y-3">
            <h2 className="text-lg font-bold text-foreground">4. Service Level & Availability</h2>
            <p>
              We strive to deliver 99.9% uptime for the Aegivion platform. Scheduled maintenance windows, upstream cloud provider outages,
              and emergency security patches are announced in advance via the status dashboard.
            </p>
          </section>

          <section className="space-y-3">
            <h2 className="text-lg font-bold text-foreground">5. Termination & Suspension</h2>
            <p>
              Either party may terminate the Service agreement at any time. Aegivion reserves the right to suspend API access in the event
              of detected denial-of-service attempts, fraudulent scanning activity, or severe terms violations.
            </p>
          </section>

          <section className="space-y-3">
            <h2 className="text-lg font-bold text-foreground">6. Contact & Legal Notices</h2>
            <p>
              For legal inquiries, dispute notifications, or enterprise custom MSA agreements, contact:
            </p>
            <div className="rounded-xl border border-border/60 bg-card p-4 text-xs font-mono text-foreground">
              Aegivion Security Inc. — Legal Counsel<br />
              Email: legal@aegivion.com · compliance@aegivion.com
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
