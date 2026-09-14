# Final Presentation: Demo Script

**Title:** Aegivion - AI-Powered Cloud Security Posture Management (CSPM)

---

## 1. Introduction & Dashboard Overview (1 Min)
**Speaker:** "Welcome to Aegivion. Today we're going to show you how our platform detects, explains, and remediates complex, multi-stage attack paths in the cloud."
*   **Action:** Log into the Aegivion dashboard.
*   **Talking Point:** Highlight the top-level metrics: the Global Risk Score, the number of active Critical Findings, and the compliance framework status (e.g., CIS AWS Foundations).

## 2. The Attack Path Discovery (2 Mins)
**Speaker:** "Traditional tools just give you a list of alerts. Aegivion connects the dots. Let's look at a critical incident our engine just flagged."
*   **Action:** Navigate to the **Findings Graph View**.
*   **Talking Point:** Point out the visual nodes.
    *   "Here we see the entry point: An **EC2 Instance** that is publicly exposed to the internet."
    *   "Why is it exposed? Because of this **Security Group** allowing inbound traffic on Port 22 (SSH) and 80 (HTTP) from `0.0.0.0/0`."
    *   "But the risk doesn't stop there. If an attacker breaches this EC2 instance, they inherit this **overprivileged IAM Role**."
    *   "And that IAM role has `s3:GetObject` permissions to our **Sensitive S3 Bucket** containing PII."
*   **Conclusion:** "An attacker goes from the public internet directly to sensitive customer data in three steps."

## 3. AI Explanation & Context (1 Min)
**Speaker:** "Not everyone on the team is an AWS IAM expert. That's where Aegivion's AI steps in."
*   **Action:** Click the **"Explain Risk"** button on the attack path.
*   **Talking Point:** Show the auto-generated explanation.
    *   "Our FastAPI backend queries Qdrant to pull the exact architectural context, and our AI summarizes it in plain English."
    *   "It explains *how* the attack would happen and *what* the blast radius is."

## 4. Remediation via AI Chat (1 Min)
**Speaker:** "Now, how do we fix this before it's exploited?"
*   **Action:** Open the **AI Chat** panel next to the finding.
*   **Action:** Type: *"How do I fix the Security Group and IAM role to break this attack path?"*
*   **Talking Point:** The AI assistant provides a two-step fix:
    1. A Terraform snippet to restrict the Security Group to corporate IPs.
    2. An updated IAM policy limiting S3 access.
*   **Action:** Click **"Generate Remediation PR"** (or show the CLI script).

## 5. Conclusion (30 Secs)
**Speaker:** "In under 5 minutes, Aegivion detected a multi-hop vulnerability, explained the risk in human terms, and provided the exact code needed to secure the environment. Thank you."
