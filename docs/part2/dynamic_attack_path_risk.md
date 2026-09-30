# Dynamic Attack-Path Risk Engine (Step 3B)

## 1. Path Existence vs Path Risk vs Activation
The `DynamicAttackPathRiskEngine` introduces a crucial distinction in the Aegivion platform:
*   **Path Existence:** Does a graph path structurally exist from an entry point to a target? (Structural property)
*   **Path Risk:** How dangerous is that path based on misconfigurations, privileges, and reachability? (Security-risk calculation)
*   **Attack Activation:** Is current behavior actually activating the path? (Temporal/behavioral evidence)

This engine ONLY calculates **Path Risk**. It is purely analytical and reads from the Security Digital Twin graph.

## 2. Graph Model
Paths are modeled as lists of nodes and edges retrieved from the Digital Twin:
`ENTRY → IDENTITY → PRIVILEGE → RESOURCE → RELATIONSHIP → TARGET`

## 3. Node Risk
Nodes contribute risk based on their inherent characteristics (e.g., exposure or known vulnerabilities). The entry node forms the base risk score for the path.

## 4. Edge Risk
Different edges transmit risk differently. Relationships like `OWNS` or `ASSUMES_ROLE` represent strong links with minimal risk attenuation (Multiplier = 0.95), while weaker links like `CONNECTED_TO` attenuate risk more heavily (Multiplier = 0.80).

## 5. Privilege Risk
Identities with `administrative` privileges bump the risk score by `+0.4`. Identities with `elevated`, `write`, or `delete` privileges bump the risk score by `+0.2`. `read` and `standard` privileges do not artificially inflate risk.

## 6. Reachability
Paths that are directly reachable (1 hop) carry a high inherent risk penalty (`x 1.2` multiplier). For multi-hop paths, risk naturally decays based on friction/length.

## 7. Target Impact
The criticality of the final target node strongly influences the path's risk. If a path ends at a `mission_critical`, `sensitive`, or `production` resource, it adds a `+0.3` multiplier scaled by 1.5 (`+0.45`). If intermediate nodes are critical, they add smaller incremental risks (`+0.2` to `+0.3`).

## 8. Path Length
Path length interacts with reachability. The formula employs a decay factor: `max(0.5, 1.0 - (path_length * 0.05))`. Shorter paths are generally more exploitable.

## 9. Risk Propagation Formula
```text
Score = Entry Risk + Privilege Bumps + Intermediate Criticality Bumps + Target Criticality Bump + Edge Bumps
Final PathRisk = Score * Edge Multiplier Product * Reachability Factor (decay)
Final PathRisk = min(1.0, max(0.0, Final PathRisk))
```
Scores map to standard tiers: `>= 0.85 (CRITICAL)`, `>= 0.65 (HIGH)`, `>= 0.40 (MEDIUM)`, `< 0.40 (LOW)`.

## 10. Dynamic Recalculation
Risk is recalculated on demand using the current graph state provided by the `SecurityDigitalTwin`. We do not persistently store static risk if underlying IAM policies or resources change.

## 11. Multi-Cloud Normalization
The engine is provider-neutral. AWS, Azure, and GCP graph models use standardized `CloudIdentity`, `CloudAsset`, and `AssetRelationship` contracts, meaning this single deterministic formula works seamlessly across clouds.

## 12. Evidence Traceability
Every node and edge evaluated outputs a `RiskContribution` specifying exactly the `element_id`, `factor` (e.g., `PRIVILEGED_ACCESS`), `contribution` (value), and `classification` (e.g., `OBSERVED`).

## 13. Tenant Isolation
The engine strictly requires an `organization_id` at invocation. All nodes and edges supplied to it are bound to this context, ensuring no cross-tenant graph traversal occurs during evaluation.

## 14. Limitations
*   The engine is dependent on the freshness of the Security Digital Twin state.
*   Path traversal logic relies on the assumption that external engines filter out disjoint paths before invoking the calculation.
*   It does not predict future paths or execute cloud mutations (remediation).

## 15. Test Methodology
Tests cover:
*   Deterministic score verification
*   Higher risk for privileged identities and critical targets
*   Read-only vs destructive path differentials
*   Direct vs multi-hop reachability scaling
*   Graceful failure on unknown criticality
*   Tenant isolation validation (cross-tenant tests)
*   Evidence traceability assertions
