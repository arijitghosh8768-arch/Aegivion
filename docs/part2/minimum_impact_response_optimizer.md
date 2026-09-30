# Minimum-Impact Response Optimizer (Step 4C)

## 1. Purpose
The Minimum-Impact Response Optimizer determines which predefined response candidate provides the best security improvement relative to its modeled operational impact. It shifts the paradigm from simply choosing the "most aggressive" action to selecting the action that safely curtails an attack path while causing the least business disruption.

## 2. Safety Boundary
Step 4C remains an **analytical and read-only layer**. The optimizer never mutates real cloud infrastructure, calls cloud SDKs, runs shell commands, or triggers automated remediation directly. Optimization evaluates what the best action would be without authorizing or executing it. Authorization is handled exclusively by Step 4D (Safety / Policy), and execution occurs in Step 5.

## 3. Candidate Taxonomy
The optimizer works exclusively with a controlled, logical taxonomy of actions, including:
- `RESTRICT_IDENTITY_PRIVILEGE`
- `DISABLE_COMPROMISED_IDENTITY`
- `REVOKE_COMPROMISED_CREDENTIAL`
- `RESTRICT_RESOURCE_ACCESS`
- `REMOVE_PUBLIC_ACCESS`
- `ISOLATE_NETWORK_PATH`

## 4. Optimization Objective
The optimizer mathematically balances security against impact using the following normalized formula:

```text
MinimumImpactScore = 
    SecurityBenefit 
  - BusinessImpactPenalty 
  - BlastRadiusPenalty 
  - ActionRiskPenalty 
  + ReversibilityBonus
```

Weights can be configured centrally, with positive weights focusing on benefit/reversibility and negative weights on penalties.

## 5. Security Benefit
Security Benefit is modeled through four primary components derived directly from the Step 4B simulation:
- **Attack-path reduction**: How effectively the candidate trims modeled attack paths.
- **Risk reduction**: The reduction in the modeled path-risk score.
- **Critical asset protection**: The number of critical assets the candidate makes unreachable.
- **Reachability reduction**: The overall reduction in resources reachable by the compromised identity.

## 6. Operational Impact
- **Business impact**: How much legitimate functionality could be disrupted. Driven by metadata (e.g., `production=True`).
- **Blast radius**: Derived from Step 4B, reflecting the breadth of assets and services affected by the action.
- **Action risk**: The inherent risk of the action (e.g., deleting a role vs. temporarily revoking a token).
- **Reversibility**: A bonus applied to actions that can be easily undone, highly preferring temporary mitigations over destructive ones.

## 7. Ranking
The optimizer ranks all feasible response candidates by their `MinimumImpactScore` in descending order. It provides an auditable rationale explaining exactly why a candidate received its score across every dimension. 

## 8. Ambiguity
If the top candidates score within a configurable tolerance (e.g., 0.05), the optimization state is marked as `AMBIGUOUS_TOP_CANDIDATES`, and uncertainty is escalated. The engine does not pretend a meaningless mathematical difference constitutes a definitive operational choice.

## 9. Confidence
The optimizer assesses its own decision confidence based on the prediction state (Step 4A), simulation completeness (Step 4B), and metadata availability. A lack of business metadata, for example, forces the engine to declare `HIGH` uncertainty.

## 10. Provenance
Every element of rationale is explicitly tracked via provenance tags:
- `OBSERVED`: Direct factual evidence from the Digital Twin.
- `SIMULATED`: Hypothetical changes computed via Step 4B.
- `INFERRED`: Derived conclusions from the optimizer (e.g., score values).
- `UNKNOWN`: Missing data points (e.g., unknown business impact).

## 11. Limitations
- **Incomplete Metadata**: Without thorough business metadata, impact defaults to approximations with high uncertainty.
- **Graph Completeness**: The optimization is only as good as the underlying Security Digital Twin graph.
- **Not an Authorization**: "Top-ranked" does not imply "Authorized."
- **Deterministic Baseline**: The static weighting formula provides a reproducible baseline, not an evolving AI model.

## 12. Future Research
Future iterations could explore:
- Multi-objective Pareto optimization.
- Adaptive weighting based on historical feedback.
- Cost-sensitive optimizations reflecting exact dollar values.
- Organization-specific business impact models (custom risk appetites).
- Reinforcement learning for iterative improvement.
