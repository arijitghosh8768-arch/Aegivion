# What-If Attack Simulation (Step 4B)

## 1. Purpose
The What-If Attack Simulation Engine is the "sandbox brain" of Aegivion. It answers: "If a predicted attack stage occurred, what assets, identities, relationships, attack paths, and blast radius could be affected?" It evaluates these questions purely in memory without mutating the real cloud infrastructure.

## 2. Safety Model
The simulator must NEVER mutate the real environment. It operates entirely on an in-memory clone of the Security Digital Twin state. It does not contain any AWS, Azure, or GCP SDK calls and strictly rejects unsupported hypothetical scenarios. **Step 4B never performs real cloud mutation and never selects or executes remediation.**

## 3. Simulation State
The simulator consumes a `SimulationState` representing the Digital Twin:
- `assets`: Nodes representing resources (e.g., databases, buckets).
- `identities`: Nodes representing actors (e.g., users, roles).
- `relationships`: Edges representing permissions/access between nodes.
This state is deep-copied at the start of simulation to ensure isolation.

## 4. Scenario Taxonomy
Supported hypothetical operations include:
- `MARK_IDENTITY_COMPROMISED`
- `GRANT_SIMULATED_PRIVILEGE`
- `ADD_SIMULATED_RELATIONSHIP`
- `ENABLE_SIMULATED_ACCESS`
- `MARK_RESOURCE_REACHABLE`
- `SIMULATE_DATA_ACCESS`
- `SIMULATE_DATA_EXFILTRATION`
- `SIMULATE_DESTRUCTIVE_ACCESS`

Any unsupported operations (like `RUN_SHELL` or SDK commands) are explicitly rejected.

## 5. Graph Traversal
The engine uses Breadth-First Search (BFS) to determine reachability. It traverses relationships originating from compromised identities to compute which assets an attacker could theoretically reach in the simulated scenario.

## 6. Attack-Path Calculation
An attack path is built concurrently during graph traversal. It records the nodes visited, path length, and risk score (which spikes if the path terminates on a critical asset).

## 7. Blast Radius
The blast radius aggregates metrics across newly reachable assets, capturing:
- Number of affected assets
- Critical and sensitive assets exposed
- Multi-provider and multi-region impact
- Maximum depth of new attack paths

## 8. Risk Delta
Risk delta calculates the difference between simulated and baseline risk (`simulated_risk - baseline_risk`). It indicates whether the hypothetical scenario increases overall attack-path exposure. A positive delta means the scenario opens new or riskier avenues of attack.

## 9. Provenance
Every piece of evidence in the simulation is strictly categorized:
- **OBSERVED**: Direct facts from the baseline Digital Twin.
- **SIMULATED**: Hypothetical changes applied by the scenario.
- **INFERRED**: Graph results (e.g., blast radius) inferred from simulated changes.
- **UNKNOWN**: Missing metadata.

## 10. Limitations
- **Incomplete Cloud Visibility**: If the original Digital Twin lacks certain relationships, the simulation cannot model them.
- **Missing Asset Criticality**: If assets lack metadata, impact defaults to `UNKNOWN`.
- **Graph Truncation**: To prevent DoS, the engine enforces `max_depth`, `max_paths`, and `max_nodes`. Reaching a limit forces the state to `PARTIAL` with `HIGH` uncertainty.
- **Deterministic**: The simulation uses a deterministic BFS model rather than a probabilistic simulation.
- **Intent**: A simulated path does not establish that an attacker *will* exploit it, only that they *could*.

## 11. Safety Boundary
**Step 4B never performs real cloud mutation and never selects or executes remediation.** Its output is solely intended to inform Step 4C (Minimum-Impact Response).
