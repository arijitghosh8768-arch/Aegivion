# Aegivion Algorithm #1 - Evaluation Report

_Generated: 2026-09-26T21:26:20.937751+00:00_

> **All labels in this evaluation are SYNTHETIC. Metrics support relative comparison between detector configurations only; they do not validate real-world performance and no such claim is made.**

## Method

Hybrid identity-behavior detector evaluated against three ablations (rules only; rules + behavioral baseline; rules + baseline + ML) and the full pipeline (adds risk fusion, ARDE validation and calibrated confidence). Chronological train/validation/test split per identity stream; thresholds tuned on validation only; test scored once.

## Dataset

* total events: 2704
* positive (compromise) events: 64
* NORMAL: 1440 events / 0 positives across 8 streams
* SINGLE_ANOMALY: 240 events / 0 positives across 8 streams
* MULTI_SIGNAL_ANOMALY: 240 events / 0 positives across 8 streams
* SIMULATED_CREDENTIAL_COMPROMISE: 784 events / 64 positives across 4 streams

## Results (test split, frozen thresholds)

| system | precision | recall | F1 | PR-AUC | ROC-AUC | FPR | FNR | latency(ev) | Brier | ECE | P@R.8 | R@FPR.1 |
|---|---|---|---|---|---|---|---|---|---|---|---|---|
| A: rules only | 1.0000 | 0.6000 | 0.7500 | 0.6556 | 0.8000 | 0.0000 | 0.4000 | 0 | 0.0728 | 0.0732 | 0.1356 | 0.6000 |
| B: rules + baseline | 1.0000 | 1.0000 | 1.0000 | 1.0000 | 1.0000 | 0.0000 | 0.0000 | 0 | 0.0084 | 0.0623 | 1.0000 | 1.0000 |
| C: rules + baseline + ML | 1.0000 | 1.0000 | 1.0000 | 1.0000 | 1.0000 | 0.0000 | 0.0000 | 0 | 0.0203 | 0.0843 | 1.0000 | 1.0000 |
| D: full pipeline | 1.0000 | 1.0000 | 1.0000 | 1.0000 | 1.0000 | 0.0000 | 0.0000 | 0 | 0.0183 | 0.0967 | 1.0000 | 1.0000 |

### Confusion matrices

* **A: rules only**: TP=24 FP=0 FN=16 TN=504
* **B: rules + baseline**: TP=40 FP=0 FN=0 TN=504
* **C: rules + baseline + ML**: TP=40 FP=0 FN=0 TN=504
* **D: full pipeline**: TP=40 FP=0 FN=0 TN=504

## Ablation study

| configuration removed | F1 | precision | recall | FPR | PR-AUC |
|---|---|---|---|---|---|
| without_rules | 1.0000 | 1.0000 | 1.0000 | 0.0000 | 1.0000 |
| without_ml | 1.0000 | 1.0000 | 1.0000 | 0.0000 | 1.0000 |
| without_privilege_features | 1.0000 | 1.0000 | 1.0000 | 0.0000 | 1.0000 |
| without_temporal | 1.0000 | 1.0000 | 1.0000 | 0.0000 | 1.0000 |
| without_arde | 1.0000 | 1.0000 | 1.0000 | 0.0000 | 1.0000 |

Interpretation: a layer 'contributes' when removing it degrades F1 or materially raises FPR. Layers whose removal changes nothing are candidates for simplification - reported as measured, not rationalized.

## False-positive analysis

**A: rules only**

**B: rules + baseline**

**C: rules + baseline + ML**

**D: full pipeline**

## Cross-identity generalization

| identity | n_test | positives | precision | recall | FPR |
|---|---|---|---|---|---|
| user/research-0 | 88 | 10 | 1.0000 | 1.0000 | 0.0000 |
| user/research-1 | 48 | 0 | - | - | 0.0000 |
| user/research-2 | 88 | 10 | 1.0000 | 1.0000 | 0.0000 |
| user/research-3 | 48 | 0 | - | - | 0.0000 |
| user/research-4 | 88 | 10 | 1.0000 | 1.0000 | 0.0000 |
| user/research-5 | 48 | 0 | - | - | 0.0000 |
| user/research-6 | 88 | 10 | 1.0000 | 1.0000 | 0.0000 |
| user/research-7 | 48 | 0 | - | - | 0.0000 |

## Drift simulation

```json
{
  "drift_phases": [
    "device_change",
    "travel",
    "hours_shift",
    "new_api"
  ],
  "drift_events_scored": 120,
  "drift_events_flagged_as_findings": 0,
  "late_attack_detected": true,
  "late_attack_caught_at": "DoThing",
  "note": "flagged drift events above zero indicate the risk-aware baseline update cadence is conservative; none of them are suppressed silently"
}
```

## Performance

* throughput: 5651.6 events/s
* mean inference latency: 0.1766 ms
* p95 inference latency: 0.2458 ms
* memory delta during run: 0.0 MB
* notes: baseline learn: 300 events in 0.004s; timings are environment-dependent and not comparable across machines

## Limitations

* Synthetic labels: relative comparisons only; no real-world validation.
* The Isolation Forest is a pure-Python implementation (scikit-learn is not a project dependency).
* Timings are environment-dependent; the benchmark machine is not specified or controlled.
* Thresholds are tuned for F1 on validation; security operations may prefer recall-oriented operating points (`target_recall` strategy).
* The supervised second model remains untrained: no real labeled incident data exists in this repository.

## Error analysis

False positives are categorized by the signals that produced them (travel, VPN egress, new device, unusual hour, novel API, frequency, privilege). The governed suppression engine addresses the travel/VPN/maintenance categories; peer baselines address cold-start noise.

## Future work

* Train and calibrate the supervised model on real labeled incident data (isotonic/Platt).
* Replace the deterministic sequence heuristic with a learned sequence model once real sequences exist.
* Evaluate on multi-account, multi-region telemetry with peer groups at scale.
* Calibration-aware threshold schedules per identity category.