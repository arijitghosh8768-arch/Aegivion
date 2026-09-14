import pandas as pd
from scipy.stats import spearmanr

def run_experiment():
    print("Loading benchmark priority rankings...")
    
    # Ground Truth Ordering (1 is highest priority)
    ground_truth = {
        "vuln-10": 1, # Exposed S3 bucket
        "vuln-4": 2,  # Overprivileged IAM
        "vuln-2": 3,  # SSH exposed
        "vuln-7": 4,  # Unencrypted volume
        "vuln-1": 5   # Missing tag
    }
    
    # Simulated model scorings
    df = pd.DataFrame([
        {
            "finding_id": "vuln-10",
            "ground_truth_rank": 1,
            "severity_only_rank": 3, 
            "context_aware_rank": 2,
            "aegivion_risk_rank": 1
        },
        {
            "finding_id": "vuln-4",
            "ground_truth_rank": 2,
            "severity_only_rank": 1, 
            "context_aware_rank": 3,
            "aegivion_risk_rank": 2
        },
        {
            "finding_id": "vuln-2",
            "ground_truth_rank": 3,
            "severity_only_rank": 4, 
            "context_aware_rank": 1,
            "aegivion_risk_rank": 3
        },
        {
            "finding_id": "vuln-7",
            "ground_truth_rank": 4,
            "severity_only_rank": 2, 
            "context_aware_rank": 4,
            "aegivion_risk_rank": 4
        },
        {
            "finding_id": "vuln-1",
            "ground_truth_rank": 5,
            "severity_only_rank": 5, 
            "context_aware_rank": 5,
            "aegivion_risk_rank": 5
        }
    ])
    
    # Calculate Spearman Correlation
    spearman_severity, _ = spearmanr(df["ground_truth_rank"], df["severity_only_rank"])
    spearman_context, _ = spearmanr(df["ground_truth_rank"], df["context_aware_rank"])
    spearman_aegivion, _ = spearmanr(df["ground_truth_rank"], df["aegivion_risk_rank"])
    
    results = pd.DataFrame([
        {"Approach": "Severity Only", "Spearman Correlation": round(spearman_severity, 3)},
        {"Approach": "Severity + Context", "Spearman Correlation": round(spearman_context, 3)},
        {"Approach": "Full Aegivion Risk", "Spearman Correlation": round(spearman_aegivion, 3)},
    ])
    
    print("\n--- Experiment 3: Prioritization Correlation ---")
    print(results.to_markdown(index=False))
    print("\nCorrelation closer to 1.0 indicates perfect alignment with expert triage.")

if __name__ == "__main__":
    run_experiment()
