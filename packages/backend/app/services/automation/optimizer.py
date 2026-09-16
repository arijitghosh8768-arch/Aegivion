from typing import List, Optional
from pydantic import BaseModel

class CandidateAction(BaseModel):
    id: str
    action_type: str
    attack_path_reduction: float  # 0.0 to 1.0
    business_impact: str          # "LOW", "MEDIUM", "HIGH"
    blast_radius: str             # "LOW", "MEDIUM", "HIGH"
    is_reversible: bool
    confidence: float             # 0.0 to 1.0
    
    # Computed score placeholder
    optimization_score: float = 0.0

class MinimumImpactOptimizer:
    """
    Evaluates multiple response candidates to find the optimal balance between
    security effectiveness (attack path reduction) and operational safety 
    (minimum business impact).
    """
    
    # Algorithm Weights
    WEIGHT_REDUCTION = 40.0
    WEIGHT_CONFIDENCE = 20.0
    
    # Penalties and Bonuses
    IMPACT_SCORES = {
        "LOW": 20.0,
        "MEDIUM": 0.0,
        "HIGH": -30.0
    }
    
    BLAST_SCORES = {
        "LOW": 10.0,
        "MEDIUM": 0.0,
        "HIGH": -15.0
    }
    
    REVERSIBLE_BONUS = 10.0

    def calculate_score(self, candidate: CandidateAction) -> float:
        """
        Calculates the fitness score for a candidate. 
        Higher is better (safer + more effective).
        """
        score = 0.0
        
        # 1. Base Effectiveness
        score += (candidate.attack_path_reduction * self.WEIGHT_REDUCTION)
        score += (candidate.confidence * self.WEIGHT_CONFIDENCE)
        
        # 2. Business & Blast Penalties/Rewards
        score += self.IMPACT_SCORES.get(candidate.business_impact.upper(), 0.0)
        score += self.BLAST_SCORES.get(candidate.blast_radius.upper(), 0.0)
        
        # 3. Reversibility Bonus
        if candidate.is_reversible:
            score += self.REVERSIBLE_BONUS
            
        return round(score, 2)

    def rank_candidates(self, candidates: List[CandidateAction]) -> List[CandidateAction]:
        """
        Scores and ranks a list of candidates from best to worst.
        """
        for candidate in candidates:
            candidate.optimization_score = self.calculate_score(candidate)
            
        # Sort descending by score
        return sorted(candidates, key=lambda c: c.optimization_score, reverse=True)

    def select_best_candidate(self, candidates: List[CandidateAction]) -> Optional[CandidateAction]:
        """
        Returns the top candidate. If the top candidate's score is too low,
        returns None (indicating no safe/effective action exists).
        """
        if not candidates:
            return None
            
        ranked = self.rank_candidates(candidates)
        top_candidate = ranked[0]
        
        # Define an absolute minimum threshold to propose an action
        # E.g., if it's HIGH impact, HIGH blast, irreversible, and low reduction, 
        # the score will be negative.
        if top_candidate.optimization_score < 20.0:
            return None
            
        return top_candidate

optimizer_engine = MinimumImpactOptimizer()
