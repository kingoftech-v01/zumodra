"""
Hybrid Ranking Engine Service

Implements features.md Section 4.1-4.3:
- RuleScore: Deterministic ATS filters with knockout logic
- AIScore: ML-based matching using embeddings
- VerificationScore: Trust score integration from accounts.TrustScore

This engine combines three scoring dimensions to provide transparent,
explainable candidate rankings for job postings.

Author: Adams Pierre David
Since: 3.0.0
"""

import logging
from dataclasses import dataclass, field
from decimal import Decimal
from typing import List, Dict, Optional, Tuple, Any, TYPE_CHECKING
import math

from django.db import transaction
from django.utils import timezone
from django.db.models import QuerySet

if TYPE_CHECKING:
    from tenants.models import Tenant
    from accounts.models import TrustScore
    from ai_matching.models import RankingProfile, RankingRule, CandidateRanking

logger = logging.getLogger(__name__)


# ============================================================================
# Data Classes
# ============================================================================

@dataclass
class RuleEvaluationResult:
    """Result of evaluating a single rule against a candidate."""
    rule_id: int
    rule_name: str
    rule_type: str  # 'knockout', 'preference', 'bonus'
    passed: bool
    score: Decimal
    reason: str


@dataclass
class RuleScoreResult:
    """Aggregated result of all rule evaluations."""
    total_score: Decimal
    passed_knockout: bool
    knockout_reasons: List[str] = field(default_factory=list)
    rules_evaluated: int = 0
    rules_passed: int = 0
    rule_details: List[RuleEvaluationResult] = field(default_factory=list)


@dataclass
class AIScoreResult:
    """Result of AI-based matching calculation."""
    total_score: Decimal
    skill_match_score: Decimal = Decimal('0.00')
    experience_match_score: Decimal = Decimal('0.00')
    culture_fit_score: Decimal = Decimal('0.00')
    location_match_score: Decimal = Decimal('0.00')
    salary_match_score: Decimal = Decimal('0.00')
    embedding_similarity: Optional[float] = None
    matched_skills: List[str] = field(default_factory=list)
    missing_skills: List[str] = field(default_factory=list)
    bonus_skills: List[str] = field(default_factory=list)


@dataclass
class VerificationScoreResult:
    """Result of verification/trust score calculation."""
    total_score: Decimal
    identity_score: Decimal = Decimal('0.00')
    career_score: Decimal = Decimal('0.00')
    trust_score: Decimal = Decimal('0.00')
    is_id_verified: bool = False
    is_career_verified: bool = False
    trust_level: str = 'new'


@dataclass
class RankingResult:
    """Complete ranking result for a candidate-job pair."""
    candidate_id: int
    job_id: int
    rule_score: Decimal
    ai_score: Decimal
    verification_score: Decimal
    overall_score: Decimal
    passed_knockout: bool
    is_recommended: bool
    rank_position: Optional[int] = None
    bonus_points: Decimal = Decimal('0.00')
    bonuses_applied: List[Dict[str, Any]] = field(default_factory=list)
    knockout_reasons: List[str] = field(default_factory=list)
    top_strengths: List[str] = field(default_factory=list)
    improvement_areas: List[str] = field(default_factory=list)
    explanation: Dict[str, Any] = field(default_factory=dict)


# ============================================================================
# Hybrid Ranking Engine
# ============================================================================

class HybridRankingEngine:
    """
    Implements the hybrid ranking system combining rules, AI, and verification.

    Features (from features.md Section 4):
    - RuleScore: Deterministic ATS filters with Boolean knockouts
    - AIScore: ML-based matching using embeddings and semantic similarity
    - VerificationScore: Trust integration from TrustScore model

    The engine provides:
    - Transparent three-score breakdown
    - Configurable weights via RankingProfile
    - Knockout rules for instant disqualification
    - Bonus points for verified candidates
    - Explainable ranking factors

    Usage:
        engine = HybridRankingEngine(tenant=request.tenant)
        rankings = engine.rank_candidates_for_job(job_id=123, candidate_ids=[1, 2, 3])
    """

    def __init__(
        self,
        tenant: 'Tenant',
        ranking_profile: Optional['RankingProfile'] = None
    ):
        """
        Initialize the ranking engine.

        Args:
            tenant: The tenant context for multi-tenant isolation
            ranking_profile: Optional custom ranking profile. If not provided,
                           the tenant's default profile will be used.
        """
        self.tenant = tenant
        self._profile = ranking_profile
        self._rules_cache: Optional[QuerySet] = None
        self._embedding_service = None

        logger.info(
            f"HybridRankingEngine initialized for tenant={tenant.id}, "
            f"profile={'custom' if ranking_profile else 'default'}"
        )

    @property
    def profile(self) -> 'RankingProfile':
        """
        Get the ranking profile, loading default if necessary.

        Returns:
            RankingProfile instance for the current tenant.

        Raises:
            ValueError: If no ranking profile is available.
        """
        if self._profile is None:
            self._profile = self._load_default_profile()
        return self._profile

    def _load_default_profile(self) -> 'RankingProfile':
        """Load the default ranking profile for the tenant."""
        from ai_matching.models import RankingProfile

        try:
            profile = RankingProfile.objects.filter(
                tenant=self.tenant,
                is_default=True,
                is_active=True
            ).first()

            if profile:
                logger.debug(f"Loaded default profile: {profile.name}")
                return profile

            # Try any active profile
            profile = RankingProfile.objects.filter(
                tenant=self.tenant,
                is_active=True
            ).first()

            if profile:
                logger.warning(
                    f"No default profile found, using: {profile.name}"
                )
                return profile

            # Create a default profile if none exists
            profile = self._create_default_profile()
            logger.info(f"Created default profile for tenant={self.tenant.id}")
            return profile

        except Exception as e:
            logger.error(f"Error loading ranking profile: {e}")
            raise ValueError(
                f"No ranking profile available for tenant {self.tenant.id}"
            )

    def _create_default_profile(self) -> 'RankingProfile':
        """Create a default ranking profile for the tenant."""
        from ai_matching.models import RankingProfile

        profile = RankingProfile.objects.create(
            tenant=self.tenant,
            name='Default Ranking Profile',
            description='Auto-generated default ranking profile',
            is_default=True,
            is_active=True,
        )
        return profile

    def _get_active_rules(self, job_category: Optional[str] = None) -> QuerySet:
        """
        Get active rules for the tenant, optionally filtered by job category.

        Args:
            job_category: Optional job category to filter rules.

        Returns:
            QuerySet of RankingRule instances.
        """
        from ai_matching.models import RankingRule

        if self._rules_cache is not None:
            return self._rules_cache

        rules = RankingRule.objects.filter(
            tenant=self.tenant,
            is_active=True
        ).order_by('priority')

        if job_category:
            rules = rules.filter(
                models.Q(apply_to_all_jobs=True) |
                models.Q(job_categories__contains=[job_category])
            )

        self._rules_cache = rules
        return rules

    def _get_embedding_service(self):
        """Get or create the embedding service instance."""
        if self._embedding_service is None:
            try:
                from ai_matching.services import EmbeddingService
                self._embedding_service = EmbeddingService()
            except ImportError:
                logger.warning("EmbeddingService not available, using fallback")
                self._embedding_service = None
        return self._embedding_service

    # ========================================================================
    # Main Entry Point
    # ========================================================================

    def rank_candidates_for_job(
        self,
        job_id: int,
        candidate_ids: List[int],
        save_results: bool = True
    ) -> List[RankingResult]:
        """
        Main entry point - ranks all candidates for a job.

        This method orchestrates the entire ranking process:
        1. Load job and candidate data
        2. Calculate rule scores (knockouts and preferences)
        3. Calculate AI scores (embeddings and semantic matching)
        4. Calculate verification scores (trust integration)
        5. Apply bonuses
        6. Calculate weighted overall scores
        7. Sort and assign rank positions

        Args:
            job_id: The ID of the job posting to rank candidates for.
            candidate_ids: List of candidate IDs to rank.
            save_results: Whether to save results to CandidateRanking model.

        Returns:
            List of RankingResult objects sorted by overall_score descending.

        Raises:
            ValueError: If job_id or candidate_ids are invalid.
        """
        if not job_id:
            raise ValueError("job_id is required")

        if not candidate_ids:
            logger.info(f"No candidates to rank for job={job_id}")
            return []

        logger.info(
            f"Starting ranking for job={job_id}, "
            f"candidates={len(candidate_ids)}, tenant={self.tenant.id}"
        )

        start_time = timezone.now()

        try:
            # Load job data
            job_data = self._load_job_data(job_id)
            if not job_data:
                raise ValueError(f"Job {job_id} not found")

            # Load candidate data
            candidates_data = self._load_candidates_data(candidate_ids)

            # Get active rules
            rules = self._get_active_rules(
                job_category=job_data.get('category')
            )

            rankings = []

            for candidate_id in candidate_ids:
                candidate_data = candidates_data.get(candidate_id, {})

                if not candidate_data:
                    logger.warning(
                        f"No data for candidate {candidate_id}, skipping"
                    )
                    continue

                try:
                    ranking = self._rank_single_candidate(
                        job_id=job_id,
                        job_data=job_data,
                        candidate_id=candidate_id,
                        candidate_data=candidate_data,
                        rules=rules
                    )
                    rankings.append(ranking)

                except Exception as e:
                    logger.error(
                        f"Error ranking candidate {candidate_id} "
                        f"for job {job_id}: {e}",
                        exc_info=True
                    )
                    continue

            # Sort by overall score descending
            rankings.sort(key=lambda x: x.overall_score, reverse=True)

            # Assign rank positions
            for position, ranking in enumerate(rankings, start=1):
                ranking.rank_position = position

            # Save results if requested
            if save_results and rankings:
                self._save_rankings(rankings)

            elapsed_ms = (timezone.now() - start_time).total_seconds() * 1000
            logger.info(
                f"Ranking complete for job={job_id}: "
                f"{len(rankings)} candidates ranked in {elapsed_ms:.0f}ms"
            )

            return rankings

        except Exception as e:
            logger.error(
                f"Error in rank_candidates_for_job: {e}",
                exc_info=True
            )
            raise

    def _rank_single_candidate(
        self,
        job_id: int,
        job_data: Dict[str, Any],
        candidate_id: int,
        candidate_data: Dict[str, Any],
        rules: QuerySet
    ) -> RankingResult:
        """
        Rank a single candidate for a job.

        Args:
            job_id: Job ID
            job_data: Job posting data dictionary
            candidate_id: Candidate ID
            candidate_data: Candidate profile data dictionary
            rules: QuerySet of RankingRule instances

        Returns:
            RankingResult for this candidate-job pair.
        """
        profile = self.profile

        # Step 1: Calculate rule score
        rule_result = self._calculate_rule_score(candidate_data, rules)

        # Step 2: Calculate AI score
        ai_result = self._calculate_ai_score(
            job_data=job_data,
            candidate_data=candidate_data,
            profile=profile
        )

        # Step 3: Calculate verification score
        user = candidate_data.get('user')
        verification_result = self._calculate_verification_score(user)

        # Create ranking result
        ranking = RankingResult(
            candidate_id=candidate_id,
            job_id=job_id,
            rule_score=rule_result.total_score,
            ai_score=ai_result.total_score,
            verification_score=verification_result.total_score,
            overall_score=Decimal('0.00'),
            passed_knockout=rule_result.passed_knockout,
            is_recommended=False,
            knockout_reasons=rule_result.knockout_reasons,
        )

        # Step 4: Apply bonuses
        ranking = self._apply_bonuses(ranking, profile, verification_result)

        # Step 5: Calculate overall score
        ranking = self._calculate_overall_score(ranking, profile)

        # Generate explanation
        ranking.explanation = self._generate_explanation(
            ranking, rule_result, ai_result, verification_result
        )
        ranking.top_strengths = self._extract_strengths(
            ai_result, verification_result
        )
        ranking.improvement_areas = self._extract_improvements(
            ai_result, rule_result
        )

        return ranking

    # ========================================================================
    # Rule Score Calculation
    # ========================================================================

    def _calculate_rule_score(
        self,
        candidate_data: Dict[str, Any],
        rules: QuerySet
    ) -> RuleScoreResult:
        """
        Evaluate all rules, return score and knockout status.

        Implements features.md Section 4.1 - Rules-Based ATS Engine:
        - Boolean knockout filters (must pass)
        - Preference rules (weighted scoring)
        - Bonus rules (additional points)

        Args:
            candidate_data: Dictionary of candidate profile data.
            rules: QuerySet of RankingRule instances to evaluate.

        Returns:
            RuleScoreResult with total score and knockout status.
        """
        result = RuleScoreResult(
            total_score=Decimal('0.00'),
            passed_knockout=True,
            knockout_reasons=[],
            rules_evaluated=0,
            rules_passed=0,
            rule_details=[]
        )

        if not rules.exists():
            # No rules = full score
            result.total_score = Decimal('100.00')
            return result

        total_weight = Decimal('0.00')
        weighted_score = Decimal('0.00')

        for rule in rules:
            result.rules_evaluated += 1

            try:
                passed, score, reason = rule.evaluate(candidate_data)

                rule_detail = RuleEvaluationResult(
                    rule_id=rule.id,
                    rule_name=rule.name,
                    rule_type=rule.rule_type,
                    passed=passed,
                    score=score,
                    reason=reason
                )
                result.rule_details.append(rule_detail)

                if passed:
                    result.rules_passed += 1

                # Handle knockout rules
                if rule.rule_type == 'knockout':
                    if not passed:
                        result.passed_knockout = False
                        result.knockout_reasons.append(
                            f"{rule.name}: {reason}"
                        )

                # Handle preference rules
                elif rule.rule_type == 'preference':
                    total_weight += rule.weight
                    if passed:
                        weighted_score += score

                # Handle bonus rules
                elif rule.rule_type == 'bonus':
                    if passed:
                        weighted_score += score

            except Exception as e:
                logger.warning(
                    f"Error evaluating rule {rule.name}: {e}"
                )
                continue

        # Calculate final score
        if total_weight > 0:
            # Normalize to 0-100 scale
            result.total_score = (weighted_score / total_weight) * Decimal('100')
        elif result.rules_passed == result.rules_evaluated:
            result.total_score = Decimal('100.00')
        else:
            ratio = Decimal(result.rules_passed) / Decimal(result.rules_evaluated)
            result.total_score = ratio * Decimal('100')

        # Cap at 100
        result.total_score = min(result.total_score, Decimal('100.00'))

        logger.debug(
            f"Rule score: {result.total_score}, "
            f"passed={result.rules_passed}/{result.rules_evaluated}, "
            f"knockout={result.passed_knockout}"
        )

        return result

    # ========================================================================
    # AI Score Calculation
    # ========================================================================

    def _calculate_ai_score(
        self,
        job_data: Dict[str, Any],
        candidate_data: Dict[str, Any],
        profile: 'RankingProfile'
    ) -> AIScoreResult:
        """
        Calculate AI matching score from embeddings and features.

        Implements features.md Section 4.2 - AI Scoring Engine:
        - Embedding-based similarity
        - Skill matching with semantic similarity
        - Experience level matching
        - Culture fit prediction
        - Location/remote preference matching
        - Salary alignment

        Args:
            job_data: Job posting data with embeddings.
            candidate_data: Candidate profile data with embeddings.
            profile: RankingProfile with weight configuration.

        Returns:
            AIScoreResult with component scores and matched skills.
        """
        result = AIScoreResult(
            total_score=Decimal('0.00'),
        )

        try:
            # Calculate embedding similarity if available
            job_embedding = job_data.get('embedding')
            candidate_embedding = candidate_data.get('embedding')

            if job_embedding and candidate_embedding:
                similarity = self._cosine_similarity(
                    job_embedding, candidate_embedding
                )
                result.embedding_similarity = similarity

            # Calculate component scores
            result.skill_match_score = self._calculate_skill_match(
                job_data, candidate_data
            )
            result.experience_match_score = self._calculate_experience_match(
                job_data, candidate_data
            )
            result.culture_fit_score = self._calculate_culture_fit(
                job_data, candidate_data
            )
            result.location_match_score = self._calculate_location_match(
                job_data, candidate_data
            )
            result.salary_match_score = self._calculate_salary_match(
                job_data, candidate_data
            )

            # Extract skill details
            skill_analysis = self._analyze_skills(job_data, candidate_data)
            result.matched_skills = skill_analysis.get('matched', [])
            result.missing_skills = skill_analysis.get('missing', [])
            result.bonus_skills = skill_analysis.get('bonus', [])

            # Calculate weighted total using profile weights
            result.total_score = (
                result.skill_match_score * profile.skill_match_weight +
                result.experience_match_score * profile.experience_match_weight +
                result.culture_fit_score * profile.culture_fit_weight +
                result.location_match_score * profile.location_match_weight +
                result.salary_match_score * profile.salary_match_weight
            )

            # Normalize to 0-100 scale
            result.total_score = min(
                result.total_score * Decimal('100'),
                Decimal('100.00')
            )

        except Exception as e:
            logger.error(f"Error calculating AI score: {e}", exc_info=True)
            # Return neutral score on error
            result.total_score = Decimal('50.00')

        logger.debug(
            f"AI score: {result.total_score}, "
            f"skill={result.skill_match_score}, "
            f"exp={result.experience_match_score}"
        )

        return result

    def _cosine_similarity(
        self,
        vec1: List[float],
        vec2: List[float]
    ) -> float:
        """
        Calculate cosine similarity between two vectors.

        Args:
            vec1: First embedding vector.
            vec2: Second embedding vector.

        Returns:
            Cosine similarity score between -1 and 1.
        """
        if not vec1 or not vec2 or len(vec1) != len(vec2):
            return 0.0

        dot_product = sum(a * b for a, b in zip(vec1, vec2))
        magnitude1 = math.sqrt(sum(a * a for a in vec1))
        magnitude2 = math.sqrt(sum(b * b for b in vec2))

        if magnitude1 == 0 or magnitude2 == 0:
            return 0.0

        return dot_product / (magnitude1 * magnitude2)

    def _calculate_skill_match(
        self,
        job_data: Dict[str, Any],
        candidate_data: Dict[str, Any]
    ) -> Decimal:
        """Calculate skill matching score."""
        job_skills = set(s.lower() for s in job_data.get('required_skills', []))
        candidate_skills = set(s.lower() for s in candidate_data.get('skills', []))

        if not job_skills:
            return Decimal('1.00')

        matched = len(job_skills & candidate_skills)
        total = len(job_skills)

        return Decimal(str(matched / total)) if total > 0 else Decimal('1.00')

    def _calculate_experience_match(
        self,
        job_data: Dict[str, Any],
        candidate_data: Dict[str, Any]
    ) -> Decimal:
        """Calculate experience level matching score."""
        min_years = job_data.get('min_experience_years', 0)
        max_years = job_data.get('max_experience_years')
        candidate_years = candidate_data.get('total_experience_years', 0)

        if min_years == 0 and max_years is None:
            return Decimal('1.00')

        if candidate_years < min_years:
            # Below minimum - partial credit based on gap
            gap = min_years - candidate_years
            if gap <= 1:
                return Decimal('0.75')
            elif gap <= 2:
                return Decimal('0.50')
            else:
                return Decimal('0.25')

        if max_years is not None and candidate_years > max_years:
            # Above maximum - slight penalty for overqualification
            gap = candidate_years - max_years
            if gap <= 2:
                return Decimal('0.90')
            else:
                return Decimal('0.75')

        return Decimal('1.00')

    def _calculate_culture_fit(
        self,
        job_data: Dict[str, Any],
        candidate_data: Dict[str, Any]
    ) -> Decimal:
        """Calculate culture fit prediction score."""
        # This would ideally use more sophisticated analysis
        # For now, use a baseline with embedding similarity boost
        company_values = job_data.get('company_values', [])
        candidate_values = candidate_data.get('values', [])

        if not company_values:
            return Decimal('0.70')  # Neutral baseline

        if not candidate_values:
            return Decimal('0.60')

        values_match = len(
            set(v.lower() for v in company_values) &
            set(v.lower() for v in candidate_values)
        )
        values_score = min(values_match / len(company_values), 1.0)

        return Decimal(str(0.5 + 0.5 * values_score))

    def _calculate_location_match(
        self,
        job_data: Dict[str, Any],
        candidate_data: Dict[str, Any]
    ) -> Decimal:
        """Calculate location/remote preference matching score."""
        job_is_remote = job_data.get('is_remote', False)
        job_location = job_data.get('location', '')
        candidate_remote_pref = candidate_data.get('remote_preference', 'flexible')
        candidate_location = candidate_data.get('location', '')

        # Fully remote job
        if job_is_remote:
            if candidate_remote_pref in ['remote', 'flexible']:
                return Decimal('1.00')
            else:
                return Decimal('0.70')

        # On-site job
        if candidate_remote_pref == 'remote':
            return Decimal('0.30')

        # Location matching for hybrid/on-site
        if job_location and candidate_location:
            if job_location.lower() == candidate_location.lower():
                return Decimal('1.00')
            else:
                return Decimal('0.60')

        return Decimal('0.75')

    def _calculate_salary_match(
        self,
        job_data: Dict[str, Any],
        candidate_data: Dict[str, Any]
    ) -> Decimal:
        """Calculate salary expectation alignment score."""
        job_min = job_data.get('salary_min')
        job_max = job_data.get('salary_max')
        candidate_expected = candidate_data.get('salary_expectation')

        if job_min is None and job_max is None:
            return Decimal('1.00')  # No salary info

        if candidate_expected is None:
            return Decimal('0.80')  # Unknown expectation

        if job_max and candidate_expected > job_max * 1.2:
            return Decimal('0.30')  # Too high

        if job_min and candidate_expected < job_min * 0.8:
            return Decimal('0.70')  # Lower than minimum (might be okay)

        return Decimal('1.00')

    def _analyze_skills(
        self,
        job_data: Dict[str, Any],
        candidate_data: Dict[str, Any]
    ) -> Dict[str, List[str]]:
        """Analyze skill overlap and gaps."""
        job_required = set(s.lower() for s in job_data.get('required_skills', []))
        job_preferred = set(s.lower() for s in job_data.get('preferred_skills', []))
        candidate_skills = set(s.lower() for s in candidate_data.get('skills', []))

        all_job_skills = job_required | job_preferred

        return {
            'matched': list(candidate_skills & all_job_skills),
            'missing': list(job_required - candidate_skills),
            'bonus': list(candidate_skills - all_job_skills),
        }

    # ========================================================================
    # Verification Score Calculation
    # ========================================================================

    def _calculate_verification_score(
        self,
        user: Optional[Any]
    ) -> VerificationScoreResult:
        """
        Get verification score from TrustScore model.

        Implements features.md Section 4.3 - Verification Score:
        - Identity verification (Level 1 KYC)
        - Career verification (Level 2 Employment + Education)
        - Overall trust score from TrustScore model

        Args:
            user: User instance to get TrustScore for.

        Returns:
            VerificationScoreResult with component scores.
        """
        result = VerificationScoreResult(
            total_score=Decimal('50.00'),  # Neutral baseline for unverified
        )

        if user is None:
            logger.debug("No user provided for verification score")
            return result

        try:
            # Get TrustScore from user
            trust_score = getattr(user, 'trust_score', None)

            if trust_score is None:
                logger.debug(f"No TrustScore for user {user.id}")
                return result

            # Extract scores from TrustScore model
            result.identity_score = trust_score.identity_score
            result.career_score = trust_score.career_score
            result.trust_score = trust_score.overall_score
            result.is_id_verified = trust_score.is_id_verified
            result.is_career_verified = trust_score.is_career_verified
            result.trust_level = trust_score.trust_level

            profile = self.profile

            # Calculate weighted total using profile weights
            result.total_score = (
                result.identity_score * profile.identity_verification_weight +
                result.career_score * profile.career_verification_weight +
                result.trust_score * profile.trust_score_weight
            )

            # Already on 0-100 scale from TrustScore
            result.total_score = min(result.total_score, Decimal('100.00'))

            logger.debug(
                f"Verification score: {result.total_score}, "
                f"id={result.is_id_verified}, career={result.is_career_verified}"
            )

        except Exception as e:
            logger.warning(
                f"Error getting verification score: {e}"
            )

        return result

    # ========================================================================
    # Bonus Application
    # ========================================================================

    def _apply_bonuses(
        self,
        ranking: RankingResult,
        profile: 'RankingProfile',
        verification_result: VerificationScoreResult
    ) -> RankingResult:
        """
        Apply bonus points for verified career, premium trust, etc.

        Implements features.md Section 4.3 - Bonus Rules:
        - Bonus for verified career (employment + education)
        - Bonus for premium trust level
        - Bonus for successful platform history

        Args:
            ranking: Current RankingResult to apply bonuses to.
            profile: RankingProfile with bonus configuration.
            verification_result: Verification score details.

        Returns:
            Updated RankingResult with bonuses applied.
        """
        bonuses_applied = []
        total_bonus = Decimal('0.00')

        # Bonus for verified career
        if verification_result.is_career_verified:
            bonus = profile.bonus_for_verified_career
            total_bonus += bonus
            bonuses_applied.append({
                'type': 'verified_career',
                'points': float(bonus),
                'reason': 'Career verified (80%+ employment/education)'
            })

        # Bonus for premium trust level
        if verification_result.trust_level == 'premium':
            bonus = profile.bonus_for_premium_trust
            total_bonus += bonus
            bonuses_applied.append({
                'type': 'premium_trust',
                'points': float(bonus),
                'reason': 'Premium trust level achieved'
            })
        elif verification_result.trust_level == 'high':
            # Half bonus for high trust
            bonus = profile.bonus_for_premium_trust / 2
            total_bonus += bonus
            bonuses_applied.append({
                'type': 'high_trust',
                'points': float(bonus),
                'reason': 'High trust level'
            })

        # Bonus for platform experience (would check completed jobs, etc.)
        # This would require additional data from the candidate
        # Placeholder for future enhancement

        ranking.bonus_points = total_bonus
        ranking.bonuses_applied = bonuses_applied

        return ranking

    # ========================================================================
    # Overall Score Calculation
    # ========================================================================

    def _calculate_overall_score(
        self,
        ranking: RankingResult,
        profile: 'RankingProfile'
    ) -> RankingResult:
        """
        Calculate weighted combination of all scores.

        Implements features.md Section 4.3 - Combined Ranking:
        MatchScore = w_r * RuleScore + w_a * AIScore + w_v * VerificationScore + Bonuses

        Args:
            ranking: RankingResult with component scores.
            profile: RankingProfile with weight configuration.

        Returns:
            Updated RankingResult with overall score and recommendation.
        """
        # If knockout failed, overall score is 0
        if not ranking.passed_knockout:
            ranking.overall_score = Decimal('0.00')
            ranking.is_recommended = False
            return ranking

        # Calculate weighted score
        weighted_score = (
            ranking.rule_score * profile.rule_score_weight +
            ranking.ai_score * profile.ai_score_weight +
            ranking.verification_score * profile.verification_score_weight
        )

        # Add bonuses
        ranking.overall_score = weighted_score + ranking.bonus_points

        # Cap at 100
        ranking.overall_score = min(ranking.overall_score, Decimal('100.00'))

        # Determine recommendation based on thresholds
        ranking.is_recommended = (
            ranking.passed_knockout and
            ranking.rule_score >= profile.minimum_rule_score and
            ranking.ai_score >= profile.minimum_ai_score and
            ranking.verification_score >= profile.minimum_verification_score and
            ranking.overall_score >= profile.minimum_overall_score
        )

        return ranking

    # ========================================================================
    # Explanation Generation
    # ========================================================================

    def _generate_explanation(
        self,
        ranking: RankingResult,
        rule_result: RuleScoreResult,
        ai_result: AIScoreResult,
        verification_result: VerificationScoreResult
    ) -> Dict[str, Any]:
        """Generate human-readable explanation of ranking."""
        explanation = {
            'summary': f"Overall match score: {ranking.overall_score:.1f}/100",
            'breakdown': {
                'rules': {
                    'score': float(ranking.rule_score),
                    'weight': float(self.profile.rule_score_weight),
                    'details': f"Passed {rule_result.rules_passed}/{rule_result.rules_evaluated} requirements"
                },
                'ai_match': {
                    'score': float(ranking.ai_score),
                    'weight': float(self.profile.ai_score_weight),
                    'components': {
                        'skills': float(ai_result.skill_match_score * 100),
                        'experience': float(ai_result.experience_match_score * 100),
                        'culture_fit': float(ai_result.culture_fit_score * 100),
                        'location': float(ai_result.location_match_score * 100),
                        'salary': float(ai_result.salary_match_score * 100),
                    }
                },
                'verification': {
                    'score': float(ranking.verification_score),
                    'weight': float(self.profile.verification_score_weight),
                    'components': {
                        'identity': float(verification_result.identity_score),
                        'career': float(verification_result.career_score),
                        'trust': float(verification_result.trust_score),
                    },
                    'flags': {
                        'id_verified': verification_result.is_id_verified,
                        'career_verified': verification_result.is_career_verified,
                        'trust_level': verification_result.trust_level,
                    }
                }
            },
            'bonuses': ranking.bonuses_applied,
            'knockout_passed': ranking.passed_knockout,
            'knockout_reasons': ranking.knockout_reasons,
            'skill_analysis': {
                'matched': ai_result.matched_skills,
                'missing': ai_result.missing_skills,
                'bonus': ai_result.bonus_skills,
            },
            'recommended': ranking.is_recommended,
            'calculated_at': timezone.now().isoformat(),
        }

        return explanation

    def _extract_strengths(
        self,
        ai_result: AIScoreResult,
        verification_result: VerificationScoreResult
    ) -> List[str]:
        """Extract top strengths from results."""
        strengths = []

        if ai_result.skill_match_score >= Decimal('0.80'):
            strengths.append("Strong skill match with job requirements")

        if ai_result.experience_match_score >= Decimal('0.90'):
            strengths.append("Experience level well-aligned with role")

        if verification_result.is_id_verified:
            strengths.append("Identity verified (KYC complete)")

        if verification_result.is_career_verified:
            strengths.append("Career history verified (80%+ confirmed)")

        if ai_result.matched_skills:
            top_skills = ai_result.matched_skills[:3]
            strengths.append(f"Key skills matched: {', '.join(top_skills)}")

        if verification_result.trust_level in ['premium', 'high']:
            strengths.append(f"{verification_result.trust_level.title()} trust level")

        return strengths[:5]  # Return top 5

    def _extract_improvements(
        self,
        ai_result: AIScoreResult,
        rule_result: RuleScoreResult
    ) -> List[str]:
        """Extract areas for improvement."""
        improvements = []

        if ai_result.missing_skills:
            missing = ai_result.missing_skills[:3]
            improvements.append(f"Missing required skills: {', '.join(missing)}")

        if ai_result.experience_match_score < Decimal('0.70'):
            improvements.append("Experience level below ideal range")

        if ai_result.skill_match_score < Decimal('0.60'):
            improvements.append("Skill match could be stronger")

        for detail in rule_result.rule_details:
            if not detail.passed and detail.rule_type == 'preference':
                improvements.append(f"{detail.rule_name}: {detail.reason}")

        return improvements[:5]  # Return top 5

    # ========================================================================
    # Data Loading
    # ========================================================================

    def _load_job_data(self, job_id: int) -> Optional[Dict[str, Any]]:
        """Load job posting data for ranking."""
        try:
            from ats.models import JobPosting

            job = JobPosting.objects.filter(
                tenant=self.tenant,
                id=job_id
            ).select_related('matching_profile').first()

            if not job:
                return None

            # Extract job data
            data = {
                'id': job.id,
                'title': job.title,
                'description': getattr(job, 'description', ''),
                'requirements': getattr(job, 'requirements', ''),
                'category': getattr(job, 'category', None),
                'location': getattr(job, 'location', ''),
                'is_remote': getattr(job, 'is_remote', False),
                'salary_min': getattr(job, 'salary_min', None),
                'salary_max': getattr(job, 'salary_max', None),
                'min_experience_years': getattr(job, 'min_experience_years', 0),
                'max_experience_years': getattr(job, 'max_experience_years', None),
                'required_skills': [],
                'preferred_skills': [],
                'company_values': [],
                'embedding': None,
            }

            # Get matching profile data if available
            if hasattr(job, 'matching_profile') and job.matching_profile:
                mp = job.matching_profile
                data['required_skills'] = list(
                    mp.required_skills_normalized.keys()
                ) if mp.required_skills_normalized else []
                data['preferred_skills'] = list(
                    mp.nice_to_have_normalized.keys()
                ) if mp.nice_to_have_normalized else []
                data['company_values'] = mp.company_values or []
                data['embedding'] = mp.embedding

            return data

        except Exception as e:
            logger.error(f"Error loading job data: {e}", exc_info=True)
            return None

    def _load_candidates_data(
        self,
        candidate_ids: List[int]
    ) -> Dict[int, Dict[str, Any]]:
        """Load candidate profile data for ranking."""
        result = {}

        try:
            from ats.models import Candidate

            candidates = Candidate.objects.filter(
                tenant=self.tenant,
                id__in=candidate_ids
            ).select_related('user', 'matching_profile')

            for candidate in candidates:
                data = {
                    'id': candidate.id,
                    'user': candidate.user,
                    'skills': [],
                    'total_experience_years': 0,
                    'location': '',
                    'remote_preference': 'flexible',
                    'salary_expectation': None,
                    'values': [],
                    'embedding': None,
                }

                # Extract skills
                if hasattr(candidate, 'skills'):
                    try:
                        data['skills'] = list(
                            candidate.skills.values_list('name', flat=True)
                        )
                    except Exception:
                        pass

                # Get matching profile data if available
                if hasattr(candidate, 'matching_profile') and candidate.matching_profile:
                    mp = candidate.matching_profile
                    data['total_experience_years'] = float(
                        mp.total_experience_years or 0
                    )
                    data['skills'] = mp.primary_skills or data['skills']
                    data['embedding'] = mp.embedding

                    # Extract skills from normalized field
                    if mp.skills_normalized:
                        data['skills'] = list(mp.skills_normalized.keys())

                result[candidate.id] = data

        except Exception as e:
            logger.error(f"Error loading candidates data: {e}", exc_info=True)

        return result

    # ========================================================================
    # Persistence
    # ========================================================================

    @transaction.atomic
    def _save_rankings(self, rankings: List[RankingResult]):
        """Save ranking results to database."""
        from ai_matching.models import CandidateRanking

        for ranking in rankings:
            try:
                obj, created = CandidateRanking.objects.update_or_create(
                    tenant=self.tenant,
                    job_id=ranking.job_id,
                    candidate_id=ranking.candidate_id,
                    defaults={
                        'ranking_profile': self.profile,
                        'rule_score': ranking.rule_score,
                        'ai_score': ranking.ai_score,
                        'verification_score': ranking.verification_score,
                        'overall_score': ranking.overall_score,
                        'passed_knockout': ranking.passed_knockout,
                        'knockout_reasons': ranking.knockout_reasons,
                        'bonus_points': ranking.bonus_points,
                        'bonuses_applied': ranking.bonuses_applied,
                        'is_recommended': ranking.is_recommended,
                        'rank_position': ranking.rank_position,
                        'ranking_explanation': ranking.explanation,
                        'top_strengths': ranking.top_strengths,
                        'improvement_areas': ranking.improvement_areas,
                        'recalculated_at': timezone.now() if not created else None,
                    }
                )

                logger.debug(
                    f"{'Created' if created else 'Updated'} ranking: "
                    f"job={ranking.job_id}, candidate={ranking.candidate_id}"
                )

            except Exception as e:
                logger.error(
                    f"Error saving ranking for job={ranking.job_id}, "
                    f"candidate={ranking.candidate_id}: {e}"
                )

    # ========================================================================
    # Utility Methods
    # ========================================================================

    def recalculate_for_job(self, job_id: int) -> List[RankingResult]:
        """
        Recalculate rankings for all candidates who applied to a job.

        Args:
            job_id: The job ID to recalculate rankings for.

        Returns:
            List of updated RankingResult objects.
        """
        from ai_matching.models import CandidateRanking

        existing = CandidateRanking.objects.filter(
            tenant=self.tenant,
            job_id=job_id
        ).values_list('candidate_id', flat=True)

        candidate_ids = list(existing)

        if not candidate_ids:
            logger.info(f"No existing rankings to recalculate for job={job_id}")
            return []

        logger.info(
            f"Recalculating {len(candidate_ids)} rankings for job={job_id}"
        )

        return self.rank_candidates_for_job(
            job_id=job_id,
            candidate_ids=candidate_ids,
            save_results=True
        )

    def get_top_candidates(
        self,
        job_id: int,
        limit: int = 10,
        only_recommended: bool = True
    ) -> List[RankingResult]:
        """
        Get top-ranked candidates for a job.

        Args:
            job_id: The job ID to get rankings for.
            limit: Maximum number of candidates to return.
            only_recommended: If True, only return recommended candidates.

        Returns:
            List of RankingResult objects for top candidates.
        """
        from ai_matching.models import CandidateRanking

        queryset = CandidateRanking.objects.filter(
            tenant=self.tenant,
            job_id=job_id
        )

        if only_recommended:
            queryset = queryset.filter(is_recommended=True)

        rankings = queryset.order_by('-overall_score')[:limit]

        results = []
        for r in rankings:
            results.append(RankingResult(
                candidate_id=r.candidate_id,
                job_id=r.job_id,
                rule_score=r.rule_score,
                ai_score=r.ai_score,
                verification_score=r.verification_score,
                overall_score=r.overall_score,
                passed_knockout=r.passed_knockout,
                is_recommended=r.is_recommended,
                rank_position=r.rank_position,
                bonus_points=r.bonus_points,
                bonuses_applied=r.bonuses_applied,
                knockout_reasons=r.knockout_reasons,
                top_strengths=r.top_strengths,
                improvement_areas=r.improvement_areas,
                explanation=r.ranking_explanation,
            ))

        return results
