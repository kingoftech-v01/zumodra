"""
AI Matching Services Package

This package contains service classes for AI-powered matching operations:
- HybridRankingEngine: Implements the hybrid ATS ranking system (rules + AI + verification)
- MatchingService: Core candidate-job matching logic
- RecommendationService: Personalized recommendations
- EmbeddingService: OpenAI/local embedding generation
- ResumeParserService: Resume parsing and extraction
- JobDescriptionAnalyzer: Job description analysis
- BiasDetectionService: Bias detection and mitigation
"""

import logging
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from django.conf import settings
from django.core.cache import cache

from .ranking_engine import HybridRankingEngine
from .embeddings import EmbeddingService
from .resume_parser import ResumeParserService
from .job_analyzer import JobDescriptionAnalyzer
from .bias_detection import BiasDetectionService

logger = logging.getLogger(__name__)


@dataclass
class MatchResult:
    """Result of a candidate-job match calculation."""
    candidate_id: int
    job_id: int
    overall_score: float
    skill_score: float = 0.0
    experience_score: float = 0.0
    location_score: float = 0.0
    salary_score: float = 0.0
    semantic_score: float = 0.0
    breakdown: Dict[str, Any] = field(default_factory=dict)
    confidence: float = 0.0
    matched_skills: List[str] = field(default_factory=list)
    missing_skills: List[str] = field(default_factory=list)
    recommendations: List[str] = field(default_factory=list)


class MatchingService:
    """
    Core service for candidate-job matching.

    Implements multi-dimensional matching using:
    - Skill overlap (required vs preferred)
    - Experience level alignment
    - Location/remote compatibility
    - Salary expectation alignment
    - Semantic similarity via embeddings

    Usage:
        service = MatchingService(tenant=tenant)

        # Get match score for a single candidate-job pair
        result = service.calculate_match(candidate, job)
        print(f"Match score: {result.overall_score}")

        # Batch match candidates to a job
        results = service.match_candidates_to_job(job_id, limit=20)
        for r in results:
            print(f"Candidate {r['candidate_id']}: {r['overall_score']}")
    """

    # Scoring weights (must sum to 1.0)
    WEIGHT_SKILLS = 0.35
    WEIGHT_EXPERIENCE = 0.20
    WEIGHT_LOCATION = 0.15
    WEIGHT_SALARY = 0.10
    WEIGHT_SEMANTIC = 0.20

    def __init__(self, tenant=None):
        self.tenant = tenant
        # Only initialize ranking engine if tenant is provided
        # (some uses don't require the full ranking engine)
        self._ranking_engine = None
        self.embedding_service = EmbeddingService()
        self.job_analyzer = JobDescriptionAnalyzer()
        self.resume_parser = ResumeParserService()
        self.bias_detector = BiasDetectionService()

    @property
    def ranking_engine(self):
        """Lazy-load ranking engine when tenant is available."""
        if self._ranking_engine is None and self.tenant is not None:
            self._ranking_engine = HybridRankingEngine(self.tenant)
        return self._ranking_engine

    def calculate_match(
        self,
        candidate: Dict[str, Any],
        job: Dict[str, Any],
        include_semantic: bool = True
    ) -> MatchResult:
        """
        Calculate comprehensive match score between candidate and job.

        Args:
            candidate: Candidate data dict with skills, experience, etc.
            job: Job data dict with requirements, salary range, etc.
            include_semantic: Whether to use AI embedding similarity

        Returns:
            MatchResult with overall score and breakdown
        """
        result = MatchResult(
            candidate_id=candidate.get('id', 0),
            job_id=job.get('id', 0),
            overall_score=0.0
        )

        # Calculate each component score
        result.skill_score, result.matched_skills, result.missing_skills = \
            self._calculate_skill_match(candidate, job)
        result.experience_score = self._calculate_experience_match(candidate, job)
        result.location_score = self._calculate_location_match(candidate, job)
        result.salary_score = self._calculate_salary_match(candidate, job)

        if include_semantic:
            result.semantic_score = self._calculate_semantic_match(candidate, job)

        # Calculate weighted overall score
        result.overall_score = (
            self.WEIGHT_SKILLS * result.skill_score +
            self.WEIGHT_EXPERIENCE * result.experience_score +
            self.WEIGHT_LOCATION * result.location_score +
            self.WEIGHT_SALARY * result.salary_score +
            self.WEIGHT_SEMANTIC * result.semantic_score
        )

        # Calculate confidence based on data completeness
        result.confidence = self._calculate_confidence(candidate, job)

        # Build breakdown dict
        result.breakdown = {
            'skills': {
                'score': result.skill_score,
                'weight': self.WEIGHT_SKILLS,
                'matched': result.matched_skills,
                'missing': result.missing_skills,
            },
            'experience': {
                'score': result.experience_score,
                'weight': self.WEIGHT_EXPERIENCE,
            },
            'location': {
                'score': result.location_score,
                'weight': self.WEIGHT_LOCATION,
            },
            'salary': {
                'score': result.salary_score,
                'weight': self.WEIGHT_SALARY,
            },
            'semantic': {
                'score': result.semantic_score,
                'weight': self.WEIGHT_SEMANTIC,
            },
        }

        # Generate recommendations
        result.recommendations = self._generate_recommendations(result, job)

        return result

    def _calculate_skill_match(
        self,
        candidate: Dict,
        job: Dict
    ) -> tuple:
        """
        Calculate skill match score.

        Returns (score, matched_skills, missing_skills).
        Required skills are weighted 2x more than preferred.
        """
        candidate_skills = set(s.lower() for s in candidate.get('skills', []))
        required_skills = set(s.lower() for s in job.get('required_skills', []))
        preferred_skills = set(s.lower() for s in job.get('preferred_skills', []))

        if not required_skills and not preferred_skills:
            return 0.5, [], []  # No skills defined, neutral score

        # Calculate matches
        matched_required = candidate_skills & required_skills
        matched_preferred = candidate_skills & preferred_skills
        matched_all = list(matched_required | matched_preferred)

        # Missing required skills
        missing_required = list(required_skills - candidate_skills)

        # Score calculation (required = 2x weight)
        total_weight = len(required_skills) * 2 + len(preferred_skills)
        if total_weight == 0:
            return 0.5, matched_all, missing_required

        earned_weight = len(matched_required) * 2 + len(matched_preferred)
        score = earned_weight / total_weight

        return score, matched_all, missing_required

    def _calculate_experience_match(
        self,
        candidate: Dict,
        job: Dict
    ) -> float:
        """
        Calculate experience match score.

        Penalizes under-qualification more than over-qualification.
        """
        candidate_years = candidate.get('years_experience', 0)
        min_years = job.get('min_experience_years', 0)
        max_years = job.get('max_experience_years')

        if min_years == 0:
            return 0.7  # No requirement, neutral-positive score

        if candidate_years < min_years:
            # Under-qualified: score decreases with gap
            gap = min_years - candidate_years
            return max(0.0, 1.0 - (gap * 0.15))

        if max_years and candidate_years > max_years:
            # Over-qualified: slight penalty
            gap = candidate_years - max_years
            return max(0.5, 1.0 - (gap * 0.05))

        # Within range: perfect match
        return 1.0

    def _calculate_location_match(
        self,
        candidate: Dict,
        job: Dict
    ) -> float:
        """
        Calculate location compatibility score.

        Considers remote work options, relocation willingness, commute distance.
        """
        job_is_remote = job.get('remote_option', False)
        candidate_wants_remote = candidate.get('prefers_remote', False)

        if job_is_remote:
            if candidate_wants_remote:
                return 1.0  # Perfect match for remote seekers
            return 0.9  # Good match, can work remotely if needed

        # On-site/hybrid job
        candidate_location = candidate.get('location', '').lower()
        job_location = job.get('location', '').lower()

        if not job_location:
            return 0.7  # No location specified

        # Check for same city/region
        if candidate_location and job_location:
            if candidate_location == job_location:
                return 1.0
            # Check if willing to relocate
            if candidate.get('willing_to_relocate', False):
                return 0.8
            return 0.4  # Location mismatch

        return 0.5  # Unknown, neutral score

    def _calculate_salary_match(
        self,
        candidate: Dict,
        job: Dict
    ) -> float:
        """
        Calculate salary expectation alignment.

        Returns high score if expectations align with job range.
        """
        candidate_min = candidate.get('salary_expectation_min', 0)
        candidate_max = candidate.get('salary_expectation_max', 0)
        job_min = job.get('salary_min', 0)
        job_max = job.get('salary_max', 0)

        # If no salary info, neutral score
        if not job_min and not job_max:
            return 0.7
        if not candidate_min and not candidate_max:
            return 0.7

        # Check for overlap
        if job_max and candidate_min:
            if candidate_min > job_max:
                # Candidate expects more than job pays
                gap_ratio = (candidate_min - job_max) / job_max if job_max > 0 else 1
                return max(0.0, 1.0 - gap_ratio)

        if job_min and candidate_max:
            if candidate_max < job_min:
                # Candidate expects less than job range (unusual)
                return 0.9  # Good for employer, slight caution

        # Ranges overlap
        return 1.0

    def _calculate_semantic_match(
        self,
        candidate: Dict,
        job: Dict
    ) -> float:
        """
        Calculate semantic similarity using embeddings.

        Compares candidate profile text against job description.
        """
        try:
            # Build candidate text from profile
            candidate_text = self._build_candidate_text(candidate)
            job_text = self._build_job_text(job)

            if not candidate_text or not job_text:
                return 0.5  # No text available

            # Get embeddings
            candidate_embedding = self.embedding_service.execute(candidate_text)
            job_embedding = self.embedding_service.execute(job_text)

            if not candidate_embedding.success or not job_embedding.success:
                return 0.5

            # Calculate cosine similarity
            similarity = self.embedding_service.cosine_similarity(
                candidate_embedding.embedding,
                job_embedding.embedding
            )

            # Normalize to 0-1 range (cosine similarity can be negative)
            return self.embedding_service.normalize_similarity(similarity)

        except Exception as e:
            logger.warning(f"Semantic matching failed: {e}")
            return 0.5

    def _build_candidate_text(self, candidate: Dict) -> str:
        """Build text representation of candidate for embedding."""
        parts = []

        if candidate.get('summary'):
            parts.append(candidate['summary'])

        if candidate.get('skills'):
            parts.append(f"Skills: {', '.join(candidate['skills'])}")

        if candidate.get('title'):
            parts.append(f"Title: {candidate['title']}")

        if candidate.get('experience'):
            for exp in candidate['experience'][:3]:  # Top 3 experiences
                if isinstance(exp, dict):
                    parts.append(
                        f"{exp.get('title', '')} at {exp.get('company', '')}"
                    )
                elif isinstance(exp, str):
                    parts.append(exp)

        return ' | '.join(parts)

    def _build_job_text(self, job: Dict) -> str:
        """Build text representation of job for embedding."""
        job_description = job.get('description', '')
        job_title = job.get('title', '')
        return self.job_analyzer.get_job_embedding_text(job_description, job_title)

    def _calculate_confidence(
        self,
        candidate: Dict,
        job: Dict
    ) -> float:
        """
        Calculate confidence level based on data completeness.

        Higher confidence when more data is available.
        """
        data_points = 0
        total_points = 10

        # Candidate data
        if candidate.get('skills'):
            data_points += 2
        if candidate.get('years_experience'):
            data_points += 1
        if candidate.get('location'):
            data_points += 1
        if candidate.get('summary'):
            data_points += 1

        # Job data
        if job.get('required_skills'):
            data_points += 2
        if job.get('min_experience_years'):
            data_points += 1
        if job.get('location'):
            data_points += 1
        if job.get('description'):
            data_points += 1

        return data_points / total_points

    def _generate_recommendations(
        self,
        result: MatchResult,
        job: Dict
    ) -> List[str]:
        """Generate actionable recommendations for the candidate."""
        recommendations = []

        if result.missing_skills:
            top_missing = result.missing_skills[:3]
            recommendations.append(
                f"Consider developing skills in: {', '.join(top_missing)}"
            )

        if result.experience_score < 0.5:
            recommendations.append(
                "Gain more experience in this field to improve match quality"
            )

        if result.location_score < 0.5:
            if job.get('remote_option'):
                recommendations.append(
                    "This role offers remote work options"
                )
            else:
                recommendations.append(
                    "Consider relocation or look for remote positions"
                )

        return recommendations

    def match_candidates_to_job(
        self,
        job_id: int,
        limit: int = 10,
        min_score: float = 0.3
    ) -> List[Dict[str, Any]]:
        """
        Match and rank candidates for a specific job.

        Args:
            job_id: ID of the job to match against
            limit: Maximum number of results
            min_score: Minimum match score threshold

        Returns:
            List of match results, sorted by score descending
        """
        try:
            from ai_matching.models import Job, CandidateProfile

            job = Job.objects.get(id=job_id)
            job_dict = self._job_to_dict(job)

            candidates = CandidateProfile.objects.filter(is_active=True)
            results = []

            for candidate in candidates:
                candidate_dict = self._candidate_to_dict(candidate)
                match = self.calculate_match(candidate_dict, job_dict)

                if match.overall_score >= min_score:
                    results.append({
                        'candidate_id': candidate.id,
                        'job_id': job_id,
                        'overall_score': match.overall_score,
                        'skill_score': match.skill_score,
                        'experience_score': match.experience_score,
                        'breakdown': match.breakdown,
                        'matched_skills': match.matched_skills,
                        'missing_skills': match.missing_skills,
                        'confidence': match.confidence,
                    })

            # Sort by score descending
            results.sort(key=lambda x: x['overall_score'], reverse=True)
            return results[:limit]

        except Exception as e:
            logger.error(f"Error matching candidates to job {job_id}: {e}")
            return []

    def match_jobs_to_candidate(
        self,
        candidate_id: int,
        limit: int = 10,
        min_score: float = 0.3
    ) -> List[Dict[str, Any]]:
        """
        Match and rank jobs for a specific candidate.

        Args:
            candidate_id: ID of the candidate to match
            limit: Maximum number of results
            min_score: Minimum match score threshold

        Returns:
            List of match results, sorted by score descending
        """
        try:
            from ai_matching.models import Job, CandidateProfile

            candidate = CandidateProfile.objects.get(id=candidate_id)
            candidate_dict = self._candidate_to_dict(candidate)

            jobs = Job.objects.filter(status='open')
            results = []

            for job in jobs:
                job_dict = self._job_to_dict(job)
                match = self.calculate_match(candidate_dict, job_dict)

                if match.overall_score >= min_score:
                    results.append({
                        'job_id': job.id,
                        'candidate_id': candidate_id,
                        'overall_score': match.overall_score,
                        'skill_score': match.skill_score,
                        'experience_score': match.experience_score,
                        'breakdown': match.breakdown,
                        'matched_skills': match.matched_skills,
                        'missing_skills': match.missing_skills,
                        'confidence': match.confidence,
                    })

            # Sort by score descending
            results.sort(key=lambda x: x['overall_score'], reverse=True)
            return results[:limit]

        except Exception as e:
            logger.error(f"Error matching jobs to candidate {candidate_id}: {e}")
            return []

    def get_match_score(self, candidate_id: int, job_id: int) -> float:
        """
        Get quick match score between candidate and job.

        Args:
            candidate_id: ID of the candidate
            job_id: ID of the job

        Returns:
            Match score between 0 and 1
        """
        cache_key = f"match_score:{candidate_id}:{job_id}"
        cached = cache.get(cache_key)
        if cached is not None:
            return cached

        try:
            from ai_matching.models import Job, CandidateProfile

            candidate = CandidateProfile.objects.get(id=candidate_id)
            job = Job.objects.get(id=job_id)

            candidate_dict = self._candidate_to_dict(candidate)
            job_dict = self._job_to_dict(job)

            result = self.calculate_match(candidate_dict, job_dict)
            score = result.overall_score

            # Cache for 1 hour
            cache.set(cache_key, score, 3600)
            return score

        except Exception as e:
            logger.error(f"Error getting match score: {e}")
            return 0.0

    def _job_to_dict(self, job) -> Dict:
        """Convert Job model instance to dict for matching."""
        return {
            'id': job.id,
            'title': job.title,
            'description': getattr(job, 'description', ''),
            'required_skills': list(getattr(job, 'required_skills', []) or []),
            'preferred_skills': list(getattr(job, 'preferred_skills', []) or []),
            'min_experience_years': getattr(job, 'min_experience_years', 0),
            'max_experience_years': getattr(job, 'max_experience_years', None),
            'location': getattr(job, 'location', ''),
            'remote_option': getattr(job, 'remote_option', False),
            'salary_min': getattr(job, 'salary_min', 0),
            'salary_max': getattr(job, 'salary_max', 0),
        }

    def _candidate_to_dict(self, candidate) -> Dict:
        """Convert CandidateProfile model instance to dict for matching."""
        return {
            'id': candidate.id,
            'title': getattr(candidate, 'title', ''),
            'summary': getattr(candidate, 'summary', ''),
            'skills': list(getattr(candidate, 'skills', []) or []),
            'years_experience': getattr(candidate, 'years_experience', 0),
            'location': getattr(candidate, 'location', ''),
            'prefers_remote': getattr(candidate, 'prefers_remote', False),
            'willing_to_relocate': getattr(candidate, 'willing_to_relocate', False),
            'salary_expectation_min': getattr(candidate, 'salary_expectation_min', 0),
            'salary_expectation_max': getattr(candidate, 'salary_expectation_max', 0),
            'experience': list(getattr(candidate, 'work_history', []) or []),
        }


class RecommendationService:
    """
    Service for generating personalized recommendations.

    Uses matching scores with bias mitigation and user feedback
    to generate fair, relevant recommendations.

    Usage:
        service = RecommendationService(tenant=tenant)

        # Get job recommendations for a candidate
        jobs = service.get_job_recommendations(candidate_id, limit=10)

        # Get candidate recommendations for a job
        candidates = service.get_candidate_recommendations(job_id, limit=10)

        # Record feedback for learning
        service.record_feedback(recommendation_id, 'positive')
    """

    def __init__(self, tenant=None):
        self.tenant = tenant
        self.matching_service = MatchingService(tenant=tenant)
        self.bias_detector = BiasDetectionService()

    def get_job_recommendations(
        self,
        candidate_id: int,
        limit: int = 10,
        apply_bias_mitigation: bool = True
    ) -> List[Dict[str, Any]]:
        """
        Get personalized job recommendations for a candidate.

        Args:
            candidate_id: ID of the candidate
            limit: Maximum recommendations to return
            apply_bias_mitigation: Whether to check/mitigate bias

        Returns:
            List of recommended jobs with match scores
        """
        # Get initial matches
        matches = self.matching_service.match_jobs_to_candidate(
            candidate_id,
            limit=limit * 2  # Get more for filtering
        )

        if not matches:
            return []

        # Apply bias mitigation if enabled
        if apply_bias_mitigation and len(matches) >= 10:
            matches = self.bias_detector.mitigate_bias(
                matches,
                protected_attributes=['gender', 'age_group']
            )

        # Enhance with recommendation metadata
        recommendations = []
        for match in matches[:limit]:
            recommendations.append({
                'job_id': match['job_id'],
                'score': match['overall_score'],
                'confidence': match.get('confidence', 0.5),
                'reasons': self._generate_recommendation_reasons(match),
                'matched_skills': match.get('matched_skills', []),
                'skill_gaps': match.get('missing_skills', []),
            })

        return recommendations

    def get_candidate_recommendations(
        self,
        job_id: int,
        limit: int = 10,
        apply_bias_mitigation: bool = True
    ) -> List[Dict[str, Any]]:
        """
        Get candidate recommendations for a job posting.

        Args:
            job_id: ID of the job posting
            limit: Maximum recommendations to return
            apply_bias_mitigation: Whether to check/mitigate bias

        Returns:
            List of recommended candidates with match scores
        """
        # Get initial matches
        matches = self.matching_service.match_candidates_to_job(
            job_id,
            limit=limit * 2  # Get more for filtering
        )

        if not matches:
            return []

        # Apply bias mitigation if enabled
        if apply_bias_mitigation and len(matches) >= 10:
            bias_check = self.bias_detector.check_bias(matches)
            if bias_check['bias_detected']:
                logger.warning(
                    f"Bias detected in job {job_id} recommendations: "
                    f"{bias_check['affected_groups']}"
                )
                matches = self.bias_detector.mitigate_bias(
                    matches,
                    protected_attributes=['gender', 'age_group']
                )

        # Enhance with recommendation metadata
        recommendations = []
        for match in matches[:limit]:
            recommendations.append({
                'candidate_id': match['candidate_id'],
                'score': match.get('adjusted_score', match['overall_score']),
                'original_score': match['overall_score'],
                'confidence': match.get('confidence', 0.5),
                'reasons': self._generate_recommendation_reasons(match),
                'matched_skills': match.get('matched_skills', []),
                'skill_gaps': match.get('missing_skills', []),
            })

        return recommendations

    def get_jobs_for_candidate(
        self,
        candidate,
        limit: int = 10
    ) -> List[Dict[str, Any]]:
        """
        Get job recommendations for a CandidateProfile model instance.

        Args:
            candidate: CandidateProfile model instance
            limit: Maximum recommendations

        Returns:
            List of job recommendations
        """
        return self.get_job_recommendations(candidate.id, limit)

    def get_candidates_for_job(
        self,
        job,
        limit: int = 10
    ) -> List[Dict[str, Any]]:
        """
        Get candidate recommendations for a Job model instance.

        Args:
            job: Job model instance
            limit: Maximum recommendations

        Returns:
            List of candidate recommendations
        """
        return self.get_candidate_recommendations(job.id, limit)

    def _generate_recommendation_reasons(
        self,
        match: Dict
    ) -> List[str]:
        """Generate human-readable reasons for a recommendation."""
        reasons = []
        score = match.get('overall_score', 0)

        if score >= 0.8:
            reasons.append("Excellent overall match")
        elif score >= 0.6:
            reasons.append("Good match potential")

        skill_score = match.get('skill_score', 0)
        if skill_score >= 0.8:
            reasons.append("Strong skill alignment")
        elif skill_score >= 0.6:
            reasons.append("Relevant skills present")

        matched = match.get('matched_skills', [])
        if len(matched) >= 5:
            reasons.append(f"Matches {len(matched)} key skills")
        elif matched:
            reasons.append(f"Skills match: {', '.join(matched[:3])}")

        exp_score = match.get('experience_score', 0)
        if exp_score >= 0.9:
            reasons.append("Experience level matches requirements")

        return reasons if reasons else ["Potential match based on profile"]

    def record_feedback(
        self,
        recommendation_id: int,
        feedback: str,
        user_id: Optional[int] = None
    ) -> bool:
        """
        Record user feedback on a recommendation.

        Feedback is used to improve future recommendations.

        Args:
            recommendation_id: ID of the recommendation
            feedback: Feedback type ('positive', 'negative', 'neutral')
            user_id: Optional user ID who gave feedback

        Returns:
            True if feedback was recorded successfully
        """
        try:
            from ai_matching.models import RecommendationFeedback

            valid_feedback = ['positive', 'negative', 'neutral', 'applied', 'hired']
            if feedback not in valid_feedback:
                logger.warning(f"Invalid feedback type: {feedback}")
                return False

            RecommendationFeedback.objects.create(
                recommendation_id=recommendation_id,
                feedback_type=feedback,
                user_id=user_id,
            )

            logger.info(
                f"Recorded {feedback} feedback for recommendation {recommendation_id}"
            )
            return True

        except Exception as e:
            logger.error(f"Error recording feedback: {e}")
            return False


__all__ = [
    'HybridRankingEngine',
    'MatchingService',
    'RecommendationService',
    'EmbeddingService',
    'ResumeParserService',
    'JobDescriptionAnalyzer',
    'BiasDetectionService',
    'MatchResult',
]
