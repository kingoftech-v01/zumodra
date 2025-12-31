"""
Core Matching Algorithms

This module contains matching algorithm implementations for calculating
similarity scores between candidates and jobs across multiple dimensions.
"""

from abc import ABC, abstractmethod
from typing import Dict, List, Any, Optional, Tuple
from dataclasses import dataclass
from decimal import Decimal
import math
import logging

logger = logging.getLogger(__name__)


# ============================================================================
# Base Classes
# ============================================================================

@dataclass
class MatchScore:
    """Result of a matching operation."""
    score: float  # 0-1 normalized score
    confidence: str  # 'high', 'medium', 'low'
    details: Dict[str, Any]
    explanation: str


class BaseMatcher(ABC):
    """Base class for all matching algorithms."""

    @abstractmethod
    def score(self, candidate, job) -> float:
        """
        Calculate match score between candidate and job.

        Args:
            candidate: CandidateProfile instance
            job: Job instance

        Returns:
            Float score between 0 and 1
        """
        pass

    def get_weight(self) -> float:
        """Get the weight of this matcher in composite scoring."""
        return 1.0


# ============================================================================
# Skill Matcher
# ============================================================================

class SkillMatcher(BaseMatcher):
    """
    Calculates skill overlap between candidate and job requirements.
    Uses both exact matching and semantic similarity for skill comparison.
    """

    def __init__(self, use_semantic: bool = False):
        """
        Initialize skill matcher.

        Args:
            use_semantic: Whether to use semantic similarity for non-exact matches
        """
        self.use_semantic = use_semantic
        self._skill_synonyms = self._load_skill_synonyms()

    def _load_skill_synonyms(self) -> Dict[str, List[str]]:
        """Load skill synonym mappings."""
        return {
            'javascript': ['js', 'ecmascript', 'es6', 'es2015'],
            'python': ['py', 'python3', 'python2'],
            'typescript': ['ts'],
            'postgresql': ['postgres', 'pgsql'],
            'mongodb': ['mongo'],
            'kubernetes': ['k8s'],
            'amazon web services': ['aws'],
            'google cloud platform': ['gcp'],
            'machine learning': ['ml', 'ai/ml'],
            'deep learning': ['dl', 'neural networks'],
            'natural language processing': ['nlp'],
            'react.js': ['react', 'reactjs'],
            'node.js': ['nodejs', 'node'],
            'vue.js': ['vue', 'vuejs'],
            'angular.js': ['angular', 'angularjs'],
        }

    def score(self, candidate, job) -> float:
        """
        Calculate skill match score.

        Considers:
        - Exact skill matches
        - Synonym matches
        - Skill proficiency levels (if available)
        """
        # Get candidate skills
        candidate_skills = self._get_candidate_skills(candidate)
        # Get job required skills
        job_skills = self._get_job_skills(job)

        if not job_skills:
            return 1.0  # No required skills means any candidate matches

        # Calculate matches
        exact_matches = []
        synonym_matches = []

        candidate_skills_lower = {s.lower() for s in candidate_skills}
        job_skills_lower = {s.lower() for s in job_skills}

        for job_skill in job_skills_lower:
            if job_skill in candidate_skills_lower:
                exact_matches.append(job_skill)
            else:
                # Check synonyms
                for canonical, synonyms in self._skill_synonyms.items():
                    if job_skill == canonical or job_skill in synonyms:
                        # Check if candidate has any synonym
                        if canonical in candidate_skills_lower:
                            synonym_matches.append(job_skill)
                            break
                        for syn in synonyms:
                            if syn in candidate_skills_lower:
                                synonym_matches.append(job_skill)
                                break

        # Calculate score
        total_matches = len(exact_matches) + len(synonym_matches) * 0.9
        score = min(1.0, total_matches / len(job_skills))

        return score

    def _get_candidate_skills(self, candidate) -> List[str]:
        """Extract skills from candidate profile."""
        try:
            return list(candidate.skills.values_list('name', flat=True))
        except Exception:
            return []

    def _get_job_skills(self, job) -> List[str]:
        """Extract required skills from job."""
        # Try to get from embedding if available
        try:
            if hasattr(job, 'embedding') and job.embedding.skills_extracted:
                return job.embedding.skills_extracted
        except Exception:
            pass

        # Parse from requirements text
        return self._extract_skills_from_text(
            f"{job.description} {job.requirements}"
        )

    def _extract_skills_from_text(self, text: str) -> List[str]:
        """Extract skills from text using keyword matching."""
        from .services import TECH_SKILLS, SOFT_SKILLS

        text_lower = text.lower()
        found_skills = []

        for skill in TECH_SKILLS + SOFT_SKILLS:
            if skill in text_lower:
                found_skills.append(skill)

        return found_skills

    def get_match_details(self, candidate, job) -> Dict[str, Any]:
        """Get detailed breakdown of skill matching."""
        candidate_skills = set(s.lower() for s in self._get_candidate_skills(candidate))
        job_skills = set(s.lower() for s in self._get_job_skills(job))

        matched = list(candidate_skills & job_skills)
        missing = list(job_skills - candidate_skills)
        extra = list(candidate_skills - job_skills)

        return {
            'matched_skills': matched,
            'missing_skills': missing,
            'extra_skills': extra,
            'match_percentage': len(matched) / len(job_skills) * 100 if job_skills else 100
        }

    def get_weight(self) -> float:
        return 0.30  # 30% of total score


# ============================================================================
# Experience Matcher
# ============================================================================

class ExperienceMatcher(BaseMatcher):
    """
    Calculates match based on years of experience requirements.
    """

    def score(self, candidate, job) -> float:
        """
        Calculate experience match score.

        Returns:
        - 1.0 if candidate meets or exceeds requirements
        - Partial score if candidate is close to requirements
        - 0.0 if significantly underqualified
        """
        candidate_years = self._get_candidate_experience(candidate)
        min_years, max_years = self._get_job_experience_range(job)

        if min_years == 0 and max_years == 0:
            return 1.0  # No experience requirement

        # Perfect match: within range
        if min_years <= candidate_years <= max_years:
            return 1.0

        # Overqualified: slightly penalize
        if candidate_years > max_years:
            overage = candidate_years - max_years
            return max(0.7, 1.0 - (overage * 0.05))

        # Underqualified: calculate partial score
        if candidate_years < min_years:
            shortage = min_years - candidate_years
            # Allow some flexibility (up to 2 years short)
            if shortage <= 2:
                return max(0.5, 1.0 - (shortage * 0.25))
            else:
                return max(0.0, 0.5 - ((shortage - 2) * 0.1))

        return 0.5

    def _get_candidate_experience(self, candidate) -> float:
        """Calculate total years of experience for candidate."""
        try:
            # Try from embedding first
            if hasattr(candidate, 'embedding') and candidate.embedding.total_experience_years:
                return float(candidate.embedding.total_experience_years)
        except Exception:
            pass

        # Calculate from work experiences
        try:
            from django.utils import timezone
            from datetime import date

            total_years = 0.0
            for exp in candidate.work_experiences.all():
                start = exp.start_date
                end = exp.end_date or date.today()
                years = (end - start).days / 365.25
                total_years += years

            return round(total_years, 1)
        except Exception as e:
            logger.warning(f"Failed to calculate experience: {e}")
            return 0.0

    def _get_job_experience_range(self, job) -> Tuple[int, int]:
        """Extract experience requirements from job."""
        try:
            if hasattr(job, 'embedding'):
                embedding = job.embedding
                return (
                    embedding.experience_years_min or 0,
                    embedding.experience_years_max or 99
                )
        except Exception:
            pass

        # Parse from requirements text
        import re
        text = f"{job.description} {job.requirements}".lower()

        # Pattern: X-Y years
        match = re.search(r'(\d+)\s*[-to]+\s*(\d+)\s*years?', text)
        if match:
            return (int(match.group(1)), int(match.group(2)))

        # Pattern: X+ years or minimum X years
        match = re.search(r'(\d+)\+?\s*years?', text)
        if match:
            min_years = int(match.group(1))
            return (min_years, min_years + 10)

        return (0, 99)  # No specific requirement

    def get_weight(self) -> float:
        return 0.20  # 20% of total score


# ============================================================================
# Location Matcher
# ============================================================================

class LocationMatcher(BaseMatcher):
    """
    Calculates match based on location compatibility.
    Considers remote work options, commute distance, and relocation.
    """

    def __init__(self, max_commute_km: float = 50.0):
        """
        Initialize location matcher.

        Args:
            max_commute_km: Maximum acceptable commute distance in kilometers
        """
        self.max_commute_km = max_commute_km

    def score(self, candidate, job) -> float:
        """
        Calculate location match score.

        Returns:
        - 1.0 for remote jobs or same city
        - Partial score based on distance
        - 0.5 minimum for any match (assumes relocation is possible)
        """
        # Check if job is remote
        if self._is_job_remote(job):
            return 1.0

        # Get locations
        candidate_location = self._get_candidate_location(candidate)
        job_location = self._get_job_location(job)

        if not candidate_location or not job_location:
            return 0.7  # Unknown location, assume moderate match

        # Same city
        if self._same_city(candidate_location, job_location):
            return 1.0

        # Calculate distance
        distance = self._calculate_distance(candidate_location, job_location)

        if distance is None:
            return 0.7

        # Score based on distance
        if distance <= self.max_commute_km:
            return 1.0 - (distance / self.max_commute_km * 0.2)
        else:
            # Beyond commute range, but relocation possible
            return max(0.5, 0.8 - (distance / 500 * 0.3))

    def _is_job_remote(self, job) -> bool:
        """Check if job allows remote work."""
        try:
            if hasattr(job, 'embedding') and job.embedding.is_remote is not None:
                return job.embedding.is_remote
        except Exception:
            pass

        # Check description for remote keywords
        text = f"{job.description} {job.requirements}".lower()
        remote_keywords = ['remote', 'work from home', 'wfh', 'distributed', 'anywhere']
        return any(kw in text for kw in remote_keywords)

    def _get_candidate_location(self, candidate) -> Optional[Dict[str, Any]]:
        """Get candidate location information."""
        try:
            # Try to get from related work experiences or profile
            if hasattr(candidate, 'user') and hasattr(candidate.user, 'profile'):
                profile = candidate.user.profile
                if profile.city:
                    return {
                        'city': profile.city,
                        'country': getattr(profile, 'country', ''),
                        'lat': getattr(profile, 'lat', None),
                        'lng': getattr(profile, 'lng', None)
                    }
        except Exception:
            pass
        return None

    def _get_job_location(self, job) -> Optional[Dict[str, Any]]:
        """Get job location information."""
        try:
            if job.position and job.position.site:
                site = job.position.site
                return {
                    'city': site.city,
                    'country': site.country,
                    'address': site.address
                }
        except Exception:
            pass
        return None

    def _same_city(
        self,
        loc1: Dict[str, Any],
        loc2: Dict[str, Any]
    ) -> bool:
        """Check if two locations are in the same city."""
        city1 = loc1.get('city', '').lower().strip()
        city2 = loc2.get('city', '').lower().strip()
        return city1 and city2 and city1 == city2

    def _calculate_distance(
        self,
        loc1: Dict[str, Any],
        loc2: Dict[str, Any]
    ) -> Optional[float]:
        """Calculate distance between two locations in kilometers."""
        lat1 = loc1.get('lat')
        lng1 = loc1.get('lng')
        lat2 = loc2.get('lat')
        lng2 = loc2.get('lng')

        if not all([lat1, lng1, lat2, lng2]):
            return None

        # Haversine formula
        R = 6371  # Earth's radius in km

        lat1_rad = math.radians(lat1)
        lat2_rad = math.radians(lat2)
        delta_lat = math.radians(lat2 - lat1)
        delta_lng = math.radians(lng2 - lng1)

        a = (math.sin(delta_lat / 2) ** 2 +
             math.cos(lat1_rad) * math.cos(lat2_rad) *
             math.sin(delta_lng / 2) ** 2)
        c = 2 * math.atan2(math.sqrt(a), math.sqrt(1 - a))

        return R * c

    def get_weight(self) -> float:
        return 0.15  # 15% of total score


# ============================================================================
# Salary Matcher
# ============================================================================

class SalaryMatcher(BaseMatcher):
    """
    Calculates match based on salary expectations alignment.
    """

    def __init__(self, tolerance_percent: float = 0.15):
        """
        Initialize salary matcher.

        Args:
            tolerance_percent: Acceptable deviation from expectations (default 15%)
        """
        self.tolerance = tolerance_percent

    def score(self, candidate, job) -> float:
        """
        Calculate salary alignment score.

        Returns:
        - 1.0 if salary expectations align
        - Partial score if there's negotiation room
        - 0.0 if expectations are way off
        """
        candidate_expectation = self._get_candidate_salary_expectation(candidate)
        job_range = self._get_job_salary_range(job)

        if not candidate_expectation or not job_range:
            return 0.8  # Unknown salary, assume moderate match

        job_min, job_max = job_range

        # Within range
        if job_min <= candidate_expectation <= job_max:
            return 1.0

        # Within tolerance
        tolerance_amount = job_max * self.tolerance

        if candidate_expectation < job_min:
            # Candidate expects less - good for employer
            return 1.0

        if candidate_expectation <= job_max + tolerance_amount:
            # Slightly above range, negotiable
            overage = (candidate_expectation - job_max) / tolerance_amount
            return max(0.6, 1.0 - overage * 0.4)

        # Way above range
        return max(0.0, 0.5 - (candidate_expectation - job_max) / job_max)

    def _get_candidate_salary_expectation(self, candidate) -> Optional[float]:
        """Get candidate's salary expectation."""
        # This would typically come from candidate profile or preferences
        # For now, return None (unknown)
        return None

    def _get_job_salary_range(self, job) -> Optional[Tuple[float, float]]:
        """Get job salary range."""
        try:
            if job.salary_from and job.salary_to:
                return (float(job.salary_from), float(job.salary_to))
            elif job.salary_from:
                return (float(job.salary_from), float(job.salary_from) * 1.3)
        except Exception:
            pass
        return None

    def get_weight(self) -> float:
        return 0.15  # 15% of total score


# ============================================================================
# Culture Fit Scorer
# ============================================================================

class CultureFitScorer(BaseMatcher):
    """
    Calculates match based on culture and values alignment.
    Uses soft skills, preferences, and company values.
    """

    # Value categories and their indicators
    VALUE_INDICATORS = {
        'innovation': [
            'innovative', 'creative', 'cutting-edge', 'disruptive',
            'experiment', 'startup', 'agile', 'fast-paced'
        ],
        'collaboration': [
            'team', 'collaborative', 'together', 'partnership',
            'cross-functional', 'communication'
        ],
        'growth': [
            'learning', 'development', 'growth', 'mentorship',
            'career', 'opportunities', 'training'
        ],
        'work_life_balance': [
            'flexible', 'remote', 'balance', 'wellness',
            'benefits', 'pto', 'vacation'
        ],
        'impact': [
            'mission', 'impact', 'meaningful', 'difference',
            'purpose', 'social', 'sustainability'
        ]
    }

    def score(self, candidate, job) -> float:
        """
        Calculate culture fit score.

        Based on:
        - Matching soft skills
        - Company values alignment
        - Work style preferences
        """
        candidate_values = self._get_candidate_values(candidate)
        job_values = self._get_job_values(job)

        if not job_values:
            return 0.7  # No clear values, assume moderate fit

        # Calculate overlap
        common_values = set(candidate_values) & set(job_values)
        if not job_values:
            return 0.7

        return len(common_values) / len(job_values)

    def _get_candidate_values(self, candidate) -> List[str]:
        """Extract values from candidate profile."""
        values = []

        # Check bio/summary for value indicators
        bio = getattr(candidate, 'bio', '') or ''
        bio_lower = bio.lower()

        for value, indicators in self.VALUE_INDICATORS.items():
            if any(ind in bio_lower for ind in indicators):
                values.append(value)

        # Check work experiences
        try:
            for exp in candidate.work_experiences.all():
                desc = (exp.description or '').lower()
                for value, indicators in self.VALUE_INDICATORS.items():
                    if any(ind in desc for ind in indicators):
                        if value not in values:
                            values.append(value)
        except Exception:
            pass

        return values

    def _get_job_values(self, job) -> List[str]:
        """Extract values from job description."""
        values = []
        text = f"{job.description} {job.requirements}".lower()

        for value, indicators in self.VALUE_INDICATORS.items():
            if any(ind in text for ind in indicators):
                values.append(value)

        return values

    def get_weight(self) -> float:
        return 0.10  # 10% of total score


# ============================================================================
# Education Matcher
# ============================================================================

class EducationMatcher(BaseMatcher):
    """
    Calculates match based on education requirements.
    """

    EDUCATION_LEVELS = {
        'high_school': 1,
        'associate': 2,
        "bachelor's": 3,
        'bachelors': 3,
        'bs': 3,
        'ba': 3,
        "master's": 4,
        'masters': 4,
        'ms': 4,
        'ma': 4,
        'mba': 4,
        'phd': 5,
        'doctorate': 5,
        'any': 0
    }

    def score(self, candidate, job) -> float:
        """
        Calculate education match score.

        Returns:
        - 1.0 if candidate meets or exceeds requirements
        - Partial score if close
        - 0.5 minimum (education can be compensated with experience)
        """
        candidate_level = self._get_candidate_education_level(candidate)
        required_level = self._get_job_education_requirement(job)

        if required_level == 0:
            return 1.0  # No requirement

        if candidate_level >= required_level:
            return 1.0

        # Close enough
        diff = required_level - candidate_level
        if diff == 1:
            return 0.8
        elif diff == 2:
            return 0.6
        else:
            return 0.5

    def _get_candidate_education_level(self, candidate) -> int:
        """Get candidate's highest education level."""
        max_level = 0

        try:
            for edu in candidate.educations.all():
                degree = (edu.degree or '').lower()
                for edu_name, level in self.EDUCATION_LEVELS.items():
                    if edu_name in degree:
                        max_level = max(max_level, level)
        except Exception:
            pass

        return max_level

    def _get_job_education_requirement(self, job) -> int:
        """Get job's education requirement."""
        text = f"{job.description} {job.requirements}".lower()

        for edu_name, level in sorted(
            self.EDUCATION_LEVELS.items(),
            key=lambda x: x[1],
            reverse=True
        ):
            if edu_name in text:
                return level

        return 0  # No specific requirement

    def get_weight(self) -> float:
        return 0.10  # 10% of total score


# ============================================================================
# Composite Scorer
# ============================================================================

class CompositeScorer:
    """
    Combines multiple matchers into a weighted composite score.
    Used as the main entry point for rule-based matching.
    """

    def __init__(
        self,
        matchers: List[BaseMatcher] = None,
        weights: Dict[str, float] = None
    ):
        """
        Initialize composite scorer.

        Args:
            matchers: List of matcher instances. If None, uses default set.
            weights: Optional custom weights by matcher class name.
        """
        self.matchers = matchers or [
            SkillMatcher(),
            ExperienceMatcher(),
            LocationMatcher(),
            SalaryMatcher(),
            CultureFitScorer(),
            EducationMatcher()
        ]
        self.custom_weights = weights or {}

    def score(self, candidate, job) -> Dict[str, Any]:
        """
        Calculate composite match score.

        Returns:
            Dict with overall_score and component scores
        """
        component_scores = {}
        weighted_sum = 0.0
        total_weight = 0.0

        for matcher in self.matchers:
            matcher_name = matcher.__class__.__name__
            try:
                score = matcher.score(candidate, job)
                weight = self.custom_weights.get(
                    matcher_name,
                    matcher.get_weight()
                )

                component_scores[matcher_name] = {
                    'score': round(score, 4),
                    'weight': weight
                }

                weighted_sum += score * weight
                total_weight += weight

            except Exception as e:
                logger.warning(f"Matcher {matcher_name} failed: {e}")
                component_scores[matcher_name] = {
                    'score': 0.5,  # Default neutral score on failure
                    'weight': 0,
                    'error': str(e)
                }

        overall_score = weighted_sum / total_weight if total_weight > 0 else 0.5

        # Get skill details for matched/missing skills
        skill_details = {}
        for matcher in self.matchers:
            if isinstance(matcher, SkillMatcher):
                skill_details = matcher.get_match_details(candidate, job)
                break

        return {
            'overall_score': round(overall_score, 4),
            'skill_score': component_scores.get('SkillMatcher', {}).get('score', 0),
            'experience_score': component_scores.get('ExperienceMatcher', {}).get('score', 0),
            'location_score': component_scores.get('LocationMatcher', {}).get('score', 0),
            'salary_score': component_scores.get('SalaryMatcher', {}).get('score', 0),
            'culture_score': component_scores.get('CultureFitScorer', {}).get('score', 0),
            'education_score': component_scores.get('EducationMatcher', {}).get('score', 0),
            'matched_skills': skill_details.get('matched_skills', []),
            'missing_skills': skill_details.get('missing_skills', []),
            'component_scores': component_scores,
            'explanation': {
                'algorithm': 'rule_based',
                'matchers_used': [m.__class__.__name__ for m in self.matchers],
                'total_weight': total_weight
            }
        }

    def get_top_matches(
        self,
        candidate,
        jobs,
        limit: int = 10
    ) -> List[Dict]:
        """
        Get top matching jobs for a candidate.

        Args:
            candidate: CandidateProfile instance
            jobs: QuerySet or list of Job instances
            limit: Maximum number of results

        Returns:
            List of dicts with job and score info, sorted by score
        """
        results = []

        for job in jobs:
            try:
                score_result = self.score(candidate, job)
                results.append({
                    'job': job,
                    'score': score_result['overall_score'],
                    'details': score_result
                })
            except Exception as e:
                logger.warning(f"Failed to score job {job.id}: {e}")

        # Sort by score descending
        results.sort(key=lambda x: x['score'], reverse=True)

        return results[:limit]

    def get_top_candidates(
        self,
        job,
        candidates,
        limit: int = 10
    ) -> List[Dict]:
        """
        Get top matching candidates for a job.

        Args:
            job: Job instance
            candidates: QuerySet or list of CandidateProfile instances
            limit: Maximum number of results

        Returns:
            List of dicts with candidate and score info, sorted by score
        """
        results = []

        for candidate in candidates:
            try:
                score_result = self.score(candidate, job)
                results.append({
                    'candidate': candidate,
                    'score': score_result['overall_score'],
                    'details': score_result
                })
            except Exception as e:
                logger.warning(f"Failed to score candidate {candidate.id}: {e}")

        # Sort by score descending
        results.sort(key=lambda x: x['score'], reverse=True)

        return results[:limit]
