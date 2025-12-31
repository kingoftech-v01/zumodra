"""
ATS Scoring - Candidate Scoring and Ranking System

This module implements a comprehensive candidate scoring system:
- SkillMatchScorer: Evaluates skill alignment with job requirements
- ExperienceScorer: Assesses experience level and relevance
- CulturalFitScorer: Evaluates cultural alignment signals
- CompositeScorer: Combines multiple scorers with configurable weights

The scoring system follows HR best practices:
- Objective, criteria-based evaluation
- Transparency in scoring factors
- Configurable weights per job type
- Bias reduction through structured assessment
- Integration with AI-powered insights
"""

from dataclasses import dataclass, field
from typing import List, Dict, Optional, Any, Set, Tuple
from abc import ABC, abstractmethod
from enum import Enum
from decimal import Decimal
import re
import logging
from difflib import SequenceMatcher

from django.utils import timezone

logger = logging.getLogger(__name__)


# ==================== SCORING ENUMS AND DATA CLASSES ====================

class ScoreLevel(Enum):
    """Score level categories."""
    EXCEPTIONAL = "exceptional"  # 90-100
    STRONG = "strong"            # 75-89
    QUALIFIED = "qualified"      # 60-74
    DEVELOPING = "developing"    # 40-59
    WEAK = "weak"                # 20-39
    POOR = "poor"                # 0-19


@dataclass
class ScoreComponent:
    """Individual scoring component with details."""
    name: str
    score: float  # 0-100
    weight: float  # 0-1
    weighted_score: float  # score * weight
    details: Dict[str, Any] = field(default_factory=dict)
    breakdown: List[Dict[str, Any]] = field(default_factory=list)

    @property
    def level(self) -> ScoreLevel:
        """Get score level category."""
        if self.score >= 90:
            return ScoreLevel.EXCEPTIONAL
        elif self.score >= 75:
            return ScoreLevel.STRONG
        elif self.score >= 60:
            return ScoreLevel.QUALIFIED
        elif self.score >= 40:
            return ScoreLevel.DEVELOPING
        elif self.score >= 20:
            return ScoreLevel.WEAK
        return ScoreLevel.POOR


@dataclass
class ScoringResult:
    """Complete scoring result for a candidate-job pair."""
    candidate_id: int
    job_id: int
    total_score: float
    level: ScoreLevel
    components: List[ScoreComponent]
    recommendations: List[str]
    strengths: List[str]
    gaps: List[str]
    calculated_at: Any = None
    metadata: Dict[str, Any] = field(default_factory=dict)

    def __post_init__(self):
        if self.calculated_at is None:
            self.calculated_at = timezone.now()

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization."""
        return {
            'candidate_id': self.candidate_id,
            'job_id': self.job_id,
            'total_score': round(self.total_score, 2),
            'level': self.level.value,
            'components': [
                {
                    'name': c.name,
                    'score': round(c.score, 2),
                    'weight': c.weight,
                    'weighted_score': round(c.weighted_score, 2),
                    'level': c.level.value,
                    'details': c.details,
                    'breakdown': c.breakdown
                }
                for c in self.components
            ],
            'recommendations': self.recommendations,
            'strengths': self.strengths,
            'gaps': self.gaps,
            'calculated_at': self.calculated_at.isoformat() if self.calculated_at else None,
            'metadata': self.metadata
        }


# ==================== BASE SCORER CLASS ====================

class BaseScorer(ABC):
    """
    Abstract base class for all scorers.

    Each scorer evaluates one aspect of candidate fit
    and returns a ScoreComponent with details.
    """

    def __init__(
        self,
        name: str,
        weight: float = 1.0,
        config: Dict[str, Any] = None
    ):
        self.name = name
        self.weight = weight
        self.config = config or {}

    @abstractmethod
    def calculate_score(
        self,
        candidate: Any,
        job: Any,
        context: Dict[str, Any] = None
    ) -> ScoreComponent:
        """
        Calculate score for this dimension.

        Args:
            candidate: Candidate model instance
            job: JobPosting model instance
            context: Additional context (application, feedback, etc.)

        Returns:
            ScoreComponent with score and details
        """
        pass

    def _normalize_score(self, score: float) -> float:
        """Ensure score is between 0 and 100."""
        return max(0, min(100, score))


# ==================== SKILL MATCH SCORER ====================

class SkillMatchScorer(BaseScorer):
    """
    Evaluates how well candidate skills match job requirements.

    Scoring factors:
    - Required skills match percentage
    - Preferred skills match percentage
    - Skill similarity (fuzzy matching)
    - Skill proficiency levels (if available)
    - Related/transferable skills
    """

    def __init__(
        self,
        weight: float = 0.35,
        required_weight: float = 0.7,
        preferred_weight: float = 0.3,
        fuzzy_threshold: float = 0.8,
        **kwargs
    ):
        super().__init__(name="Skill Match", weight=weight, **kwargs)
        self.required_weight = required_weight
        self.preferred_weight = preferred_weight
        self.fuzzy_threshold = fuzzy_threshold

        # Common skill synonyms for fuzzy matching
        self.skill_synonyms = {
            'javascript': ['js', 'ecmascript', 'es6', 'es2015'],
            'python': ['py', 'python3', 'python2'],
            'react': ['reactjs', 'react.js'],
            'angular': ['angularjs', 'angular.js'],
            'vue': ['vuejs', 'vue.js'],
            'node': ['nodejs', 'node.js'],
            'postgresql': ['postgres', 'psql'],
            'mysql': ['mariadb'],
            'mongodb': ['mongo'],
            'kubernetes': ['k8s'],
            'amazon web services': ['aws'],
            'google cloud platform': ['gcp', 'google cloud'],
            'microsoft azure': ['azure'],
            'machine learning': ['ml'],
            'artificial intelligence': ['ai'],
            'natural language processing': ['nlp'],
            'user interface': ['ui'],
            'user experience': ['ux'],
            'continuous integration': ['ci'],
            'continuous deployment': ['cd'],
            'devops': ['dev ops'],
        }

    def calculate_score(
        self,
        candidate: Any,
        job: Any,
        context: Dict[str, Any] = None
    ) -> ScoreComponent:
        """Calculate skill match score."""
        # Normalize skills to lowercase sets
        candidate_skills = self._normalize_skills(candidate.skills or [])
        required_skills = self._normalize_skills(job.required_skills or [])
        preferred_skills = self._normalize_skills(job.preferred_skills or [])

        breakdown = []

        # Calculate required skills match
        required_matches = self._find_skill_matches(candidate_skills, required_skills)
        required_score = (
            (len(required_matches) / len(required_skills) * 100)
            if required_skills else 100
        )

        breakdown.append({
            'category': 'Required Skills',
            'matched': list(required_matches),
            'missing': list(required_skills - set(required_matches.keys())),
            'total_required': len(required_skills),
            'matched_count': len(required_matches),
            'score': round(required_score, 2)
        })

        # Calculate preferred skills match
        preferred_matches = self._find_skill_matches(candidate_skills, preferred_skills)
        preferred_score = (
            (len(preferred_matches) / len(preferred_skills) * 100)
            if preferred_skills else 100
        )

        breakdown.append({
            'category': 'Preferred Skills',
            'matched': list(preferred_matches),
            'missing': list(preferred_skills - set(preferred_matches.keys())),
            'total_preferred': len(preferred_skills),
            'matched_count': len(preferred_matches),
            'score': round(preferred_score, 2)
        })

        # Calculate additional skills (candidate has but not required)
        all_required = required_skills | preferred_skills
        additional_skills = candidate_skills - all_required
        additional_bonus = min(10, len(additional_skills) * 2)  # Up to 10 bonus points

        breakdown.append({
            'category': 'Additional Skills',
            'skills': list(additional_skills)[:10],
            'count': len(additional_skills),
            'bonus': additional_bonus
        })

        # Combine scores
        base_score = (
            required_score * self.required_weight +
            preferred_score * self.preferred_weight
        )
        final_score = self._normalize_score(base_score + additional_bonus)

        details = {
            'required_skills_matched': len(required_matches),
            'required_skills_total': len(required_skills),
            'preferred_skills_matched': len(preferred_matches),
            'preferred_skills_total': len(preferred_skills),
            'additional_skills': len(additional_skills),
            'fuzzy_matches': sum(
                1 for v in required_matches.values() if v != 'exact'
            ) + sum(
                1 for v in preferred_matches.values() if v != 'exact'
            )
        }

        return ScoreComponent(
            name=self.name,
            score=final_score,
            weight=self.weight,
            weighted_score=final_score * self.weight,
            details=details,
            breakdown=breakdown
        )

    def _normalize_skills(self, skills: List[str]) -> Set[str]:
        """Normalize skills to lowercase and expand synonyms."""
        normalized = set()
        for skill in skills:
            skill_lower = skill.lower().strip()
            normalized.add(skill_lower)

            # Add synonyms
            for main_skill, synonyms in self.skill_synonyms.items():
                if skill_lower == main_skill or skill_lower in synonyms:
                    normalized.add(main_skill)
                    normalized.update(synonyms)

        return normalized

    def _find_skill_matches(
        self,
        candidate_skills: Set[str],
        required_skills: Set[str]
    ) -> Dict[str, str]:
        """Find matches between candidate and required skills."""
        matches = {}

        for required in required_skills:
            # Exact match
            if required in candidate_skills:
                matches[required] = 'exact'
                continue

            # Fuzzy match
            for candidate_skill in candidate_skills:
                similarity = SequenceMatcher(None, required, candidate_skill).ratio()
                if similarity >= self.fuzzy_threshold:
                    matches[required] = f'fuzzy:{candidate_skill}'
                    break

                # Check if one contains the other
                if required in candidate_skill or candidate_skill in required:
                    matches[required] = f'partial:{candidate_skill}'
                    break

        return matches


# ==================== EXPERIENCE SCORER ====================

class ExperienceScorer(BaseScorer):
    """
    Evaluates candidate experience against job requirements.

    Scoring factors:
    - Years of experience vs. required level
    - Industry relevance
    - Job title progression
    - Company prestige/relevance
    - Career trajectory

    Configuration options for bias reduction:
    - career_progression_weight: Weight given to career progression (default 0.15)
    - disable_progression_penalty: If True, don't penalize lateral career moves
    - include_progression_in_score: If False, exclude progression from scoring entirely
    """

    # Experience level to years mapping
    LEVEL_YEARS = {
        'entry': (0, 1),
        'junior': (1, 2),
        'mid': (2, 5),
        'senior': (5, 8),
        'lead': (8, 12),
        'executive': (10, 30)
    }

    def __init__(
        self,
        weight: float = 0.25,
        overqualified_penalty: float = 0.1,
        underqualified_penalty: float = 0.2,
        career_progression_weight: float = 0.15,
        disable_progression_penalty: bool = False,
        include_progression_in_score: bool = True,
        **kwargs
    ):
        super().__init__(name="Experience Match", weight=weight, **kwargs)
        self.overqualified_penalty = overqualified_penalty
        self.underqualified_penalty = underqualified_penalty
        self.career_progression_weight = career_progression_weight
        self.disable_progression_penalty = disable_progression_penalty
        self.include_progression_in_score = include_progression_in_score

    def calculate_score(
        self,
        candidate: Any,
        job: Any,
        context: Dict[str, Any] = None
    ) -> ScoreComponent:
        """Calculate experience match score."""
        breakdown = []
        scores = []

        # Calculate weights based on whether progression is included
        if self.include_progression_in_score:
            # Distribute weights: years=0.4, title=0.25, industry=0.2, progression=configurable
            remaining_weight = 1.0 - self.career_progression_weight
            years_weight = 0.4 * remaining_weight / 0.85  # Scale to fit
            title_weight = 0.25 * remaining_weight / 0.85
            industry_weight = 0.2 * remaining_weight / 0.85
            progression_weight = self.career_progression_weight
        else:
            # Progression excluded: redistribute among other factors
            years_weight = 0.47
            title_weight = 0.30
            industry_weight = 0.23
            progression_weight = 0.0

        # Years of experience score
        years_score = self._calculate_years_score(candidate, job)
        scores.append(('years', years_score['score'], years_weight))
        breakdown.append({
            'category': 'Years of Experience',
            'weight': round(years_weight, 3),
            **years_score
        })

        # Title relevance score
        title_score = self._calculate_title_score(candidate, job)
        scores.append(('title', title_score['score'], title_weight))
        breakdown.append({
            'category': 'Title Relevance',
            'weight': round(title_weight, 3),
            **title_score
        })

        # Industry relevance score
        industry_score = self._calculate_industry_score(candidate, job)
        scores.append(('industry', industry_score['score'], industry_weight))
        breakdown.append({
            'category': 'Industry Relevance',
            'weight': round(industry_weight, 3),
            **industry_score
        })

        # Career progression score (optional, configurable)
        if self.include_progression_in_score:
            progression_score = self._calculate_progression_score(candidate)
            scores.append(('progression', progression_score['score'], progression_weight))
            breakdown.append({
                'category': 'Career Progression',
                'weight': round(progression_weight, 3),
                'bias_config': {
                    'penalty_disabled': self.disable_progression_penalty,
                    'configurable_weight': self.career_progression_weight
                },
                **progression_score
            })
        else:
            breakdown.append({
                'category': 'Career Progression',
                'status': 'excluded',
                'reason': 'Progression scoring disabled to reduce bias'
            })

        # Calculate weighted total
        total_score = sum(score * weight for _, score, weight in scores)
        final_score = self._normalize_score(total_score)

        details = {
            'candidate_years': candidate.years_experience,
            'required_level': job.experience_level,
            'expected_years_range': self.LEVEL_YEARS.get(job.experience_level, (0, 100)),
            'current_title': candidate.current_title,
            'current_company': candidate.current_company
        }

        return ScoreComponent(
            name=self.name,
            score=final_score,
            weight=self.weight,
            weighted_score=final_score * self.weight,
            details=details,
            breakdown=breakdown
        )

    def _calculate_years_score(
        self,
        candidate: Any,
        job: Any
    ) -> Dict[str, Any]:
        """Calculate years of experience score."""
        candidate_years = candidate.years_experience or 0
        min_years, max_years = self.LEVEL_YEARS.get(job.experience_level, (0, 100))

        if min_years <= candidate_years <= max_years:
            # Within range - full score
            score = 100
            status = 'ideal'
        elif candidate_years < min_years:
            # Underqualified
            gap = min_years - candidate_years
            score = max(0, 100 - (gap * 20 * self.underqualified_penalty * 10))
            status = 'underqualified'
        else:
            # Overqualified
            excess = candidate_years - max_years
            score = max(60, 100 - (excess * 5 * self.overqualified_penalty * 10))
            status = 'overqualified'

        return {
            'score': round(score, 2),
            'candidate_years': candidate_years,
            'required_range': f"{min_years}-{max_years}",
            'status': status
        }

    def _calculate_title_score(
        self,
        candidate: Any,
        job: Any
    ) -> Dict[str, Any]:
        """Calculate title relevance score."""
        candidate_title = (candidate.current_title or '').lower()
        job_title = job.title.lower()

        if not candidate_title:
            return {'score': 50, 'reason': 'No current title provided'}

        # Direct match
        if candidate_title == job_title:
            return {'score': 100, 'reason': 'Exact title match'}

        # Check for common title patterns
        similarity = SequenceMatcher(None, candidate_title, job_title).ratio()

        # Check for seniority keywords
        seniority_keywords = ['senior', 'lead', 'principal', 'staff', 'junior', 'associate']
        candidate_seniority = [k for k in seniority_keywords if k in candidate_title]
        job_seniority = [k for k in seniority_keywords if k in job_title]

        seniority_match = bool(set(candidate_seniority) & set(job_seniority))

        # Calculate score
        base_score = similarity * 100
        if seniority_match:
            base_score += 15

        score = min(100, base_score)

        return {
            'score': round(score, 2),
            'similarity': round(similarity, 2),
            'candidate_title': candidate.current_title,
            'job_title': job.title,
            'seniority_match': seniority_match
        }

    def _calculate_industry_score(
        self,
        candidate: Any,
        job: Any
    ) -> Dict[str, Any]:
        """Calculate industry relevance score."""
        # This would ideally match against industry taxonomies
        # For now, use simple keyword matching

        candidate_company = (candidate.current_company or '').lower()
        job_team = (job.team or '').lower()
        job_category = job.category.name.lower() if job.category else ''

        # Look for industry keywords in resume text
        resume_text = (candidate.resume_text or '').lower()

        industry_keywords = {
            'technology': ['software', 'tech', 'it', 'digital', 'saas', 'startup'],
            'finance': ['bank', 'financial', 'investment', 'fintech', 'trading'],
            'healthcare': ['health', 'medical', 'pharma', 'hospital', 'clinical'],
            'retail': ['retail', 'ecommerce', 'store', 'consumer', 'shop'],
            'manufacturing': ['manufacturing', 'factory', 'production', 'industrial'],
        }

        # Determine job industry (simplified)
        job_industry = 'technology'  # Default
        for industry, keywords in industry_keywords.items():
            if any(kw in job_category or kw in job_team for kw in keywords):
                job_industry = industry
                break

        # Check if candidate has relevant experience
        industry_keywords_for_job = industry_keywords.get(job_industry, [])
        matches = sum(1 for kw in industry_keywords_for_job if kw in resume_text)

        score = min(100, 50 + (matches * 10))

        return {
            'score': round(score, 2),
            'detected_industry': job_industry,
            'keyword_matches': matches
        }

    def _calculate_progression_score(self, candidate: Any) -> Dict[str, Any]:
        """
        Calculate career progression score.

        When disable_progression_penalty is True, lateral moves are scored
        the same as upward progression to reduce bias against candidates
        who have made valid lateral career changes.
        """
        work_experience = candidate.work_experience or []

        if not work_experience:
            return {'score': 50, 'reason': 'No work history available'}

        # Analyze title progression
        titles = [exp.get('title', '') for exp in work_experience if exp.get('title')]

        if len(titles) < 2:
            return {'score': 60, 'reason': 'Limited work history'}

        # Check for progression indicators
        progression_indicators = ['senior', 'lead', 'manager', 'director', 'head', 'vp', 'chief']

        progression_count = 0
        prev_level = 0
        for title in titles:
            title_lower = title.lower()
            current_level = sum(1 for ind in progression_indicators if ind in title_lower)
            if current_level > prev_level:
                progression_count += 1
            prev_level = current_level

        # Score based on progression
        if progression_count >= 2:
            score = 100
            status = 'strong_progression'
        elif progression_count == 1:
            score = 80
            status = 'moderate_progression'
        else:
            # When disable_progression_penalty is True, don't penalize lateral moves
            if self.disable_progression_penalty:
                score = 80  # Same as moderate progression
                status = 'lateral_moves_no_penalty'
            else:
                score = 60
                status = 'lateral_moves'

        return {
            'score': score,
            'status': status,
            'positions_analyzed': len(titles),
            'progression_count': progression_count,
            'penalty_applied': not self.disable_progression_penalty and status == 'lateral_moves'
        }


# ==================== CULTURAL FIT SCORER ====================

class CulturalFitScorer(BaseScorer):
    """
    Evaluates cultural fit indicators.

    Scoring factors:
    - Communication style signals
    - Values alignment indicators
    - Work style preferences
    - Team collaboration signals
    - Remote/on-site fit

    Note: This is based on objective data points, not subjective bias.
    """

    def __init__(
        self,
        weight: float = 0.15,
        **kwargs
    ):
        super().__init__(name="Cultural Fit", weight=weight, **kwargs)

    def calculate_score(
        self,
        candidate: Any,
        job: Any,
        context: Dict[str, Any] = None
    ) -> ScoreComponent:
        """Calculate cultural fit score."""
        breakdown = []
        scores = []

        # Location/Remote fit
        location_score = self._calculate_location_fit(candidate, job)
        scores.append(('location', location_score['score'], 0.3))
        breakdown.append({
            'category': 'Location Fit',
            **location_score
        })

        # Work style indicators
        workstyle_score = self._calculate_workstyle_fit(candidate, job)
        scores.append(('workstyle', workstyle_score['score'], 0.25))
        breakdown.append({
            'category': 'Work Style',
            **workstyle_score
        })

        # Communication indicators
        communication_score = self._calculate_communication_fit(candidate, job)
        scores.append(('communication', communication_score['score'], 0.25))
        breakdown.append({
            'category': 'Communication',
            **communication_score
        })

        # Team/company size fit
        team_score = self._calculate_team_fit(candidate, job)
        scores.append(('team', team_score['score'], 0.2))
        breakdown.append({
            'category': 'Team Fit',
            **team_score
        })

        # Calculate weighted total
        total_score = sum(score * weight for _, score, weight in scores)
        final_score = self._normalize_score(total_score)

        details = {
            'remote_policy': job.remote_policy,
            'candidate_location': f"{candidate.city}, {candidate.country}",
            'willing_to_relocate': candidate.willing_to_relocate
        }

        return ScoreComponent(
            name=self.name,
            score=final_score,
            weight=self.weight,
            weighted_score=final_score * self.weight,
            details=details,
            breakdown=breakdown
        )

    def _calculate_location_fit(
        self,
        candidate: Any,
        job: Any
    ) -> Dict[str, Any]:
        """Calculate location compatibility."""
        remote_policy = job.remote_policy

        if remote_policy == 'remote':
            return {
                'score': 100,
                'reason': 'Fully remote position - location neutral'
            }

        candidate_city = (candidate.city or '').lower()
        job_city = (job.location_city or '').lower()

        if not candidate_city or not job_city:
            return {
                'score': 70,
                'reason': 'Location information incomplete'
            }

        if candidate_city == job_city:
            return {
                'score': 100,
                'reason': 'Same city location'
            }

        # Check same region/country
        candidate_country = (candidate.country or '').lower()
        job_country = (job.location_country or '').lower()

        if candidate_country == job_country:
            if remote_policy == 'hybrid':
                if candidate.willing_to_relocate:
                    return {
                        'score': 85,
                        'reason': 'Different city but willing to relocate'
                    }
                return {
                    'score': 70,
                    'reason': 'Different city, hybrid role may work'
                }

        # Different country
        if candidate.willing_to_relocate:
            return {
                'score': 60,
                'reason': 'International candidate, willing to relocate'
            }

        if remote_policy == 'on_site':
            return {
                'score': 30,
                'reason': 'Location mismatch for on-site role'
            }

        return {
            'score': 50,
            'reason': 'Location mismatch with flexibility'
        }

    def _calculate_workstyle_fit(
        self,
        candidate: Any,
        job: Any
    ) -> Dict[str, Any]:
        """Calculate work style compatibility."""
        # Analyze from resume text and job description
        resume_text = (candidate.resume_text or '').lower()
        job_desc = (job.description or '').lower()

        workstyle_signals = {
            'collaborative': ['team', 'collaborate', 'cross-functional', 'partnership'],
            'independent': ['autonomous', 'self-directed', 'independently', 'self-starter'],
            'structured': ['process', 'methodology', 'documentation', 'procedures'],
            'agile': ['agile', 'scrum', 'sprint', 'iterative', 'flexible'],
            'leadership': ['lead', 'mentor', 'manage', 'coach', 'guide'],
        }

        candidate_signals = {}
        job_signals = {}

        for style, keywords in workstyle_signals.items():
            candidate_count = sum(1 for kw in keywords if kw in resume_text)
            job_count = sum(1 for kw in keywords if kw in job_desc)
            if candidate_count:
                candidate_signals[style] = candidate_count
            if job_count:
                job_signals[style] = job_count

        # Calculate overlap
        common_styles = set(candidate_signals.keys()) & set(job_signals.keys())
        if not job_signals:
            score = 70  # Neutral if job doesn't specify
        elif common_styles:
            overlap_ratio = len(common_styles) / len(job_signals)
            score = 50 + (overlap_ratio * 50)
        else:
            score = 50

        return {
            'score': round(score, 2),
            'candidate_styles': list(candidate_signals.keys()),
            'job_styles': list(job_signals.keys()),
            'overlap': list(common_styles)
        }

    def _calculate_communication_fit(
        self,
        candidate: Any,
        job: Any
    ) -> Dict[str, Any]:
        """Calculate communication style compatibility."""
        # Check language requirements
        candidate_languages = set(lang.lower() for lang in (candidate.languages or []))
        required_languages = set(lang.lower() for lang in (job.languages_required or []))

        if not required_languages:
            language_score = 100
        else:
            match_count = len(candidate_languages & required_languages)
            language_score = (match_count / len(required_languages)) * 100

        # Check for communication-related signals
        resume_text = (candidate.resume_text or '').lower()
        communication_keywords = [
            'presentation', 'stakeholder', 'client-facing', 'written',
            'verbal', 'communication', 'public speaking', 'negotiation'
        ]

        communication_signals = sum(
            1 for kw in communication_keywords if kw in resume_text
        )
        communication_bonus = min(20, communication_signals * 4)

        score = language_score * 0.6 + 40 + communication_bonus * 0.4
        score = min(100, score)

        return {
            'score': round(score, 2),
            'language_match': list(candidate_languages & required_languages),
            'missing_languages': list(required_languages - candidate_languages),
            'communication_signals': communication_signals
        }

    def _calculate_team_fit(
        self,
        candidate: Any,
        job: Any
    ) -> Dict[str, Any]:
        """Calculate team/company size fit."""
        # Analyze work history for company size experience
        work_experience = candidate.work_experience or []

        # Company size indicators (simplified)
        startup_keywords = ['startup', 'early-stage', 'seed', 'series a']
        enterprise_keywords = ['fortune', 'enterprise', 'corporation', 'global']

        startup_exp = 0
        enterprise_exp = 0

        for exp in work_experience:
            company = (exp.get('company', '') or '').lower()
            if any(kw in company for kw in startup_keywords):
                startup_exp += 1
            if any(kw in company for kw in enterprise_keywords):
                enterprise_exp += 1

        # Default to balanced score if no clear pattern
        score = 70
        experience_type = 'mixed'

        if startup_exp > enterprise_exp:
            experience_type = 'startup'
            score = 75
        elif enterprise_exp > startup_exp:
            experience_type = 'enterprise'
            score = 75

        return {
            'score': score,
            'experience_type': experience_type,
            'startup_experience': startup_exp,
            'enterprise_experience': enterprise_exp
        }


# ==================== EDUCATION SCORER ====================

class EducationScorer(BaseScorer):
    """
    Evaluates educational background against requirements.

    Scoring factors:
    - Degree level match
    - Field of study relevance
    - Institution quality indicators
    - Certifications match
    """

    DEGREE_LEVELS = {
        'high school': 1,
        'associate': 2,
        'bachelor': 3,
        'master': 4,
        'phd': 5,
        'doctorate': 5
    }

    def __init__(
        self,
        weight: float = 0.1,
        **kwargs
    ):
        super().__init__(name="Education Match", weight=weight, **kwargs)

    def calculate_score(
        self,
        candidate: Any,
        job: Any,
        context: Dict[str, Any] = None
    ) -> ScoreComponent:
        """Calculate education match score."""
        breakdown = []

        # Degree match
        degree_score = self._calculate_degree_match(candidate, job)
        breakdown.append({
            'category': 'Degree Level',
            **degree_score
        })

        # Field of study match
        field_score = self._calculate_field_match(candidate, job)
        breakdown.append({
            'category': 'Field of Study',
            **field_score
        })

        # Certifications match
        cert_score = self._calculate_certification_match(candidate, job)
        breakdown.append({
            'category': 'Certifications',
            **cert_score
        })

        # Weighted combination
        final_score = (
            degree_score['score'] * 0.4 +
            field_score['score'] * 0.35 +
            cert_score['score'] * 0.25
        )

        details = {
            'education_entries': len(candidate.education or []),
            'certifications_count': len(candidate.certifications or [])
        }

        return ScoreComponent(
            name=self.name,
            score=self._normalize_score(final_score),
            weight=self.weight,
            weighted_score=final_score * self.weight,
            details=details,
            breakdown=breakdown
        )

    def _calculate_degree_match(
        self,
        candidate: Any,
        job: Any
    ) -> Dict[str, Any]:
        """Calculate degree level match."""
        education = candidate.education or []
        requirements_text = (job.education_requirements or '').lower()

        # Find highest degree
        highest_level = 0
        highest_degree = 'none'

        for edu in education:
            degree = (edu.get('degree', '') or '').lower()
            for level_name, level_num in self.DEGREE_LEVELS.items():
                if level_name in degree and level_num > highest_level:
                    highest_level = level_num
                    highest_degree = degree

        # Determine required level
        required_level = 0
        for level_name, level_num in self.DEGREE_LEVELS.items():
            if level_name in requirements_text:
                required_level = max(required_level, level_num)

        if required_level == 0:
            # No specific requirement
            return {
                'score': 80,
                'reason': 'No specific degree requirement',
                'candidate_degree': highest_degree
            }

        if highest_level >= required_level:
            return {
                'score': 100,
                'reason': 'Meets or exceeds degree requirement',
                'candidate_degree': highest_degree
            }
        elif highest_level == required_level - 1:
            return {
                'score': 70,
                'reason': 'Slightly below degree requirement',
                'candidate_degree': highest_degree
            }
        else:
            return {
                'score': 40,
                'reason': 'Below degree requirement',
                'candidate_degree': highest_degree
            }

    def _calculate_field_match(
        self,
        candidate: Any,
        job: Any
    ) -> Dict[str, Any]:
        """Calculate field of study match."""
        education = candidate.education or []
        requirements_text = (job.education_requirements or '').lower()
        job_category = (job.category.name if job.category else '').lower()

        # Common field mappings
        field_keywords = {
            'computer science': ['cs', 'computing', 'software', 'programming'],
            'engineering': ['engineering', 'technical'],
            'business': ['business', 'mba', 'management', 'administration'],
            'data science': ['data', 'statistics', 'analytics', 'mathematics'],
            'design': ['design', 'ux', 'ui', 'visual', 'creative'],
        }

        # Extract candidate fields
        candidate_fields = set()
        for edu in education:
            field = (edu.get('field_of_study', '') or '').lower()
            candidate_fields.add(field)
            for main_field, keywords in field_keywords.items():
                if any(kw in field for kw in keywords):
                    candidate_fields.add(main_field)

        # Check for field match
        for main_field, keywords in field_keywords.items():
            if any(kw in requirements_text or kw in job_category for kw in keywords):
                if main_field in candidate_fields or any(kw in str(candidate_fields) for kw in keywords):
                    return {
                        'score': 100,
                        'reason': 'Field of study matches',
                        'matched_field': main_field
                    }

        return {
            'score': 60,
            'reason': 'Field of study not directly matched',
            'candidate_fields': list(candidate_fields)[:5]
        }

    def _calculate_certification_match(
        self,
        candidate: Any,
        job: Any
    ) -> Dict[str, Any]:
        """Calculate certification match."""
        candidate_certs = set(
            c.lower() if isinstance(c, str) else (c.get('name', '') or '').lower()
            for c in (candidate.certifications or [])
        )
        required_certs = set(c.lower() for c in (job.certifications_required or []))

        if not required_certs:
            bonus = min(20, len(candidate_certs) * 4)
            return {
                'score': 70 + bonus,
                'reason': 'No specific certifications required',
                'candidate_certs': list(candidate_certs)[:5]
            }

        matched = candidate_certs & required_certs
        match_ratio = len(matched) / len(required_certs)

        return {
            'score': match_ratio * 100,
            'reason': f"Matched {len(matched)} of {len(required_certs)} required",
            'matched': list(matched),
            'missing': list(required_certs - matched)
        }


# ==================== COMPOSITE SCORER ====================

class CompositeScorer:
    """
    Combines multiple scorers for comprehensive candidate evaluation.

    Provides:
    - Weighted combination of all scoring dimensions
    - Customizable weights per job type
    - Detailed breakdown and recommendations
    - Scoring history and analytics
    - Human-readable explanations for GDPR Article 22 compliance
    """

    # Default weights by job type
    DEFAULT_WEIGHTS = {
        'technical': {
            'skill_match': 0.4,
            'experience': 0.25,
            'education': 0.15,
            'cultural_fit': 0.2
        },
        'leadership': {
            'skill_match': 0.25,
            'experience': 0.35,
            'education': 0.1,
            'cultural_fit': 0.3
        },
        'entry_level': {
            'skill_match': 0.3,
            'experience': 0.15,
            'education': 0.3,
            'cultural_fit': 0.25
        },
        'default': {
            'skill_match': 0.35,
            'experience': 0.25,
            'education': 0.15,
            'cultural_fit': 0.25
        }
    }

    # Human-readable templates for GDPR Article 22 compliance
    EXPLANATION_TEMPLATES = {
        'skill_match': {
            'high': "Your skills closely match the requirements for this position. You demonstrated {matched_count} of {total_count} required skills.",
            'medium': "You have some of the skills required for this position ({matched_count} of {total_count}). Key skills that could strengthen your application: {missing_skills}.",
            'low': "There is a gap between your skills and the job requirements. The position requires: {missing_skills}."
        },
        'experience': {
            'high': "Your experience level ({years} years) aligns well with what we're looking for in this role.",
            'medium': "Your experience level is close to our requirements. We're looking for {required_range} years of experience.",
            'low': "Your experience level ({years} years) differs from our target range of {required_range} years."
        },
        'education': {
            'high': "Your educational background meets or exceeds the requirements for this position.",
            'medium': "Your educational background partially meets our requirements.",
            'low': "The position has specific educational requirements that differ from your background."
        },
        'cultural_fit': {
            'high': "Based on objective factors, you appear to be a good fit for our work environment and location requirements.",
            'medium': "There are some considerations regarding work location or environment fit.",
            'low': "There may be challenges with location requirements or work style compatibility."
        }
    }

    def __init__(
        self,
        job_type: str = 'default',
        custom_weights: Dict[str, float] = None,
        experience_scorer_config: Dict[str, Any] = None
    ):
        self.job_type = job_type
        self.weights = custom_weights or self.DEFAULT_WEIGHTS.get(
            job_type, self.DEFAULT_WEIGHTS['default']
        )

        # Allow configurable experience scorer settings (for bias reduction)
        exp_config = experience_scorer_config or {}

        # Initialize scorers
        self.scorers = [
            SkillMatchScorer(weight=self.weights.get('skill_match', 0.35)),
            ExperienceScorer(
                weight=self.weights.get('experience', 0.25),
                career_progression_weight=exp_config.get('career_progression_weight', 0.15),
                disable_progression_penalty=exp_config.get('disable_progression_penalty', False),
                include_progression_in_score=exp_config.get('include_progression_in_score', True)
            ),
            EducationScorer(weight=self.weights.get('education', 0.15)),
            CulturalFitScorer(weight=self.weights.get('cultural_fit', 0.25)),
        ]

    def calculate_score(
        self,
        candidate: Any,
        job: Any,
        context: Dict[str, Any] = None
    ) -> ScoringResult:
        """
        Calculate comprehensive score for candidate-job pair.

        Args:
            candidate: Candidate model instance
            job: JobPosting model instance
            context: Additional context (application, interviews, etc.)

        Returns:
            ScoringResult with complete breakdown
        """
        context = context or {}
        components = []
        total_weighted_score = 0

        # Run each scorer
        for scorer in self.scorers:
            try:
                component = scorer.calculate_score(candidate, job, context)
                components.append(component)
                total_weighted_score += component.weighted_score
            except Exception as e:
                logger.error(f"Scorer {scorer.name} failed: {e}")
                # Add placeholder component
                components.append(ScoreComponent(
                    name=scorer.name,
                    score=50,
                    weight=scorer.weight,
                    weighted_score=50 * scorer.weight,
                    details={'error': str(e)}
                ))
                total_weighted_score += 50 * scorer.weight

        # Generate insights
        strengths = self._identify_strengths(components)
        gaps = self._identify_gaps(components)
        recommendations = self._generate_recommendations(components, candidate, job)

        # Determine overall level
        level = self._get_score_level(total_weighted_score)

        return ScoringResult(
            candidate_id=candidate.id,
            job_id=job.id,
            total_score=total_weighted_score,
            level=level,
            components=components,
            recommendations=recommendations,
            strengths=strengths,
            gaps=gaps,
            metadata={
                'job_type': self.job_type,
                'weights_used': self.weights,
                'scorer_count': len(self.scorers)
            }
        )

    def _get_score_level(self, score: float) -> ScoreLevel:
        """Determine score level from total score."""
        if score >= 90:
            return ScoreLevel.EXCEPTIONAL
        elif score >= 75:
            return ScoreLevel.STRONG
        elif score >= 60:
            return ScoreLevel.QUALIFIED
        elif score >= 40:
            return ScoreLevel.DEVELOPING
        elif score >= 20:
            return ScoreLevel.WEAK
        return ScoreLevel.POOR

    def _identify_strengths(self, components: List[ScoreComponent]) -> List[str]:
        """Identify candidate strengths from scoring components."""
        strengths = []

        for component in components:
            if component.score >= 80:
                strengths.append(f"Strong {component.name.lower()} ({component.score:.0f}%)")

                # Add specific strengths from breakdown
                for item in component.breakdown:
                    if item.get('score', 0) >= 90:
                        strengths.append(
                            f"Excellent {item.get('category', 'score')}"
                        )

        return strengths[:5]  # Top 5 strengths

    def _identify_gaps(self, components: List[ScoreComponent]) -> List[str]:
        """Identify candidate gaps from scoring components."""
        gaps = []

        for component in components:
            if component.score < 60:
                gaps.append(f"Needs improvement in {component.name.lower()} ({component.score:.0f}%)")

                # Add specific gaps from breakdown
                for item in component.breakdown:
                    if item.get('missing'):
                        missing = item.get('missing', [])[:3]
                        if missing:
                            gaps.append(f"Missing: {', '.join(missing)}")

        return gaps[:5]  # Top 5 gaps

    def _generate_recommendations(
        self,
        components: List[ScoreComponent],
        candidate: Any,
        job: Any
    ) -> List[str]:
        """Generate actionable recommendations."""
        recommendations = []
        total_score = sum(c.weighted_score for c in components)

        if total_score >= 85:
            recommendations.append("Highly recommended - prioritize for interview")
        elif total_score >= 70:
            recommendations.append("Good fit - proceed with standard evaluation")
        elif total_score >= 55:
            recommendations.append("Potential fit - consider with reservations")
        else:
            recommendations.append("Below threshold - review before proceeding")

        # Specific recommendations based on components
        for component in components:
            if component.score < 50:
                if component.name == "Skill Match":
                    recommendations.append(
                        "Consider skills assessment to verify capabilities"
                    )
                elif component.name == "Experience Match":
                    recommendations.append(
                        "Discuss career progression and relevant experience"
                    )
                elif component.name == "Cultural Fit":
                    recommendations.append(
                        "Include culture-focused interview questions"
                    )

        return recommendations[:5]

    def get_human_readable_explanation(
        self,
        result: ScoringResult,
        candidate: Any = None,
        job: Any = None,
        language: str = 'en'
    ) -> Dict[str, Any]:
        """
        Generate human-readable explanation of scoring for GDPR Article 22 compliance.

        GDPR Article 22 requires that individuals have the right to obtain meaningful
        information about the logic involved in automated decision-making.

        Args:
            result: The ScoringResult to explain
            candidate: Optional candidate for additional context
            job: Optional job for additional context
            language: Language code for explanation (default: 'en')

        Returns:
            Dict containing:
            - summary: Overall explanation paragraph
            - component_explanations: List of explanations for each scoring component
            - methodology: Description of how scores are calculated
            - your_rights: Information about data subject rights
            - factors_considered: List of factors that influenced the decision
            - factors_not_considered: Explicit list of factors NOT used (for bias transparency)
        """
        explanations = []
        factors_considered = []
        factors_not_considered = [
            "Age",
            "Gender",
            "Race or ethnicity",
            "Religion",
            "Marital status",
            "Disability status",
            "National origin",
            "Genetic information",
            "Sexual orientation",
            "Pregnancy status"
        ]

        for component in result.components:
            level = 'high' if component.score >= 75 else 'medium' if component.score >= 50 else 'low'
            component_key = component.name.lower().replace(' ', '_')

            template = self.EXPLANATION_TEMPLATES.get(component_key, {}).get(level, '')

            # Build context for template
            context = {}

            if component_key == 'skill_match':
                details = component.details
                context = {
                    'matched_count': details.get('required_skills_matched', 0),
                    'total_count': details.get('required_skills_total', 0),
                    'missing_skills': ', '.join(
                        item.get('missing', [])[:3]
                        for item in component.breakdown
                        if item.get('missing')
                    ) or 'various technical skills'
                }
                factors_considered.append("Listed skills and qualifications")
                factors_considered.append("Required skills match")
                factors_considered.append("Preferred skills match")

            elif component_key == 'experience_match':
                details = component.details
                context = {
                    'years': details.get('candidate_years', 0),
                    'required_range': details.get('expected_years_range', (0, 0))
                }
                if isinstance(context['required_range'], tuple):
                    context['required_range'] = f"{context['required_range'][0]}-{context['required_range'][1]}"
                factors_considered.append("Years of professional experience")
                factors_considered.append("Job title relevance")
                factors_considered.append("Industry experience")

            elif component_key == 'education_match':
                factors_considered.append("Educational qualifications")
                factors_considered.append("Relevant certifications")

            elif component_key == 'cultural_fit':
                factors_considered.append("Location compatibility")
                factors_considered.append("Work style indicators from resume")
                factors_considered.append("Language requirements")

            # Format the explanation
            try:
                explanation_text = template.format(**context) if template else f"Score: {component.score:.0f}%"
            except KeyError:
                explanation_text = f"Your {component.name.lower()} score is {component.score:.0f}%."

            explanations.append({
                'component': component.name,
                'score': round(component.score, 1),
                'weight': f"{component.weight * 100:.0f}%",
                'level': level,
                'explanation': explanation_text,
                'details': component.breakdown
            })

        # Build summary
        level_desc = {
            ScoreLevel.EXCEPTIONAL: "an exceptional",
            ScoreLevel.STRONG: "a strong",
            ScoreLevel.QUALIFIED: "a qualified",
            ScoreLevel.DEVELOPING: "a developing",
            ScoreLevel.WEAK: "a limited",
            ScoreLevel.POOR: "a poor"
        }

        summary = (
            f"Based on our automated evaluation system, your application received "
            f"{level_desc.get(result.level, 'a')} match score of {result.total_score:.1f}%. "
            f"This score was calculated using objective criteria including skills match, "
            f"experience level, educational background, and work environment compatibility. "
            f"No personal characteristics such as age, gender, race, or disability status "
            f"were considered in this evaluation."
        )

        methodology = (
            "Our scoring system evaluates candidates using weighted criteria:\n"
            f"- Skill Match ({self.weights.get('skill_match', 0.35) * 100:.0f}%): "
            "How well your listed skills align with job requirements.\n"
            f"- Experience Match ({self.weights.get('experience', 0.25) * 100:.0f}%): "
            "Your years and type of experience compared to the role.\n"
            f"- Education Match ({self.weights.get('education', 0.15) * 100:.0f}%): "
            "Your educational background and certifications.\n"
            f"- Cultural Fit ({self.weights.get('cultural_fit', 0.25) * 100:.0f}%): "
            "Location, work style, and language compatibility.\n\n"
            "Each criterion is scored 0-100 and combined using the weights above."
        )

        your_rights = (
            "Under GDPR Article 22, you have the right to:\n"
            "- Request human review of this automated decision\n"
            "- Express your point of view regarding the decision\n"
            "- Contest the decision if you believe it is inaccurate\n"
            "- Request information about the logic involved in the decision\n\n"
            "To exercise these rights, please contact our recruitment team."
        )

        return {
            'summary': summary,
            'overall_score': round(result.total_score, 1),
            'overall_level': result.level.value,
            'component_explanations': explanations,
            'methodology': methodology,
            'factors_considered': list(set(factors_considered)),
            'factors_not_considered': factors_not_considered,
            'your_rights': your_rights,
            'strengths': result.strengths,
            'gaps': result.gaps,
            'generated_at': result.calculated_at.isoformat() if result.calculated_at else None,
            'gdpr_article_22_compliant': True
        }


# ==================== SCORING SERVICE ====================

class ScoringService:
    """
    Service class for candidate scoring operations.

    Provides:
    - Score calculation for applications
    - Batch scoring
    - Score comparison and ranking
    """

    def __init__(self):
        self.scorer_cache: Dict[str, CompositeScorer] = {}

    def score_application(
        self,
        application,
        recalculate: bool = False
    ) -> ScoringResult:
        """
        Calculate score for an application.

        Args:
            application: Application model instance
            recalculate: Force recalculation even if cached

        Returns:
            ScoringResult with complete scoring
        """
        candidate = application.candidate
        job = application.job

        # Get or create appropriate scorer
        job_type = self._determine_job_type(job)
        scorer = self._get_scorer(job_type)

        # Calculate score
        context = {
            'application': application,
            'interviews': list(application.interviews.all()),
            'feedback': list(
                fb for interview in application.interviews.all()
                for fb in interview.feedback.all()
            )
        }

        result = scorer.calculate_score(candidate, job, context)

        # Update application with score
        application.ai_match_score = Decimal(str(result.total_score))
        application.save(update_fields=['ai_match_score'])

        return result

    def batch_score(
        self,
        applications,
        parallel: bool = False
    ) -> List[ScoringResult]:
        """Score multiple applications."""
        results = []
        for application in applications:
            try:
                result = self.score_application(application)
                results.append(result)
            except Exception as e:
                logger.error(f"Batch scoring error for app {application.id}: {e}")
        return results

    def rank_candidates(
        self,
        job,
        top_n: int = None
    ) -> List[Dict[str, Any]]:
        """
        Rank all candidates for a job by score.

        Returns list of candidates with scores, sorted by total score.
        """
        from .models import Application

        applications = Application.objects.filter(job=job).select_related('candidate')

        # Score all applications
        scored = []
        for app in applications:
            if app.ai_match_score is None:
                result = self.score_application(app)
                scored.append({
                    'application_id': app.id,
                    'candidate_id': app.candidate.id,
                    'candidate_name': app.candidate.full_name,
                    'score': result.total_score,
                    'level': result.level.value,
                    'result': result
                })
            else:
                scored.append({
                    'application_id': app.id,
                    'candidate_id': app.candidate.id,
                    'candidate_name': app.candidate.full_name,
                    'score': float(app.ai_match_score),
                    'level': self._get_level_from_score(float(app.ai_match_score)),
                    'result': None
                })

        # Sort by score descending
        scored.sort(key=lambda x: x['score'], reverse=True)

        if top_n:
            scored = scored[:top_n]

        return scored

    def _determine_job_type(self, job) -> str:
        """Determine job type for scorer selection."""
        title_lower = job.title.lower()

        if any(kw in title_lower for kw in ['engineer', 'developer', 'technical', 'architect']):
            return 'technical'
        elif any(kw in title_lower for kw in ['manager', 'director', 'lead', 'head', 'vp']):
            return 'leadership'
        elif job.experience_level in ['entry', 'junior']:
            return 'entry_level'

        return 'default'

    def _get_scorer(self, job_type: str) -> CompositeScorer:
        """Get or create scorer for job type."""
        if job_type not in self.scorer_cache:
            self.scorer_cache[job_type] = CompositeScorer(job_type=job_type)
        return self.scorer_cache[job_type]

    def _get_level_from_score(self, score: float) -> str:
        """Get level string from score."""
        if score >= 90:
            return 'exceptional'
        elif score >= 75:
            return 'strong'
        elif score >= 60:
            return 'qualified'
        elif score >= 40:
            return 'developing'
        elif score >= 20:
            return 'weak'
        return 'poor'


# Create singleton service instance
scoring_service = ScoringService()
