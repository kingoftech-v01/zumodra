"""
AI Services for Candidate-Job Matching

This module contains service classes for AI-powered operations including:
- Embedding generation (OpenAI and local fallback)
- Resume parsing and skill extraction
- Job description analysis
- Bias detection in job postings
- Matching and recommendation engines
"""

import logging
import re
from abc import ABC, abstractmethod
from typing import List, Dict, Optional, Tuple, Any
from dataclasses import dataclass
from decimal import Decimal

from django.conf import settings
from django.utils import timezone
from django.db import transaction

logger = logging.getLogger(__name__)


# ============================================================================
# Configuration and Constants
# ============================================================================

OPENAI_EMBEDDING_MODEL = 'text-embedding-ada-002'
EMBEDDING_DIMENSION = 1536

# Common bias indicators for job postings
GENDER_BIASED_TERMS = {
    'male_coded': [
        'aggressive', 'ambitious', 'analytical', 'assertive', 'autonomous',
        'challenging', 'competitive', 'confident', 'decisive', 'determined',
        'dominant', 'driven', 'fearless', 'headstrong', 'hierarchical',
        'independent', 'leader', 'ninja', 'rockstar', 'strong'
    ],
    'female_coded': [
        'collaborative', 'committed', 'compassionate', 'considerate',
        'cooperative', 'dependable', 'empathetic', 'interpersonal', 'loyal',
        'nurturing', 'pleasant', 'polite', 'sensitive', 'supportive',
        'sympathetic', 'understanding', 'warm'
    ]
}

AGE_BIASED_TERMS = [
    'digital native', 'young', 'energetic', 'fresh graduate', 'recent graduate',
    'up to X years', 'maximum X years experience', 'youthful', 'dynamic',
    'entry-level only', 'junior culture'
]

# Skills database for extraction
TECH_SKILLS = [
    'python', 'javascript', 'java', 'c++', 'c#', 'ruby', 'go', 'rust', 'swift',
    'kotlin', 'typescript', 'php', 'scala', 'r', 'matlab', 'sql', 'nosql',
    'mongodb', 'postgresql', 'mysql', 'redis', 'elasticsearch', 'docker',
    'kubernetes', 'aws', 'azure', 'gcp', 'terraform', 'ansible', 'jenkins',
    'git', 'react', 'angular', 'vue', 'node.js', 'django', 'flask', 'fastapi',
    'spring', 'rails', 'laravel', 'express', 'graphql', 'rest api', 'microservices',
    'machine learning', 'deep learning', 'tensorflow', 'pytorch', 'nlp',
    'computer vision', 'data science', 'data engineering', 'etl', 'spark',
    'hadoop', 'kafka', 'airflow', 'pandas', 'numpy', 'scikit-learn'
]

SOFT_SKILLS = [
    'communication', 'leadership', 'teamwork', 'problem solving', 'critical thinking',
    'time management', 'adaptability', 'creativity', 'emotional intelligence',
    'conflict resolution', 'decision making', 'negotiation', 'presentation',
    'project management', 'agile', 'scrum', 'mentoring', 'collaboration'
]


# ============================================================================
# Data Classes
# ============================================================================

@dataclass
class EmbeddingResult:
    """Result of embedding generation."""
    vector: List[float]
    model: str
    tokens_used: int = 0
    success: bool = True
    error: Optional[str] = None


@dataclass
class ParsedResume:
    """Parsed resume content."""
    skills: List[str]
    experience_years: float
    education: List[Dict[str, str]]
    work_history: List[Dict[str, Any]]
    certifications: List[str]
    summary: str
    raw_text: str


@dataclass
class JobAnalysis:
    """Analyzed job description."""
    required_skills: List[str]
    preferred_skills: List[str]
    experience_range: Tuple[int, int]  # (min, max) years
    education_level: str
    is_remote: bool
    salary_range: Optional[Tuple[float, float]]
    key_responsibilities: List[str]
    company_values: List[str]


@dataclass
class BiasReport:
    """Bias detection report."""
    has_bias: bool
    bias_score: float  # 0-1, higher = more biased
    gender_bias: Dict[str, List[str]]
    age_bias: List[str]
    other_bias: List[str]
    suggestions: List[Dict[str, str]]


# ============================================================================
# Base Service Classes
# ============================================================================

class BaseAIService(ABC):
    """Base class for AI services with fallback support."""

    def __init__(self):
        self.is_available = True
        self.last_error = None

    @abstractmethod
    def execute(self, *args, **kwargs):
        """Execute the service operation."""
        pass

    def check_availability(self) -> bool:
        """Check if the AI service is available."""
        from .models import AIServiceStatus
        try:
            status = AIServiceStatus.objects.get(service_name=self.service_name)
            return status.is_available
        except AIServiceStatus.DoesNotExist:
            return True

    def record_success(self):
        """Record successful API call."""
        from .models import AIServiceStatus
        status, _ = AIServiceStatus.objects.get_or_create(
            service_name=self.service_name,
            defaults={'is_available': True}
        )
        status.record_success()

    def record_failure(self, error: str):
        """Record failed API call."""
        from .models import AIServiceStatus
        status, _ = AIServiceStatus.objects.get_or_create(
            service_name=self.service_name,
            defaults={'is_available': True}
        )
        status.record_failure(error)
        self.last_error = error


# ============================================================================
# Embedding Service
# ============================================================================

class EmbeddingService(BaseAIService):
    """
    Service for generating text embeddings.
    Supports OpenAI API with fallback to local models.
    """

    service_name = 'openai_embedding'

    def __init__(self):
        super().__init__()
        self.openai_client = None
        self._init_openai_client()

    def _init_openai_client(self):
        """Initialize OpenAI client if API key is available."""
        try:
            import openai
            api_key = getattr(settings, 'OPENAI_API_KEY', None)
            if api_key:
                self.openai_client = openai.OpenAI(api_key=api_key)
        except ImportError:
            logger.warning("OpenAI package not installed. Using fallback embedding.")
        except Exception as e:
            logger.error(f"Failed to initialize OpenAI client: {e}")

    def execute(self, text: str, model: str = None) -> EmbeddingResult:
        """
        Generate embedding for text.
        Falls back to local embedding if OpenAI is unavailable.
        """
        model = model or OPENAI_EMBEDDING_MODEL

        # Try OpenAI first
        if self.openai_client and self.check_availability():
            try:
                result = self._generate_openai_embedding(text, model)
                self.record_success()
                return result
            except Exception as e:
                logger.warning(f"OpenAI embedding failed: {e}. Using fallback.")
                self.record_failure(str(e))

        # Fallback to local embedding
        return self._generate_local_embedding(text)

    def _generate_openai_embedding(self, text: str, model: str) -> EmbeddingResult:
        """Generate embedding using OpenAI API."""
        response = self.openai_client.embeddings.create(
            input=text,
            model=model
        )
        return EmbeddingResult(
            vector=response.data[0].embedding,
            model=model,
            tokens_used=response.usage.total_tokens,
            success=True
        )

    def _generate_local_embedding(self, text: str) -> EmbeddingResult:
        """
        Generate embedding using local method (TF-IDF + hashing).
        This is a fallback when OpenAI is unavailable.
        """
        import hashlib
        import math

        # Simple hashing-based embedding for fallback
        words = text.lower().split()
        vector = [0.0] * EMBEDDING_DIMENSION

        for i, word in enumerate(words):
            # Hash the word to get consistent positions
            hash_obj = hashlib.md5(word.encode())
            hash_int = int(hash_obj.hexdigest(), 16)

            # Distribute word influence across multiple dimensions
            for j in range(min(10, EMBEDDING_DIMENSION)):
                pos = (hash_int + j * 7) % EMBEDDING_DIMENSION
                # Use TF-IDF-like weighting
                tf = words.count(word) / len(words) if words else 0
                idf = math.log(1 + 1 / (1 + words.count(word)))
                vector[pos] += tf * idf

        # Normalize vector
        magnitude = math.sqrt(sum(x * x for x in vector))
        if magnitude > 0:
            vector = [x / magnitude for x in vector]

        return EmbeddingResult(
            vector=vector,
            model='local_fallback',
            tokens_used=len(words),
            success=True
        )

    def batch_execute(self, texts: List[str], model: str = None) -> List[EmbeddingResult]:
        """Generate embeddings for multiple texts."""
        return [self.execute(text, model) for text in texts]


# ============================================================================
# Matching Service
# ============================================================================

class MatchingService:
    """
    Service for calculating match scores between candidates and jobs.
    Uses embeddings for semantic matching with rule-based fallback.
    """

    def __init__(self):
        self.embedding_service = EmbeddingService()

    def calculate_match(
        self,
        candidate_profile,
        job,
        use_ai: bool = True
    ) -> Dict[str, Any]:
        """
        Calculate match score between a candidate and a job.

        Returns:
            Dict with overall_score, component scores, and explanation
        """
        from .matching import CompositeScorer

        # Get or create embeddings
        candidate_embedding = self._get_candidate_embedding(candidate_profile)
        job_embedding = self._get_job_embedding(job)

        # Use AI-based matching if available
        if use_ai and candidate_embedding and job_embedding:
            return self._ai_match(
                candidate_profile, job,
                candidate_embedding, job_embedding
            )

        # Fallback to rule-based matching
        return self._rule_based_match(candidate_profile, job)

    def _get_candidate_embedding(self, candidate_profile):
        """Get or create candidate embedding."""
        from .models import CandidateEmbedding

        try:
            return candidate_profile.embedding
        except CandidateEmbedding.DoesNotExist:
            # Generate embedding on the fly
            return self._create_candidate_embedding(candidate_profile)

    def _get_job_embedding(self, job):
        """Get or create job embedding."""
        from .models import JobEmbedding

        try:
            return job.embedding
        except JobEmbedding.DoesNotExist:
            return self._create_job_embedding(job)

    def _create_candidate_embedding(self, candidate_profile):
        """Create embedding for candidate profile."""
        from .models import CandidateEmbedding

        # Build text representation of candidate
        text_parts = []

        # Add bio
        if candidate_profile.bio:
            text_parts.append(candidate_profile.bio)

        # Add skills
        skills = list(candidate_profile.skills.values_list('name', flat=True))
        if skills:
            text_parts.append(f"Skills: {', '.join(skills)}")

        # Add work experiences
        for exp in candidate_profile.work_experiences.all():
            text_parts.append(
                f"{exp.job_title} at {exp.company_name}: {exp.description}"
            )

        # Add education
        for edu in candidate_profile.educations.all():
            text_parts.append(
                f"{edu.degree} in {edu.field_of_study} from {edu.school_name}"
            )

        combined_text = " ".join(text_parts)
        embedding_result = self.embedding_service.execute(combined_text)

        if embedding_result.success:
            embedding = CandidateEmbedding.objects.create(
                candidate=candidate_profile,
                embedding_vector=embedding_result.vector,
                embedding_model=embedding_result.model,
                skills_extracted=skills
            )
            return embedding
        return None

    def _create_job_embedding(self, job):
        """Create embedding for job."""
        from .models import JobEmbedding

        # Build text representation of job
        text = f"{job.title} {job.description} {job.requirements}"
        embedding_result = self.embedding_service.execute(text)

        if embedding_result.success:
            # Extract skills from job description
            skills_extracted = self._extract_skills_from_text(
                f"{job.description} {job.requirements}"
            )

            embedding = JobEmbedding.objects.create(
                job=job,
                embedding_vector=embedding_result.vector,
                embedding_model=embedding_result.model,
                skills_extracted=skills_extracted
            )
            return embedding
        return None

    def _extract_skills_from_text(self, text: str) -> List[str]:
        """Extract skills from text using keyword matching."""
        text_lower = text.lower()
        found_skills = []

        for skill in TECH_SKILLS + SOFT_SKILLS:
            if skill in text_lower:
                found_skills.append(skill)

        return found_skills

    def _ai_match(
        self,
        candidate_profile,
        job,
        candidate_embedding,
        job_embedding
    ) -> Dict[str, Any]:
        """Calculate match using AI embeddings."""
        import math

        # Calculate cosine similarity
        def cosine_similarity(vec1, vec2):
            dot_product = sum(a * b for a, b in zip(vec1, vec2))
            magnitude1 = math.sqrt(sum(a * a for a in vec1))
            magnitude2 = math.sqrt(sum(b * b for b in vec2))
            if magnitude1 * magnitude2 == 0:
                return 0
            return dot_product / (magnitude1 * magnitude2)

        # Overall similarity from embeddings
        overall_similarity = cosine_similarity(
            candidate_embedding.embedding_vector,
            job_embedding.embedding_vector
        )

        # Calculate component scores
        skill_score = self._calculate_skill_score(
            candidate_embedding.skills_extracted or [],
            job_embedding.skills_extracted or []
        )

        # Combine with rule-based components
        from .matching import (
            ExperienceMatcher, LocationMatcher, SalaryMatcher
        )

        exp_matcher = ExperienceMatcher()
        exp_score = exp_matcher.score(candidate_profile, job)

        loc_matcher = LocationMatcher()
        loc_score = loc_matcher.score(candidate_profile, job)

        sal_matcher = SalaryMatcher()
        sal_score = sal_matcher.score(candidate_profile, job)

        # Weighted combination
        weights = {
            'embedding': 0.3,
            'skill': 0.25,
            'experience': 0.2,
            'location': 0.15,
            'salary': 0.1
        }

        overall_score = (
            weights['embedding'] * overall_similarity +
            weights['skill'] * skill_score +
            weights['experience'] * exp_score +
            weights['location'] * loc_score +
            weights['salary'] * sal_score
        )

        # Determine matched and missing skills
        candidate_skills = set(s.lower() for s in (candidate_embedding.skills_extracted or []))
        job_skills = set(s.lower() for s in (job_embedding.skills_extracted or []))
        matched = list(candidate_skills & job_skills)
        missing = list(job_skills - candidate_skills)

        return {
            'overall_score': round(overall_score, 4),
            'skill_score': round(skill_score, 4),
            'experience_score': round(exp_score, 4),
            'location_score': round(loc_score, 4),
            'salary_score': round(sal_score, 4),
            'matched_skills': matched,
            'missing_skills': missing,
            'algorithm': 'ai_embedding',
            'confidence': 'high' if overall_score > 0.7 else ('medium' if overall_score > 0.4 else 'low'),
            'explanation': {
                'embedding_similarity': round(overall_similarity, 4),
                'weights_used': weights,
                'total_job_skills': len(job_skills),
                'matched_skill_count': len(matched)
            }
        }

    def _rule_based_match(self, candidate_profile, job) -> Dict[str, Any]:
        """Calculate match using rule-based approach (fallback)."""
        from .matching import CompositeScorer

        scorer = CompositeScorer()
        result = scorer.score(candidate_profile, job)

        return {
            'overall_score': result['overall_score'],
            'skill_score': result.get('skill_score', 0),
            'experience_score': result.get('experience_score', 0),
            'location_score': result.get('location_score', 0),
            'salary_score': result.get('salary_score', 0),
            'matched_skills': result.get('matched_skills', []),
            'missing_skills': result.get('missing_skills', []),
            'algorithm': 'rule_based',
            'confidence': 'medium',
            'explanation': result.get('explanation', {})
        }

    def _calculate_skill_score(
        self,
        candidate_skills: List[str],
        job_skills: List[str]
    ) -> float:
        """Calculate skill overlap score."""
        if not job_skills:
            return 1.0  # No required skills means perfect match

        candidate_set = set(s.lower() for s in candidate_skills)
        job_set = set(s.lower() for s in job_skills)

        if not job_set:
            return 1.0

        matched = len(candidate_set & job_set)
        return matched / len(job_set)


# ============================================================================
# Recommendation Service
# ============================================================================

class RecommendationService:
    """
    Service for generating job and candidate recommendations.
    """

    def __init__(self):
        self.matching_service = MatchingService()

    def get_jobs_for_candidate(
        self,
        candidate_profile,
        limit: int = 20,
        filters: Dict = None
    ) -> List[Dict]:
        """
        Get recommended jobs for a candidate.

        Args:
            candidate_profile: CandidateProfile instance
            limit: Maximum number of recommendations
            filters: Optional filters (location, salary, etc.)

        Returns:
            List of recommended jobs with scores
        """
        from configurations.models import Job
        from .models import MatchingResult, RecommendationLog
        import time

        start_time = time.time()
        filters = filters or {}

        # Get active jobs
        jobs_qs = Job.objects.filter(is_active=True)

        # Apply filters
        if filters.get('location'):
            jobs_qs = jobs_qs.filter(
                position__site__city__icontains=filters['location']
            )
        if filters.get('min_salary'):
            jobs_qs = jobs_qs.filter(salary_from__gte=filters['min_salary'])

        # Calculate matches for all jobs
        recommendations = []
        for job in jobs_qs[:100]:  # Limit processing to 100 jobs
            # Check for cached result
            try:
                cached = MatchingResult.objects.get(
                    candidate=candidate_profile,
                    job=job,
                    is_stale=False
                )
                if not cached.is_expired:
                    recommendations.append({
                        'job': job,
                        'score': float(cached.overall_score),
                        'cached': True
                    })
                    continue
            except MatchingResult.DoesNotExist:
                pass

            # Calculate new match
            match_result = self.matching_service.calculate_match(
                candidate_profile, job
            )
            recommendations.append({
                'job': job,
                'score': match_result['overall_score'],
                'match_details': match_result,
                'cached': False
            })

        # Sort by score and limit
        recommendations.sort(key=lambda x: x['score'], reverse=True)
        recommendations = recommendations[:limit]

        # Log recommendation
        processing_time = int((time.time() - start_time) * 1000)
        RecommendationLog.objects.create(
            user=candidate_profile.user,
            recommendation_type='jobs_for_candidate',
            recommended_items=[r['job'].id for r in recommendations],
            recommendation_scores={
                str(r['job'].id): r['score'] for r in recommendations
            },
            context=filters,
            processing_time_ms=processing_time,
            fallback_used=any(
                r.get('match_details', {}).get('algorithm') == 'rule_based'
                for r in recommendations
            )
        )

        return recommendations

    def get_candidates_for_job(
        self,
        job,
        limit: int = 20,
        filters: Dict = None
    ) -> List[Dict]:
        """
        Get recommended candidates for a job posting.

        Args:
            job: Job instance
            limit: Maximum number of recommendations
            filters: Optional filters

        Returns:
            List of recommended candidates with scores
        """
        from configurations.models import CandidateProfile
        from .models import MatchingResult, RecommendationLog
        import time

        start_time = time.time()
        filters = filters or {}

        # Get candidates
        candidates_qs = CandidateProfile.objects.all()

        # Apply filters
        if filters.get('min_experience'):
            # Filter by experience if available in embedding
            pass

        recommendations = []
        for candidate in candidates_qs[:100]:
            # Check for cached result
            try:
                cached = MatchingResult.objects.get(
                    candidate=candidate,
                    job=job,
                    is_stale=False
                )
                if not cached.is_expired:
                    recommendations.append({
                        'candidate': candidate,
                        'score': float(cached.overall_score),
                        'cached': True
                    })
                    continue
            except MatchingResult.DoesNotExist:
                pass

            # Calculate new match
            match_result = self.matching_service.calculate_match(candidate, job)
            recommendations.append({
                'candidate': candidate,
                'score': match_result['overall_score'],
                'match_details': match_result,
                'cached': False
            })

        # Sort by score and limit
        recommendations.sort(key=lambda x: x['score'], reverse=True)
        recommendations = recommendations[:limit]

        # Log recommendation
        processing_time = int((time.time() - start_time) * 1000)
        RecommendationLog.objects.create(
            user_id=job.company.profile.memberships.first().user_id if hasattr(job.company, 'profile') else 1,
            recommendation_type='candidates_for_job',
            recommended_items=[r['candidate'].id for r in recommendations],
            recommendation_scores={
                str(r['candidate'].id): r['score'] for r in recommendations
            },
            context={'job_id': job.id, **filters},
            processing_time_ms=processing_time
        )

        return recommendations


# ============================================================================
# Resume Parser Service
# ============================================================================

class ResumeParserService(BaseAIService):
    """
    Service for parsing resumes and extracting structured information.
    """

    service_name = 'resume_parser'

    def execute(self, resume_text: str) -> ParsedResume:
        """
        Parse resume text and extract structured information.

        Args:
            resume_text: Plain text content of resume

        Returns:
            ParsedResume with extracted information
        """
        # Try AI-based parsing first
        if self.check_availability():
            try:
                result = self._ai_parse(resume_text)
                self.record_success()
                return result
            except Exception as e:
                logger.warning(f"AI resume parsing failed: {e}")
                self.record_failure(str(e))

        # Fallback to rule-based parsing
        return self._rule_based_parse(resume_text)

    def _ai_parse(self, resume_text: str) -> ParsedResume:
        """Parse resume using AI (OpenAI GPT)."""
        import openai
        import json

        api_key = getattr(settings, 'OPENAI_API_KEY', None)
        if not api_key:
            raise ValueError("OpenAI API key not configured")

        client = openai.OpenAI(api_key=api_key)

        prompt = """Extract structured information from this resume. Return a JSON object with:
- skills: list of technical and soft skills
- experience_years: total years of experience (number)
- education: list of {degree, field, school, year}
- work_history: list of {title, company, duration_years, responsibilities}
- certifications: list of certification names
- summary: brief professional summary

Resume:
"""

        response = client.chat.completions.create(
            model="gpt-3.5-turbo",
            messages=[
                {"role": "system", "content": "You are a resume parser. Extract structured information and return valid JSON."},
                {"role": "user", "content": prompt + resume_text}
            ],
            temperature=0.1
        )

        parsed = json.loads(response.choices[0].message.content)

        return ParsedResume(
            skills=parsed.get('skills', []),
            experience_years=float(parsed.get('experience_years', 0)),
            education=parsed.get('education', []),
            work_history=parsed.get('work_history', []),
            certifications=parsed.get('certifications', []),
            summary=parsed.get('summary', ''),
            raw_text=resume_text
        )

    def _rule_based_parse(self, resume_text: str) -> ParsedResume:
        """Parse resume using rule-based approach (fallback)."""
        text_lower = resume_text.lower()

        # Extract skills
        skills = []
        for skill in TECH_SKILLS + SOFT_SKILLS:
            if skill in text_lower:
                skills.append(skill)

        # Extract years of experience
        experience_years = 0.0
        year_patterns = [
            r'(\d+)\+?\s*years?\s*(?:of\s*)?experience',
            r'experience:\s*(\d+)\+?\s*years?',
            r'(\d+)\+?\s*years?\s*in\s*(?:the\s*)?(?:industry|field)'
        ]
        for pattern in year_patterns:
            match = re.search(pattern, text_lower)
            if match:
                experience_years = float(match.group(1))
                break

        # Extract education (basic pattern matching)
        education = []
        edu_patterns = [
            r"(bachelor'?s?|master'?s?|phd|doctorate|bs|ms|ba|ma|mba)\s*(?:in|of)?\s*([a-z\s]+)",
        ]
        for pattern in edu_patterns:
            matches = re.findall(pattern, text_lower)
            for degree, field in matches:
                education.append({
                    'degree': degree.strip(),
                    'field': field.strip(),
                    'school': '',
                    'year': ''
                })

        # Extract certifications
        certifications = []
        cert_keywords = ['certified', 'certification', 'certificate', 'credential']
        for line in resume_text.split('\n'):
            if any(kw in line.lower() for kw in cert_keywords):
                certifications.append(line.strip())

        # Generate summary (first 200 chars or first paragraph)
        summary = resume_text[:200].strip()
        if '\n\n' in resume_text:
            summary = resume_text.split('\n\n')[0].strip()

        return ParsedResume(
            skills=skills,
            experience_years=experience_years,
            education=education,
            work_history=[],
            certifications=certifications,
            summary=summary,
            raw_text=resume_text
        )


# ============================================================================
# Job Description Analyzer
# ============================================================================

class JobDescriptionAnalyzer(BaseAIService):
    """
    Service for analyzing job descriptions and extracting requirements.
    """

    service_name = 'openai_chat'

    def execute(self, job_description: str, job_title: str = '') -> JobAnalysis:
        """
        Analyze job description and extract structured requirements.

        Args:
            job_description: Full job description text
            job_title: Optional job title for context

        Returns:
            JobAnalysis with extracted requirements
        """
        if self.check_availability():
            try:
                result = self._ai_analyze(job_description, job_title)
                self.record_success()
                return result
            except Exception as e:
                logger.warning(f"AI job analysis failed: {e}")
                self.record_failure(str(e))

        return self._rule_based_analyze(job_description, job_title)

    def _ai_analyze(self, job_description: str, job_title: str) -> JobAnalysis:
        """Analyze job using AI."""
        import openai
        import json

        api_key = getattr(settings, 'OPENAI_API_KEY', None)
        if not api_key:
            raise ValueError("OpenAI API key not configured")

        client = openai.OpenAI(api_key=api_key)

        prompt = """Analyze this job posting and extract:
- required_skills: must-have skills
- preferred_skills: nice-to-have skills
- experience_min: minimum years required
- experience_max: maximum years (or same as min if not specified)
- education_level: required education (e.g., "Bachelor's", "Master's", "Any")
- is_remote: true/false
- salary_min: minimum salary if mentioned (null if not)
- salary_max: maximum salary if mentioned (null if not)
- key_responsibilities: main job duties
- company_values: any mentioned company values

Return valid JSON.

Job Title: {title}
Job Description: {description}
"""

        response = client.chat.completions.create(
            model="gpt-3.5-turbo",
            messages=[
                {"role": "system", "content": "You are a job posting analyzer. Extract structured requirements and return valid JSON."},
                {"role": "user", "content": prompt.format(title=job_title, description=job_description)}
            ],
            temperature=0.1
        )

        parsed = json.loads(response.choices[0].message.content)

        salary_range = None
        if parsed.get('salary_min') and parsed.get('salary_max'):
            salary_range = (float(parsed['salary_min']), float(parsed['salary_max']))

        return JobAnalysis(
            required_skills=parsed.get('required_skills', []),
            preferred_skills=parsed.get('preferred_skills', []),
            experience_range=(
                int(parsed.get('experience_min', 0)),
                int(parsed.get('experience_max', parsed.get('experience_min', 0)))
            ),
            education_level=parsed.get('education_level', 'Any'),
            is_remote=parsed.get('is_remote', False),
            salary_range=salary_range,
            key_responsibilities=parsed.get('key_responsibilities', []),
            company_values=parsed.get('company_values', [])
        )

    def _rule_based_analyze(self, job_description: str, job_title: str) -> JobAnalysis:
        """Analyze job using rule-based approach."""
        text_lower = job_description.lower()

        # Extract skills
        required_skills = []
        preferred_skills = []

        for skill in TECH_SKILLS + SOFT_SKILLS:
            if skill in text_lower:
                # Check if it's in a "required" context
                if any(kw in text_lower for kw in ['must have', 'required', 'essential']):
                    required_skills.append(skill)
                else:
                    preferred_skills.append(skill)

        # Extract experience range
        exp_min, exp_max = 0, 0
        exp_patterns = [
            r'(\d+)-(\d+)\s*years?\s*(?:of\s*)?experience',
            r'(\d+)\+?\s*years?\s*(?:of\s*)?experience',
            r'minimum\s*(\d+)\s*years?'
        ]
        for pattern in exp_patterns:
            match = re.search(pattern, text_lower)
            if match:
                groups = match.groups()
                exp_min = int(groups[0])
                exp_max = int(groups[1]) if len(groups) > 1 and groups[1] else exp_min
                break

        # Check for remote
        is_remote = any(term in text_lower for term in ['remote', 'work from home', 'wfh', 'distributed team'])

        # Extract education
        education_level = 'Any'
        if "master's" in text_lower or 'ms ' in text_lower or 'ma ' in text_lower:
            education_level = "Master's"
        elif "bachelor's" in text_lower or 'bs ' in text_lower or 'ba ' in text_lower:
            education_level = "Bachelor's"
        elif 'phd' in text_lower or 'doctorate' in text_lower:
            education_level = "PhD"

        # Extract salary range
        salary_range = None
        salary_pattern = r'\$(\d{2,3}),?(\d{3})?\s*[-to]+\s*\$?(\d{2,3}),?(\d{3})?'
        match = re.search(salary_pattern, job_description)
        if match:
            groups = match.groups()
            try:
                min_sal = int(groups[0] + (groups[1] or '000'))
                max_sal = int(groups[2] + (groups[3] or '000'))
                salary_range = (float(min_sal), float(max_sal))
            except (ValueError, TypeError):
                pass

        return JobAnalysis(
            required_skills=required_skills,
            preferred_skills=preferred_skills,
            experience_range=(exp_min, exp_max),
            education_level=education_level,
            is_remote=is_remote,
            salary_range=salary_range,
            key_responsibilities=[],
            company_values=[]
        )


# ============================================================================
# Bias Detection Service
# ============================================================================

class BiasDetectionService(BaseAIService):
    """
    Service for detecting bias in job postings.
    """

    service_name = 'openai_chat'

    def execute(self, text: str, content_type: str = 'job_posting') -> BiasReport:
        """
        Check text for potential bias.

        Args:
            text: Text to analyze
            content_type: Type of content being analyzed

        Returns:
            BiasReport with findings and suggestions
        """
        # Always run rule-based check (fast)
        rule_result = self._rule_based_check(text)

        # Optionally enhance with AI
        if self.check_availability() and rule_result.has_bias:
            try:
                ai_result = self._ai_check(text)
                self.record_success()
                # Merge results
                return self._merge_results(rule_result, ai_result)
            except Exception as e:
                logger.warning(f"AI bias check failed: {e}")
                self.record_failure(str(e))

        return rule_result

    def _rule_based_check(self, text: str) -> BiasReport:
        """Check for bias using keyword matching."""
        text_lower = text.lower()

        gender_bias = {'male_coded': [], 'female_coded': []}
        for term in GENDER_BIASED_TERMS['male_coded']:
            if term in text_lower:
                gender_bias['male_coded'].append(term)
        for term in GENDER_BIASED_TERMS['female_coded']:
            if term in text_lower:
                gender_bias['female_coded'].append(term)

        age_bias = []
        for term in AGE_BIASED_TERMS:
            if term in text_lower:
                age_bias.append(term)

        # Calculate bias score
        male_count = len(gender_bias['male_coded'])
        female_count = len(gender_bias['female_coded'])
        age_count = len(age_bias)

        # Gender imbalance contributes to bias score
        gender_imbalance = abs(male_count - female_count) / max(male_count + female_count, 1)
        bias_score = min(1.0, (gender_imbalance * 0.5 + age_count * 0.1))

        has_bias = bias_score > 0.2

        # Generate suggestions
        suggestions = []
        if male_count > female_count:
            suggestions.append({
                'issue': 'Male-coded language',
                'suggestion': 'Consider using more neutral terms. Replace "aggressive" with "proactive", "ninja" with "expert".'
            })
        if age_bias:
            suggestions.append({
                'issue': 'Age-related terms',
                'suggestion': 'Remove age-specific language. Focus on skills and experience level instead of "young" or "fresh graduate".'
            })

        return BiasReport(
            has_bias=has_bias,
            bias_score=round(bias_score, 4),
            gender_bias=gender_bias,
            age_bias=age_bias,
            other_bias=[],
            suggestions=suggestions
        )

    def _ai_check(self, text: str) -> BiasReport:
        """Check for bias using AI."""
        import openai
        import json

        api_key = getattr(settings, 'OPENAI_API_KEY', None)
        if not api_key:
            raise ValueError("OpenAI API key not configured")

        client = openai.OpenAI(api_key=api_key)

        prompt = """Analyze this job posting for potential bias (gender, age, racial, disability, etc.).
Return JSON with:
- has_bias: true/false
- bias_score: 0-1 (higher = more biased)
- gender_bias: {male_coded: [...terms], female_coded: [...terms]}
- age_bias: [...terms]
- other_bias: [...terms]
- suggestions: [{issue: "...", suggestion: "..."}, ...]

Job Posting:
"""

        response = client.chat.completions.create(
            model="gpt-3.5-turbo",
            messages=[
                {"role": "system", "content": "You are an expert in workplace diversity and bias detection."},
                {"role": "user", "content": prompt + text}
            ],
            temperature=0.1
        )

        parsed = json.loads(response.choices[0].message.content)

        return BiasReport(
            has_bias=parsed.get('has_bias', False),
            bias_score=float(parsed.get('bias_score', 0)),
            gender_bias=parsed.get('gender_bias', {'male_coded': [], 'female_coded': []}),
            age_bias=parsed.get('age_bias', []),
            other_bias=parsed.get('other_bias', []),
            suggestions=parsed.get('suggestions', [])
        )

    def _merge_results(self, rule_result: BiasReport, ai_result: BiasReport) -> BiasReport:
        """Merge rule-based and AI results."""
        # Combine findings
        gender_bias = {
            'male_coded': list(set(
                rule_result.gender_bias['male_coded'] +
                ai_result.gender_bias['male_coded']
            )),
            'female_coded': list(set(
                rule_result.gender_bias['female_coded'] +
                ai_result.gender_bias['female_coded']
            ))
        }

        return BiasReport(
            has_bias=rule_result.has_bias or ai_result.has_bias,
            bias_score=max(rule_result.bias_score, ai_result.bias_score),
            gender_bias=gender_bias,
            age_bias=list(set(rule_result.age_bias + ai_result.age_bias)),
            other_bias=ai_result.other_bias,
            suggestions=rule_result.suggestions + ai_result.suggestions
        )

    def log_audit(
        self,
        content_id: int,
        content_type: str,
        report: BiasReport,
        user=None
    ):
        """Log bias check results for audit."""
        from .models import BiasAuditLog

        BiasAuditLog.objects.create(
            content_type=content_type,
            content_id=content_id,
            bias_detected=report.has_bias,
            bias_types=list(report.gender_bias.keys()) + (['age'] if report.age_bias else []),
            bias_score=Decimal(str(report.bias_score)),
            flagged_phrases={
                'gender': report.gender_bias,
                'age': report.age_bias,
                'other': report.other_bias
            },
            suggestions=report.suggestions,
            auditor=user,
            automated=user is None
        )


# ============================================================================
# ENHANCED SERVICES FOR CYCLE 7
# ============================================================================

# Constants for sentence-transformers
SENTENCE_TRANSFORMER_MODEL = 'all-MiniLM-L6-v2'
SENTENCE_TRANSFORMER_DIMENSION = 384


@dataclass
class NormalizedSkill:
    """Normalized skill with metadata."""
    canonical_name: str
    display_name: str
    category: str
    weight: float
    is_required: bool = False
    related_skills: List[str] = None

    def __post_init__(self):
        if self.related_skills is None:
            self.related_skills = []


@dataclass
class MatchExplanation:
    """Detailed explanation of a match."""
    summary: str
    strengths: List[str]
    gaps: List[str]
    recommendations: List[str]
    score_breakdown: Dict[str, float]


# ============================================================================
# Sentence Transformer Embedding Service
# ============================================================================

class SentenceTransformerEmbeddingService(BaseAIService):
    """
    Service for generating embeddings using sentence-transformers.

    Uses all-MiniLM-L6-v2 by default for a good balance of speed and quality.
    384-dimensional embeddings, much smaller than OpenAI's 1536.
    """

    service_name = 'local_embedding'

    def __init__(self, model_name: str = None):
        super().__init__()
        self.model_name = model_name or SENTENCE_TRANSFORMER_MODEL
        self.model = None
        self._init_model()

    def _init_model(self):
        """Initialize the sentence transformer model."""
        try:
            from sentence_transformers import SentenceTransformer
            self.model = SentenceTransformer(self.model_name)
            logger.info(f"Loaded sentence-transformer model: {self.model_name}")
        except ImportError:
            logger.warning(
                "sentence-transformers not installed. "
                "Install with: pip install sentence-transformers"
            )
        except Exception as e:
            logger.error(f"Failed to load sentence-transformer: {e}")

    def execute(self, text: str) -> EmbeddingResult:
        """
        Generate embedding for text using sentence-transformers.

        Args:
            text: Text to embed

        Returns:
            EmbeddingResult with 384-dimensional vector
        """
        if not self.model:
            return self._fallback_embedding(text)

        try:
            # Generate embedding
            embedding = self.model.encode(text, convert_to_numpy=True)

            self.record_success()
            return EmbeddingResult(
                vector=embedding.tolist(),
                model=self.model_name,
                tokens_used=len(text.split()),
                success=True
            )
        except Exception as e:
            logger.error(f"Sentence-transformer embedding failed: {e}")
            self.record_failure(str(e))
            return self._fallback_embedding(text)

    def batch_execute(self, texts: List[str]) -> List[EmbeddingResult]:
        """
        Generate embeddings for multiple texts efficiently.

        Batching is more efficient with sentence-transformers.
        """
        if not self.model:
            return [self._fallback_embedding(text) for text in texts]

        try:
            embeddings = self.model.encode(texts, convert_to_numpy=True)

            results = []
            for text, embedding in zip(texts, embeddings):
                results.append(EmbeddingResult(
                    vector=embedding.tolist(),
                    model=self.model_name,
                    tokens_used=len(text.split()),
                    success=True
                ))

            self.record_success()
            return results
        except Exception as e:
            logger.error(f"Batch embedding failed: {e}")
            self.record_failure(str(e))
            return [self._fallback_embedding(text) for text in texts]

    def _fallback_embedding(self, text: str) -> EmbeddingResult:
        """Generate fallback embedding using hash-based method."""
        import hashlib
        import math

        words = text.lower().split()
        vector = [0.0] * SENTENCE_TRANSFORMER_DIMENSION

        for i, word in enumerate(words):
            hash_obj = hashlib.md5(word.encode())
            hash_int = int(hash_obj.hexdigest(), 16)

            for j in range(min(10, SENTENCE_TRANSFORMER_DIMENSION)):
                pos = (hash_int + j * 7) % SENTENCE_TRANSFORMER_DIMENSION
                tf = words.count(word) / len(words) if words else 0
                idf = math.log(1 + 1 / (1 + words.count(word)))
                vector[pos] += tf * idf

        # Normalize
        magnitude = math.sqrt(sum(x * x for x in vector))
        if magnitude > 0:
            vector = [x / magnitude for x in vector]

        return EmbeddingResult(
            vector=vector,
            model='hash_fallback',
            tokens_used=len(words),
            success=True
        )

    @staticmethod
    def compute_similarity(embedding1: List[float], embedding2: List[float]) -> float:
        """
        Compute cosine similarity between two embeddings.

        Args:
            embedding1: First embedding vector
            embedding2: Second embedding vector

        Returns:
            Cosine similarity score (-1 to 1)
        """
        import math

        if len(embedding1) != len(embedding2):
            raise ValueError("Embedding dimensions must match")

        dot_product = sum(a * b for a, b in zip(embedding1, embedding2))
        magnitude1 = math.sqrt(sum(a * a for a in embedding1))
        magnitude2 = math.sqrt(sum(b * b for b in embedding2))

        if magnitude1 * magnitude2 == 0:
            return 0.0

        return dot_product / (magnitude1 * magnitude2)


# ============================================================================
# Skill Normalization Service
# ============================================================================

class SkillNormalizationService:
    """
    Service for normalizing and standardizing skills.

    Provides:
    - Skill name normalization to canonical forms
    - Related skill discovery
    - Skill similarity computation
    - Hierarchical skill taxonomy navigation
    """

    # Hierarchical skill taxonomy
    SKILL_TAXONOMY = {
        'programming': {
            'python': {
                'aliases': ['python3', 'py', 'python 3'],
                'related': ['django', 'flask', 'fastapi', 'pandas', 'numpy'],
                'category': 'programming',
                'subcategory': 'languages',
            },
            'javascript': {
                'aliases': ['js', 'ecmascript', 'es6', 'es2015'],
                'related': ['typescript', 'node.js', 'react', 'angular', 'vue'],
                'category': 'programming',
                'subcategory': 'languages',
            },
            'java': {
                'aliases': ['java8', 'java11', 'java17'],
                'related': ['spring', 'spring boot', 'maven', 'gradle', 'jvm'],
                'category': 'programming',
                'subcategory': 'languages',
            },
            'typescript': {
                'aliases': ['ts'],
                'related': ['javascript', 'angular', 'react', 'node.js'],
                'category': 'programming',
                'subcategory': 'languages',
            },
            'sql': {
                'aliases': ['structured query language'],
                'related': ['postgresql', 'mysql', 'sqlite', 'oracle', 'sql server'],
                'category': 'programming',
                'subcategory': 'query_languages',
            },
        },
        'frameworks': {
            'django': {
                'aliases': ['django framework', 'django python'],
                'related': ['python', 'drf', 'celery', 'postgresql'],
                'category': 'frameworks',
                'subcategory': 'web',
            },
            'react': {
                'aliases': ['reactjs', 'react.js', 'react js'],
                'related': ['javascript', 'redux', 'next.js', 'typescript'],
                'category': 'frameworks',
                'subcategory': 'frontend',
            },
            'angular': {
                'aliases': ['angularjs', 'angular.js'],
                'related': ['typescript', 'rxjs', 'ngrx'],
                'category': 'frameworks',
                'subcategory': 'frontend',
            },
            'spring': {
                'aliases': ['spring framework', 'spring boot', 'springboot'],
                'related': ['java', 'maven', 'hibernate', 'jpa'],
                'category': 'frameworks',
                'subcategory': 'backend',
            },
        },
        'cloud': {
            'aws': {
                'aliases': ['amazon web services', 'amazon aws'],
                'related': ['ec2', 's3', 'lambda', 'rds', 'cloudformation'],
                'category': 'cloud',
                'subcategory': 'platforms',
            },
            'azure': {
                'aliases': ['microsoft azure', 'azure cloud'],
                'related': ['azure devops', 'azure functions', 'cosmos db'],
                'category': 'cloud',
                'subcategory': 'platforms',
            },
            'gcp': {
                'aliases': ['google cloud', 'google cloud platform'],
                'related': ['bigquery', 'cloud functions', 'gke'],
                'category': 'cloud',
                'subcategory': 'platforms',
            },
            'docker': {
                'aliases': ['docker container', 'containerization'],
                'related': ['kubernetes', 'docker-compose', 'container'],
                'category': 'cloud',
                'subcategory': 'containers',
            },
            'kubernetes': {
                'aliases': ['k8s', 'kube'],
                'related': ['docker', 'helm', 'istio', 'container orchestration'],
                'category': 'cloud',
                'subcategory': 'orchestration',
            },
        },
        'data': {
            'machine learning': {
                'aliases': ['ml', 'machine-learning'],
                'related': ['deep learning', 'tensorflow', 'pytorch', 'scikit-learn'],
                'category': 'data',
                'subcategory': 'ai_ml',
            },
            'data science': {
                'aliases': ['data scientist skills', 'ds'],
                'related': ['python', 'pandas', 'numpy', 'machine learning', 'statistics'],
                'category': 'data',
                'subcategory': 'analytics',
            },
            'sql': {
                'aliases': ['structured query language', 'sql queries'],
                'related': ['postgresql', 'mysql', 'database', 'data modeling'],
                'category': 'data',
                'subcategory': 'databases',
            },
        },
        'soft_skills': {
            'communication': {
                'aliases': ['communication skills', 'verbal communication', 'written communication'],
                'related': ['presentation', 'public speaking', 'writing'],
                'category': 'soft_skills',
                'subcategory': 'interpersonal',
            },
            'leadership': {
                'aliases': ['team leadership', 'people management', 'leader'],
                'related': ['management', 'mentoring', 'team building'],
                'category': 'soft_skills',
                'subcategory': 'management',
            },
            'problem solving': {
                'aliases': ['problem-solving', 'analytical thinking', 'troubleshooting'],
                'related': ['critical thinking', 'analytical skills', 'debugging'],
                'category': 'soft_skills',
                'subcategory': 'cognitive',
            },
        },
    }

    def __init__(self):
        self._build_skill_index()
        self.embedding_service = None
        self._skill_embeddings_cache = {}

    def _build_skill_index(self):
        """Build a flat index for fast skill lookup."""
        self._skill_index = {}

        for category, skills in self.SKILL_TAXONOMY.items():
            for skill_name, skill_data in skills.items():
                # Add canonical name
                self._skill_index[skill_name.lower()] = {
                    'canonical': skill_name,
                    **skill_data
                }

                # Add aliases
                for alias in skill_data.get('aliases', []):
                    self._skill_index[alias.lower()] = {
                        'canonical': skill_name,
                        **skill_data
                    }

    def normalize_skill(self, skill: str) -> Optional[NormalizedSkill]:
        """
        Normalize a skill name to its canonical form.

        Args:
            skill: Raw skill name

        Returns:
            NormalizedSkill if found, None otherwise
        """
        skill_lower = skill.lower().strip()

        # Direct lookup
        if skill_lower in self._skill_index:
            data = self._skill_index[skill_lower]
            return NormalizedSkill(
                canonical_name=data['canonical'],
                display_name=data['canonical'].title(),
                category=data.get('category', 'other'),
                weight=1.0,
                related_skills=data.get('related', [])
            )

        # Try database lookup
        try:
            from .models import SkillTaxonomy
            taxonomy_skill = SkillTaxonomy.normalize_skill(skill)
            if taxonomy_skill:
                return NormalizedSkill(
                    canonical_name=taxonomy_skill.canonical_name,
                    display_name=taxonomy_skill.display_name,
                    category=taxonomy_skill.category,
                    weight=taxonomy_skill.popularity_score,
                    related_skills=list(
                        taxonomy_skill.related_skills.values_list('canonical_name', flat=True)
                    )
                )
        except Exception:
            pass

        # Return as-is if not found
        return NormalizedSkill(
            canonical_name=skill_lower,
            display_name=skill.title(),
            category='unknown',
            weight=0.5,
            related_skills=[]
        )

    def get_related_skills(self, skill: str) -> List[str]:
        """
        Get skills related to the given skill.

        Args:
            skill: Skill name

        Returns:
            List of related skill names
        """
        normalized = self.normalize_skill(skill)
        if normalized:
            return normalized.related_skills
        return []

    def compute_skill_similarity(self, skill1: str, skill2: str) -> float:
        """
        Compute similarity between two skills.

        Uses both taxonomy relationships and embedding similarity.

        Args:
            skill1: First skill name
            skill2: Second skill name

        Returns:
            Similarity score (0-1)
        """
        # Normalize both skills
        norm1 = self.normalize_skill(skill1)
        norm2 = self.normalize_skill(skill2)

        if not norm1 or not norm2:
            return 0.0

        # Exact match
        if norm1.canonical_name == norm2.canonical_name:
            return 1.0

        # Check if one is related to the other
        if (norm2.canonical_name in norm1.related_skills or
                norm1.canonical_name in norm2.related_skills):
            return 0.8

        # Same category bonus
        category_bonus = 0.2 if norm1.category == norm2.category else 0.0

        # Try embedding similarity if available
        try:
            if self.embedding_service is None:
                self.embedding_service = SentenceTransformerEmbeddingService()

            # Get or compute embeddings
            emb1 = self._get_skill_embedding(norm1.canonical_name)
            emb2 = self._get_skill_embedding(norm2.canonical_name)

            if emb1 and emb2:
                embedding_sim = SentenceTransformerEmbeddingService.compute_similarity(
                    emb1, emb2
                )
                return min(1.0, max(0.0, embedding_sim + category_bonus))
        except Exception:
            pass

        return category_bonus

    def _get_skill_embedding(self, skill: str) -> Optional[List[float]]:
        """Get or compute embedding for a skill."""
        if skill in self._skill_embeddings_cache:
            return self._skill_embeddings_cache[skill]

        if self.embedding_service:
            result = self.embedding_service.execute(skill)
            if result.success:
                self._skill_embeddings_cache[skill] = result.vector
                return result.vector

        return None

    def normalize_skill_list(
        self,
        skills: List[str],
        with_weights: bool = True
    ) -> Dict[str, Dict]:
        """
        Normalize a list of skills and compute weights.

        Args:
            skills: List of raw skill names
            with_weights: Whether to compute skill weights

        Returns:
            Dict mapping skill IDs to normalized skill data
        """
        normalized = {}

        for i, skill in enumerate(skills):
            norm = self.normalize_skill(skill)
            if norm:
                # Use canonical name as key
                key = norm.canonical_name.lower().replace(' ', '_')

                # Weight decreases based on position (first skills more important)
                position_weight = 1.0 - (i * 0.02)  # Reduce by 2% per position

                normalized[key] = {
                    'name': norm.display_name,
                    'canonical': norm.canonical_name,
                    'category': norm.category,
                    'weight': norm.weight * position_weight if with_weights else 1.0,
                    'related': norm.related_skills[:5],  # Top 5 related
                }

        return normalized


# ============================================================================
# Enhanced Candidate Matching Service
# ============================================================================

class CandidateMatchingService:
    """
    AI-powered candidate matching service.

    Provides sophisticated matching between candidates and jobs using:
    - Sentence-transformer embeddings
    - Skill normalization and semantic matching
    - Multi-factor scoring with configurable weights
    - Explainable AI outputs
    """

    def __init__(self):
        self.embedding_service = SentenceTransformerEmbeddingService()
        self.skill_service = SkillNormalizationService()

    def match_candidate_to_job(
        self,
        candidate,
        job,
        weights: Dict[str, float] = None
    ) -> 'MatchResult':
        """
        Match a single candidate to a job.

        Args:
            candidate: Candidate instance
            job: JobPosting instance
            weights: Optional custom weights for scoring components

        Returns:
            MatchResult with scores and explanation
        """
        import time
        from .models import MatchResult, MatchingProfile, JobMatchingProfile

        start_time = time.time()

        # Default weights
        default_weights = {
            'skills': 0.35,
            'experience': 0.20,
            'education': 0.10,
            'cultural_fit': 0.15,
            'location': 0.10,
            'salary': 0.10,
        }
        weights = weights or default_weights

        # Get or create matching profiles
        candidate_profile = self._get_or_create_candidate_profile(candidate)
        job_profile = self._get_or_create_job_profile(job)

        # Use job-specific weights if available
        if job_profile and job_profile.skills_weight:
            weights = {
                'skills': job_profile.skills_weight,
                'experience': job_profile.experience_weight,
                'education': job_profile.education_weight,
                'cultural_fit': job_profile.cultural_fit_weight,
                'location': job_profile.location_weight,
                'salary': job_profile.salary_weight,
            }

        # Calculate component scores
        skill_result = self._calculate_skill_score(candidate_profile, job_profile)
        experience_score = self._calculate_experience_score(candidate_profile, job_profile)
        education_score = self._calculate_education_score(candidate_profile, job_profile)
        cultural_score = self._calculate_cultural_fit_score(candidate_profile, job_profile)
        location_score = self._calculate_location_score(candidate, job)
        salary_score = self._calculate_salary_score(candidate, job)

        # Calculate embedding similarity
        embedding_similarity = None
        if (candidate_profile and candidate_profile.embedding and
                job_profile and job_profile.embedding):
            embedding_similarity = SentenceTransformerEmbeddingService.compute_similarity(
                candidate_profile.embedding,
                job_profile.embedding
            )

        # Calculate weighted overall score
        overall_score = (
            weights['skills'] * skill_result['score'] +
            weights['experience'] * experience_score +
            weights['education'] * education_score +
            weights['cultural_fit'] * cultural_score +
            weights['location'] * location_score +
            weights['salary'] * salary_score
        )

        # Determine confidence level
        if overall_score >= 0.7 and embedding_similarity and embedding_similarity > 0.5:
            confidence = 'high'
        elif overall_score >= 0.4:
            confidence = 'medium'
        else:
            confidence = 'low'

        # Generate explanation
        explanation = self._generate_explanation(
            candidate, job,
            skill_result, experience_score, education_score,
            cultural_score, location_score, salary_score,
            overall_score, weights
        )

        # Compute time
        computation_time_ms = int((time.time() - start_time) * 1000)

        # Create or update MatchResult
        from .models import MatchResult as MatchResultModel, AIModelVersion

        # Get active model version
        model_version = AIModelVersion.get_active_version('skill_matcher')
        version_str = model_version.version if model_version else '1.0.0'

        match_result, _ = MatchResultModel.objects.update_or_create(
            tenant=candidate.tenant if hasattr(candidate, 'tenant') else None,
            candidate=candidate,
            job=job,
            defaults={
                'overall_score': overall_score,
                'skill_match_score': skill_result['score'],
                'experience_match_score': experience_score,
                'education_match_score': education_score,
                'cultural_fit_score': cultural_score,
                'location_match_score': location_score,
                'salary_match_score': salary_score,
                'embedding_similarity': embedding_similarity,
                'matched_skills': skill_result.get('matched', []),
                'missing_skills': skill_result.get('missing', []),
                'bonus_skills': skill_result.get('bonus', []),
                'explanation': explanation.__dict__,
                'confidence_level': confidence,
                'algorithm_used': 'hybrid',
                'model_version': version_str,
                'computation_time_ms': computation_time_ms,
                'is_stale': False,
            }
        )

        return match_result

    def match_candidates_to_job(
        self,
        job,
        limit: int = 100,
        min_score: float = 0.0,
        filters: Dict = None
    ) -> List['MatchResult']:
        """
        Match all candidates to a job and return top matches.

        Args:
            job: JobPosting instance
            limit: Maximum number of candidates to return
            min_score: Minimum score threshold
            filters: Optional filters

        Returns:
            List of MatchResult instances sorted by score
        """
        from jobs.models import Candidate
        from .models import MatchResult

        filters = filters or {}

        # Get candidates
        candidates_qs = Candidate.objects.all()

        # Apply filters
        if filters.get('location'):
            candidates_qs = candidates_qs.filter(
                location__icontains=filters['location']
            )
        if filters.get('min_experience'):
            candidates_qs = candidates_qs.filter(
                years_of_experience__gte=filters['min_experience']
            )

        results = []
        for candidate in candidates_qs[:500]:  # Process up to 500
            # Check for cached non-stale result
            try:
                cached = MatchResult.objects.get(
                    candidate=candidate,
                    job=job,
                    is_stale=False
                )
                if not cached.is_expired and cached.overall_score >= min_score:
                    results.append(cached)
                    continue
            except MatchResult.DoesNotExist:
                pass

            # Calculate new match
            match_result = self.match_candidate_to_job(candidate, job)
            if match_result.overall_score >= min_score:
                results.append(match_result)

        # Sort by score and limit
        results.sort(key=lambda x: x.overall_score, reverse=True)
        return results[:limit]

    def match_jobs_to_candidate(
        self,
        candidate,
        limit: int = 50,
        min_score: float = 0.0,
        filters: Dict = None
    ) -> List['MatchResult']:
        """
        Match all jobs to a candidate and return top matches.

        Args:
            candidate: Candidate instance
            limit: Maximum number of jobs to return
            min_score: Minimum score threshold
            filters: Optional filters

        Returns:
            List of MatchResult instances sorted by score
        """
        from jobs.models import JobPosting
        from .models import MatchResult

        filters = filters or {}

        # Get active jobs
        jobs_qs = JobPosting.objects.filter(status='open')

        # Apply filters
        if filters.get('location'):
            jobs_qs = jobs_qs.filter(location__icontains=filters['location'])
        if filters.get('remote_only'):
            jobs_qs = jobs_qs.filter(is_remote=True)

        results = []
        for job in jobs_qs[:500]:
            try:
                cached = MatchResult.objects.get(
                    candidate=candidate,
                    job=job,
                    is_stale=False
                )
                if not cached.is_expired and cached.overall_score >= min_score:
                    results.append(cached)
                    continue
            except MatchResult.DoesNotExist:
                pass

            match_result = self.match_candidate_to_job(candidate, job)
            if match_result.overall_score >= min_score:
                results.append(match_result)

        results.sort(key=lambda x: x.overall_score, reverse=True)
        return results[:limit]

    def explain_match(self, match_result) -> str:
        """
        Generate a human-readable explanation of a match.

        Args:
            match_result: MatchResult instance

        Returns:
            Formatted explanation string
        """
        return match_result.generate_explanation_text()

    def rerank_candidates(
        self,
        job,
        candidates: List,
        preferences: Dict
    ) -> List:
        """
        Re-rank candidates based on recruiter preferences.

        Args:
            job: JobPosting instance
            candidates: List of candidates to rerank
            preferences: Dict of preferences (e.g., prioritize_skills, must_have_skills)

        Returns:
            Re-ranked list of candidates
        """
        from .models import MatchResult

        # Get match results
        results = []
        for candidate in candidates:
            try:
                match = MatchResult.objects.get(candidate=candidate, job=job)
            except MatchResult.DoesNotExist:
                match = self.match_candidate_to_job(candidate, job)
            results.append((candidate, match))

        # Apply preference adjustments
        for candidate, match in results:
            adjustment = 0.0

            # Check must-have skills
            if preferences.get('must_have_skills'):
                must_have = set(s.lower() for s in preferences['must_have_skills'])
                matched = set(s.lower() for s in match.matched_skills)
                if not must_have.issubset(matched):
                    adjustment -= 0.3  # Significant penalty

            # Boost for specific skill matches
            if preferences.get('prioritize_skills'):
                priority = set(s.lower() for s in preferences['prioritize_skills'])
                matched = set(s.lower() for s in match.matched_skills)
                overlap = len(priority & matched) / len(priority) if priority else 0
                adjustment += overlap * 0.2

            # Adjust score (stored as attribute for sorting)
            candidate._adjusted_score = match.overall_score + adjustment

        # Sort by adjusted score
        results.sort(key=lambda x: x[0]._adjusted_score, reverse=True)
        return [candidate for candidate, _ in results]

    def _get_or_create_candidate_profile(self, candidate) -> Optional['MatchingProfile']:
        """Get or create matching profile for candidate."""
        from .models import MatchingProfile

        try:
            return candidate.matching_profile
        except MatchingProfile.DoesNotExist:
            # Create new profile
            return self._create_candidate_profile(candidate)

    def _get_or_create_job_profile(self, job) -> Optional['JobMatchingProfile']:
        """Get or create matching profile for job."""
        from .models import JobMatchingProfile

        try:
            return job.matching_profile
        except JobMatchingProfile.DoesNotExist:
            return self._create_job_profile(job)

    def _create_candidate_profile(self, candidate) -> 'MatchingProfile':
        """Create a new matching profile for a candidate."""
        from .models import MatchingProfile

        # Build text for embedding
        text_parts = []

        if hasattr(candidate, 'resume_text') and candidate.resume_text:
            text_parts.append(candidate.resume_text)

        if hasattr(candidate, 'skills'):
            skills = list(candidate.skills.values_list('name', flat=True))
            text_parts.append(' '.join(skills))

        if hasattr(candidate, 'summary') and candidate.summary:
            text_parts.append(candidate.summary)

        combined_text = ' '.join(text_parts) or candidate.name

        # Generate embedding
        embedding_result = self.embedding_service.execute(combined_text)

        # Normalize skills
        skills_list = list(candidate.skills.values_list('name', flat=True)) if hasattr(candidate, 'skills') else []
        normalized_skills = self.skill_service.normalize_skill_list(skills_list)

        # Calculate scores
        experience_score = self._compute_experience_score_value(candidate)
        education_score = self._compute_education_score_value(candidate)

        profile = MatchingProfile.objects.create(
            tenant=candidate.tenant if hasattr(candidate, 'tenant') else None,
            candidate=candidate,
            embedding=embedding_result.vector if embedding_result.success else None,
            skills_normalized=normalized_skills,
            experience_score=experience_score,
            education_score=education_score,
            overall_quality_score=(experience_score + education_score) / 2,
            processing_status='completed',
            processing_version='1.0.0'
        )

        return profile

    def _create_job_profile(self, job) -> 'JobMatchingProfile':
        """Create a new matching profile for a job."""
        from .models import JobMatchingProfile

        # Build text for embedding
        text_parts = [job.title]

        if hasattr(job, 'description') and job.description:
            text_parts.append(job.description)

        if hasattr(job, 'requirements') and job.requirements:
            text_parts.append(job.requirements)

        combined_text = ' '.join(text_parts)

        # Generate embedding
        embedding_result = self.embedding_service.execute(combined_text)

        # Extract and normalize skills
        required_skills = self._extract_skills_from_text(job.requirements if hasattr(job, 'requirements') else '')
        nice_to_have = self._extract_skills_from_text(job.nice_to_have if hasattr(job, 'nice_to_have') else '')

        normalized_required = self.skill_service.normalize_skill_list(required_skills)
        normalized_nice = self.skill_service.normalize_skill_list(nice_to_have)

        profile = JobMatchingProfile.objects.create(
            tenant=job.tenant if hasattr(job, 'tenant') else None,
            job=job,
            embedding=embedding_result.vector if embedding_result.success else None,
            required_skills_normalized=normalized_required,
            nice_to_have_normalized=normalized_nice,
            min_experience_years=job.min_experience if hasattr(job, 'min_experience') else None,
            max_experience_years=job.max_experience if hasattr(job, 'max_experience') else None,
            is_remote=job.is_remote if hasattr(job, 'is_remote') else None,
            processing_status='completed',
            processing_version='1.0.0'
        )

        return profile

    def _calculate_skill_score(self, candidate_profile, job_profile) -> Dict:
        """Calculate skill match score with detailed breakdown."""
        if not candidate_profile or not job_profile:
            return {'score': 0.5, 'matched': [], 'missing': [], 'bonus': []}

        candidate_skills = set(candidate_profile.skills_normalized.keys())
        required_skills = set(job_profile.required_skills_normalized.keys())
        nice_to_have = set(job_profile.nice_to_have_normalized.keys())

        # Direct matches
        matched_required = candidate_skills & required_skills
        matched_nice = candidate_skills & nice_to_have

        # Missing required skills
        missing = required_skills - candidate_skills

        # Bonus skills (candidate has but not required)
        bonus = candidate_skills - required_skills - nice_to_have

        # Calculate score
        if required_skills:
            required_score = len(matched_required) / len(required_skills)
        else:
            required_score = 1.0

        nice_score = len(matched_nice) / len(nice_to_have) if nice_to_have else 0

        # Weighted combination (required skills more important)
        score = 0.8 * required_score + 0.2 * nice_score

        # Small bonus for extra relevant skills
        if bonus and len(bonus) <= 5:
            score = min(1.0, score + 0.05)

        return {
            'score': round(score, 4),
            'matched': list(matched_required | matched_nice),
            'missing': list(missing),
            'bonus': list(bonus)[:10]  # Limit bonus skills shown
        }

    def _calculate_experience_score(self, candidate_profile, job_profile) -> float:
        """Calculate experience match score."""
        if not candidate_profile or not job_profile:
            return 0.5

        candidate_exp = float(candidate_profile.total_experience_years or 0)
        min_exp = job_profile.min_experience_years or 0
        max_exp = job_profile.max_experience_years or 20

        if candidate_exp >= min_exp and candidate_exp <= max_exp:
            return 1.0
        elif candidate_exp < min_exp:
            gap = min_exp - candidate_exp
            return max(0.0, 1.0 - (gap * 0.15))  # 15% penalty per year under
        else:
            # Overqualified - slight penalty
            excess = candidate_exp - max_exp
            return max(0.5, 1.0 - (excess * 0.05))  # 5% penalty per year over

    def _calculate_education_score(self, candidate_profile, job_profile) -> float:
        """Calculate education match score."""
        education_levels = {
            'high school': 1,
            'associate': 2,
            'bachelor': 3,
            'bachelors': 3,
            'master': 4,
            'masters': 4,
            'mba': 4,
            'phd': 5,
            'doctorate': 5,
        }

        candidate_level = education_levels.get(
            (candidate_profile.highest_education_level or '').lower(), 0
        )
        required_level = education_levels.get(
            (job_profile.required_education_level or '').lower(), 0
        )

        if required_level == 0:  # No requirement
            return 1.0

        if candidate_level >= required_level:
            return 1.0
        elif candidate_level == required_level - 1:
            return 0.7  # One level below
        else:
            return 0.4  # Significantly below

    def _calculate_cultural_fit_score(self, candidate_profile, job_profile) -> float:
        """Calculate cultural fit score based on values alignment."""
        if not job_profile or not job_profile.company_values:
            return 0.7  # Default moderate fit when no values specified

        # This would ideally use NLP to compare candidate's summary/values
        # with company values. For now, return moderate score.
        return 0.6

    def _calculate_location_score(self, candidate, job) -> float:
        """Calculate location match score."""
        job_remote = getattr(job, 'is_remote', None)
        job_location = getattr(job, 'location', '')
        candidate_location = getattr(candidate, 'location', '')

        if job_remote:
            return 1.0  # Remote jobs match everyone

        if not job_location or not candidate_location:
            return 0.5  # Unknown

        if job_location.lower() in candidate_location.lower():
            return 1.0

        # Could add geospatial distance calculation here
        return 0.5

    def _calculate_salary_score(self, candidate, job) -> float:
        """Calculate salary expectation match score."""
        candidate_salary = getattr(candidate, 'expected_salary', None)
        job_min = getattr(job, 'salary_min', None)
        job_max = getattr(job, 'salary_max', None)

        if not candidate_salary or (not job_min and not job_max):
            return 0.7  # Unknown

        if job_min and job_max:
            if job_min <= candidate_salary <= job_max:
                return 1.0
            elif candidate_salary < job_min:
                return 0.9  # Under budget is good for employer
            else:
                gap_percent = (candidate_salary - job_max) / job_max
                return max(0.3, 1.0 - gap_percent)

        return 0.6

    def _extract_skills_from_text(self, text: str) -> List[str]:
        """Extract skills from text using keyword matching."""
        text_lower = text.lower()
        found_skills = []

        for skill in TECH_SKILLS + SOFT_SKILLS:
            if skill in text_lower:
                found_skills.append(skill)

        return found_skills

    def _compute_experience_score_value(self, candidate) -> float:
        """Compute normalized experience score for a candidate."""
        years = getattr(candidate, 'years_of_experience', 0) or 0

        # Normalize to 0-1 (assume 20+ years is max)
        return min(1.0, years / 20.0)

    def _compute_education_score_value(self, candidate) -> float:
        """Compute normalized education score for a candidate."""
        education_levels = {
            'high school': 0.2,
            'associate': 0.4,
            'bachelor': 0.6,
            'bachelors': 0.6,
            'master': 0.8,
            'masters': 0.8,
            'mba': 0.85,
            'phd': 1.0,
            'doctorate': 1.0,
        }

        edu = getattr(candidate, 'highest_education', '') or ''
        return education_levels.get(edu.lower(), 0.3)

    def _generate_explanation(
        self,
        candidate, job,
        skill_result, experience_score, education_score,
        cultural_score, location_score, salary_score,
        overall_score, weights
    ) -> MatchExplanation:
        """Generate detailed explanation of the match."""
        strengths = []
        gaps = []
        recommendations = []

        # Analyze skill match
        if skill_result['score'] >= 0.8:
            strengths.append(
                f"Strong skill match: {len(skill_result['matched'])} matching skills"
            )
        elif skill_result['missing']:
            gaps.append(
                f"Missing required skills: {', '.join(skill_result['missing'][:5])}"
            )
            recommendations.append(
                f"Consider candidates who can quickly learn: {skill_result['missing'][0]}"
            )

        # Analyze experience
        if experience_score >= 0.9:
            strengths.append("Experience level aligns well with requirements")
        elif experience_score < 0.6:
            gaps.append("Experience level may not meet requirements")

        # Analyze education
        if education_score >= 0.9:
            strengths.append("Education exceeds or meets requirements")
        elif education_score < 0.5:
            gaps.append("Education level below stated requirements")

        # Bonus skills
        if skill_result['bonus']:
            strengths.append(
                f"Additional relevant skills: {', '.join(skill_result['bonus'][:3])}"
            )

        # Summary
        if overall_score >= 0.7:
            summary = f"Strong candidate match ({overall_score:.0%}). Recommend for interview."
        elif overall_score >= 0.5:
            summary = f"Moderate match ({overall_score:.0%}). Consider if key requirements met."
        else:
            summary = f"Limited match ({overall_score:.0%}). Significant gaps identified."

        return MatchExplanation(
            summary=summary,
            strengths=strengths,
            gaps=gaps,
            recommendations=recommendations,
            score_breakdown={
                'skills': round(skill_result['score'] * weights['skills'], 3),
                'experience': round(experience_score * weights['experience'], 3),
                'education': round(education_score * weights['education'], 3),
                'cultural_fit': round(cultural_score * weights['cultural_fit'], 3),
                'location': round(location_score * weights['location'], 3),
                'salary': round(salary_score * weights['salary'], 3),
            }
        )


# ============================================================================
# Enhanced Resume Parsing Service
# ============================================================================

class EnhancedResumeParserService(ResumeParserService):
    """
    Enhanced resume parsing with better extraction and scoring.
    """

    def __init__(self):
        super().__init__()
        self.skill_service = SkillNormalizationService()
        self.embedding_service = SentenceTransformerEmbeddingService()

    def execute(self, resume_text: str) -> ParsedResume:
        """Parse resume with enhanced extraction."""
        # Get base parsing
        parsed = super().execute(resume_text)

        # Enhance with normalized skills
        normalized_skills = []
        for skill in parsed.skills:
            norm = self.skill_service.normalize_skill(skill)
            if norm and norm.canonical_name not in normalized_skills:
                normalized_skills.append(norm.canonical_name)

        parsed.skills = normalized_skills

        return parsed

    def extract_skills(self, text: str) -> List[str]:
        """Extract skills from text with normalization."""
        text_lower = text.lower()
        found_skills = []

        for skill in TECH_SKILLS + SOFT_SKILLS:
            if skill in text_lower:
                norm = self.skill_service.normalize_skill(skill)
                if norm and norm.canonical_name not in found_skills:
                    found_skills.append(norm.canonical_name)

        return found_skills

    def extract_experience(self, text: str) -> List[Dict]:
        """Extract work experience entries."""
        experiences = []

        # Pattern for experience blocks
        exp_pattern = r'(?:^|\n)([A-Z][^,\n]+),?\s*(?:at\s+)?([A-Z][^,\n]+)'

        # This is a simplified extraction - real implementation would be more sophisticated
        return experiences

    def extract_education(self, text: str) -> List[Dict]:
        """Extract education entries."""
        return super()._rule_based_parse(text).education

    def compute_overall_score(self, parsed_resume: ParsedResume) -> float:
        """
        Compute overall quality score for a parsed resume.

        Considers:
        - Skill diversity and relevance
        - Experience depth
        - Education completeness
        - Profile completeness
        """
        score = 0.0

        # Skills (40% weight)
        skill_count = len(parsed_resume.skills)
        if skill_count >= 10:
            score += 0.4
        else:
            score += 0.4 * (skill_count / 10)

        # Experience (30% weight)
        if parsed_resume.experience_years >= 5:
            score += 0.3
        else:
            score += 0.3 * (parsed_resume.experience_years / 5)

        # Education (20% weight)
        if parsed_resume.education:
            score += 0.2
        else:
            score += 0.1

        # Summary/Completeness (10% weight)
        if parsed_resume.summary and len(parsed_resume.summary) > 50:
            score += 0.1

        return round(score, 4)


# ============================================================================
# Bias Detection and Mitigation Service
# ============================================================================

class EnhancedBiasDetectionService(BiasDetectionService):
    """
    Enhanced bias detection with fairness metrics.
    """

    def check_for_bias(
        self,
        match_results: List,
        demographic_data: Dict = None
    ) -> 'BiasReport':
        """
        Check for bias in matching results.

        Args:
            match_results: List of MatchResult instances
            demographic_data: Optional demographic data for analysis

        Returns:
            BiasReport with findings
        """
        if not match_results:
            return BiasReport(
                has_bias=False,
                bias_score=0.0,
                gender_bias={'male_coded': [], 'female_coded': []},
                age_bias=[],
                other_bias=[],
                suggestions=[]
            )

        # Calculate score distribution
        scores = [r.overall_score for r in match_results]
        mean_score = sum(scores) / len(scores)
        std_score = (sum((s - mean_score) ** 2 for s in scores) / len(scores)) ** 0.5

        # Check for score clustering
        issues = []
        if std_score < 0.1:
            issues.append("Scores are too clustered - may indicate homogeneous candidate pool")

        # If demographic data available, check for disparate impact
        if demographic_data:
            groups = demographic_data.get('groups', {})
            group_scores = {}

            for group, candidates in groups.items():
                group_results = [r for r in match_results if r.candidate_id in candidates]
                if group_results:
                    group_scores[group] = sum(r.overall_score for r in group_results) / len(group_results)

            # Check disparate impact (80% rule)
            if group_scores:
                max_score = max(group_scores.values())
                for group, score in group_scores.items():
                    if score / max_score < 0.8:
                        issues.append(f"Potential disparate impact detected for group: {group}")

        has_bias = len(issues) > 0
        bias_score = len(issues) * 0.2  # Simple scoring

        return BiasReport(
            has_bias=has_bias,
            bias_score=min(1.0, bias_score),
            gender_bias={'male_coded': [], 'female_coded': []},
            age_bias=[],
            other_bias=issues,
            suggestions=[{'issue': issue, 'suggestion': 'Review matching criteria'} for issue in issues]
        )

    def adjust_for_bias(
        self,
        scores: List[float],
        adjustments: Dict
    ) -> List[float]:
        """
        Apply bias corrections to scores.

        Args:
            scores: Original scores
            adjustments: Adjustment factors by group

        Returns:
            Adjusted scores
        """
        # This is a placeholder - real implementation would be more sophisticated
        return scores

    def generate_fairness_metrics(self) -> Dict:
        """
        Generate fairness metrics for the matching system.

        Returns:
            Dict with fairness metrics
        """
        return {
            'demographic_parity': None,
            'equal_opportunity': None,
            'calibration': None,
            'individual_fairness': None,
        }


# ============================================================================
# HYBRID RANKING ENGINE - Three-Score System (Cycle 8)
# ============================================================================

class HybridRankingEngine:
    """
    Hybrid Ranking Engine implementing the three-score formula:

    FinalScore = (RuleScore × 0.30) + (AIScore × 0.50) + (VerificationScore × 0.20)

    Components:
    - RuleScore (30%): Deterministic rules (knockout + preference + bonus)
    - AIScore (50%): AI-powered matching (skill, experience, culture, location, salary)
    - VerificationScore (20%): Trust/verification level of the candidate

    This engine integrates with:
    - RankingProfile: Tenant-configurable weights and thresholds
    - RankingRule: Deterministic rules for knockout/preferences
    - TrustScore: Verification-based scoring from accounts app
    - CandidateRanking: Storage for computed rankings
    """

    def __init__(self, tenant=None):
        """
        Initialize the ranking engine.

        Args:
            tenant: Optional tenant for multi-tenant context
        """
        self.tenant = tenant
        self.matching_service = CandidateMatchingService()
        self.skill_service = SkillNormalizationService()
        self._ranking_profile = None
        self._rules_cache = None

    def get_ranking_profile(self):
        """Get the active ranking profile for the tenant."""
        if self._ranking_profile is None:
            from .models import RankingProfile
            try:
                self._ranking_profile = RankingProfile.objects.get(
                    tenant=self.tenant,
                    is_active=True
                )
            except RankingProfile.DoesNotExist:
                # Use default weights
                self._ranking_profile = RankingProfile(
                    rule_score_weight=Decimal('0.30'),
                    ai_score_weight=Decimal('0.50'),
                    verification_score_weight=Decimal('0.20')
                )
        return self._ranking_profile

    def get_rules(self, job=None):
        """Get ranking rules for the tenant/job."""
        if self._rules_cache is None:
            from .models import RankingRule
            rules_qs = RankingRule.objects.filter(
                tenant=self.tenant,
                is_active=True
            ).order_by('priority')

            if job:
                rules_qs = rules_qs.filter(
                    models.Q(job__isnull=True) | models.Q(job=job)
                )

            self._rules_cache = list(rules_qs)
        return self._rules_cache

    def rank_candidate(
        self,
        candidate,
        job,
        save_result: bool = True
    ) -> 'CandidateRanking':
        """
        Rank a single candidate for a job using the hybrid formula.

        Args:
            candidate: Candidate instance
            job: Job posting instance
            save_result: Whether to save the ranking to database

        Returns:
            CandidateRanking instance with all scores
        """
        from .models import CandidateRanking
        import time

        start_time = time.time()
        profile = self.get_ranking_profile()
        rules = self.get_rules(job)

        # Step 1: Calculate Rule Score (deterministic)
        rule_result = self._calculate_rule_score(candidate, job, rules)

        # Check for knockout
        if rule_result['knocked_out']:
            # Candidate failed a knockout rule
            ranking = CandidateRanking(
                tenant=self.tenant,
                candidate=candidate,
                job=job,
                rule_score=Decimal('0.00'),
                ai_score=Decimal('0.00'),
                verification_score=Decimal('0.00'),
                overall_score=Decimal('0.00'),
                is_knocked_out=True,
                knockout_reason=rule_result['knockout_reason'],
                knocked_out_by_rule=rule_result.get('knockout_rule_name'),
            )
            if save_result:
                ranking.save()
            return ranking

        # Step 2: Calculate AI Score (50% weight with sub-components)
        ai_result = self._calculate_ai_score(candidate, job, profile)

        # Step 3: Calculate Verification Score (from TrustScore)
        verification_score = self._calculate_verification_score(candidate, profile)

        # Step 4: Calculate Final Score using weights
        rule_weight = float(profile.rule_score_weight)
        ai_weight = float(profile.ai_score_weight)
        verification_weight = float(profile.verification_score_weight)

        final_score = (
            rule_result['score'] * rule_weight +
            ai_result['overall'] * ai_weight +
            verification_score * verification_weight
        )

        # Apply bonuses from profile
        if profile.bonus_for_verified_career and verification_score >= 0.8:
            final_score = min(1.0, final_score + float(profile.bonus_for_verified_career))
        if profile.bonus_for_premium_trust and verification_score >= 0.9:
            final_score = min(1.0, final_score + float(profile.bonus_for_premium_trust))

        # Calculate computation time
        computation_time = int((time.time() - start_time) * 1000)

        # Create ranking object
        ranking = CandidateRanking(
            tenant=self.tenant,
            candidate=candidate,
            job=job,
            # Main scores
            rule_score=Decimal(str(round(rule_result['score'], 4))),
            ai_score=Decimal(str(round(ai_result['overall'], 4))),
            verification_score=Decimal(str(round(verification_score, 4))),
            overall_score=Decimal(str(round(final_score, 4))),
            # AI sub-components
            skill_match_score=Decimal(str(round(ai_result.get('skill', 0), 4))),
            experience_match_score=Decimal(str(round(ai_result.get('experience', 0), 4))),
            culture_fit_score=Decimal(str(round(ai_result.get('culture', 0), 4))),
            location_match_score=Decimal(str(round(ai_result.get('location', 0), 4))),
            salary_match_score=Decimal(str(round(ai_result.get('salary', 0), 4))),
            # Details
            matched_skills=ai_result.get('matched_skills', []),
            missing_skills=ai_result.get('missing_skills', []),
            bonus_skills=ai_result.get('bonus_skills', []),
            rules_passed=rule_result.get('rules_passed', []),
            rules_failed=rule_result.get('rules_failed', []),
            # Weights used
            weights_used={
                'rule': rule_weight,
                'ai': ai_weight,
                'verification': verification_weight,
            },
            # Metadata
            computation_time_ms=computation_time,
            is_knocked_out=False,
        )

        if save_result:
            ranking.save()

        return ranking

    def rank_candidates_for_job(
        self,
        job,
        candidates=None,
        limit: int = 100,
        min_score: float = 0.0,
        include_knocked_out: bool = False
    ) -> List['CandidateRanking']:
        """
        Rank all candidates for a job posting.

        Args:
            job: Job posting instance
            candidates: Optional queryset/list of candidates (defaults to all)
            limit: Maximum number of rankings to return
            min_score: Minimum overall score threshold
            include_knocked_out: Whether to include knocked-out candidates

        Returns:
            List of CandidateRanking instances sorted by overall_score desc
        """
        from jobs.models import Candidate
        from .models import CandidateRanking

        if candidates is None:
            candidates = Candidate.objects.all()

        rankings = []

        for candidate in candidates[:500]:  # Process up to 500
            # Check for existing non-stale ranking
            try:
                existing = CandidateRanking.objects.get(
                    candidate=candidate,
                    job=job,
                    is_stale=False
                )
                if hasattr(existing, 'is_expired') and not existing.is_expired:
                    if existing.overall_score >= Decimal(str(min_score)):
                        if include_knocked_out or not existing.is_knocked_out:
                            rankings.append(existing)
                    continue
            except CandidateRanking.DoesNotExist:
                pass

            # Calculate new ranking
            ranking = self.rank_candidate(candidate, job)

            if float(ranking.overall_score) >= min_score:
                if include_knocked_out or not ranking.is_knocked_out:
                    rankings.append(ranking)

        # Sort by overall score descending
        rankings.sort(key=lambda x: float(x.overall_score), reverse=True)

        return rankings[:limit]

    def _calculate_rule_score(
        self,
        candidate,
        job,
        rules: List
    ) -> Dict[str, Any]:
        """
        Calculate the rule-based score component.

        Evaluates knockout, preference, and bonus rules.

        Args:
            candidate: Candidate instance
            job: Job posting instance
            rules: List of RankingRule instances

        Returns:
            Dict with score, knocked_out flag, and rule details
        """
        score = 0.0
        knocked_out = False
        knockout_reason = None
        knockout_rule_name = None
        rules_passed = []
        rules_failed = []

        # Build candidate data for rule evaluation
        candidate_data = self._build_candidate_data(candidate)

        # Separate rules by type
        knockout_rules = [r for r in rules if r.rule_type == 'knockout']
        preference_rules = [r for r in rules if r.rule_type == 'preference']
        bonus_rules = [r for r in rules if r.rule_type == 'bonus']

        # Evaluate knockout rules first
        for rule in knockout_rules:
            passed, rule_score, reason = rule.evaluate(candidate_data)
            if not passed:
                knocked_out = True
                knockout_reason = reason or f"Failed knockout rule: {rule.name}"
                knockout_rule_name = rule.name
                rules_failed.append({
                    'rule': rule.name,
                    'type': 'knockout',
                    'reason': reason
                })
                break
            else:
                rules_passed.append({'rule': rule.name, 'type': 'knockout'})

        if knocked_out:
            return {
                'score': 0.0,
                'knocked_out': True,
                'knockout_reason': knockout_reason,
                'knockout_rule_name': knockout_rule_name,
                'rules_passed': rules_passed,
                'rules_failed': rules_failed,
            }

        # Evaluate preference rules (contribute to base score)
        preference_total = 0.0
        preference_count = len(preference_rules) or 1

        for rule in preference_rules:
            passed, rule_score, reason = rule.evaluate(candidate_data)
            weight = float(rule.weight) if hasattr(rule, 'weight') else 1.0

            if passed:
                preference_total += rule_score * weight
                rules_passed.append({
                    'rule': rule.name,
                    'type': 'preference',
                    'score': rule_score
                })
            else:
                rules_failed.append({
                    'rule': rule.name,
                    'type': 'preference',
                    'reason': reason
                })

        # Base score from preferences (normalized to 0-1)
        if preference_rules:
            max_possible = sum(float(r.weight) if hasattr(r, 'weight') else 1.0 for r in preference_rules)
            score = preference_total / max_possible if max_possible > 0 else 0.5
        else:
            score = 0.5  # Default if no preference rules

        # Evaluate bonus rules (add to score, capped at 1.0)
        for rule in bonus_rules:
            passed, bonus_score, reason = rule.evaluate(candidate_data)
            if passed:
                bonus_amount = float(rule.bonus_points) if hasattr(rule, 'bonus_points') else 0.05
                score = min(1.0, score + bonus_amount)
                rules_passed.append({
                    'rule': rule.name,
                    'type': 'bonus',
                    'bonus': bonus_amount
                })

        return {
            'score': round(score, 4),
            'knocked_out': False,
            'knockout_reason': None,
            'rules_passed': rules_passed,
            'rules_failed': rules_failed,
        }

    def _calculate_ai_score(
        self,
        candidate,
        job,
        profile
    ) -> Dict[str, float]:
        """
        Calculate the AI-based score component.

        Uses the CandidateMatchingService for semantic matching.

        Args:
            candidate: Candidate instance
            job: Job posting instance
            profile: RankingProfile with AI component weights

        Returns:
            Dict with overall AI score and sub-component scores
        """
        try:
            # Get match result from existing service
            match_result = self.matching_service.match_candidate_to_job(candidate, job)

            # Extract component scores
            skill_score = float(match_result.skill_match_score or 0)
            experience_score = float(match_result.experience_match_score or 0)
            culture_score = float(match_result.cultural_fit_score or 0)
            location_score = float(match_result.location_match_score or 0)
            salary_score = float(match_result.salary_match_score or 0)

            # Get weights from profile
            skill_weight = float(profile.ai_skill_match_weight or Decimal('0.35'))
            exp_weight = float(profile.ai_experience_match_weight or Decimal('0.20'))
            culture_weight = float(profile.ai_culture_fit_weight or Decimal('0.15'))
            location_weight = float(profile.ai_location_match_weight or Decimal('0.15'))
            salary_weight = float(profile.ai_salary_match_weight or Decimal('0.15'))

            # Normalize weights
            total_weight = skill_weight + exp_weight + culture_weight + location_weight + salary_weight
            if total_weight != 1.0:
                skill_weight /= total_weight
                exp_weight /= total_weight
                culture_weight /= total_weight
                location_weight /= total_weight
                salary_weight /= total_weight

            # Calculate weighted overall AI score
            overall_ai = (
                skill_score * skill_weight +
                experience_score * exp_weight +
                culture_score * culture_weight +
                location_score * location_weight +
                salary_score * salary_weight
            )

            return {
                'overall': round(overall_ai, 4),
                'skill': skill_score,
                'experience': experience_score,
                'culture': culture_score,
                'location': location_score,
                'salary': salary_score,
                'matched_skills': match_result.matched_skills or [],
                'missing_skills': match_result.missing_skills or [],
                'bonus_skills': match_result.bonus_skills if hasattr(match_result, 'bonus_skills') else [],
            }

        except Exception as e:
            logger.warning(f"AI score calculation failed: {e}")
            # Return moderate default scores on failure
            return {
                'overall': 0.5,
                'skill': 0.5,
                'experience': 0.5,
                'culture': 0.5,
                'location': 0.5,
                'salary': 0.5,
                'matched_skills': [],
                'missing_skills': [],
                'bonus_skills': [],
            }

    def _calculate_verification_score(
        self,
        candidate,
        profile
    ) -> float:
        """
        Calculate the verification/trust score component.

        Based on the candidate's TrustScore from the accounts app.

        Args:
            candidate: Candidate instance
            profile: RankingProfile for thresholds

        Returns:
            Float verification score (0-1)
        """
        try:
            # Get user from candidate
            user = candidate.user if hasattr(candidate, 'user') else None
            if not user:
                return 0.3  # Default for candidates without user link

            # Get TrustScore from accounts app
            from tenant_profiles.models import TrustScore

            try:
                trust_score = TrustScore.objects.get(user=user)

                # Normalize overall_score to 0-1 (stored as 0-100)
                overall = float(trust_score.overall_score or 0) / 100.0

                # Weight verification components
                id_bonus = 0.1 if trust_score.is_id_verified else 0.0
                career_bonus = 0.1 if trust_score.is_career_verified else 0.0

                # Calculate verification score
                verification_score = min(1.0, overall + id_bonus + career_bonus)

                return round(verification_score, 4)

            except TrustScore.DoesNotExist:
                # No trust score yet - return baseline
                return 0.3

        except Exception as e:
            logger.warning(f"Verification score calculation failed: {e}")
            return 0.3

    def _build_candidate_data(self, candidate) -> Dict[str, Any]:
        """
        Build a data dictionary from candidate for rule evaluation.

        Args:
            candidate: Candidate instance

        Returns:
            Dict with candidate attributes for rule matching
        """
        data = {
            'id': candidate.id,
            'name': getattr(candidate, 'name', ''),
        }

        # Skills
        if hasattr(candidate, 'skills'):
            data['skills'] = list(candidate.skills.values_list('name', flat=True))
        else:
            data['skills'] = []

        # Experience
        data['experience_years'] = getattr(candidate, 'years_of_experience', 0) or 0

        # Education
        data['education_level'] = getattr(candidate, 'highest_education', '') or ''

        # Location
        data['location'] = getattr(candidate, 'location', '') or ''

        # Salary
        data['expected_salary'] = getattr(candidate, 'expected_salary', None)

        # Additional fields
        data['is_remote_available'] = getattr(candidate, 'is_remote_available', True)
        data['languages'] = getattr(candidate, 'languages', []) or []
        data['certifications'] = getattr(candidate, 'certifications', []) or []

        return data

    def invalidate_cache(self, job=None, candidate=None):
        """
        Invalidate cached rankings.

        Args:
            job: Specific job to invalidate (None for all)
            candidate: Specific candidate to invalidate (None for all)
        """
        from .models import CandidateRanking

        qs = CandidateRanking.objects.filter(tenant=self.tenant)

        if job:
            qs = qs.filter(job=job)
        if candidate:
            qs = qs.filter(candidate=candidate)

        qs.update(is_stale=True)

        # Clear internal caches
        self._ranking_profile = None
        self._rules_cache = None

    def recalculate_all_rankings(self, job):
        """
        Recalculate all rankings for a job (e.g., after rule changes).

        Args:
            job: Job posting to recalculate rankings for

        Returns:
            Number of rankings recalculated
        """
        from .models import CandidateRanking

        # Get all existing rankings for this job
        existing = CandidateRanking.objects.filter(
            tenant=self.tenant,
            job=job
        ).select_related('candidate')

        count = 0
        for ranking in existing:
            # Recalculate
            self.rank_candidate(ranking.candidate, job, save_result=True)
            count += 1

        return count

    def get_ranking_explanation(self, ranking) -> Dict[str, Any]:
        """
        Generate a detailed explanation of a ranking.

        Args:
            ranking: CandidateRanking instance

        Returns:
            Dict with human-readable explanation
        """
        profile = self.get_ranking_profile()

        explanation = {
            'summary': '',
            'overall_score': float(ranking.overall_score),
            'components': {
                'rule_score': {
                    'value': float(ranking.rule_score),
                    'weight': float(profile.rule_score_weight),
                    'contribution': float(ranking.rule_score) * float(profile.rule_score_weight),
                },
                'ai_score': {
                    'value': float(ranking.ai_score),
                    'weight': float(profile.ai_score_weight),
                    'contribution': float(ranking.ai_score) * float(profile.ai_score_weight),
                    'breakdown': {
                        'skill_match': float(ranking.skill_match_score or 0),
                        'experience_match': float(ranking.experience_match_score or 0),
                        'culture_fit': float(ranking.culture_fit_score or 0),
                        'location_match': float(ranking.location_match_score or 0),
                        'salary_match': float(ranking.salary_match_score or 0),
                    }
                },
                'verification_score': {
                    'value': float(ranking.verification_score),
                    'weight': float(profile.verification_score_weight),
                    'contribution': float(ranking.verification_score) * float(profile.verification_score_weight),
                },
            },
            'skills': {
                'matched': ranking.matched_skills or [],
                'missing': ranking.missing_skills or [],
                'bonus': ranking.bonus_skills or [],
            },
            'rules': {
                'passed': ranking.rules_passed or [],
                'failed': ranking.rules_failed or [],
            },
        }

        # Generate summary
        score = float(ranking.overall_score)
        if ranking.is_knocked_out:
            explanation['summary'] = f"Candidate was disqualified: {ranking.knockout_reason}"
        elif score >= 0.8:
            explanation['summary'] = f"Excellent match ({score:.0%}). Highly recommended for interview."
        elif score >= 0.6:
            explanation['summary'] = f"Good match ({score:.0%}). Strong candidate worth considering."
        elif score >= 0.4:
            explanation['summary'] = f"Moderate match ({score:.0%}). Review gaps before proceeding."
        else:
            explanation['summary'] = f"Limited match ({score:.0%}). Significant gaps identified."

        return explanation
