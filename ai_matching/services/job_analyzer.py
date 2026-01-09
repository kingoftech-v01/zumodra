"""
Job Description Analyzer Service

Extracts requirements and metadata from job descriptions including:
- Required and preferred skills
- Experience level requirements
- Education requirements
- Job type and remote options
- Responsibilities and benefits
"""
import logging
import re
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)


@dataclass
class AnalyzedJob:
    """Structured analysis of a job description."""
    required_skills: List[str] = field(default_factory=list)
    preferred_skills: List[str] = field(default_factory=list)
    experience_level: str = 'mid'
    min_experience_years: Optional[int] = None
    max_experience_years: Optional[int] = None
    education_requirements: List[str] = field(default_factory=list)
    responsibilities: List[str] = field(default_factory=list)
    benefits: List[str] = field(default_factory=list)
    job_type: str = 'full-time'
    remote_option: bool = False
    salary_min: Optional[int] = None
    salary_max: Optional[int] = None
    salary_currency: str = 'USD'


class JobDescriptionAnalyzer:
    """
    Service for analyzing job descriptions.

    Extracts structured data from job posting text including
    requirements, skills, and job characteristics.

    Usage:
        analyzer = JobDescriptionAnalyzer()
        result = analyzer.analyze(job_description_text)
        print(f"Required skills: {result['required_skills']}")
        print(f"Experience: {result['min_experience_years']}+ years")
    """

    # Experience level patterns
    EXPERIENCE_PATTERNS = [
        (r'(\d+)\+?\s*(?:years?|yrs?)\s*(?:of)?\s*(?:experience|exp)', 'min'),
        (r'minimum\s*(?:of)?\s*(\d+)\s*years?', 'min'),
        (r'at\s*least\s*(\d+)\s*years?', 'min'),
        (r'(\d+)\s*[-–—to]+\s*(\d+)\s*years?\s*(?:of)?\s*(?:experience|exp)', 'range'),
        (r'(?:up\s*to|maximum)\s*(\d+)\s*years?', 'max'),
    ]

    # Education patterns
    EDUCATION_KEYWORDS = [
        ("bachelor's", 'bachelors'),
        ("bachelor", 'bachelors'),
        ("master's", 'masters'),
        ("master", 'masters'),
        ("phd", 'phd'),
        ("doctorate", 'phd'),
        ("mba", 'mba'),
        ("associate", 'associate'),
        ("high school", 'high_school'),
        ("diploma", 'diploma'),
        ("degree", 'degree'),
    ]

    # Job type indicators
    JOB_TYPE_PATTERNS = {
        'contract': ['contract', 'contractor', 'freelance', 'consulting'],
        'part-time': ['part-time', 'part time', 'parttime'],
        'internship': ['intern', 'internship', 'co-op', 'coop'],
        'temporary': ['temporary', 'temp', 'seasonal'],
    }

    # Remote work indicators
    REMOTE_KEYWORDS = [
        'remote', 'work from home', 'wfh', 'distributed',
        'anywhere', 'virtual', 'telecommute', 'telework'
    ]

    # Salary patterns
    SALARY_PATTERNS = [
        r'\$\s*(\d{2,3})[,.]?(\d{3})?\s*[-–—to]+\s*\$?\s*(\d{2,3})[,.]?(\d{3})?',
        r'(\d{2,3})[,.]?(\d{3})?\s*[-–—to]+\s*(\d{2,3})[,.]?(\d{3})?\s*(?:USD|per year|annually|/year)',
    ]

    def __init__(self):
        # Import skill patterns from resume parser
        from .resume_parser import ResumeParserService
        self._skill_extractor = ResumeParserService()

    def analyze(self, job_description: str) -> Dict[str, Any]:
        """
        Analyze a job description.

        Args:
            job_description: Full job description text

        Returns:
            Dict with extracted requirements and metadata
        """
        if not job_description:
            return self._empty_result()

        text_lower = job_description.lower()
        analyzed = AnalyzedJob()

        # Extract experience requirements
        exp_result = self._extract_experience_requirements(text_lower)
        analyzed.min_experience_years = exp_result.get('min')
        analyzed.max_experience_years = exp_result.get('max')
        analyzed.experience_level = exp_result.get('level', 'mid')

        # Extract education requirements
        analyzed.education_requirements = self._extract_education_requirements(
            text_lower
        )

        # Extract skills
        skills = self._extract_skills(job_description)
        analyzed.required_skills = skills.get('required', [])
        analyzed.preferred_skills = skills.get('preferred', [])

        # Extract responsibilities
        analyzed.responsibilities = self._extract_responsibilities(
            job_description
        )

        # Extract benefits
        analyzed.benefits = self._extract_benefits(job_description)

        # Determine job type
        analyzed.job_type = self._determine_job_type(text_lower)

        # Check remote option
        analyzed.remote_option = self._check_remote_option(text_lower)

        # Extract salary
        salary = self._extract_salary(job_description)
        analyzed.salary_min = salary.get('min')
        analyzed.salary_max = salary.get('max')
        analyzed.salary_currency = salary.get('currency', 'USD')

        return {
            'required_skills': analyzed.required_skills,
            'preferred_skills': analyzed.preferred_skills,
            'experience_level': analyzed.experience_level,
            'min_experience_years': analyzed.min_experience_years,
            'max_experience_years': analyzed.max_experience_years,
            'education_requirements': analyzed.education_requirements,
            'responsibilities': analyzed.responsibilities,
            'benefits': analyzed.benefits,
            'job_type': analyzed.job_type,
            'remote_option': analyzed.remote_option,
            'salary_min': analyzed.salary_min,
            'salary_max': analyzed.salary_max,
            'salary_currency': analyzed.salary_currency,
        }

    def _empty_result(self) -> Dict[str, Any]:
        """Return empty analysis result."""
        return {
            'required_skills': [],
            'preferred_skills': [],
            'experience_level': 'mid',
            'min_experience_years': None,
            'max_experience_years': None,
            'education_requirements': [],
            'responsibilities': [],
            'benefits': [],
            'job_type': 'full-time',
            'remote_option': False,
            'salary_min': None,
            'salary_max': None,
            'salary_currency': 'USD',
        }

    def _extract_experience_requirements(self, text: str) -> Dict[str, Any]:
        """Extract experience level requirements."""
        result = {
            'min': None,
            'max': None,
            'level': 'mid'
        }

        for pattern, pattern_type in self.EXPERIENCE_PATTERNS:
            match = re.search(pattern, text, re.IGNORECASE)
            if match:
                groups = match.groups()
                if pattern_type == 'min':
                    result['min'] = int(groups[0])
                elif pattern_type == 'max':
                    result['max'] = int(groups[0])
                elif pattern_type == 'range':
                    result['min'] = int(groups[0])
                    result['max'] = int(groups[1])
                break

        # Determine level from years
        min_years = result['min'] or 0
        if min_years == 0:
            if 'entry' in text or 'junior' in text or 'graduate' in text:
                result['level'] = 'entry'
            else:
                result['level'] = 'entry'
        elif min_years <= 2:
            result['level'] = 'junior'
        elif min_years <= 5:
            result['level'] = 'mid'
        elif min_years <= 8:
            result['level'] = 'senior'
        else:
            result['level'] = 'lead'

        # Override based on explicit keywords
        if 'senior' in text or 'sr.' in text or 'lead' in text:
            if result['level'] in ['entry', 'junior']:
                result['level'] = 'senior'
        elif 'principal' in text or 'staff' in text or 'architect' in text:
            result['level'] = 'lead'

        return result

    def _extract_education_requirements(self, text: str) -> List[str]:
        """Extract education requirements."""
        requirements = []

        for keyword, edu_type in self.EDUCATION_KEYWORDS:
            if keyword in text:
                if edu_type not in [r.lower() for r in requirements]:
                    requirements.append(edu_type.replace('_', ' ').title())

        return requirements[:5]

    def _extract_skills(self, text: str) -> Dict[str, List[str]]:
        """Extract required and preferred skills."""
        text_lower = text.lower()

        # Get all skills using resume parser's skill extraction
        all_skills = set(self._skill_extractor.extract_skills(text))

        # Find required section
        required_section = self._find_section(
            text_lower,
            ['required', 'must have', 'requirements', 'qualifications']
        )

        # Find preferred section
        preferred_section = self._find_section(
            text_lower,
            ['preferred', 'nice to have', 'bonus', 'plus', 'desired']
        )

        required = set()
        preferred = set()

        # Extract skills from specific sections
        if required_section:
            required = set(self._skill_extractor.extract_skills(required_section))

        if preferred_section:
            preferred = set(self._skill_extractor.extract_skills(preferred_section))

        # Skills not in either section default to required
        remaining = all_skills - required - preferred
        required.update(remaining)

        return {
            'required': sorted(list(required)),
            'preferred': sorted(list(preferred))
        }

    def _find_section(self, text: str, keywords: List[str]) -> str:
        """Find a section by keywords."""
        for keyword in keywords:
            # Look for section header followed by content
            pattern = rf'{keyword}[:\s]*(.+?)(?=\n\s*[a-z]+\s*:|$)'
            match = re.search(pattern, text, re.IGNORECASE | re.DOTALL)
            if match:
                content = match.group(1)[:2000]
                return content
        return ''

    def _extract_responsibilities(self, text: str) -> List[str]:
        """Extract job responsibilities."""
        responsibilities = []

        section = self._find_section(
            text.lower(),
            ['responsibilities', 'duties', 'what you will do',
             'what you\'ll do', 'role', 'you will']
        )

        if not section:
            return responsibilities

        # Extract bullet points or sentences
        items = re.split(r'[•\-\*\n]', section)
        for item in items:
            item = item.strip()
            # Filter: must be reasonable length and contain words
            if item and 15 < len(item) < 300:
                if re.search(r'[a-zA-Z]{3,}', item):
                    responsibilities.append(item)

        return responsibilities[:15]

    def _extract_benefits(self, text: str) -> List[str]:
        """Extract job benefits."""
        benefits = []

        section = self._find_section(
            text.lower(),
            ['benefits', 'perks', 'what we offer', 'we offer',
             'compensation', 'why join']
        )

        if not section:
            return benefits

        items = re.split(r'[•\-\*\n]', section)
        for item in items:
            item = item.strip()
            if item and 5 < len(item) < 200:
                if re.search(r'[a-zA-Z]{3,}', item):
                    benefits.append(item)

        return benefits[:15]

    def _determine_job_type(self, text: str) -> str:
        """Determine job type from text."""
        for job_type, keywords in self.JOB_TYPE_PATTERNS.items():
            for keyword in keywords:
                if keyword in text:
                    return job_type
        return 'full-time'

    def _check_remote_option(self, text: str) -> bool:
        """Check if remote work is offered."""
        for keyword in self.REMOTE_KEYWORDS:
            if keyword in text:
                return True

        # Also check for hybrid
        if 'hybrid' in text:
            return True

        return False

    def _extract_salary(self, text: str) -> Dict[str, Any]:
        """Extract salary range from text."""
        result = {'min': None, 'max': None, 'currency': 'USD'}

        for pattern in self.SALARY_PATTERNS:
            match = re.search(pattern, text, re.IGNORECASE)
            if match:
                groups = match.groups()
                try:
                    # Parse min salary
                    min_str = groups[0]
                    if groups[1]:
                        min_str += groups[1]
                    result['min'] = int(min_str.replace(',', '').replace('.', ''))

                    # Parse max salary
                    max_str = groups[2]
                    if len(groups) > 3 and groups[3]:
                        max_str += groups[3]
                    result['max'] = int(max_str.replace(',', '').replace('.', ''))

                    break
                except (ValueError, IndexError):
                    continue

        return result

    def extract_requirements(self, text: str) -> List[str]:
        """
        Extract a simple list of requirements from job description.

        Args:
            text: Job description text

        Returns:
            List of requirement strings
        """
        result = self.analyze(text)
        requirements = []

        # Add skills
        requirements.extend(result['required_skills'])

        # Add experience
        if result['min_experience_years']:
            requirements.append(
                f"{result['min_experience_years']}+ years experience"
            )

        # Add education
        requirements.extend(result['education_requirements'])

        return requirements

    def get_job_embedding_text(self, job_description: str, job_title: str = '') -> str:
        """
        Generate text suitable for embedding generation.

        Combines title and key requirements into embedding-friendly text.

        Args:
            job_description: Full job description
            job_title: Job title

        Returns:
            Concatenated text for embedding
        """
        parts = []

        if job_title:
            parts.append(job_title)

        analysis = self.analyze(job_description)

        # Add skills
        if analysis['required_skills']:
            parts.append(' '.join(analysis['required_skills'][:20]))

        # Add experience level
        parts.append(f"{analysis['experience_level']} level position")

        # Add first few responsibilities
        if analysis['responsibilities']:
            parts.append(' '.join(analysis['responsibilities'][:3]))

        return ' '.join(parts)
