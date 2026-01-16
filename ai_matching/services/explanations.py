"""
Match Explanation Service

Generates human-readable explanations for candidate-job match scores
using OpenAI GPT-4.

Provides:
- Detailed explanations of why a candidate matches or doesn't match a job
- Actionable recommendations for candidates to improve their profile
- Insights for recruiters on candidate strengths and gaps
"""
import logging
from dataclasses import dataclass
from typing import Any, Dict, List, Optional

from django.conf import settings

logger = logging.getLogger(__name__)


@dataclass
class MatchExplanation:
    """Explanation of a candidate-job match."""
    overall_explanation: str
    strengths: List[str]
    weaknesses: List[str]
    recommendations: List[str]
    detailed_breakdown: Dict[str, str]
    confidence: float = 0.0


class MatchExplanationService:
    """
    Service for generating AI-powered match explanations.

    Uses OpenAI GPT-4 to generate natural language explanations
    of match scores, making them understandable for both recruiters
    and candidates.

    Usage:
        service = MatchExplanationService()

        # Generate explanation from match result
        explanation = service.generate_explanation(match_result)
        print(explanation.overall_explanation)
        print("Strengths:", explanation.strengths)
        print("Areas to improve:", explanation.recommendations)
    """

    def __init__(self):
        self.openai_key = settings.OPENAI_API_KEY
        self.model = getattr(settings, 'OPENAI_MODEL', 'gpt-4')
        self._client = None

    @property
    def client(self):
        """Lazy-load OpenAI client."""
        if self._client is None and self.openai_key:
            try:
                import openai
                self._client = openai.OpenAI(api_key=self.openai_key)
            except ImportError:
                logger.error("openai package not installed")
            except Exception as e:
                logger.error(f"Failed to initialize OpenAI client: {e}")
        return self._client

    def generate_explanation(
        self,
        match_result: Dict[str, Any],
        candidate_name: Optional[str] = None,
        job_title: Optional[str] = None
    ) -> MatchExplanation:
        """
        Generate comprehensive explanation for a match result.

        Args:
            match_result: Dict with match scores and breakdown
            candidate_name: Optional candidate name for personalization
            job_title: Optional job title for context

        Returns:
            MatchExplanation with detailed insights
        """
        # Check if OpenAI is available
        if not self.client:
            return self._generate_fallback_explanation(match_result)

        try:
            # Build prompt for GPT-4
            prompt = self._build_explanation_prompt(
                match_result,
                candidate_name,
                job_title
            )

            # Call GPT-4
            response = self.client.chat.completions.create(
                model=self.model,
                messages=[
                    {
                        "role": "system",
                        "content": (
                            "You are an expert HR analyst and career coach. "
                            "You provide clear, actionable insights on candidate-job matches. "
                            "Be honest but constructive, focusing on growth opportunities."
                        )
                    },
                    {
                        "role": "user",
                        "content": prompt
                    }
                ],
                temperature=0.7,
                max_tokens=800
            )

            # Parse response
            explanation_text = response.choices[0].message.content

            # Extract structured data from response
            explanation = self._parse_gpt_response(
                explanation_text,
                match_result
            )

            return explanation

        except Exception as e:
            logger.error(f"GPT-4 explanation generation failed: {e}")
            return self._generate_fallback_explanation(match_result)

    def _build_explanation_prompt(
        self,
        match_result: Dict[str, Any],
        candidate_name: Optional[str] = None,
        job_title: Optional[str] = None
    ) -> str:
        """Build prompt for GPT-4 explanation generation."""
        # Extract scores
        overall_score = match_result.get('overall_score', 0) * 100
        skill_score = match_result.get('skill_score', 0) * 100
        experience_score = match_result.get('experience_score', 0) * 100
        location_score = match_result.get('location_score', 0) * 100
        salary_score = match_result.get('salary_score', 0) * 100
        semantic_score = match_result.get('semantic_score', 0) * 100

        # Get matched and missing skills
        matched_skills = match_result.get('matched_skills', [])
        missing_skills = match_result.get('missing_skills', [])

        # Build context strings
        candidate_context = candidate_name or "The candidate"
        job_context = job_title or "this position"

        prompt = f"""Analyze this candidate-job match and provide a clear explanation:

**Match Overview:**
- Overall Match Score: {overall_score:.0f}/100
- Skills Match: {skill_score:.0f}/100
- Experience Match: {experience_score:.0f}/100
- Location Match: {location_score:.0f}/100
- Salary Alignment: {salary_score:.0f}/100
- Semantic Match: {semantic_score:.0f}/100

**Skills Analysis:**
- Matched Skills: {', '.join(matched_skills[:10]) if matched_skills else 'None listed'}
- Missing Required Skills: {', '.join(missing_skills[:10]) if missing_skills else 'None'}

**Context:**
- Candidate: {candidate_context}
- Position: {job_context}

Please provide:

1. **OVERALL ASSESSMENT** (2-3 sentences): Summarize whether {candidate_context} is a good fit for {job_context} and why.

2. **KEY STRENGTHS** (3-5 bullet points): What makes this candidate stand out? Focus on concrete skills and qualifications.

3. **AREAS FOR IMPROVEMENT** (2-4 bullet points): What gaps exist? Be specific about missing qualifications.

4. **RECOMMENDATIONS** (3-4 bullet points): Actionable advice for the candidate to improve their profile or for next steps.

Format your response clearly with these four sections."""

        return prompt

    def _parse_gpt_response(
        self,
        response_text: str,
        match_result: Dict[str, Any]
    ) -> MatchExplanation:
        """Parse GPT-4 response into structured explanation."""
        # Initialize explanation
        explanation = MatchExplanation(
            overall_explanation="",
            strengths=[],
            weaknesses=[],
            recommendations=[],
            detailed_breakdown={},
            confidence=match_result.get('confidence', 0.7)
        )

        # Split response into sections
        sections = {
            'overall': [],
            'strengths': [],
            'areas': [],
            'recommendations': []
        }

        current_section = None
        lines = response_text.split('\n')

        for line in lines:
            line = line.strip()
            if not line:
                continue

            # Detect section headers
            line_lower = line.lower()
            if 'overall' in line_lower and 'assessment' in line_lower:
                current_section = 'overall'
                continue
            elif 'strength' in line_lower:
                current_section = 'strengths'
                continue
            elif 'area' in line_lower or 'improvement' in line_lower or 'gap' in line_lower:
                current_section = 'areas'
                continue
            elif 'recommendation' in line_lower:
                current_section = 'recommendations'
                continue

            # Add content to current section
            if current_section and line:
                # Remove bullet points and numbers
                clean_line = line.lstrip('•-*0123456789. ')
                if clean_line:
                    sections[current_section].append(clean_line)

        # Build explanation from sections
        explanation.overall_explanation = ' '.join(sections['overall'])
        explanation.strengths = sections['strengths']
        explanation.weaknesses = sections['areas']
        explanation.recommendations = sections['recommendations']

        # Build detailed breakdown
        explanation.detailed_breakdown = {
            'skills': self._explain_score(
                match_result.get('skill_score', 0),
                'Skills match',
                match_result.get('matched_skills', []),
                match_result.get('missing_skills', [])
            ),
            'experience': self._explain_score(
                match_result.get('experience_score', 0),
                'Experience level'
            ),
            'location': self._explain_score(
                match_result.get('location_score', 0),
                'Location compatibility'
            ),
            'salary': self._explain_score(
                match_result.get('salary_score', 0),
                'Salary alignment'
            ),
            'semantic': self._explain_score(
                match_result.get('semantic_score', 0),
                'Profile similarity'
            ),
        }

        return explanation

    def _explain_score(
        self,
        score: float,
        category: str,
        matched: Optional[List[str]] = None,
        missing: Optional[List[str]] = None
    ) -> str:
        """Generate explanation for a specific score category."""
        score_pct = score * 100

        if score >= 0.8:
            level = "Excellent"
        elif score >= 0.6:
            level = "Good"
        elif score >= 0.4:
            level = "Fair"
        else:
            level = "Needs improvement"

        explanation = f"{category}: {level} ({score_pct:.0f}/100)"

        if matched:
            explanation += f". Matches: {', '.join(matched[:5])}"
        if missing:
            explanation += f". Missing: {', '.join(missing[:5])}"

        return explanation

    def _generate_fallback_explanation(
        self,
        match_result: Dict[str, Any]
    ) -> MatchExplanation:
        """
        Generate rule-based explanation when GPT-4 is not available.

        Uses template-based approach with score thresholds.
        """
        overall_score = match_result.get('overall_score', 0)
        skill_score = match_result.get('skill_score', 0)
        experience_score = match_result.get('experience_score', 0)
        matched_skills = match_result.get('matched_skills', [])
        missing_skills = match_result.get('missing_skills', [])

        # Generate overall explanation
        if overall_score >= 0.8:
            overall_text = (
                "This is an excellent match. The candidate's profile aligns "
                "strongly with the job requirements across multiple dimensions."
            )
        elif overall_score >= 0.6:
            overall_text = (
                "This is a good match. The candidate meets many of the key "
                "requirements, though there are some areas for improvement."
            )
        elif overall_score >= 0.4:
            overall_text = (
                "This is a moderate match. The candidate shows potential but "
                "has notable gaps in required qualifications."
            )
        else:
            overall_text = (
                "This is a weak match. The candidate does not meet many of "
                "the core requirements for this position."
            )

        # Generate strengths
        strengths = []
        if skill_score >= 0.7:
            strengths.append(
                f"Strong skill match with {len(matched_skills)} relevant skills"
            )
        if experience_score >= 0.8:
            strengths.append(
                "Experience level aligns well with job requirements"
            )
        if matched_skills:
            top_skills = ', '.join(matched_skills[:5])
            strengths.append(f"Proficient in key areas: {top_skills}")

        if not strengths:
            strengths.append("Profile shows basic alignment with job posting")

        # Generate weaknesses
        weaknesses = []
        if skill_score < 0.5:
            weaknesses.append(
                "Limited match on required technical skills"
            )
        if experience_score < 0.5:
            weaknesses.append(
                "Experience level doesn't fully align with requirements"
            )
        if missing_skills:
            top_missing = ', '.join(missing_skills[:5])
            weaknesses.append(f"Missing key skills: {top_missing}")

        if not weaknesses:
            weaknesses.append("Minor gaps in profile completeness")

        # Generate recommendations
        recommendations = []
        if missing_skills:
            recommendations.append(
                f"Consider developing skills in: {', '.join(missing_skills[:3])}"
            )
        if skill_score < 0.6:
            recommendations.append(
                "Highlight any transferable skills or recent projects"
            )
        if experience_score < 0.6:
            recommendations.append(
                "Emphasize relevant experience even from different roles"
            )
        recommendations.append(
            "Tailor your resume to highlight the most relevant qualifications"
        )

        # Build detailed breakdown
        detailed_breakdown = {
            'skills': self._explain_score(
                skill_score, 'Skills', matched_skills, missing_skills
            ),
            'experience': self._explain_score(
                experience_score, 'Experience'
            ),
            'location': self._explain_score(
                match_result.get('location_score', 0), 'Location'
            ),
            'salary': self._explain_score(
                match_result.get('salary_score', 0), 'Salary'
            ),
            'semantic': self._explain_score(
                match_result.get('semantic_score', 0), 'Semantic Match'
            ),
        }

        return MatchExplanation(
            overall_explanation=overall_text,
            strengths=strengths,
            weaknesses=weaknesses,
            recommendations=recommendations,
            detailed_breakdown=detailed_breakdown,
            confidence=match_result.get('confidence', 0.5)
        )

    def explain_batch(
        self,
        match_results: List[Dict[str, Any]],
        limit: int = 10
    ) -> List[MatchExplanation]:
        """
        Generate explanations for multiple matches.

        Args:
            match_results: List of match result dicts
            limit: Maximum number to process

        Returns:
            List of MatchExplanation objects
        """
        explanations = []
        for result in match_results[:limit]:
            explanation = self.generate_explanation(result)
            explanations.append(explanation)
        return explanations

    def get_comparative_explanation(
        self,
        match_results: List[Dict[str, Any]],
        top_n: int = 3
    ) -> str:
        """
        Generate comparative explanation for top N candidates.

        Useful for recruiters to understand relative strengths
        of multiple candidates.

        Args:
            match_results: List of match results (sorted by score)
            top_n: Number of top candidates to compare

        Returns:
            Comparative analysis text
        """
        if not match_results or not self.client:
            return "Comparative analysis unavailable"

        # Get top N matches
        top_matches = sorted(
            match_results,
            key=lambda x: x.get('overall_score', 0),
            reverse=True
        )[:top_n]

        # Build comparison prompt
        prompt = "Compare these candidates for the position:\n\n"
        for i, match in enumerate(top_matches, 1):
            prompt += f"**Candidate {i}:**\n"
            prompt += f"- Overall Score: {match.get('overall_score', 0)*100:.0f}/100\n"
            prompt += f"- Skills: {match.get('skill_score', 0)*100:.0f}/100\n"
            prompt += f"- Experience: {match.get('experience_score', 0)*100:.0f}/100\n"
            prompt += f"- Matched Skills: {', '.join(match.get('matched_skills', [])[:5])}\n\n"

        prompt += "\nProvide a brief comparison highlighting each candidate's unique strengths and who might be best for what reasons."

        try:
            response = self.client.chat.completions.create(
                model=self.model,
                messages=[
                    {
                        "role": "system",
                        "content": "You are an expert recruiter comparing candidate profiles."
                    },
                    {
                        "role": "user",
                        "content": prompt
                    }
                ],
                temperature=0.7,
                max_tokens=500
            )

            return response.choices[0].message.content

        except Exception as e:
            logger.error(f"Comparative explanation failed: {e}")
            return "Unable to generate comparative analysis at this time"


__all__ = ['MatchExplanationService', 'MatchExplanation']
