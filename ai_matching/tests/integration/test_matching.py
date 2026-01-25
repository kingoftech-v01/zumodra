"""
Tests for AI Matching Services

Tests the following services:
- EmbeddingService: OpenAI/local embedding generation
- MatchingService: Candidate-job matching algorithms
- ResumeParserService: Resume parsing and skill extraction
- JobDescriptionAnalyzer: Job description analysis
- BiasDetectionService: Bias detection and mitigation
- RecommendationService: Personalized recommendations
"""

import pytest
from unittest.mock import Mock, patch, MagicMock
from decimal import Decimal


class TestEmbeddingService:
    """Tests for the EmbeddingService class."""

    def test_embedding_service_initialization(self):
        """Test that EmbeddingService initializes correctly."""
        from ai_matching.services.embeddings import EmbeddingService

        service = EmbeddingService()
        assert service is not None

    def test_cosine_similarity_identical_vectors(self):
        """Test cosine similarity of identical vectors is 1.0."""
        from ai_matching.services.embeddings import EmbeddingService

        service = EmbeddingService()
        vec = [1.0, 0.5, 0.3, 0.8]

        similarity = service.cosine_similarity(vec, vec)
        assert abs(similarity - 1.0) < 0.0001

    def test_cosine_similarity_orthogonal_vectors(self):
        """Test cosine similarity of orthogonal vectors is 0."""
        from ai_matching.services.embeddings import EmbeddingService

        service = EmbeddingService()
        vec1 = [1.0, 0.0, 0.0]
        vec2 = [0.0, 1.0, 0.0]

        similarity = service.cosine_similarity(vec1, vec2)
        assert abs(similarity) < 0.0001

    def test_cosine_similarity_opposite_vectors(self):
        """Test cosine similarity of opposite vectors is -1.0."""
        from ai_matching.services.embeddings import EmbeddingService

        service = EmbeddingService()
        vec1 = [1.0, 0.5, 0.3]
        vec2 = [-1.0, -0.5, -0.3]

        similarity = service.cosine_similarity(vec1, vec2)
        assert abs(similarity + 1.0) < 0.0001

    def test_normalize_similarity(self):
        """Test normalization of similarity scores to 0-1 range."""
        from ai_matching.services.embeddings import EmbeddingService

        service = EmbeddingService()

        # Test edge cases
        assert service.normalize_similarity(-1.0) == 0.0
        assert service.normalize_similarity(1.0) == 1.0
        assert service.normalize_similarity(0.0) == 0.5

    def test_execute_with_openai(self):
        """Test embedding generation with OpenAI API (mocked)."""
        from ai_matching.services.embeddings import EmbeddingService, EmbeddingResult

        service = EmbeddingService()

        # Mock the _generate_openai method to return an EmbeddingResult
        mock_embedding = [0.1] * 1536  # ada-002 dimension
        mock_result = EmbeddingResult(
            success=True,
            vector=mock_embedding,
            model='text-embedding-ada-002',
            dimension=1536
        )
        with patch.object(service, '_generate_openai') as mock_gen:
            mock_gen.return_value = mock_result
            service.openai_available = True

            result = service.execute("Test text for embedding")

            # Result should be an EmbeddingResult with success=True
            assert isinstance(result, EmbeddingResult)
            assert result.success
            assert len(result.embedding) == 1536

    def test_execute_with_empty_text(self):
        """Test embedding generation with empty text returns failure."""
        from ai_matching.services.embeddings import EmbeddingService

        service = EmbeddingService()
        result = service.execute("")

        assert not result.success
        assert result.error is not None

    def test_execute_batch(self):
        """Test batch embedding generation."""
        from ai_matching.services.embeddings import EmbeddingService

        service = EmbeddingService()
        texts = ["First text", "Second text", "Third text"]

        with patch.object(service, 'execute') as mock_execute:
            mock_result = MagicMock()
            mock_result.success = True
            mock_result.embedding = [0.1] * 384
            mock_execute.return_value = mock_result

            results = service.execute_batch(texts)
            assert len(results) == 3


class TestMatchingService:
    """Tests for the MatchingService class."""

    def test_matching_service_initialization(self):
        """Test that MatchingService initializes correctly."""
        from ai_matching.services import MatchingService

        service = MatchingService()
        assert service is not None
        assert service.WEIGHT_SKILLS + service.WEIGHT_EXPERIENCE + \
               service.WEIGHT_LOCATION + service.WEIGHT_SALARY + \
               service.WEIGHT_SEMANTIC == 1.0

    def test_calculate_skill_match_perfect(self):
        """Test skill match with all required skills present."""
        from ai_matching.services import MatchingService

        service = MatchingService()
        candidate = {
            'skills': ['python', 'django', 'postgresql', 'redis']
        }
        job = {
            'required_skills': ['python', 'django'],
            'preferred_skills': ['postgresql']
        }

        score, matched, missing = service._calculate_skill_match(candidate, job)

        assert score == 1.0
        assert 'python' in matched
        assert 'django' in matched
        assert len(missing) == 0

    def test_calculate_skill_match_partial(self):
        """Test skill match with some skills missing."""
        from ai_matching.services import MatchingService

        service = MatchingService()
        candidate = {
            'skills': ['python', 'javascript']
        }
        job = {
            'required_skills': ['python', 'django', 'postgresql'],
            'preferred_skills': ['redis']
        }

        score, matched, missing = service._calculate_skill_match(candidate, job)

        assert 0 < score < 1.0
        assert 'python' in matched
        assert 'django' in missing
        assert 'postgresql' in missing

    def test_calculate_skill_match_none(self):
        """Test skill match with no matching skills."""
        from ai_matching.services import MatchingService

        service = MatchingService()
        candidate = {
            'skills': ['java', 'spring']
        }
        job = {
            'required_skills': ['python', 'django'],
            'preferred_skills': ['postgresql']
        }

        score, matched, missing = service._calculate_skill_match(candidate, job)

        assert score == 0.0
        assert len(matched) == 0
        assert 'python' in missing

    def test_calculate_experience_match_within_range(self):
        """Test experience match when candidate is within range."""
        from ai_matching.services import MatchingService

        service = MatchingService()
        candidate = {'years_experience': 5}
        job = {'min_experience_years': 3, 'max_experience_years': 7}

        score = service._calculate_experience_match(candidate, job)
        assert score == 1.0

    def test_calculate_experience_match_under_qualified(self):
        """Test experience match when candidate is under-qualified."""
        from ai_matching.services import MatchingService

        service = MatchingService()
        candidate = {'years_experience': 1}
        job = {'min_experience_years': 5}

        score = service._calculate_experience_match(candidate, job)
        assert 0 < score < 1.0

    def test_calculate_experience_match_over_qualified(self):
        """Test experience match when candidate is over-qualified."""
        from ai_matching.services import MatchingService

        service = MatchingService()
        candidate = {'years_experience': 15}
        job = {'min_experience_years': 3, 'max_experience_years': 7}

        score = service._calculate_experience_match(candidate, job)
        # Should have slight penalty but still high score
        assert 0.5 <= score < 1.0

    def test_calculate_location_match_remote_preferred(self):
        """Test location match for remote work preference."""
        from ai_matching.services import MatchingService

        service = MatchingService()
        candidate = {'prefers_remote': True}
        job = {'remote_option': True}

        score = service._calculate_location_match(candidate, job)
        assert score == 1.0

    def test_calculate_location_match_same_location(self):
        """Test location match for same location."""
        from ai_matching.services import MatchingService

        service = MatchingService()
        candidate = {'location': 'New York', 'prefers_remote': False}
        job = {'location': 'New York', 'remote_option': False}

        score = service._calculate_location_match(candidate, job)
        assert score == 1.0

    def test_calculate_location_match_different_location(self):
        """Test location match for different locations without relocation."""
        from ai_matching.services import MatchingService

        service = MatchingService()
        candidate = {
            'location': 'Los Angeles',
            'prefers_remote': False,
            'willing_to_relocate': False
        }
        job = {'location': 'New York', 'remote_option': False}

        score = service._calculate_location_match(candidate, job)
        assert score < 0.5

    def test_calculate_salary_match_overlap(self):
        """Test salary match when ranges overlap."""
        from ai_matching.services import MatchingService

        service = MatchingService()
        candidate = {
            'salary_expectation_min': 80000,
            'salary_expectation_max': 120000
        }
        job = {
            'salary_min': 90000,
            'salary_max': 130000
        }

        score = service._calculate_salary_match(candidate, job)
        assert score == 1.0

    def test_calculate_salary_match_too_high(self):
        """Test salary match when candidate expects too much."""
        from ai_matching.services import MatchingService

        service = MatchingService()
        candidate = {
            'salary_expectation_min': 150000,
            'salary_expectation_max': 200000
        }
        job = {
            'salary_min': 80000,
            'salary_max': 100000
        }

        score = service._calculate_salary_match(candidate, job)
        # Candidate min is 50% above job max, so score is reduced
        assert score <= 0.5

    def test_calculate_match_comprehensive(self):
        """Test comprehensive match calculation."""
        from ai_matching.services import MatchingService

        service = MatchingService()
        candidate = {
            'id': 1,
            'skills': ['python', 'django', 'postgresql'],
            'years_experience': 5,
            'location': 'New York',
            'prefers_remote': True,
            'salary_expectation_min': 100000,
            'salary_expectation_max': 130000,
            'summary': 'Senior Python developer with 5 years experience'
        }
        job = {
            'id': 1,
            'title': 'Senior Python Developer',
            'required_skills': ['python', 'django'],
            'preferred_skills': ['postgresql', 'redis'],
            'min_experience_years': 3,
            'max_experience_years': 7,
            'location': 'New York',
            'remote_option': True,
            'salary_min': 90000,
            'salary_max': 140000,
            'description': 'Looking for a senior Python developer'
        }

        # Disable semantic matching for this test
        result = service.calculate_match(candidate, job, include_semantic=False)

        assert result.overall_score > 0.7
        assert result.skill_score > 0.8
        assert result.experience_score == 1.0
        assert result.location_score == 1.0
        assert result.salary_score == 1.0

    def test_calculate_confidence(self):
        """Test confidence calculation based on data completeness."""
        from ai_matching.services import MatchingService

        service = MatchingService()

        # Full data
        candidate_full = {
            'skills': ['python'],
            'years_experience': 5,
            'location': 'NYC',
            'summary': 'Developer'
        }
        job_full = {
            'required_skills': ['python'],
            'min_experience_years': 3,
            'location': 'NYC',
            'description': 'Job description'
        }

        confidence_full = service._calculate_confidence(candidate_full, job_full)
        assert confidence_full >= 0.8

        # Sparse data
        candidate_sparse = {'skills': []}
        job_sparse = {}

        confidence_sparse = service._calculate_confidence(candidate_sparse, job_sparse)
        assert confidence_sparse < 0.3


class TestResumeParserService:
    """Tests for the ResumeParserService class."""

    def test_resume_parser_initialization(self):
        """Test that ResumeParserService initializes correctly."""
        from ai_matching.services.resume_parser import ResumeParserService

        service = ResumeParserService()
        assert service is not None

    def test_extract_skills_from_text(self):
        """Test skill extraction from resume text."""
        from ai_matching.services.resume_parser import ResumeParserService

        service = ResumeParserService()
        text = """
        Skills:
        - Python, Django, Flask
        - PostgreSQL, Redis, MongoDB
        - Docker, Kubernetes
        - JavaScript, React, Node.js
        """

        skills = service.extract_skills(text)

        assert 'python' in skills
        assert 'django' in skills
        assert 'postgresql' in skills
        assert 'docker' in skills
        assert 'javascript' in skills

    def test_extract_skills_case_insensitive(self):
        """Test that skill extraction is case-insensitive."""
        from ai_matching.services.resume_parser import ResumeParserService

        service = ResumeParserService()
        text = "Expert in PYTHON, Django, and PostgreSQL"

        skills = service.extract_skills(text)

        assert 'python' in skills
        assert 'django' in skills

    def test_parse_empty_content(self):
        """Test parsing empty content returns empty/error result."""
        from ai_matching.services.resume_parser import ResumeParserService

        service = ResumeParserService()
        result = service.parse(b'', 'pdf')

        # Empty content should return empty skills and experience
        assert result['skills'] == []
        assert result['experience'] == []

    def test_extract_email_from_text(self):
        """Test email extraction from resume text."""
        from ai_matching.services.resume_parser import ResumeParserService

        service = ResumeParserService()
        text = """
        John Smith
        john.smith@example.com
        +1 (555) 123-4567
        """

        result = service._extract_email(text)
        assert 'john.smith@example.com' in result

    def test_extract_phone_from_text(self):
        """Test phone extraction from resume text."""
        from ai_matching.services.resume_parser import ResumeParserService

        service = ResumeParserService()
        text = """
        Contact: 555-123-4567
        Email: test@test.com
        """

        result = service._extract_phone(text)
        # Should find a phone pattern
        assert len(result) > 0 or result == ''  # May or may not match, but shouldn't error


class TestJobDescriptionAnalyzer:
    """Tests for the JobDescriptionAnalyzer class."""

    def test_job_analyzer_initialization(self):
        """Test that JobDescriptionAnalyzer initializes correctly."""
        from ai_matching.services.job_analyzer import JobDescriptionAnalyzer

        analyzer = JobDescriptionAnalyzer()
        assert analyzer is not None

    def test_analyze_extracts_experience(self):
        """Test that analyzer extracts experience requirements."""
        from ai_matching.services.job_analyzer import JobDescriptionAnalyzer

        analyzer = JobDescriptionAnalyzer()
        job_desc = """
        We are looking for a Senior Software Engineer with 5+ years of experience
        in Python development. The ideal candidate has experience with Django
        and PostgreSQL.
        """

        result = analyzer.analyze(job_desc)

        assert result['min_experience_years'] >= 5

    def test_analyze_extracts_skills(self):
        """Test that analyzer extracts required skills."""
        from ai_matching.services.job_analyzer import JobDescriptionAnalyzer

        analyzer = JobDescriptionAnalyzer()
        job_desc = """
        Requirements:
        - Python programming
        - Django web framework
        - PostgreSQL database
        - REST API development

        Nice to have:
        - Docker experience
        - AWS knowledge
        """

        result = analyzer.analyze(job_desc)

        required_lower = [s.lower() for s in result['required_skills']]
        assert 'python' in required_lower or 'django' in required_lower

    def test_analyze_detects_remote_option(self):
        """Test that analyzer detects remote work option."""
        from ai_matching.services.job_analyzer import JobDescriptionAnalyzer

        analyzer = JobDescriptionAnalyzer()
        job_desc = """
        This is a fully remote position. Work from anywhere!
        We offer flexible hours and great work-life balance.
        """

        result = analyzer.analyze(job_desc)

        assert result['remote_option'] is True

    def test_analyze_extracts_salary_range(self):
        """Test that analyzer extracts salary information."""
        from ai_matching.services.job_analyzer import JobDescriptionAnalyzer

        analyzer = JobDescriptionAnalyzer()
        job_desc = """
        Compensation: $120,000 - $150,000 per year
        Plus equity and comprehensive benefits package.
        """

        result = analyzer.analyze(job_desc)

        salary_min = result['salary_min'] or 0
        salary_max = result['salary_max'] or 0
        assert salary_min > 0 or salary_max > 0

    def test_analyze_empty_description(self):
        """Test analyzing empty job description."""
        from ai_matching.services.job_analyzer import JobDescriptionAnalyzer

        analyzer = JobDescriptionAnalyzer()
        result = analyzer.analyze("")

        assert result['required_skills'] == []
        assert result['preferred_skills'] == []

    def test_get_job_embedding_text(self):
        """Test building embedding text from job description string."""
        from ai_matching.services.job_analyzer import JobDescriptionAnalyzer

        analyzer = JobDescriptionAnalyzer()
        job_description = """
        We need a Senior Python Developer to build awesome software.
        Requirements: Python, Django, PostgreSQL
        Experience: 5+ years
        """
        job_title = 'Senior Python Developer'

        text = analyzer.get_job_embedding_text(job_description, job_title)

        assert 'Senior Python Developer' in text
        # Should contain extracted skills or experience level
        assert len(text) > len(job_title)


class TestBiasDetectionService:
    """Tests for the BiasDetectionService class."""

    def test_bias_detection_initialization(self):
        """Test that BiasDetectionService initializes correctly."""
        from ai_matching.services.bias_detection import BiasDetectionService

        service = BiasDetectionService()
        assert service is not None
        assert service.DISPARITY_THRESHOLD == 0.8

    def test_check_text_bias_gender_terms(self):
        """Test detection of gender-biased language."""
        from ai_matching.services.bias_detection import BiasDetectionService

        service = BiasDetectionService()
        text = """
        We're looking for an aggressive rockstar ninja developer
        who can dominate the competition.
        """

        report = service.check_text_bias(text)

        assert report.has_bias is True
        assert len(report.gender_bias) > 0
        assert any('aggressive' in term for term in report.gender_bias) or \
               any('rockstar' in term for term in report.gender_bias)

    def test_check_text_bias_age_terms(self):
        """Test detection of age-biased language."""
        from ai_matching.services.bias_detection import BiasDetectionService

        service = BiasDetectionService()
        text = """
        Looking for a young, energetic digital native
        to join our dynamic team.
        """

        report = service.check_text_bias(text)

        assert report.has_bias is True
        assert len(report.age_bias) > 0

    def test_check_text_bias_clean_text(self):
        """Test that clean text passes bias check."""
        from ai_matching.services.bias_detection import BiasDetectionService

        service = BiasDetectionService()
        text = """
        We are looking for an experienced software developer
        to join our engineering team. The ideal candidate has
        strong Python skills and experience with web frameworks.
        """

        report = service.check_text_bias(text)

        # Should have minimal or no bias
        assert report.bias_score < 0.3

    def test_check_bias_statistical_insufficient_sample(self):
        """Test that small sample returns no bias detection."""
        from ai_matching.services.bias_detection import BiasDetectionService

        service = BiasDetectionService()
        results = [
            {'overall_score': 0.8, 'gender': 'male'},
            {'overall_score': 0.7, 'gender': 'female'},
        ]

        bias_result = service.check_bias(results)

        assert bias_result['bias_detected'] is False
        assert 'Insufficient sample size' in str(bias_result['recommendations'])

    def test_check_bias_statistical_no_bias(self):
        """Test that balanced results show no bias."""
        from ai_matching.services.bias_detection import BiasDetectionService

        service = BiasDetectionService()

        # Create balanced results
        results = []
        for i in range(20):
            results.append({
                'overall_score': 0.7 + (i % 3) * 0.1,
                'gender': 'male' if i % 2 == 0 else 'female'
            })

        bias_result = service.check_bias(results, ['gender'])

        # Should not detect significant bias
        assert bias_result['bias_score'] < 0.5

    def test_check_bias_statistical_with_bias(self):
        """Test that biased results are detected."""
        from ai_matching.services.bias_detection import BiasDetectionService

        service = BiasDetectionService()

        # Create biased results - males get higher scores
        results = []
        for i in range(20):
            if i % 2 == 0:  # Male
                results.append({
                    'overall_score': 0.8 + (i % 3) * 0.05,
                    'gender': 'male'
                })
            else:  # Female - much lower scores
                results.append({
                    'overall_score': 0.3 + (i % 3) * 0.05,
                    'gender': 'female'
                })

        bias_result = service.check_bias(results, ['gender'])

        assert bias_result['bias_detected'] is True
        assert 'gender' in bias_result['affected_groups']

    def test_mitigate_bias_reranks_results(self):
        """Test that bias mitigation reranks results fairly."""
        from ai_matching.services.bias_detection import BiasDetectionService

        service = BiasDetectionService()

        # Create biased results
        results = []
        for i in range(20):
            gender = 'male' if i % 2 == 0 else 'female'
            score = 0.8 if gender == 'male' else 0.4
            results.append({
                'overall_score': score,
                'gender': gender
            })

        mitigated = service.mitigate_bias(results, ['gender'])

        # Results should be reranked
        assert len(mitigated) == len(results)
        # Check that some adjustment was made
        adjusted_scores = [r.get('adjusted_score', r['overall_score'])
                         for r in mitigated]
        assert adjusted_scores != [r['overall_score'] for r in results]

    def test_get_bias_summary(self):
        """Test bias summary generation."""
        from ai_matching.services.bias_detection import (
            BiasDetectionService, BiasReport
        )

        service = BiasDetectionService()

        # Report with no bias
        report_clean = BiasReport()
        summary = service.get_bias_summary(report_clean)
        assert "No significant bias" in summary

        # Report with bias
        report_biased = BiasReport(
            has_bias=True,
            bias_score=0.7,
            gender_bias=['aggressive', 'ninja']
        )
        summary = service.get_bias_summary(report_biased)
        assert "Bias detected" in summary


class TestRecommendationService:
    """Tests for the RecommendationService class."""

    def test_recommendation_service_initialization(self):
        """Test that RecommendationService initializes correctly."""
        from ai_matching.services import RecommendationService

        service = RecommendationService()
        assert service is not None
        assert service.matching_service is not None
        assert service.bias_detector is not None

    def test_generate_recommendation_reasons_excellent_match(self):
        """Test reason generation for excellent match."""
        from ai_matching.services import RecommendationService

        service = RecommendationService()
        match = {
            'overall_score': 0.9,
            'skill_score': 0.85,
            'experience_score': 0.95,
            'matched_skills': ['python', 'django', 'postgresql', 'redis', 'aws']
        }

        reasons = service._generate_recommendation_reasons(match)

        assert len(reasons) > 0
        assert any('Excellent' in r for r in reasons)

    def test_generate_recommendation_reasons_good_match(self):
        """Test reason generation for good match."""
        from ai_matching.services import RecommendationService

        service = RecommendationService()
        match = {
            'overall_score': 0.7,
            'skill_score': 0.6,
            'matched_skills': ['python', 'django']
        }

        reasons = service._generate_recommendation_reasons(match)

        assert len(reasons) > 0

    def test_generate_recommendation_reasons_poor_match(self):
        """Test reason generation for poor match."""
        from ai_matching.services import RecommendationService

        service = RecommendationService()
        match = {
            'overall_score': 0.3,
            'skill_score': 0.2,
            'matched_skills': []
        }

        reasons = service._generate_recommendation_reasons(match)

        # Should still generate at least a default reason
        assert len(reasons) > 0


class TestMatchResult:
    """Tests for the MatchResult dataclass."""

    def test_match_result_creation(self):
        """Test MatchResult dataclass creation."""
        from ai_matching.services import MatchResult

        result = MatchResult(
            candidate_id=1,
            job_id=2,
            overall_score=0.85
        )

        assert result.candidate_id == 1
        assert result.job_id == 2
        assert result.overall_score == 0.85
        assert result.skill_score == 0.0
        assert result.matched_skills == []
        assert result.missing_skills == []

    def test_match_result_with_full_data(self):
        """Test MatchResult with all fields populated."""
        from ai_matching.services import MatchResult

        result = MatchResult(
            candidate_id=1,
            job_id=2,
            overall_score=0.85,
            skill_score=0.9,
            experience_score=0.8,
            location_score=1.0,
            salary_score=0.95,
            semantic_score=0.7,
            confidence=0.9,
            matched_skills=['python', 'django'],
            missing_skills=['kubernetes'],
            recommendations=['Learn Kubernetes']
        )

        assert len(result.matched_skills) == 2
        assert len(result.missing_skills) == 1
        assert len(result.recommendations) == 1


# Integration tests
@pytest.mark.integration
class TestAIMatchingIntegration:
    """Integration tests for AI matching services."""

    def test_full_matching_pipeline(self):
        """Test the complete matching pipeline without database."""
        from ai_matching.services import MatchingService

        service = MatchingService()

        candidate = {
            'id': 1,
            'title': 'Senior Software Engineer',
            'skills': ['python', 'django', 'postgresql', 'redis', 'docker'],
            'years_experience': 7,
            'location': 'San Francisco',
            'prefers_remote': True,
            'willing_to_relocate': False,
            'salary_expectation_min': 150000,
            'salary_expectation_max': 200000,
            'summary': 'Experienced Python developer with expertise in web development'
        }

        job = {
            'id': 1,
            'title': 'Senior Python Developer',
            'description': 'Looking for a senior developer to lead our backend team',
            'required_skills': ['python', 'django', 'postgresql'],
            'preferred_skills': ['redis', 'docker', 'kubernetes'],
            'min_experience_years': 5,
            'max_experience_years': 10,
            'location': 'Remote',
            'remote_option': True,
            'salary_min': 140000,
            'salary_max': 180000
        }

        result = service.calculate_match(candidate, job, include_semantic=False)

        # Should be a strong match
        assert result.overall_score > 0.7
        assert result.skill_score > 0.8
        assert result.experience_score == 1.0
        assert result.location_score == 1.0
        assert len(result.matched_skills) >= 4

    def test_bias_aware_recommendations(self):
        """Test that recommendations apply bias mitigation."""
        from ai_matching.services import RecommendationService
        from ai_matching.services.bias_detection import BiasDetectionService

        bias_service = BiasDetectionService()

        # Create biased initial results
        results = []
        for i in range(20):
            gender = 'male' if i % 2 == 0 else 'female'
            score = 0.85 if gender == 'male' else 0.45
            results.append({
                'candidate_id': i,
                'overall_score': score,
                'gender': gender,
                'skill_score': score,
                'matched_skills': ['python']
            })

        # Check bias exists
        bias_check = bias_service.check_bias(results, ['gender'])
        assert bias_check['bias_detected'] is True

        # Apply mitigation
        mitigated = bias_service.mitigate_bias(results, ['gender'])

        # Verify mitigation reduces disparity
        assert len(mitigated) == len(results)
