"""
Celery Tasks for AI Matching

This module contains asynchronous tasks for the AI matching service,
including batch processing, embedding updates, and recommendation refresh.
"""

import logging
from typing import List, Optional
from decimal import Decimal

from celery import shared_task
from django.utils import timezone
from django.db import transaction

logger = logging.getLogger(__name__)


# ============================================================================
# Match Score Calculation Tasks
# ============================================================================

@shared_task(
    name='ai_matching.calculate_match_scores',
    bind=True,
    max_retries=3,
    default_retry_delay=60
)
def calculate_match_scores(
    self,
    job_ids: Optional[List[int]] = None,
    candidate_ids: Optional[List[int]] = None,
    recalculate: bool = False
):
    """
    Calculate match scores for job-candidate pairs.

    Args:
        job_ids: List of job IDs to process. If None, processes all active jobs.
        candidate_ids: List of candidate IDs to process. If None, processes all candidates.
        recalculate: Whether to recalculate existing matches.

    Returns:
        Dict with processing statistics
    """
    from configurations.models import Job, CandidateProfile
    from .models import MatchingResult
    from .services import MatchingService

    try:
        logger.info(
            f"Starting match score calculation. Jobs: {job_ids}, "
            f"Candidates: {candidate_ids}, Recalculate: {recalculate}"
        )

        # Get jobs
        jobs_qs = Job.objects.filter(is_active=True)
        if job_ids:
            jobs_qs = jobs_qs.filter(id__in=job_ids)
        jobs = list(jobs_qs)

        # Get candidates
        candidates_qs = CandidateProfile.objects.all()
        if candidate_ids:
            candidates_qs = candidates_qs.filter(id__in=candidate_ids)
        candidates = list(candidates_qs)

        logger.info(f"Processing {len(jobs)} jobs and {len(candidates)} candidates")

        matching_service = MatchingService()
        stats = {
            'total_pairs': len(jobs) * len(candidates),
            'new_matches': 0,
            'updated_matches': 0,
            'skipped': 0,
            'errors': []
        }

        for job in jobs:
            for candidate in candidates:
                try:
                    # Check if match exists and is not stale
                    if not recalculate:
                        existing = MatchingResult.objects.filter(
                            job=job,
                            candidate=candidate,
                            is_stale=False
                        ).first()

                        if existing and not existing.is_expired:
                            stats['skipped'] += 1
                            continue

                    # Calculate match
                    match_result = matching_service.calculate_match(candidate, job)

                    # Save result
                    with transaction.atomic():
                        obj, created = MatchingResult.objects.update_or_create(
                            job=job,
                            candidate=candidate,
                            defaults={
                                'overall_score': Decimal(str(match_result['overall_score'])),
                                'skill_score': Decimal(str(match_result.get('skill_score', 0))),
                                'experience_score': Decimal(str(match_result.get('experience_score', 0))),
                                'location_score': Decimal(str(match_result.get('location_score', 0))),
                                'salary_score': Decimal(str(match_result.get('salary_score', 0))),
                                'culture_score': Decimal(str(match_result.get('culture_score', 0))),
                                'education_score': Decimal(str(match_result.get('education_score', 0))),
                                'matching_algorithm': match_result.get('algorithm', 'unknown'),
                                'confidence_level': match_result.get('confidence', 'medium'),
                                'matched_skills': match_result.get('matched_skills', []),
                                'missing_skills': match_result.get('missing_skills', []),
                                'explanation': match_result.get('explanation', {}),
                                'expires_at': timezone.now() + timezone.timedelta(hours=24),
                                'is_stale': False
                            }
                        )

                        if created:
                            stats['new_matches'] += 1
                        else:
                            stats['updated_matches'] += 1

                except Exception as e:
                    logger.warning(f"Error matching job {job.id} - candidate {candidate.id}: {e}")
                    stats['errors'].append({
                        'job_id': job.id,
                        'candidate_id': candidate.id,
                        'error': str(e)
                    })

        logger.info(f"Match calculation completed. Stats: {stats}")
        return stats

    except Exception as e:
        logger.error(f"Match calculation task failed: {e}")
        self.retry(exc=e)


@shared_task(
    name='ai_matching.calculate_single_match',
    bind=True,
    max_retries=3
)
def calculate_single_match(self, job_id: int, candidate_id: int):
    """
    Calculate match score for a single job-candidate pair.

    Args:
        job_id: Job ID
        candidate_id: Candidate profile ID

    Returns:
        Match result dict
    """
    from configurations.models import Job, CandidateProfile
    from .models import MatchingResult
    from .services import MatchingService

    try:
        job = Job.objects.get(id=job_id)
        candidate = CandidateProfile.objects.get(id=candidate_id)

        matching_service = MatchingService()
        match_result = matching_service.calculate_match(candidate, job)

        # Save result
        MatchingResult.objects.update_or_create(
            job=job,
            candidate=candidate,
            defaults={
                'overall_score': Decimal(str(match_result['overall_score'])),
                'skill_score': Decimal(str(match_result.get('skill_score', 0))),
                'experience_score': Decimal(str(match_result.get('experience_score', 0))),
                'location_score': Decimal(str(match_result.get('location_score', 0))),
                'salary_score': Decimal(str(match_result.get('salary_score', 0))),
                'matching_algorithm': match_result.get('algorithm', 'unknown'),
                'confidence_level': match_result.get('confidence', 'medium'),
                'matched_skills': match_result.get('matched_skills', []),
                'missing_skills': match_result.get('missing_skills', []),
                'explanation': match_result.get('explanation', {}),
                'expires_at': timezone.now() + timezone.timedelta(hours=24),
                'is_stale': False
            }
        )

        return match_result

    except (Job.DoesNotExist, CandidateProfile.DoesNotExist) as e:
        logger.error(f"Job or Candidate not found: {e}")
        raise
    except Exception as e:
        logger.error(f"Single match calculation failed: {e}")
        self.retry(exc=e)


# ============================================================================
# Embedding Update Tasks
# ============================================================================

@shared_task(
    name='ai_matching.update_embeddings',
    bind=True,
    max_retries=3,
    default_retry_delay=120
)
def update_embeddings(
    self,
    entity_type: str = 'all',
    entity_ids: Optional[List[int]] = None,
    force: bool = False
):
    """
    Update embeddings for jobs and/or candidates.

    Args:
        entity_type: 'jobs', 'candidates', 'skills', or 'all'
        entity_ids: Specific IDs to update. If None, updates all.
        force: Whether to regenerate existing embeddings.

    Returns:
        Dict with processing statistics
    """
    from configurations.models import Job, CandidateProfile, Skill
    from .models import JobEmbedding, CandidateEmbedding, SkillEmbedding
    from .services import EmbeddingService

    try:
        logger.info(f"Starting embedding update. Type: {entity_type}, Force: {force}")

        embedding_service = EmbeddingService()
        stats = {
            'jobs_processed': 0,
            'candidates_processed': 0,
            'skills_processed': 0,
            'errors': []
        }

        # Update job embeddings
        if entity_type in ('jobs', 'all'):
            jobs_qs = Job.objects.filter(is_active=True)
            if entity_ids and entity_type == 'jobs':
                jobs_qs = jobs_qs.filter(id__in=entity_ids)

            for job in jobs_qs:
                try:
                    # Check if embedding exists and should be updated
                    if not force:
                        existing = JobEmbedding.objects.filter(job=job).first()
                        if existing and (timezone.now() - existing.updated_at).days < 7:
                            continue

                    # Generate embedding
                    text = f"{job.title} {job.description} {job.requirements}"
                    result = embedding_service.execute(text)

                    if result.success:
                        JobEmbedding.objects.update_or_create(
                            job=job,
                            defaults={
                                'embedding_vector': result.vector,
                                'embedding_model': result.model
                            }
                        )
                        stats['jobs_processed'] += 1

                except Exception as e:
                    logger.warning(f"Error updating job {job.id} embedding: {e}")
                    stats['errors'].append({'type': 'job', 'id': job.id, 'error': str(e)})

        # Update candidate embeddings
        if entity_type in ('candidates', 'all'):
            candidates_qs = CandidateProfile.objects.all()
            if entity_ids and entity_type == 'candidates':
                candidates_qs = candidates_qs.filter(id__in=entity_ids)

            for candidate in candidates_qs:
                try:
                    if not force:
                        existing = CandidateEmbedding.objects.filter(candidate=candidate).first()
                        if existing and (timezone.now() - existing.updated_at).days < 7:
                            continue

                    # Build text representation
                    text_parts = [candidate.bio or '']
                    text_parts.extend(candidate.skills.values_list('name', flat=True))

                    for exp in candidate.work_experiences.all():
                        text_parts.append(f"{exp.job_title} {exp.description}")

                    text = ' '.join(text_parts)
                    result = embedding_service.execute(text)

                    if result.success:
                        CandidateEmbedding.objects.update_or_create(
                            candidate=candidate,
                            defaults={
                                'embedding_vector': result.vector,
                                'embedding_model': result.model,
                                'skills_extracted': list(
                                    candidate.skills.values_list('name', flat=True)
                                )
                            }
                        )
                        stats['candidates_processed'] += 1

                except Exception as e:
                    logger.warning(f"Error updating candidate {candidate.id} embedding: {e}")
                    stats['errors'].append({
                        'type': 'candidate',
                        'id': candidate.id,
                        'error': str(e)
                    })

        # Update skill embeddings
        if entity_type in ('skills', 'all'):
            skills_qs = Skill.objects.all()
            if entity_ids and entity_type == 'skills':
                skills_qs = skills_qs.filter(id__in=entity_ids)

            for skill in skills_qs:
                try:
                    if not force:
                        existing = SkillEmbedding.objects.filter(skill=skill).first()
                        if existing and (timezone.now() - existing.updated_at).days < 30:
                            continue

                    text = f"{skill.name} {skill.description}"
                    result = embedding_service.execute(text)

                    if result.success:
                        SkillEmbedding.objects.update_or_create(
                            skill=skill,
                            defaults={
                                'embedding_vector': result.vector,
                                'embedding_model': result.model
                            }
                        )
                        stats['skills_processed'] += 1

                except Exception as e:
                    logger.warning(f"Error updating skill {skill.id} embedding: {e}")
                    stats['errors'].append({
                        'type': 'skill',
                        'id': skill.id,
                        'error': str(e)
                    })

        logger.info(f"Embedding update completed. Stats: {stats}")
        return stats

    except Exception as e:
        logger.error(f"Embedding update task failed: {e}")
        self.retry(exc=e)


@shared_task(name='ai_matching.update_job_embedding')
def update_job_embedding(job_id: int):
    """Update embedding for a single job."""
    return update_embeddings.delay(entity_type='jobs', entity_ids=[job_id], force=True)


@shared_task(name='ai_matching.update_candidate_embedding')
def update_candidate_embedding(candidate_id: int):
    """Update embedding for a single candidate."""
    return update_embeddings.delay(
        entity_type='candidates',
        entity_ids=[candidate_id],
        force=True
    )


# ============================================================================
# Recommendation Refresh Tasks
# ============================================================================

@shared_task(
    name='ai_matching.refresh_recommendations',
    bind=True,
    max_retries=2
)
def refresh_recommendations(self, user_id: int, recommendation_type: str = 'jobs_for_candidate'):
    """
    Refresh recommendations for a user.

    Args:
        user_id: User ID to refresh recommendations for
        recommendation_type: Type of recommendations to refresh

    Returns:
        Dict with refresh results
    """
    from django.contrib.auth import get_user_model
    from configurations.models import CandidateProfile, Job
    from .services import RecommendationService

    User = get_user_model()

    try:
        user = User.objects.get(id=user_id)
        recommendation_service = RecommendationService()

        if recommendation_type == 'jobs_for_candidate':
            try:
                candidate = CandidateProfile.objects.get(user=user)
                recommendations = recommendation_service.get_jobs_for_candidate(
                    candidate,
                    limit=50
                )
                return {
                    'user_id': user_id,
                    'type': recommendation_type,
                    'count': len(recommendations)
                }
            except CandidateProfile.DoesNotExist:
                return {'error': 'No candidate profile for user'}

        elif recommendation_type == 'candidates_for_job':
            # Get jobs owned by user's company
            jobs = Job.objects.filter(
                company__profile__memberships__user=user,
                is_active=True
            )

            total_recommendations = 0
            for job in jobs:
                recommendations = recommendation_service.get_candidates_for_job(
                    job,
                    limit=50
                )
                total_recommendations += len(recommendations)

            return {
                'user_id': user_id,
                'type': recommendation_type,
                'jobs_processed': jobs.count(),
                'total_recommendations': total_recommendations
            }

    except User.DoesNotExist:
        return {'error': 'User not found'}
    except Exception as e:
        logger.error(f"Recommendation refresh failed: {e}")
        self.retry(exc=e)


@shared_task(name='ai_matching.refresh_all_recommendations')
def refresh_all_recommendations():
    """Refresh recommendations for all active users."""
    from django.contrib.auth import get_user_model
    from configurations.models import CandidateProfile

    User = get_user_model()

    # Get users with candidate profiles
    candidate_users = CandidateProfile.objects.values_list('user_id', flat=True)

    for user_id in candidate_users:
        refresh_recommendations.delay(user_id, 'jobs_for_candidate')

    return {'users_queued': len(candidate_users)}


# ============================================================================
# Cleanup and Maintenance Tasks
# ============================================================================

@shared_task(name='ai_matching.cleanup_stale_matches')
def cleanup_stale_matches(days: int = 7):
    """
    Mark old match results as stale and optionally delete very old ones.

    Args:
        days: Age threshold in days for marking as stale

    Returns:
        Dict with cleanup statistics
    """
    from .models import MatchingResult

    cutoff = timezone.now() - timezone.timedelta(days=days)
    delete_cutoff = timezone.now() - timezone.timedelta(days=days * 4)

    # Mark as stale
    stale_count = MatchingResult.objects.filter(
        calculated_at__lt=cutoff,
        is_stale=False
    ).update(is_stale=True)

    # Delete very old matches
    deleted_count, _ = MatchingResult.objects.filter(
        calculated_at__lt=delete_cutoff
    ).delete()

    logger.info(f"Cleanup completed. Marked stale: {stale_count}, Deleted: {deleted_count}")

    return {
        'marked_stale': stale_count,
        'deleted': deleted_count
    }


@shared_task(name='ai_matching.reset_daily_api_counts')
def reset_daily_api_counts():
    """Reset daily API request counts for AI services."""
    from .models import AIServiceStatus

    AIServiceStatus.objects.all().update(requests_today=0)
    logger.info("Daily API counts reset")

    return {'status': 'reset'}


@shared_task(name='ai_matching.check_ai_service_health')
def check_ai_service_health():
    """
    Check health of AI services and update their status.

    Returns:
        Dict with health check results
    """
    from .models import AIServiceStatus
    from .services import EmbeddingService

    results = {}

    # Check OpenAI embedding service
    try:
        service = EmbeddingService()
        result = service.execute("test")

        status_obj, _ = AIServiceStatus.objects.get_or_create(
            service_name='openai_embedding',
            defaults={'is_available': True}
        )

        if result.success and result.model != 'local_fallback':
            status_obj.record_success()
            results['openai_embedding'] = 'healthy'
        else:
            status_obj.record_failure('Using fallback')
            results['openai_embedding'] = 'degraded'

    except Exception as e:
        logger.warning(f"OpenAI health check failed: {e}")
        results['openai_embedding'] = 'unhealthy'

    return results


# ============================================================================
# NEW TASKS FOR CYCLE 7 - Enhanced AI Matching
# ============================================================================

@shared_task(
    name='ai_matching.process_candidate_profile',
    bind=True,
    max_retries=3,
    default_retry_delay=60
)
def process_candidate_profile(self, candidate_id: int, force: bool = False):
    """
    Generate/update candidate matching profile with embeddings.

    Creates or updates MatchingProfile with:
    - Sentence-transformer embeddings
    - Normalized skills
    - Experience and education scores

    Args:
        candidate_id: Candidate ID to process
        force: Whether to force reprocessing even if profile exists

    Returns:
        Dict with processing results
    """
    from jobs.models import Candidate
    from .models import MatchingProfile, AIModelVersion
    from .services import (
        SentenceTransformerEmbeddingService,
        SkillNormalizationService,
        CandidateMatchingService
    )

    try:
        candidate = Candidate.objects.get(id=candidate_id)

        # Check if processing needed
        try:
            profile = candidate.matching_profile
            if not force and not profile.is_stale and profile.processing_status == 'completed':
                logger.info(f"Candidate {candidate_id} profile is current, skipping")
                return {'status': 'skipped', 'reason': 'profile_current'}
        except MatchingProfile.DoesNotExist:
            profile = None

        logger.info(f"Processing candidate {candidate_id} matching profile")

        # Get services
        embedding_service = SentenceTransformerEmbeddingService()
        skill_service = SkillNormalizationService()
        matching_service = CandidateMatchingService()

        # Mark as processing
        if profile:
            profile.processing_status = 'processing'
            profile.save(update_fields=['processing_status'])

        # Build text for embedding
        text_parts = []
        skills = []

        if hasattr(candidate, 'resume_text') and candidate.resume_text:
            text_parts.append(candidate.resume_text)

        if hasattr(candidate, 'skills'):
            skills = list(candidate.skills.values_list('name', flat=True))
            text_parts.append(' '.join(skills))

        if hasattr(candidate, 'summary') and candidate.summary:
            text_parts.append(candidate.summary)

        combined_text = ' '.join(text_parts) or candidate.name

        # Generate embeddings
        main_embedding = embedding_service.execute(combined_text)

        # Generate component embeddings
        skills_text = ' '.join(skills) if skills else ''
        skills_embedding = embedding_service.execute(skills_text) if skills_text else None

        # Normalize skills
        normalized_skills = skill_service.normalize_skill_list(skills)

        # Calculate scores
        experience_score = matching_service._compute_experience_score_value(candidate)
        education_score = matching_service._compute_education_score_value(candidate)

        # Get model version
        model_version = AIModelVersion.get_active_version('embedding')
        version_str = model_version.version if model_version else '1.0.0'

        # Create/update profile
        profile, created = MatchingProfile.objects.update_or_create(
            tenant=candidate.tenant if hasattr(candidate, 'tenant') else None,
            candidate=candidate,
            defaults={
                'embedding': main_embedding.vector if main_embedding.success else None,
                'skills_embedding': (
                    skills_embedding.vector if skills_embedding and skills_embedding.success else None
                ),
                'skills_normalized': normalized_skills,
                'experience_score': experience_score,
                'education_score': education_score,
                'overall_quality_score': (experience_score + education_score) / 2,
                'processing_status': 'completed',
                'processing_version': version_str,
                'processing_error': '',
            }
        )

        logger.info(f"Candidate {candidate_id} profile {'created' if created else 'updated'}")

        return {
            'status': 'success',
            'candidate_id': candidate_id,
            'created': created,
            'skills_normalized': len(normalized_skills),
            'embedding_model': main_embedding.model,
        }

    except Candidate.DoesNotExist:
        logger.error(f"Candidate {candidate_id} not found")
        return {'status': 'error', 'reason': 'candidate_not_found'}
    except Exception as e:
        logger.error(f"Error processing candidate {candidate_id}: {e}")

        # Mark profile as failed
        try:
            profile = MatchingProfile.objects.get(candidate_id=candidate_id)
            profile.processing_status = 'failed'
            profile.processing_error = str(e)
            profile.save(update_fields=['processing_status', 'processing_error'])
        except MatchingProfile.DoesNotExist:
            pass

        self.retry(exc=e)


@shared_task(
    name='ai_matching.process_job_profile',
    bind=True,
    max_retries=3,
    default_retry_delay=60
)
def process_job_profile(self, job_id: int, force: bool = False):
    """
    Generate/update job matching profile with embeddings.

    Args:
        job_id: JobPosting ID to process
        force: Whether to force reprocessing

    Returns:
        Dict with processing results
    """
    from jobs.models import JobPosting
    from .models import JobMatchingProfile, AIModelVersion
    from .services import SentenceTransformerEmbeddingService, SkillNormalizationService

    try:
        job = JobPosting.objects.get(id=job_id)

        # Check if processing needed
        try:
            profile = job.matching_profile
            if not force and profile.processing_status == 'completed':
                age_days = (timezone.now() - profile.last_processed).days
                if age_days < 7:
                    logger.info(f"Job {job_id} profile is current, skipping")
                    return {'status': 'skipped', 'reason': 'profile_current'}
        except JobMatchingProfile.DoesNotExist:
            profile = None

        logger.info(f"Processing job {job_id} matching profile")

        embedding_service = SentenceTransformerEmbeddingService()
        skill_service = SkillNormalizationService()

        # Mark as processing
        if profile:
            profile.processing_status = 'processing'
            profile.save(update_fields=['processing_status'])

        # Build text for embedding
        text_parts = [job.title]
        if hasattr(job, 'description') and job.description:
            text_parts.append(job.description)
        if hasattr(job, 'requirements') and job.requirements:
            text_parts.append(job.requirements)

        combined_text = ' '.join(text_parts)

        # Generate embeddings
        main_embedding = embedding_service.execute(combined_text)
        title_embedding = embedding_service.execute(job.title)

        # Extract and normalize skills
        required_skills = []
        nice_to_have = []

        if hasattr(job, 'requirements') and job.requirements:
            required_skills = skill_service._extract_skills_from_text(job.requirements)
        if hasattr(job, 'nice_to_have') and job.nice_to_have:
            nice_to_have = skill_service._extract_skills_from_text(job.nice_to_have)

        normalized_required = skill_service.normalize_skill_list(required_skills)
        normalized_nice = skill_service.normalize_skill_list(nice_to_have)

        # Get model version
        model_version = AIModelVersion.get_active_version('embedding')
        version_str = model_version.version if model_version else '1.0.0'

        # Create/update profile
        profile, created = JobMatchingProfile.objects.update_or_create(
            tenant=job.tenant if hasattr(job, 'tenant') else None,
            job=job,
            defaults={
                'embedding': main_embedding.vector if main_embedding.success else None,
                'title_embedding': title_embedding.vector if title_embedding.success else None,
                'required_skills_normalized': normalized_required,
                'nice_to_have_normalized': normalized_nice,
                'min_experience_years': getattr(job, 'min_experience', None),
                'max_experience_years': getattr(job, 'max_experience', None),
                'is_remote': getattr(job, 'is_remote', None),
                'processing_status': 'completed',
                'processing_version': version_str,
                'processing_error': '',
            }
        )

        logger.info(f"Job {job_id} profile {'created' if created else 'updated'}")

        return {
            'status': 'success',
            'job_id': job_id,
            'created': created,
            'required_skills': len(normalized_required),
            'nice_to_have_skills': len(normalized_nice),
        }

    except JobPosting.DoesNotExist:
        logger.error(f"Job {job_id} not found")
        return {'status': 'error', 'reason': 'job_not_found'}
    except Exception as e:
        logger.error(f"Error processing job {job_id}: {e}")

        try:
            profile = JobMatchingProfile.objects.get(job_id=job_id)
            profile.processing_status = 'failed'
            profile.processing_error = str(e)
            profile.save(update_fields=['processing_status', 'processing_error'])
        except JobMatchingProfile.DoesNotExist:
            pass

        self.retry(exc=e)


@shared_task(
    name='ai_matching.batch_compute_matches',
    bind=True,
    max_retries=2,
    default_retry_delay=300
)
def batch_compute_matches(
    self,
    job_id: int,
    min_score: float = 0.0,
    limit: int = 500
):
    """
    Compute matches for all candidates for a single job.

    Args:
        job_id: JobPosting ID to match candidates against
        min_score: Minimum score threshold to save
        limit: Maximum candidates to process

    Returns:
        Dict with batch processing results
    """
    from jobs.models import JobPosting, Candidate
    from .services import CandidateMatchingService

    try:
        job = JobPosting.objects.get(id=job_id)
        logger.info(f"Starting batch match computation for job {job_id}")

        matching_service = CandidateMatchingService()

        # Get all active candidates
        candidates = Candidate.objects.filter(
            status__in=['active', 'available']
        )[:limit]

        stats = {
            'job_id': job_id,
            'candidates_processed': 0,
            'matches_created': 0,
            'below_threshold': 0,
            'errors': 0,
        }

        for candidate in candidates:
            try:
                match_result = matching_service.match_candidate_to_job(candidate, job)

                if match_result.overall_score >= min_score:
                    stats['matches_created'] += 1
                else:
                    stats['below_threshold'] += 1

                stats['candidates_processed'] += 1

            except Exception as e:
                logger.warning(f"Error matching candidate {candidate.id} to job {job_id}: {e}")
                stats['errors'] += 1

        logger.info(f"Batch match completed for job {job_id}. Stats: {stats}")
        return stats

    except JobPosting.DoesNotExist:
        logger.error(f"Job {job_id} not found")
        return {'status': 'error', 'reason': 'job_not_found'}
    except Exception as e:
        logger.error(f"Batch match computation failed for job {job_id}: {e}")
        self.retry(exc=e)


@shared_task(
    name='ai_matching.batch_process_candidate_profiles',
    bind=True,
    max_retries=2
)
def batch_process_candidate_profiles(
    self,
    candidate_ids: Optional[List[int]] = None,
    force: bool = False
):
    """
    Process multiple candidate profiles in batch.

    Args:
        candidate_ids: List of candidate IDs to process. If None, processes all pending.
        force: Whether to force reprocessing

    Returns:
        Dict with batch results
    """
    from jobs.models import Candidate
    from .models import MatchingProfile

    try:
        if candidate_ids:
            candidates = Candidate.objects.filter(id__in=candidate_ids)
        else:
            # Get candidates needing processing
            existing_profile_ids = MatchingProfile.objects.filter(
                processing_status='completed'
            ).values_list('candidate_id', flat=True)

            candidates = Candidate.objects.exclude(
                id__in=existing_profile_ids
            )[:200]  # Limit batch size

        stats = {
            'total': 0,
            'queued': 0,
            'errors': 0,
        }

        for candidate in candidates:
            try:
                process_candidate_profile.delay(candidate.id, force=force)
                stats['queued'] += 1
            except Exception as e:
                logger.warning(f"Failed to queue candidate {candidate.id}: {e}")
                stats['errors'] += 1

            stats['total'] += 1

        logger.info(f"Batch candidate profile processing queued: {stats}")
        return stats

    except Exception as e:
        logger.error(f"Batch candidate profile processing failed: {e}")
        self.retry(exc=e)


@shared_task(
    name='ai_matching.batch_process_job_profiles',
    bind=True,
    max_retries=2
)
def batch_process_job_profiles(
    self,
    job_ids: Optional[List[int]] = None,
    force: bool = False
):
    """
    Process multiple job profiles in batch.

    Args:
        job_ids: List of job IDs to process. If None, processes all open jobs.
        force: Whether to force reprocessing

    Returns:
        Dict with batch results
    """
    from jobs.models import JobPosting
    from .models import JobMatchingProfile

    try:
        if job_ids:
            jobs = JobPosting.objects.filter(id__in=job_ids)
        else:
            # Get open jobs needing processing
            existing_profile_ids = JobMatchingProfile.objects.filter(
                processing_status='completed'
            ).values_list('job_id', flat=True)

            jobs = JobPosting.objects.filter(
                status='open'
            ).exclude(
                id__in=existing_profile_ids
            )[:100]

        stats = {
            'total': 0,
            'queued': 0,
            'errors': 0,
        }

        for job in jobs:
            try:
                process_job_profile.delay(job.id, force=force)
                stats['queued'] += 1
            except Exception as e:
                logger.warning(f"Failed to queue job {job.id}: {e}")
                stats['errors'] += 1

            stats['total'] += 1

        logger.info(f"Batch job profile processing queued: {stats}")
        return stats

    except Exception as e:
        logger.error(f"Batch job profile processing failed: {e}")
        self.retry(exc=e)


@shared_task(name='ai_matching.mark_stale_profiles')
def mark_stale_profiles(days: int = 7):
    """
    Mark profiles older than threshold as needing reprocessing.

    Args:
        days: Age threshold in days

    Returns:
        Dict with counts of profiles marked stale
    """
    from .models import MatchingProfile, JobMatchingProfile

    cutoff = timezone.now() - timezone.timedelta(days=days)

    candidate_count = MatchingProfile.objects.filter(
        last_processed__lt=cutoff,
        processing_status='completed'
    ).update(processing_status='pending')

    job_count = JobMatchingProfile.objects.filter(
        last_processed__lt=cutoff,
        processing_status='completed'
    ).update(processing_status='pending')

    logger.info(f"Marked stale: {candidate_count} candidate profiles, {job_count} job profiles")

    return {
        'candidate_profiles_marked': candidate_count,
        'job_profiles_marked': job_count,
    }


@shared_task(name='ai_matching.compute_bias_metrics')
def compute_bias_metrics(
    job_id: Optional[int] = None,
    period_days: int = 30
):
    """
    Compute bias metrics for matching results.

    Args:
        job_id: Optional job ID to scope metrics
        period_days: Period to analyze

    Returns:
        Dict with bias metrics
    """
    from .models import MatchResult, BiasMetric
    from .services import EnhancedBiasDetectionService
    import statistics

    try:
        period_start = timezone.now().date() - timezone.timedelta(days=period_days)
        period_end = timezone.now().date()

        # Get match results
        results_qs = MatchResult.objects.filter(
            computed_at__gte=period_start,
            computed_at__lte=period_end
        )

        if job_id:
            results_qs = results_qs.filter(job_id=job_id)

        results = list(results_qs)

        if not results:
            return {'status': 'no_data'}

        bias_service = EnhancedBiasDetectionService()
        report = bias_service.check_for_bias(results)

        # Calculate score distribution
        scores = [r.overall_score for r in results]
        score_distribution = {
            'mean': round(statistics.mean(scores), 4),
            'std': round(statistics.stdev(scores), 4) if len(scores) > 1 else 0,
            'min': min(scores),
            'max': max(scores),
        }

        # Save metrics
        metric, _ = BiasMetric.objects.update_or_create(
            tenant=results[0].tenant if results else None,
            job_id=job_id,
            period_start=period_start,
            period_end=period_end,
            defaults={
                'total_candidates_evaluated': len(results),
                'total_matches_computed': len(results),
                'score_distribution': score_distribution,
                'bias_detected': report.has_bias,
                'bias_types': report.other_bias,
                'recommendations': report.suggestions,
            }
        )

        logger.info(f"Bias metrics computed. Bias detected: {report.has_bias}")

        return {
            'status': 'success',
            'candidates_evaluated': len(results),
            'bias_detected': report.has_bias,
            'issues': report.other_bias,
        }

    except Exception as e:
        logger.error(f"Bias metrics computation failed: {e}")
        raise


# ============================================================================
# Scheduled Tasks Configuration
# ============================================================================

# These can be added to CELERY_BEAT_SCHEDULE in settings.py:
#
# CELERY_BEAT_SCHEDULE = {
#     'refresh-all-recommendations-daily': {
#         'task': 'ai_matching.refresh_all_recommendations',
#         'schedule': crontab(hour=2, minute=0),  # 2 AM daily
#     },
#     'cleanup-stale-matches-daily': {
#         'task': 'ai_matching.cleanup_stale_matches',
#         'schedule': crontab(hour=3, minute=0),  # 3 AM daily
#     },
#     'reset-api-counts-daily': {
#         'task': 'ai_matching.reset_daily_api_counts',
#         'schedule': crontab(hour=0, minute=0),  # Midnight daily
#     },
#     'check-ai-health-hourly': {
#         'task': 'ai_matching.check_ai_service_health',
#         'schedule': crontab(minute=0),  # Every hour
#     },
#     'update-embeddings-weekly': {
#         'task': 'ai_matching.update_embeddings',
#         'schedule': crontab(hour=4, minute=0, day_of_week=0),  # Sunday 4 AM
#         'kwargs': {'entity_type': 'all', 'force': False}
#     },
#     # NEW CYCLE 7 TASKS
#     'batch-process-candidate-profiles-daily': {
#         'task': 'ai_matching.batch_process_candidate_profiles',
#         'schedule': crontab(hour=1, minute=30),  # 1:30 AM daily
#     },
#     'batch-process-job-profiles-daily': {
#         'task': 'ai_matching.batch_process_job_profiles',
#         'schedule': crontab(hour=1, minute=0),  # 1 AM daily
#     },
#     'mark-stale-profiles-weekly': {
#         'task': 'ai_matching.mark_stale_profiles',
#         'schedule': crontab(hour=0, minute=30, day_of_week=0),  # Sunday 12:30 AM
#     },
#     'compute-bias-metrics-weekly': {
#         'task': 'ai_matching.compute_bias_metrics',
#         'schedule': crontab(hour=5, minute=0, day_of_week=1),  # Monday 5 AM
#     },
# }
