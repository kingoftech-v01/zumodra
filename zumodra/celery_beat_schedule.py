"""
Celery Beat Schedule Configuration for Zumodra

This module defines all periodic task schedules using Celery Beat.
Tasks are organized by category for better maintainability.

Schedule Format:
- crontab(minute, hour, day_of_week, day_of_month, month_of_year)
- timedelta for interval-based schedules

Priority Levels:
- High Priority: Financial, transactional, security tasks
- Medium Priority: User-facing, notifications, HR tasks
- Low Priority: Analytics, maintenance, cleanup tasks
"""

from celery.schedules import crontab
from datetime import timedelta


CELERY_BEAT_SCHEDULE = {
    # ==========================================================================
    # CACHE & PERFORMANCE TASKS (Hourly)
    # ==========================================================================

    'cache-warming-hourly': {
        'task': 'core.tasks.background_tasks.cache_warming_task',
        'schedule': crontab(minute=0),  # Every hour at :00
        'options': {'queue': 'low_priority', 'priority': 1},
        'description': 'Pre-warm cache with frequently accessed data',
    },

    'update-dashboard-cache-30min': {
        'task': 'analytics.tasks.update_dashboard_cache',
        'schedule': timedelta(minutes=30),
        'options': {'queue': 'analytics', 'priority': 3},
        'description': 'Update cached dashboard metrics every 30 minutes',
    },

    # ==========================================================================
    # SYSTEM MAINTENANCE TASKS (Daily)
    # ==========================================================================

    'cleanup-expired-sessions-daily': {
        'task': 'core.tasks.maintenance_tasks.cleanup_old_sessions_task',
        'schedule': crontab(hour=3, minute=0),  # Daily at 3 AM
        'options': {'queue': 'low_priority', 'priority': 1},
        'kwargs': {'days': 30},
        'description': 'Remove expired user sessions from database',
    },

    'cleanup-expired-sessions': {
        'task': 'zumodra.tasks.cleanup_expired_sessions',
        'schedule': crontab(hour=3, minute=30),  # Daily at 3:30 AM
        'options': {'queue': 'default'},
        'description': 'Remove expired user sessions from database (legacy)',
    },

    'cleanup-old-audit-logs': {
        'task': 'zumodra.tasks.cleanup_old_audit_logs',
        'schedule': crontab(hour=4, minute=0, day_of_week='sunday'),  # Weekly on Sunday at 4 AM
        'options': {'queue': 'default'},
        'kwargs': {'days': 90},  # Keep logs for 90 days
        'description': 'Archive and remove old audit logs',
    },

    'backup-database': {
        'task': 'zumodra.tasks.backup_database',
        'schedule': crontab(hour=2, minute=0),  # Daily at 2 AM
        'options': {'queue': 'default'},
        'description': 'Create database backup',
    },

    'health-check-integrations': {
        'task': 'zumodra.tasks.health_check_integrations',
        'schedule': timedelta(minutes=15),  # Every 15 minutes
        'options': {'queue': 'default'},
        'description': 'Check health of external integrations (Stripe, email, etc.)',
    },


    # ==================== DAILY DIGEST & NOTIFICATIONS ====================

    'send-daily-digest': {
        'task': 'zumodra.tasks.send_daily_digest',
        'schedule': crontab(hour=8, minute=0),  # Daily at 8 AM
        'options': {'queue': 'emails'},
        'description': 'Send daily activity digest to users',
    },

    'send-weekly-summary': {
        'task': 'zumodra.tasks.send_weekly_summary',
        'schedule': crontab(hour=9, minute=0, day_of_week='monday'),  # Every Monday at 9 AM
        'options': {'queue': 'emails'},
        'description': 'Send weekly summary report to admins',
    },


    # ==================== TENANT TASKS ====================

    'check-usage-limits': {
        'task': 'tenants.tasks.check_usage_limits',
        'schedule': timedelta(hours=1),  # Every hour
        'options': {'queue': 'default'},
        'description': 'Check tenant usage against plan limits',
    },

    'send-trial-reminders': {
        'task': 'tenants.tasks.send_trial_reminders',
        'schedule': crontab(hour=10, minute=0),  # Daily at 10 AM
        'options': {'queue': 'emails'},
        'description': 'Send trial expiration reminders',
    },

    'calculate-tenant-usage': {
        'task': 'tenants.tasks.calculate_tenant_usage',
        'schedule': crontab(hour=1, minute=0),  # Daily at 1 AM
        'options': {'queue': 'default'},
        'description': 'Calculate and update tenant resource usage',
    },

    'expire-trial-tenants': {
        'task': 'tenants.tasks.expire_trial_tenants',
        'schedule': crontab(hour=0, minute=30),  # Daily at 12:30 AM
        'options': {'queue': 'default'},
        'description': 'Expire tenants whose trial period has ended',
    },

    'cleanup-expired-invitations': {
        'task': 'tenants.tasks.cleanup_expired_invitations',
        'schedule': crontab(hour=5, minute=0),  # Daily at 5 AM
        'options': {'queue': 'default'},
        'description': 'Clean up expired tenant invitations',
    },


    # ==================== ACCOUNT TASKS ====================

    'cleanup-expired-tokens': {
        'task': 'tenant_profiles.tasks.cleanup_expired_tokens',
        'schedule': crontab(hour=4, minute=30),  # Daily at 4:30 AM
        'options': {'queue': 'hr'},
        'description': 'Remove expired authentication tokens',
    },

    'kyc-verification-reminder': {
        'task': 'tenant_profiles.tasks.kyc_verification_reminder',
        'schedule': crontab(hour=11, minute=0),  # Daily at 11 AM
        'options': {'queue': 'emails'},
        'description': 'Send KYC verification reminders',
    },

    'expire-kyc-verifications': {
        'task': 'tenant_profiles.tasks.expire_kyc_verifications',
        'schedule': crontab(hour=0, minute=0),  # Daily at midnight
        'options': {'queue': 'hr'},
        'description': 'Mark expired KYC verifications',
    },

    'cleanup-old-login-history': {
        'task': 'tenant_profiles.tasks.cleanup_old_login_history',
        'schedule': crontab(hour=3, minute=30, day_of_week='sunday'),  # Weekly on Sunday
        'options': {'queue': 'hr'},
        'kwargs': {'days': 180},  # Keep login history for 180 days
        'description': 'Clean up old login history records',
    },

    'expire-consents': {
        'task': 'tenant_profiles.tasks.expire_consents',
        'schedule': crontab(hour=1, minute=30),  # Daily at 1:30 AM
        'options': {'queue': 'hr'},
        'description': 'Mark expired progressive consents',
    },

    # --- Verification & Trust System Tasks ---

    'expire-old-verifications': {
        'task': 'tenant_profiles.tasks.expire_old_verifications',
        'schedule': crontab(hour=0, minute=45),  # Daily at 12:45 AM
        'options': {'queue': 'hr'},
        'description': 'Expire employment/education verifications past expiry date',
    },

    'send-pending-verification-reminders': {
        'task': 'tenant_profiles.tasks.send_pending_verification_reminders',
        'schedule': crontab(hour=10, minute=30),  # Daily at 10:30 AM
        'options': {'queue': 'emails'},
        'description': 'Send reminders for pending verifications older than 7 days',
    },

    'send-expiring-verification-warnings': {
        'task': 'tenant_profiles.tasks.send_expiring_verification_warnings',
        'schedule': crontab(hour=9, minute=30),  # Daily at 9:30 AM
        'options': {'queue': 'emails'},
        'kwargs': {'days_before': 30},
        'description': 'Warn users about verifications expiring in 30 days',
    },

    'analyze-pending-reviews': {
        'task': 'tenant_profiles.tasks.analyze_pending_reviews',
        'schedule': timedelta(hours=2),  # Every 2 hours
        'options': {'queue': 'hr'},
        'kwargs': {'limit': 50},
        'description': 'Analyze new reviews for policy violations',
    },

    'recalculate-all-trust-scores': {
        'task': 'tenant_profiles.tasks.recalculate_all_trust_scores',
        'schedule': crontab(hour=3, minute=0, day_of_week='sunday'),  # Weekly on Sunday at 3 AM
        'options': {'queue': 'hr'},
        'description': 'Recalculate trust scores for all users',
    },


    # ==================== ATS TASKS ====================

    'calculate-match-scores': {
        'task': 'jobs.tasks.calculate_match_scores',
        'schedule': timedelta(hours=2),  # Every 2 hours
        'options': {'queue': 'jobs'},
        'description': 'Calculate AI match scores for candidates',
    },

    'send-application-reminders': {
        'task': 'jobs.tasks.send_application_reminders',
        'schedule': crontab(hour=9, minute=30),  # Daily at 9:30 AM
        'options': {'queue': 'emails'},
        'description': 'Send reminders for pending application reviews',
    },

    'auto-reject-stale-applications': {
        'task': 'jobs.tasks.auto_reject_stale_applications',
        'schedule': crontab(hour=6, minute=0),  # Daily at 6 AM
        'options': {'queue': 'jobs'},
        'description': 'Auto-reject applications that have been stale too long',
    },

    'update-pipeline-statistics': {
        'task': 'jobs.tasks.update_pipeline_statistics',
        'schedule': crontab(hour='*/4', minute=0),  # Every 4 hours
        'options': {'queue': 'jobs'},
        'description': 'Update pipeline stage statistics',
    },

    'send-interview-reminders': {
        'task': 'jobs.tasks.send_interview_reminders',
        'schedule': crontab(minute='*/30'),  # Every 30 minutes
        'options': {'queue': 'emails'},
        'description': 'Send upcoming interview reminders',
    },

    'expire-job-postings': {
        'task': 'jobs.tasks.expire_job_postings',
        'schedule': crontab(hour=0, minute=15),  # Daily at 12:15 AM
        'options': {'queue': 'jobs'},
        'description': 'Close expired job postings',
    },


    # ==================== HR CORE TASKS ====================

    'process-time-off-accruals': {
        'task': 'hr_core.tasks.process_time_off_accruals',
        'schedule': crontab(hour=0, minute=0, day_of_month='1'),  # Monthly on 1st
        'options': {'queue': 'hr'},
        'description': 'Process monthly PTO/sick leave accruals',
    },

    'send-onboarding-reminders': {
        'task': 'hr_core.tasks.send_onboarding_reminders',
        'schedule': crontab(hour=8, minute=30),  # Daily at 8:30 AM
        'options': {'queue': 'emails'},
        'description': 'Send reminders for pending onboarding tasks',
    },

    'process-probation-ends': {
        'task': 'hr_core.tasks.process_probation_ends',
        'schedule': crontab(hour=7, minute=0),  # Daily at 7 AM
        'options': {'queue': 'hr'},
        'description': 'Process employees ending probation period',
    },

    'send-time-off-reminders': {
        'task': 'hr_core.tasks.send_time_off_reminders',
        'schedule': crontab(hour=16, minute=0),  # Daily at 4 PM
        'options': {'queue': 'emails'},
        'description': 'Send reminders for pending time-off approvals',
    },

    'update-employee-anniversaries': {
        'task': 'hr_core.tasks.update_employee_anniversaries',
        'schedule': crontab(hour=6, minute=30),  # Daily at 6:30 AM
        'options': {'queue': 'hr'},
        'description': 'Send work anniversary notifications',
    },

    'expire-pending-documents': {
        'task': 'hr_core.tasks.expire_pending_documents',
        'schedule': crontab(hour=5, minute=30),  # Daily at 5:30 AM
        'options': {'queue': 'hr'},
        'description': 'Expire documents awaiting signature',
    },


    # ==================== CAREERS TASKS ====================

    'process-public-applications': {
        'task': 'careers.tasks.process_public_applications',
        'schedule': timedelta(minutes=5),  # Every 5 minutes
        'options': {'queue': 'jobs'},
        'description': 'Process applications from public career page',
    },

    'update-job-view-counts': {
        'task': 'careers.tasks.update_job_view_counts',
        'schedule': crontab(hour='*/6', minute=15),  # Every 6 hours
        'options': {'queue': 'jobs'},
        'description': 'Aggregate and update job view counts',
    },

    'sync-job-listings': {
        'task': 'careers.tasks.sync_job_listings',
        'schedule': timedelta(minutes=10),  # Every 10 minutes
        'options': {'queue': 'jobs'},
        'description': 'Sync job listings with ATS job postings',
    },

    'generate-sitemap': {
        'task': 'careers.tasks.generate_sitemap',
        'schedule': crontab(hour=5, minute=0),  # Daily at 5 AM
        'options': {'queue': 'jobs'},
        'description': 'Regenerate career page sitemap',
    },


    # ==================== ANALYTICS TASKS ====================

    'calculate-daily-metrics': {
        'task': 'analytics.tasks.calculate_daily_metrics',
        'schedule': crontab(hour=1, minute=0),  # Daily at 1 AM
        'options': {'queue': 'analytics'},
        'description': 'Calculate daily analytics metrics',
    },

    'calculate-weekly-metrics': {
        'task': 'analytics.tasks.calculate_weekly_metrics',
        'schedule': crontab(hour=2, minute=0, day_of_week='monday'),  # Monday at 2 AM
        'options': {'queue': 'analytics'},
        'description': 'Calculate weekly analytics metrics',
    },

    'calculate-monthly-metrics': {
        'task': 'analytics.tasks.calculate_monthly_metrics',
        'schedule': crontab(hour=3, minute=0, day_of_month='1'),  # 1st of month at 3 AM
        'options': {'queue': 'analytics'},
        'description': 'Calculate monthly analytics metrics',
    },

    'generate-reports': {
        'task': 'analytics.tasks.generate_scheduled_reports',
        'schedule': crontab(hour=7, minute=0),  # Daily at 7 AM
        'options': {'queue': 'analytics'},
        'description': 'Generate scheduled analytics reports',
    },

    'cleanup-old-page-views': {
        'task': 'analytics.tasks.cleanup_old_page_views',
        'schedule': crontab(hour=4, minute=0, day_of_week='sunday'),  # Weekly on Sunday
        'options': {'queue': 'analytics'},
        'kwargs': {'days': 90},
        'description': 'Archive old page view records',
    },

    'calculate-diversity-metrics': {
        'task': 'analytics.tasks.calculate_diversity_metrics',
        'schedule': crontab(hour=2, minute=30, day_of_week='sunday'),  # Weekly on Sunday
        'options': {'queue': 'analytics'},
        'description': 'Calculate anonymized diversity metrics',
    },

    'update-dashboard-cache': {
        'task': 'analytics.tasks.update_dashboard_cache',
        'schedule': timedelta(minutes=30),  # Every 30 minutes
        'options': {'queue': 'analytics'},
        'description': 'Update cached dashboard metrics',
    },


    # ==================== NEWSLETTER TASKS ====================

    'send-scheduled-newsletters': {
        'task': 'newsletter.tasks.send_scheduled_newsletters',
        'schedule': timedelta(hours=1),  # Every hour
        'options': {'queue': 'emails'},
        'description': 'Send newsletters scheduled for this hour',
    },

    'cleanup-newsletter-stats': {
        'task': 'newsletter.tasks.cleanup_old_statistics',
        'schedule': crontab(hour=4, minute=30, day_of_month='1'),  # Monthly on 1st
        'options': {'queue': 'emails'},
        'description': 'Clean up old newsletter statistics',
    },


    # ==================== NOTIFICATION TASKS ====================

    'process-scheduled-notifications': {
        'task': 'notifications.tasks.process_scheduled_notifications',
        'schedule': timedelta(minutes=1),  # Every minute
        'options': {'queue': 'notifications'},
        'description': 'Process scheduled notifications that are due',
    },

    'retry-failed-notifications': {
        'task': 'notifications.tasks.retry_failed_notifications',
        'schedule': timedelta(hours=1),  # Every hour
        'options': {'queue': 'notifications'},
        'kwargs': {'max_age_hours': 24},
        'description': 'Retry failed notifications',
    },

    'send-notification-daily-digest': {
        'task': 'notifications.tasks.send_daily_digest',
        'schedule': crontab(hour=8, minute=0),  # Daily at 8 AM
        'options': {'queue': 'notifications'},
        'description': 'Send daily digest emails to subscribed users',
    },

    'send-notification-weekly-digest': {
        'task': 'notifications.tasks.send_weekly_digest',
        'schedule': crontab(hour=9, minute=0, day_of_week='monday'),  # Weekly on Monday
        'options': {'queue': 'notifications'},
        'description': 'Send weekly digest emails to subscribed users',
    },

    'cleanup-old-notifications': {
        'task': 'notifications.tasks.cleanup_old_notifications',
        'schedule': crontab(hour=3, minute=0, day_of_week='saturday'),  # Weekly on Saturday
        'options': {'queue': 'notifications'},
        'kwargs': {'days': 90},
        'description': 'Clean up read/dismissed notifications older than 90 days',
    },

    'cleanup-expired-notifications': {
        'task': 'notifications.tasks.cleanup_expired_notifications',
        'schedule': crontab(hour=4, minute=0),  # Daily at 4 AM
        'options': {'queue': 'notifications'},
        'description': 'Mark expired notifications as dismissed',
    },

    'send-appointment-reminders': {
        'task': 'notifications.tasks.send_appointment_reminders',
        'schedule': timedelta(hours=1),  # Every hour
        'options': {'queue': 'notifications'},
        'description': 'Send reminders for upcoming appointments',
    },


    # ==================== FINANCE TASKS ====================

    'sync-stripe-subscriptions': {
        'task': 'finance.tasks.sync_stripe_subscriptions',
        'schedule': timedelta(hours=6),  # Every 6 hours
        'options': {'queue': 'payments'},
        'description': 'Sync subscription status with Stripe',
    },

    'process-failed-payments': {
        'task': 'finance.tasks.retry_failed_payments',
        'schedule': crontab(hour=10, minute=0),  # Daily at 10 AM
        'options': {'queue': 'payments'},
        'description': 'Retry failed payment attempts',
    },

    'send-invoice-reminders': {
        'task': 'finance.tasks.send_invoice_reminders',
        'schedule': crontab(hour=9, minute=0),  # Daily at 9 AM
        'options': {'queue': 'emails'},
        'description': 'Send payment/invoice reminders',
    },

    'generate-monthly-invoices': {
        'task': 'finance.tasks.generate_monthly_invoices',
        'schedule': crontab(hour=0, minute=0, day_of_month='1'),  # 1st of month
        'options': {'queue': 'payments'},
        'description': 'Generate monthly invoices',
    },


    # ==========================================================================
    # SCALE TASKS - NEW MAINTENANCE TASKS
    # ==========================================================================

    # Weekly backup verification
    'backup-rotation-weekly': {
        'task': 'core.tasks.maintenance_tasks.backup_rotation_task',
        'schedule': crontab(hour=2, minute=0, day_of_week='sunday'),  # Sunday at 2 AM
        'options': {'queue': 'low_priority', 'priority': 1},
        'kwargs': {'retention_days': 30, 'max_backups': 100, 'min_backups': 7},
        'description': 'Rotate old backup files based on retention policy',
    },

    # SSL certificate check (4 times per day)
    'ssl-renewal-check': {
        'task': 'core.tasks.maintenance_tasks.ssl_renewal_check_task',
        'schedule': crontab(hour='*/6', minute=30),  # Every 6 hours at :30
        'options': {'queue': 'low_priority', 'priority': 2},
        'kwargs': {'warning_days': 30, 'critical_days': 7, 'notify_admins': True},
        'description': 'Check SSL certificate expiration for all domains',
    },

    # Failed payment retry
    'failed-payment-retry-core': {
        'task': 'core.tasks.maintenance_tasks.failed_payment_retry_task',
        'schedule': crontab(hour='*/4', minute=15),  # Every 4 hours at :15
        'options': {'queue': 'payments', 'priority': 8},
        'kwargs': {'max_retries': 3, 'retry_after_hours': 24, 'batch_size': 50},
        'description': 'Retry failed payment transactions with exponential backoff',
    },

    # Temp file cleanup
    'cleanup-temp-files': {
        'task': 'core.tasks.maintenance_tasks.cleanup_temp_files_task',
        'schedule': crontab(hour='*/12', minute=45),  # Every 12 hours at :45
        'options': {'queue': 'low_priority', 'priority': 1},
        'kwargs': {'max_age_hours': 24},
        'description': 'Clean up temporary files older than 24 hours',
    },

    # Database vacuum (weekly)
    'database-vacuum-weekly': {
        'task': 'core.tasks.maintenance_tasks.database_vacuum_task',
        'schedule': crontab(hour=4, minute=30, day_of_week='saturday'),  # Saturday at 4:30 AM
        'options': {'queue': 'low_priority', 'priority': 1},
        'kwargs': {'analyze': True},
        'description': 'Run VACUUM ANALYZE on PostgreSQL tables',
    },

    # Monthly analytics aggregation
    'analytics-aggregation-monthly': {
        'task': 'core.tasks.background_tasks.analytics_aggregation_task',
        'schedule': crontab(hour=1, minute=0, day_of_month='1'),  # 1st of month at 1 AM
        'options': {'queue': 'analytics', 'priority': 3},
        'kwargs': {'aggregation_type': 'monthly'},
        'description': 'Aggregate monthly analytics data for reporting',
    },

    # Weekly analytics aggregation
    'analytics-aggregation-weekly': {
        'task': 'core.tasks.background_tasks.analytics_aggregation_task',
        'schedule': crontab(hour=2, minute=0, day_of_week='monday'),  # Monday at 2 AM
        'options': {'queue': 'analytics', 'priority': 3},
        'kwargs': {'aggregation_type': 'weekly'},
        'description': 'Aggregate weekly analytics data for reporting',
    },

    # Daily analytics aggregation
    'analytics-aggregation-daily': {
        'task': 'core.tasks.background_tasks.analytics_aggregation_task',
        'schedule': crontab(hour=1, minute=30),  # Daily at 1:30 AM
        'options': {'queue': 'analytics', 'priority': 3},
        'kwargs': {'aggregation_type': 'daily'},
        'description': 'Aggregate daily analytics data for reporting',
    },


    # ==========================================================================
    # HEALTH CHECK TASKS
    # ==========================================================================

    'celery-health-check': {
        'task': 'zumodra.celery.health_check',
        'schedule': timedelta(minutes=5),  # Every 5 minutes
        'options': {'queue': 'default', 'priority': 5},
        'description': 'Celery worker health check',
    },


    # ==========================================================================
    # SERVICES (MARKETPLACE) TASKS
    # ==========================================================================

    'send-contract-reminders': {
        'task': 'services.tasks.send_contract_reminders',
        'schedule': crontab(hour=9, minute=0),  # Daily at 9 AM
        'options': {'queue': 'default'},
        'description': 'Send reminders for pending contracts',
    },

    'expire-old-proposals': {
        'task': 'services.tasks.expire_old_proposals',
        'schedule': crontab(hour=1, minute=0),  # Daily at 1 AM
        'options': {'queue': 'default'},
        'description': 'Expire proposals pending more than 30 days',
    },

    'calculate-provider-ratings': {
        'task': 'services.tasks.calculate_provider_ratings',
        'schedule': crontab(hour=2, minute=0),  # Daily at 2 AM
        'options': {'queue': 'default'},
        'description': 'Recalculate aggregate provider ratings',
    },

    'cleanup-abandoned-requests': {
        'task': 'services.tasks.cleanup_abandoned_requests',
        'schedule': crontab(hour=3, minute=0),  # Daily at 3 AM
        'options': {'queue': 'default'},
        'description': 'Clean up abandoned client requests',
    },

    'update-contract-statuses': {
        'task': 'services.tasks.update_contract_statuses',
        'schedule': crontab(hour='*/6', minute=0),  # Every 6 hours
        'options': {'queue': 'default'},
        'description': 'Update contract statuses based on deadlines',
    },

    'update-service-statistics': {
        'task': 'services.tasks.update_service_statistics',
        'schedule': crontab(hour=4, minute=0),  # Daily at 4 AM
        'options': {'queue': 'default'},
        'description': 'Update service view and order statistics',
    },

    'process-escrow-releases': {
        'task': 'services.tasks.process_escrow_releases',
        'schedule': crontab(hour='*/4', minute=30),  # Every 4 hours
        'options': {'queue': 'payments'},
        'description': 'Process pending escrow releases',
    },


    # ==========================================================================
    # CONFIGURATIONS TASKS
    # ==========================================================================

    'sync-skills-from-external': {
        'task': 'configurations.tasks.sync_skills_from_external',
        'schedule': crontab(hour=5, minute=0, day_of_week='sunday'),  # Weekly
        'options': {'queue': 'default'},
        'description': 'Sync skills from external sources',
    },

    'cleanup-unused-categories': {
        'task': 'configurations.tasks.cleanup_unused_categories',
        'schedule': crontab(hour=4, minute=0, day_of_week='sunday'),  # Weekly
        'options': {'queue': 'default'},
        'description': 'Clean up orphaned categories',
    },

    'update-company-stats': {
        'task': 'configurations.tasks.update_company_stats',
        'schedule': crontab(hour=2, minute=30),  # Daily at 2:30 AM
        'options': {'queue': 'default'},
        'description': 'Update company statistics',
    },

    'check-data-integrity': {
        'task': 'configurations.tasks.check_data_integrity',
        'schedule': crontab(hour=3, minute=30, day_of_week='sunday'),  # Weekly
        'options': {'queue': 'default'},
        'description': 'Run data integrity checks on configuration data',
    },

    'warm-configuration-cache': {
        'task': 'configurations.tasks.warm_configuration_cache',
        'schedule': crontab(hour='*/4', minute=0),  # Every 4 hours
        'options': {'queue': 'low_priority'},
        'description': 'Pre-warm configuration cache',
    },


    # ==========================================================================
    # MARKETING TASKS
    # ==========================================================================

    'process-scheduled-campaigns': {
        'task': 'marketing.tasks.process_scheduled_campaigns',
        'schedule': timedelta(hours=1),  # Every hour
        'options': {'queue': 'emails'},
        'description': 'Process and send scheduled marketing campaigns',
    },

    'calculate-conversion-metrics': {
        'task': 'marketing.tasks.calculate_conversion_metrics',
        'schedule': crontab(hour=1, minute=0),  # Daily at 1 AM
        'options': {'queue': 'analytics'},
        'description': 'Calculate daily conversion metrics',
    },

    'cleanup-old-visits': {
        'task': 'marketing.tasks.cleanup_old_visits',
        'schedule': crontab(hour=4, minute=0, day_of_week='sunday'),  # Weekly
        'options': {'queue': 'low_priority'},
        'description': 'Clean up visit tracking data older than 90 days',
    },

    'sync-newsletter-subscribers': {
        'task': 'marketing.tasks.sync_newsletter_subscribers',
        'schedule': timedelta(hours=2),  # Every 2 hours
        'options': {'queue': 'emails'},
        'description': 'Sync newsletter subscribers with email service',
    },

    'calculate-lead-scores': {
        'task': 'marketing.tasks.calculate_lead_scores',
        'schedule': crontab(hour='*/6', minute=30),  # Every 6 hours
        'options': {'queue': 'analytics'},
        'description': 'Calculate lead scores for prospects',
    },

    'update-campaign-analytics': {
        'task': 'marketing.tasks.update_campaign_analytics',
        'schedule': crontab(hour='*/4', minute=15),  # Every 4 hours
        'options': {'queue': 'analytics'},
        'description': 'Update analytics for sent campaigns',
    },

    'analyze-ab-tests': {
        'task': 'marketing.tasks.analyze_ab_tests',
        'schedule': crontab(hour=10, minute=0),  # Daily at 10 AM
        'options': {'queue': 'analytics'},
        'description': 'Analyze A/B test results and determine winners',
    },


    # ==========================================================================
    # MESSAGES SYSTEM TASKS
    # ==========================================================================

    'cleanup-old-messages': {
        'task': 'messages_sys.tasks.cleanup_old_messages',
        'schedule': crontab(hour=3, minute=0, day_of_week='sunday'),  # Weekly
        'options': {'queue': 'default'},
        'description': 'Archive/delete old messages per retention policy',
    },

    'send-unread-notifications': {
        'task': 'messages_sys.tasks.send_unread_notifications',
        'schedule': crontab(hour='*/4', minute=0),  # Every 4 hours
        'options': {'queue': 'emails'},
        'description': 'Send email notifications for unread messages',
    },

    'update-conversation-stats': {
        'task': 'messages_sys.tasks.update_conversation_stats',
        'schedule': crontab(hour=2, minute=0),  # Daily at 2 AM
        'options': {'queue': 'default'},
        'description': 'Update conversation statistics',
    },

    'update-delivery-status': {
        'task': 'messages_sys.tasks.update_delivery_status',
        'schedule': timedelta(minutes=5),  # Every 5 minutes
        'options': {'queue': 'default'},
        'description': 'Update message delivery status',
    },

    'generate-contact-suggestions': {
        'task': 'messages_sys.tasks.generate_contact_suggestions',
        'schedule': crontab(hour=5, minute=0),  # Daily at 5 AM
        'options': {'queue': 'default'},
        'description': 'Generate contact suggestions for users',
    },

    'detect-spam-messages': {
        'task': 'messages_sys.tasks.detect_spam_messages',
        'schedule': timedelta(hours=1),  # Every hour
        'options': {'queue': 'default'},
        'description': 'Detect and flag potential spam messages',
    },


    # ==========================================================================
    # ADDITIONAL FINANCE TASKS
    # ==========================================================================

    'sync-stripe-payments': {
        'task': 'finance.tasks.sync_stripe_payments',
        'schedule': timedelta(hours=1),  # Every hour
        'options': {'queue': 'payments'},
        'description': 'Sync payment statuses from Stripe',
    },

    'process-pending-refunds': {
        'task': 'finance.tasks.process_pending_refunds',
        'schedule': crontab(hour='*/4', minute=0),  # Every 4 hours
        'options': {'queue': 'payments'},
        'description': 'Process pending refund requests',
    },

    'update-subscription-status': {
        'task': 'finance.tasks.update_subscription_status',
        'schedule': crontab(hour=0, minute=30),  # Daily at 12:30 AM
        'options': {'queue': 'payments'},
        'description': 'Update subscription statuses based on payments',
    },

    'process-escrow-transactions': {
        'task': 'finance.tasks.process_escrow_transactions',
        'schedule': crontab(hour='*/6', minute=15),  # Every 6 hours
        'options': {'queue': 'payments'},
        'description': 'Process pending escrow transactions',
    },

    'generate-daily-financial-report': {
        'task': 'finance.tasks.generate_daily_financial_report',
        'schedule': crontab(hour=6, minute=0),  # Daily at 6 AM
        'options': {'queue': 'analytics'},
        'description': 'Generate daily financial summary report',
    },


    # ==========================================================================
    # SECURITY TASKS
    # ==========================================================================

    'cleanup-audit-logs': {
        'task': 'security.tasks.cleanup_audit_logs',
        'schedule': crontab(hour=4, minute=0, day_of_week='sunday'),  # Weekly
        'options': {'queue': 'default'},
        'description': 'Archive and cleanup old audit logs',
    },

    'analyze-failed-logins': {
        'task': 'security.tasks.analyze_failed_logins',
        'schedule': timedelta(minutes=30),  # Every 30 minutes
        'options': {'queue': 'default'},
        'description': 'Analyze failed logins to detect brute force attacks',
    },

    'expire-sessions': {
        'task': 'security.tasks.expire_sessions',
        'schedule': crontab(hour='*/6', minute=0),  # Every 6 hours
        'options': {'queue': 'default'},
        'description': 'Clean up expired sessions and tokens',
    },

    'generate-security-report': {
        'task': 'security.tasks.generate_security_report',
        'schedule': crontab(hour=6, minute=30),  # Daily at 6:30 AM
        'options': {'queue': 'default'},
        'description': 'Generate daily security summary report',
    },

    'detect-anomalies': {
        'task': 'security.tasks.detect_anomalies',
        'schedule': crontab(hour='*/2', minute=0),  # Every 2 hours
        'options': {'queue': 'default'},
        'description': 'Detect anomalous activity patterns',
    },

    'check-password-expiry': {
        'task': 'security.tasks.check_password_expiry',
        'schedule': crontab(hour=7, minute=0),  # Daily at 7 AM
        'options': {'queue': 'emails'},
        'description': 'Check for expired passwords and send notifications',
    },

    'update-ip-reputation': {
        'task': 'security.tasks.update_ip_reputation',
        'schedule': crontab(hour='*/4', minute=30),  # Every 4 hours
        'options': {'queue': 'default'},
        'description': 'Update IP reputation scores based on activity',
    },
}
