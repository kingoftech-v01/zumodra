"""
Management command for GDPR-compliant user data export.
Exports all data associated with a user in machine-readable format.
"""

import json
import os
from datetime import datetime
from django.core.management.base import BaseCommand, CommandError
from django.contrib.auth import get_user_model
from django.core.serializers.json import DjangoJSONEncoder
from django.db import connection
from tenants.models import Tenant
from accounts.models import (
    TenantUser, UserProfile, KYCVerification,
    ProgressiveConsent, DataAccessLog, LoginHistory
)

User = get_user_model()


class Command(BaseCommand):
    help = 'Export all user data for GDPR compliance (data portability)'

    def add_arguments(self, parser):
        parser.add_argument(
            'email',
            type=str,
            help='Email address of the user to export'
        )
        parser.add_argument(
            '--output',
            type=str,
            help='Output file path (default: user_data_<email>_<timestamp>.json)'
        )
        parser.add_argument(
            '--tenant',
            type=str,
            help='Specific tenant to export from (exports from all if not specified)'
        )
        parser.add_argument(
            '--include-ats',
            action='store_true',
            help='Include ATS data (applications, interviews)'
        )
        parser.add_argument(
            '--include-hr',
            action='store_true',
            help='Include HR data (employee records, time-off)'
        )
        parser.add_argument(
            '--include-logs',
            action='store_true',
            help='Include access and login logs'
        )
        parser.add_argument(
            '--all-data',
            action='store_true',
            help='Include all available data categories'
        )
        parser.add_argument(
            '--format',
            type=str,
            choices=['json', 'csv'],
            default='json',
            help='Output format (default: json)'
        )
        parser.add_argument(
            '--pretty',
            action='store_true',
            help='Pretty-print JSON output'
        )

    def handle(self, *args, **options):
        email = options['email']
        output_path = options.get('output')
        tenant_slug = options.get('tenant')
        include_ats = options.get('include_ats') or options.get('all_data')
        include_hr = options.get('include_hr') or options.get('all_data')
        include_logs = options.get('include_logs') or options.get('all_data')
        output_format = options.get('format', 'json')
        pretty = options.get('pretty', False)

        # Find user
        try:
            user = User.objects.get(email=email)
        except User.DoesNotExist:
            raise CommandError(f"User not found: {email}")

        self.stdout.write(f"Exporting data for user: {email}")

        # Build export data
        export_data = {
            'export_info': {
                'user_email': email,
                'export_date': datetime.now().isoformat(),
                'export_format': output_format,
                'gdpr_compliance': True,
            },
            'user_account': self._export_user_account(user),
            'profile': self._export_profile(user),
            'tenant_memberships': [],
            'kyc_verifications': self._export_kyc(user),
            'consents': self._export_consents(user),
        }

        if include_logs:
            export_data['login_history'] = self._export_login_history(user)
            export_data['data_access_logs'] = self._export_access_logs(user)

        # Export tenant-specific data
        tenants = self._get_user_tenants(user, tenant_slug)

        for tenant in tenants:
            self.stdout.write(f"  Processing tenant: {tenant.name}")
            connection.set_schema(tenant.schema_name)

            try:
                tenant_data = {
                    'tenant_name': tenant.name,
                    'tenant_slug': tenant.slug,
                    'membership': self._export_tenant_membership(user, tenant),
                }

                if include_ats:
                    tenant_data['ats_data'] = self._export_ats_data(user)

                if include_hr:
                    tenant_data['hr_data'] = self._export_hr_data(user)

                export_data['tenant_memberships'].append(tenant_data)

            finally:
                connection.set_schema_to_public()

        # Generate output file
        if not output_path:
            safe_email = email.replace('@', '_at_').replace('.', '_')
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            output_path = f"user_data_{safe_email}_{timestamp}.{output_format}"

        # Write output
        if output_format == 'json':
            self._write_json(export_data, output_path, pretty)
        else:
            self._write_csv(export_data, output_path)

        self.stdout.write(self.style.SUCCESS(f"\nData exported to: {output_path}"))

        # Print summary
        self.stdout.write("\nExport Summary:")
        self.stdout.write(f"  User account: Yes")
        self.stdout.write(f"  Profile: {'Yes' if export_data['profile'] else 'No'}")
        self.stdout.write(f"  Tenant memberships: {len(export_data['tenant_memberships'])}")
        self.stdout.write(f"  KYC verifications: {len(export_data['kyc_verifications'])}")
        self.stdout.write(f"  Consents: {len(export_data['consents'])}")

    def _export_user_account(self, user):
        """Export basic user account data."""
        return {
            'email': user.email,
            'first_name': user.first_name,
            'last_name': user.last_name,
            'date_joined': user.date_joined.isoformat() if hasattr(user, 'date_joined') else None,
            'last_login': user.last_login.isoformat() if user.last_login else None,
            'is_active': user.is_active,
        }

    def _export_profile(self, user):
        """Export user profile data."""
        try:
            profile = user.profile
            return {
                'profile_type': profile.profile_type,
                'phone': str(profile.phone) if profile.phone else None,
                'phone_verified': profile.phone_verified,
                'date_of_birth': profile.date_of_birth.isoformat() if profile.date_of_birth else None,
                'nationality': profile.nationality,
                'languages': profile.languages,
                'address': {
                    'line1': profile.address_line1,
                    'line2': profile.address_line2,
                    'city': profile.city,
                    'state': profile.state,
                    'postal_code': profile.postal_code,
                    'country': profile.country,
                },
                'bio': profile.bio,
                'social_links': {
                    'linkedin': profile.linkedin_url,
                    'github': profile.github_url,
                    'portfolio': profile.portfolio_url,
                    'twitter': profile.twitter_url,
                },
                'preferences': {
                    'language': profile.preferred_language,
                    'timezone': profile.timezone,
                    'notifications': profile.notification_preferences,
                },
                'created_at': profile.created_at.isoformat(),
                'updated_at': profile.updated_at.isoformat(),
            }
        except UserProfile.DoesNotExist:
            return None

    def _export_kyc(self, user):
        """Export KYC verification records."""
        verifications = KYCVerification.objects.filter(user=user)
        return [
            {
                'verification_type': v.verification_type,
                'status': v.status,
                'level': v.level,
                'submitted_at': v.submitted_at.isoformat() if v.submitted_at else None,
                'verified_at': v.verified_at.isoformat() if v.verified_at else None,
                'expires_at': v.expires_at.isoformat() if v.expires_at else None,
            }
            for v in verifications
        ]

    def _export_consents(self, user):
        """Export consent records."""
        consents = ProgressiveConsent.objects.filter(grantor=user)
        return [
            {
                'data_category': c.data_category,
                'status': c.status,
                'grantee_tenant': c.grantee_tenant.name if c.grantee_tenant else None,
                'purpose': c.purpose,
                'requested_at': c.requested_at.isoformat() if c.requested_at else None,
                'responded_at': c.responded_at.isoformat() if c.responded_at else None,
                'expires_at': c.expires_at.isoformat() if c.expires_at else None,
            }
            for c in consents
        ]

    def _export_login_history(self, user):
        """Export login history."""
        history = LoginHistory.objects.filter(user=user).order_by('-timestamp')[:100]
        return [
            {
                'result': h.result,
                'ip_address': h.ip_address,
                'location': h.location,
                'timestamp': h.timestamp.isoformat(),
            }
            for h in history
        ]

    def _export_access_logs(self, user):
        """Export data access logs (who accessed this user's data)."""
        logs = DataAccessLog.objects.filter(data_subject=user).order_by('-accessed_at')[:100]
        return [
            {
                'accessor_email': log.accessor.email if log.accessor else 'Unknown',
                'data_category': log.data_category,
                'data_fields': log.data_fields,
                'access_reason': log.access_reason,
                'accessed_at': log.accessed_at.isoformat(),
            }
            for log in logs
        ]

    def _get_user_tenants(self, user, tenant_slug=None):
        """Get tenants the user belongs to."""
        if tenant_slug:
            try:
                return [Tenant.objects.get(slug=tenant_slug)]
            except Tenant.DoesNotExist:
                self.stdout.write(self.style.WARNING(f"Tenant not found: {tenant_slug}"))
                return []

        # Get all tenants user is a member of
        memberships = TenantUser.objects.filter(user=user)
        return [m.tenant for m in memberships]

    def _export_tenant_membership(self, user, tenant):
        """Export tenant membership data."""
        try:
            membership = TenantUser.objects.get(user=user, tenant=tenant)
            return {
                'role': membership.role,
                'job_title': membership.job_title,
                'is_active': membership.is_active,
                'is_primary_tenant': membership.is_primary_tenant,
                'joined_at': membership.joined_at.isoformat(),
                'last_active_at': membership.last_active_at.isoformat() if membership.last_active_at else None,
            }
        except TenantUser.DoesNotExist:
            return None

    def _export_ats_data(self, user):
        """Export ATS-related data for the user."""
        try:
            from ats.models import Candidate, Application, Interview, InterviewFeedback

            data = {
                'as_candidate': None,
                'applications': [],
                'interviews': [],
                'feedback_given': [],
            }

            # Check if user is a candidate
            try:
                candidate = Candidate.objects.get(user=user)
                data['as_candidate'] = {
                    'first_name': candidate.first_name,
                    'last_name': candidate.last_name,
                    'headline': candidate.headline,
                    'summary': candidate.summary,
                    'skills': candidate.skills,
                    'source': candidate.source,
                    'created_at': candidate.created_at.isoformat(),
                }

                # Get applications
                for app in Application.objects.filter(candidate=candidate):
                    data['applications'].append({
                        'job_title': app.job.title,
                        'status': app.status,
                        'applied_at': app.applied_at.isoformat(),
                        'overall_rating': float(app.overall_rating) if app.overall_rating else None,
                    })
            except Candidate.DoesNotExist:
                pass

            # Get interviews where user was interviewer
            for interview in Interview.objects.filter(interviewers=user):
                data['interviews'].append({
                    'candidate': interview.application.candidate.full_name,
                    'job_title': interview.application.job.title,
                    'interview_type': interview.interview_type,
                    'status': interview.status,
                    'scheduled_start': interview.scheduled_start.isoformat(),
                })

            # Get feedback given by user
            for feedback in InterviewFeedback.objects.filter(interviewer=user):
                data['feedback_given'].append({
                    'candidate': feedback.interview.application.candidate.full_name,
                    'overall_rating': feedback.overall_rating,
                    'recommendation': feedback.recommendation,
                    'created_at': feedback.created_at.isoformat(),
                })

            return data

        except ImportError:
            return {'error': 'ATS module not available'}

    def _export_hr_data(self, user):
        """Export HR-related data for the user."""
        try:
            from hr_core.models import Employee, TimeOffRequest, EmployeeDocument

            data = {
                'employee_record': None,
                'time_off_requests': [],
                'documents': [],
            }

            # Get employee record
            try:
                employee = Employee.objects.get(user=user)
                data['employee_record'] = {
                    'employee_id': employee.employee_id,
                    'job_title': employee.job_title,
                    'status': employee.status,
                    'employment_type': employee.employment_type,
                    'hire_date': employee.hire_date.isoformat() if employee.hire_date else None,
                    'start_date': employee.start_date.isoformat() if employee.start_date else None,
                    'pto_balance': float(employee.pto_balance),
                    'sick_leave_balance': float(employee.sick_leave_balance),
                }

                # Get time-off requests
                for request in TimeOffRequest.objects.filter(employee=employee):
                    data['time_off_requests'].append({
                        'type': request.time_off_type.name,
                        'start_date': request.start_date.isoformat(),
                        'end_date': request.end_date.isoformat(),
                        'total_days': float(request.total_days),
                        'status': request.status,
                        'created_at': request.created_at.isoformat(),
                    })

                # Get documents (metadata only, not content)
                for doc in EmployeeDocument.objects.filter(employee=employee):
                    data['documents'].append({
                        'title': doc.title,
                        'category': doc.category,
                        'status': doc.status,
                        'created_at': doc.created_at.isoformat(),
                    })

            except Employee.DoesNotExist:
                pass

            return data

        except ImportError:
            return {'error': 'HR module not available'}

    def _write_json(self, data, filepath, pretty):
        """Write data as JSON."""
        with open(filepath, 'w', encoding='utf-8') as f:
            if pretty:
                json.dump(data, f, cls=DjangoJSONEncoder, indent=2, ensure_ascii=False)
            else:
                json.dump(data, f, cls=DjangoJSONEncoder, ensure_ascii=False)

    def _write_csv(self, data, filepath):
        """Write data as CSV (flattened structure)."""
        import csv

        # Flatten the nested structure for CSV
        rows = []

        # User account data
        if data.get('user_account'):
            for key, value in data['user_account'].items():
                rows.append({'category': 'user_account', 'field': key, 'value': str(value)})

        # Profile data
        if data.get('profile'):
            profile = data['profile']
            for key, value in profile.items():
                if isinstance(value, dict):
                    for subkey, subvalue in value.items():
                        rows.append({
                            'category': 'profile',
                            'field': f"{key}.{subkey}",
                            'value': str(subvalue)
                        })
                else:
                    rows.append({'category': 'profile', 'field': key, 'value': str(value)})

        with open(filepath, 'w', newline='', encoding='utf-8') as f:
            writer = csv.DictWriter(f, fieldnames=['category', 'field', 'value'])
            writer.writeheader()
            writer.writerows(rows)
