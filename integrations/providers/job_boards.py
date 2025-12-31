"""
Job Board Integration Providers

Implements job board integrations for:
- Indeed
- LinkedIn Jobs
- Glassdoor
"""

import logging
from datetime import datetime
from typing import Dict, Any, List, Tuple, Optional

from .base import (
    JobBoardProvider,
    IntegrationError,
    AuthenticationError,
    ConfigurationError,
)

logger = logging.getLogger(__name__)


class IndeedProvider(JobBoardProvider):
    """
    Indeed job posting integration provider.
    Uses Indeed Publisher API and XML Feed.
    """

    provider_name = 'indeed'
    display_name = 'Indeed'

    # API configuration
    api_base_url = 'https://api.indeed.com/ads/apisearch'
    post_api_url = 'https://employers.indeed.com/api/v1'

    # Indeed uses API key authentication
    oauth_authorize_url = ''
    oauth_token_url = ''

    def get_headers(self) -> Dict[str, str]:
        """Get headers for Indeed API requests."""
        creds = self.get_credentials()
        return {
            'Authorization': f"Bearer {creds.get('api_key')}",
            'Content-Type': 'application/json',
            'Accept': 'application/json',
        }

    def test_connection(self) -> Tuple[bool, str]:
        """Test Indeed API connection."""
        try:
            # Indeed doesn't have a dedicated test endpoint
            # We'll verify by checking if credentials exist
            creds = self.get_credentials()
            if creds.get('api_key'):
                return True, "Indeed API key configured"
            return False, "Indeed API key not configured"
        except Exception as e:
            return False, f"Connection error: {str(e)}"

    def get_account_info(self) -> Dict[str, Any]:
        """Get Indeed account information."""
        # Indeed API has limited account info endpoints
        config = self.integration.config if self.integration else {}
        return {
            'employer_id': config.get('employer_id'),
            'company_name': config.get('company_name'),
        }

    def post_job(self, job_data: Dict) -> Dict:
        """
        Post a job to Indeed.

        Args:
            job_data: Job posting data with:
                - title: Job title
                - description: Full job description (HTML allowed)
                - company: Company name
                - location: Job location
                - salary_min: Minimum salary
                - salary_max: Maximum salary
                - job_type: full-time, part-time, contract, etc.
                - remote: Remote work options

        Returns:
            Dict with job ID and posting URL
        """
        indeed_job = self._prepare_job_data(job_data)

        response = self.make_request(
            'POST',
            'jobs',
            data=indeed_job,
        )

        if response.status_code not in [200, 201]:
            raise IntegrationError(f"Failed to post job: {response.text}")

        data = response.json()
        return {
            'external_id': data.get('jobKey'),
            'url': data.get('viewJobUrl'),
            'status': 'published',
            'posted_at': datetime.now().isoformat(),
        }

    def update_job(self, job_id: str, job_data: Dict) -> Dict:
        """Update an existing job posting."""
        indeed_job = self._prepare_job_data(job_data)

        response = self.make_request(
            'PUT',
            f'jobs/{job_id}',
            data=indeed_job,
        )

        if response.status_code != 200:
            raise IntegrationError(f"Failed to update job: {response.text}")

        return {
            'external_id': job_id,
            'status': 'updated',
            'updated_at': datetime.now().isoformat(),
        }

    def close_job(self, job_id: str) -> bool:
        """Close/unpublish a job posting."""
        response = self.make_request(
            'DELETE',
            f'jobs/{job_id}',
        )

        return response.status_code in [200, 204]

    def get_applications(self, job_id: str) -> List[Dict]:
        """Get applications for a job posting."""
        response = self.make_request(
            'GET',
            f'jobs/{job_id}/applications',
        )

        if response.status_code != 200:
            return []

        data = response.json()
        return [
            self._normalize_application(app)
            for app in data.get('applications', [])
        ]

    def _prepare_job_data(self, job_data: Dict) -> Dict:
        """Convert normalized job data to Indeed format."""
        return {
            'title': job_data.get('title'),
            'description': job_data.get('description'),
            'company': job_data.get('company'),
            'location': {
                'city': job_data.get('city'),
                'state': job_data.get('state'),
                'country': job_data.get('country', 'US'),
            },
            'salary': {
                'min': job_data.get('salary_min'),
                'max': job_data.get('salary_max'),
                'type': job_data.get('salary_type', 'yearly'),
            },
            'type': job_data.get('job_type', 'fulltime'),
            'remote': job_data.get('remote', False),
            'experience': job_data.get('experience_level'),
            'education': job_data.get('education_level'),
        }

    def _normalize_application(self, indeed_app: Dict) -> Dict:
        """Convert Indeed application to normalized format."""
        return {
            'id': indeed_app.get('id'),
            'candidate_name': indeed_app.get('candidateName'),
            'email': indeed_app.get('email'),
            'phone': indeed_app.get('phone'),
            'resume_url': indeed_app.get('resumeUrl'),
            'cover_letter': indeed_app.get('coverLetter'),
            'applied_at': indeed_app.get('appliedDate'),
            'source': 'indeed',
        }


class LinkedInProvider(JobBoardProvider):
    """
    LinkedIn Jobs integration provider.
    Uses LinkedIn Marketing API.
    """

    provider_name = 'linkedin'
    display_name = 'LinkedIn Jobs'

    # API configuration
    api_base_url = 'https://api.linkedin.com/v2'

    # OAuth configuration
    oauth_authorize_url = 'https://www.linkedin.com/oauth/v2/authorization'
    oauth_token_url = 'https://www.linkedin.com/oauth/v2/accessToken'
    oauth_scopes = [
        'r_liteprofile',
        'r_emailaddress',
        'w_member_social',
        'rw_organization_admin',
    ]

    def test_connection(self) -> Tuple[bool, str]:
        """Test LinkedIn API connection."""
        try:
            response = self.make_request('GET', 'me')
            if response.status_code == 200:
                return True, "Successfully connected to LinkedIn"
            return False, f"Connection failed: {response.status_code}"
        except AuthenticationError as e:
            return False, f"Authentication failed: {str(e)}"
        except Exception as e:
            return False, f"Connection error: {str(e)}"

    def get_account_info(self) -> Dict[str, Any]:
        """Get LinkedIn account/organization information."""
        response = self.make_request('GET', 'me')
        if response.status_code != 200:
            raise IntegrationError("Failed to fetch account info")

        data = response.json()
        return {
            'id': data.get('id'),
            'first_name': data.get('localizedFirstName'),
            'last_name': data.get('localizedLastName'),
        }

    def post_job(self, job_data: Dict) -> Dict:
        """
        Post a job to LinkedIn.

        Note: LinkedIn Job Posting API requires partner status.
        This implementation shows the API structure.
        """
        linkedin_job = self._prepare_job_data(job_data)

        response = self.make_request(
            'POST',
            'simpleJobPostings',
            data=linkedin_job,
        )

        if response.status_code not in [200, 201]:
            raise IntegrationError(f"Failed to post job: {response.text}")

        data = response.json()
        return {
            'external_id': data.get('id'),
            'status': 'published',
            'posted_at': datetime.now().isoformat(),
        }

    def update_job(self, job_id: str, job_data: Dict) -> Dict:
        """Update an existing LinkedIn job posting."""
        linkedin_job = self._prepare_job_data(job_data)

        response = self.make_request(
            'POST',
            f'simpleJobPostings/{job_id}',
            data=linkedin_job,
        )

        if response.status_code != 200:
            raise IntegrationError(f"Failed to update job: {response.text}")

        return {
            'external_id': job_id,
            'status': 'updated',
        }

    def close_job(self, job_id: str) -> bool:
        """Close a LinkedIn job posting."""
        response = self.make_request(
            'POST',
            f'simpleJobPostings/{job_id}',
            data={'status': 'CLOSED'},
        )

        return response.status_code in [200, 204]

    def get_applications(self, job_id: str) -> List[Dict]:
        """Get applications for a LinkedIn job posting."""
        response = self.make_request(
            'GET',
            f'simpleJobPostingApplications',
            params={'jobPosting': job_id},
        )

        if response.status_code != 200:
            return []

        data = response.json()
        return [
            self._normalize_application(app)
            for app in data.get('elements', [])
        ]

    def _prepare_job_data(self, job_data: Dict) -> Dict:
        """Convert normalized job data to LinkedIn format."""
        config = self.integration.config if self.integration else {}

        return {
            'companyApplyUrl': job_data.get('apply_url'),
            'description': {
                'text': job_data.get('description'),
            },
            'listedAt': int(datetime.now().timestamp() * 1000),
            'location': job_data.get('location'),
            'title': job_data.get('title'),
            'integrationContext': config.get('integration_context'),
            'jobPostingOperationType': 'CREATE',
        }

    def _normalize_application(self, linkedin_app: Dict) -> Dict:
        """Convert LinkedIn application to normalized format."""
        return {
            'id': linkedin_app.get('id'),
            'candidate_id': linkedin_app.get('applicant'),
            'applied_at': linkedin_app.get('appliedAt'),
            'source': 'linkedin',
        }


class GlassdoorProvider(JobBoardProvider):
    """
    Glassdoor job posting integration provider.
    Uses Glassdoor Partner API.
    """

    provider_name = 'glassdoor'
    display_name = 'Glassdoor'

    # API configuration
    api_base_url = 'https://api.glassdoor.com/api/v1'

    # Glassdoor uses API key + partner ID
    oauth_authorize_url = ''
    oauth_token_url = ''

    def get_headers(self) -> Dict[str, str]:
        """Get headers for Glassdoor API requests."""
        config = self.integration.config if self.integration else {}
        creds = self.get_credentials()

        return {
            'Authorization': f"Basic {creds.get('api_key')}",
            'X-Partner-Id': config.get('partner_id', ''),
            'Content-Type': 'application/json',
        }

    def test_connection(self) -> Tuple[bool, str]:
        """Test Glassdoor API connection."""
        try:
            creds = self.get_credentials()
            config = self.integration.config if self.integration else {}

            if creds.get('api_key') and config.get('partner_id'):
                return True, "Glassdoor API configured"
            return False, "Glassdoor API credentials not complete"
        except Exception as e:
            return False, f"Connection error: {str(e)}"

    def get_account_info(self) -> Dict[str, Any]:
        """Get Glassdoor account information."""
        config = self.integration.config if self.integration else {}
        return {
            'partner_id': config.get('partner_id'),
            'company_name': config.get('company_name'),
        }

    def post_job(self, job_data: Dict) -> Dict:
        """Post a job to Glassdoor."""
        glassdoor_job = self._prepare_job_data(job_data)

        response = self.make_request(
            'POST',
            'job',
            data=glassdoor_job,
        )

        if response.status_code not in [200, 201]:
            raise IntegrationError(f"Failed to post job: {response.text}")

        data = response.json()
        return {
            'external_id': data.get('jobId'),
            'url': data.get('jobUrl'),
            'status': 'published',
            'posted_at': datetime.now().isoformat(),
        }

    def update_job(self, job_id: str, job_data: Dict) -> Dict:
        """Update a Glassdoor job posting."""
        glassdoor_job = self._prepare_job_data(job_data)

        response = self.make_request(
            'PUT',
            f'job/{job_id}',
            data=glassdoor_job,
        )

        if response.status_code != 200:
            raise IntegrationError(f"Failed to update job: {response.text}")

        return {
            'external_id': job_id,
            'status': 'updated',
        }

    def close_job(self, job_id: str) -> bool:
        """Close a Glassdoor job posting."""
        response = self.make_request(
            'DELETE',
            f'job/{job_id}',
        )

        return response.status_code in [200, 204]

    def get_applications(self, job_id: str) -> List[Dict]:
        """Get applications for a Glassdoor job posting."""
        response = self.make_request(
            'GET',
            f'job/{job_id}/applications',
        )

        if response.status_code != 200:
            return []

        data = response.json()
        return [
            self._normalize_application(app)
            for app in data.get('applications', [])
        ]

    def _prepare_job_data(self, job_data: Dict) -> Dict:
        """Convert normalized job data to Glassdoor format."""
        return {
            'jobTitle': job_data.get('title'),
            'jobDescription': job_data.get('description'),
            'employerName': job_data.get('company'),
            'location': {
                'city': job_data.get('city'),
                'state': job_data.get('state'),
                'country': job_data.get('country', 'US'),
            },
            'salary': {
                'baseSalary': {
                    'min': job_data.get('salary_min'),
                    'max': job_data.get('salary_max'),
                    'currency': job_data.get('currency', 'USD'),
                },
            },
            'employmentType': job_data.get('job_type', 'FULL_TIME'),
            'applyUrl': job_data.get('apply_url'),
        }

    def _normalize_application(self, glassdoor_app: Dict) -> Dict:
        """Convert Glassdoor application to normalized format."""
        return {
            'id': glassdoor_app.get('applicationId'),
            'candidate_name': glassdoor_app.get('applicantName'),
            'email': glassdoor_app.get('applicantEmail'),
            'resume_url': glassdoor_app.get('resumeUrl'),
            'applied_at': glassdoor_app.get('applyDate'),
            'source': 'glassdoor',
        }
