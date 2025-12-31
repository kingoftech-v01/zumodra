"""
HRIS Integration Providers

Implements HRIS integrations for:
- BambooHR
- Workday
"""

import logging
from datetime import datetime
from typing import Dict, Any, List, Tuple, Optional

from .base import (
    HRISProvider,
    IntegrationError,
    AuthenticationError,
    ConfigurationError,
)

logger = logging.getLogger(__name__)


class BambooHRProvider(HRISProvider):
    """
    BambooHR integration provider.
    Uses BambooHR API v1.
    """

    provider_name = 'bamboohr'
    display_name = 'BambooHR'

    # BambooHR uses API key authentication with company subdomain
    oauth_authorize_url = ''
    oauth_token_url = ''

    @property
    def api_base_url(self) -> str:
        """Get BambooHR API URL with company subdomain."""
        config = self.integration.config if self.integration else {}
        subdomain = config.get('subdomain', 'api')
        return f'https://api.bamboohr.com/api/gateway.php/{subdomain}/v1'

    def get_headers(self) -> Dict[str, str]:
        """Get headers for BambooHR API requests."""
        import base64
        creds = self.get_credentials()
        api_key = creds.get('api_key', '')
        auth = base64.b64encode(f"{api_key}:x".encode()).decode()

        return {
            'Authorization': f"Basic {auth}",
            'Accept': 'application/json',
            'Content-Type': 'application/json',
        }

    def test_connection(self) -> Tuple[bool, str]:
        """Test BambooHR API connection."""
        try:
            response = self.make_request('GET', 'employees/directory')
            if response.status_code == 200:
                return True, "Successfully connected to BambooHR"
            return False, f"Connection failed: {response.status_code}"
        except AuthenticationError as e:
            return False, f"Authentication failed: {str(e)}"
        except Exception as e:
            return False, f"Connection error: {str(e)}"

    def get_account_info(self) -> Dict[str, Any]:
        """Get BambooHR company information."""
        response = self.make_request('GET', 'company_info')

        if response.status_code != 200:
            raise IntegrationError("Failed to fetch company info")

        data = response.json()
        return {
            'company_id': data.get('id'),
            'company_name': data.get('name'),
            'employee_count': data.get('employees'),
        }

    def list_employees(self, status: str = 'active') -> List[Dict]:
        """
        List employees from BambooHR.

        Args:
            status: Filter by status ('active', 'inactive', 'all')

        Returns:
            List of employee dictionaries
        """
        response = self.make_request('GET', 'employees/directory')

        if response.status_code != 200:
            raise IntegrationError(f"Failed to list employees: {response.status_code}")

        data = response.json()
        employees = []

        for emp in data.get('employees', []):
            normalized = self._normalize_employee(emp)

            # Filter by status
            if status == 'all':
                employees.append(normalized)
            elif status == 'active' and normalized.get('status') == 'Active':
                employees.append(normalized)
            elif status == 'inactive' and normalized.get('status') != 'Active':
                employees.append(normalized)

        return employees

    def get_employee(self, employee_id: str) -> Dict:
        """Get detailed employee information."""
        # Request specific fields
        fields = ','.join([
            'firstName', 'lastName', 'preferredName', 'email',
            'workPhone', 'mobilePhone', 'jobTitle', 'department',
            'location', 'supervisor', 'hireDate', 'terminationDate',
            'status', 'employeeNumber', 'workEmail', 'address1',
            'address2', 'city', 'state', 'zipCode', 'country',
        ])

        response = self.make_request(
            'GET',
            f'employees/{employee_id}',
            params={'fields': fields}
        )

        if response.status_code != 200:
            raise IntegrationError(f"Failed to get employee: {response.status_code}")

        return self._normalize_employee(response.json())

    def create_employee(self, employee_data: Dict) -> Dict:
        """Create a new employee in BambooHR."""
        bamboo_employee = self._prepare_employee_data(employee_data)

        response = self.make_request('POST', 'employees', data=bamboo_employee)

        if response.status_code not in [200, 201]:
            raise IntegrationError(f"Failed to create employee: {response.text}")

        # BambooHR returns employee ID in Location header
        location = response.headers.get('Location', '')
        employee_id = location.split('/')[-1] if location else None

        return {
            'id': employee_id,
            'status': 'created',
            'created_at': datetime.now().isoformat(),
        }

    def update_employee(self, employee_id: str, employee_data: Dict) -> Dict:
        """Update employee information in BambooHR."""
        bamboo_employee = self._prepare_employee_data(employee_data)

        response = self.make_request(
            'POST',
            f'employees/{employee_id}',
            data=bamboo_employee
        )

        if response.status_code != 200:
            raise IntegrationError(f"Failed to update employee: {response.text}")

        return {
            'id': employee_id,
            'status': 'updated',
            'updated_at': datetime.now().isoformat(),
        }

    def get_time_off_requests(self, start_date: str, end_date: str) -> List[Dict]:
        """Get time off requests for a date range."""
        response = self.make_request(
            'GET',
            'time_off/requests',
            params={'start': start_date, 'end': end_date}
        )

        if response.status_code != 200:
            return []

        data = response.json()
        return [
            {
                'id': req.get('id'),
                'employee_id': req.get('employeeId'),
                'status': req.get('status', {}).get('status'),
                'start_date': req.get('start'),
                'end_date': req.get('end'),
                'type': req.get('type', {}).get('name'),
                'notes': req.get('notes'),
            }
            for req in data.get('requests', [])
        ]

    def _prepare_employee_data(self, employee_data: Dict) -> Dict:
        """Convert normalized employee data to BambooHR format."""
        return {
            'firstName': employee_data.get('first_name'),
            'lastName': employee_data.get('last_name'),
            'preferredName': employee_data.get('preferred_name'),
            'workEmail': employee_data.get('work_email'),
            'mobilePhone': employee_data.get('phone'),
            'jobTitle': employee_data.get('job_title'),
            'department': employee_data.get('department'),
            'location': employee_data.get('location'),
            'hireDate': employee_data.get('hire_date'),
            'address1': employee_data.get('address_line1'),
            'city': employee_data.get('city'),
            'state': employee_data.get('state'),
            'zipCode': employee_data.get('postal_code'),
            'country': employee_data.get('country'),
        }

    def _normalize_employee(self, bamboo_emp: Dict) -> Dict:
        """Convert BambooHR employee to normalized format."""
        return {
            'id': bamboo_emp.get('id'),
            'employee_number': bamboo_emp.get('employeeNumber'),
            'first_name': bamboo_emp.get('firstName'),
            'last_name': bamboo_emp.get('lastName'),
            'preferred_name': bamboo_emp.get('preferredName'),
            'email': bamboo_emp.get('workEmail') or bamboo_emp.get('email'),
            'phone': bamboo_emp.get('mobilePhone') or bamboo_emp.get('workPhone'),
            'job_title': bamboo_emp.get('jobTitle'),
            'department': bamboo_emp.get('department'),
            'location': bamboo_emp.get('location'),
            'supervisor': bamboo_emp.get('supervisor'),
            'hire_date': bamboo_emp.get('hireDate'),
            'termination_date': bamboo_emp.get('terminationDate'),
            'status': bamboo_emp.get('status'),
            'photo_url': bamboo_emp.get('photoUrl'),
        }

    def handle_webhook(self, event_type: str, payload: Dict) -> Dict[str, Any]:
        """Handle BambooHR webhook events."""
        logger.info(f"Processing BambooHR webhook: {event_type}")

        return {
            'action': event_type,
            'employee_id': payload.get('employeeId'),
            'fields_changed': payload.get('changedFields', []),
        }


class WorkdayProvider(HRISProvider):
    """
    Workday HRIS integration provider.
    Uses Workday REST API.
    """

    provider_name = 'workday'
    display_name = 'Workday'

    # OAuth configuration for Workday
    oauth_scopes = ['Human_Resources']

    @property
    def api_base_url(self) -> str:
        """Get Workday API URL with tenant."""
        config = self.integration.config if self.integration else {}
        tenant = config.get('tenant', '')
        return f'https://wd2-impl-services1.workday.com/ccx/api/v1/{tenant}'

    @property
    def oauth_authorize_url(self) -> str:
        config = self.integration.config if self.integration else {}
        tenant = config.get('tenant', '')
        return f'https://wd2-impl-services1.workday.com/{tenant}/authorize'

    @property
    def oauth_token_url(self) -> str:
        config = self.integration.config if self.integration else {}
        tenant = config.get('tenant', '')
        return f'https://wd2-impl-services1.workday.com/{tenant}/token'

    def test_connection(self) -> Tuple[bool, str]:
        """Test Workday API connection."""
        try:
            response = self.make_request('GET', 'workers')
            if response.status_code == 200:
                return True, "Successfully connected to Workday"
            return False, f"Connection failed: {response.status_code}"
        except AuthenticationError as e:
            return False, f"Authentication failed: {str(e)}"
        except Exception as e:
            return False, f"Connection error: {str(e)}"

    def get_account_info(self) -> Dict[str, Any]:
        """Get Workday tenant information."""
        config = self.integration.config if self.integration else {}
        return {
            'tenant': config.get('tenant'),
            'environment': config.get('environment', 'production'),
        }

    def list_employees(self, status: str = 'active') -> List[Dict]:
        """List workers from Workday."""
        params = {
            'limit': 100,
        }

        # Filter by active status
        if status == 'active':
            params['Active'] = 'true'
        elif status == 'inactive':
            params['Active'] = 'false'

        employees = []
        offset = 0

        while True:
            params['offset'] = offset
            response = self.make_request('GET', 'workers', params=params)

            if response.status_code != 200:
                raise IntegrationError(f"Failed to list workers: {response.status_code}")

            data = response.json()
            workers = data.get('data', [])

            for worker in workers:
                employees.append(self._normalize_employee(worker))

            # Check for more pages
            if len(workers) < params['limit']:
                break
            offset += params['limit']

        return employees

    def get_employee(self, employee_id: str) -> Dict:
        """Get detailed worker information from Workday."""
        response = self.make_request('GET', f'workers/{employee_id}')

        if response.status_code != 200:
            raise IntegrationError(f"Failed to get worker: {response.status_code}")

        return self._normalize_employee(response.json())

    def create_employee(self, employee_data: Dict) -> Dict:
        """
        Create a worker in Workday.
        Note: Workday typically uses business processes for hiring,
        not direct API creates. This is simplified.
        """
        workday_worker = self._prepare_employee_data(employee_data)

        response = self.make_request('POST', 'workers', data=workday_worker)

        if response.status_code not in [200, 201]:
            raise IntegrationError(f"Failed to create worker: {response.text}")

        data = response.json()
        return {
            'id': data.get('id'),
            'status': 'created',
        }

    def update_employee(self, employee_id: str, employee_data: Dict) -> Dict:
        """Update worker information in Workday."""
        workday_worker = self._prepare_employee_data(employee_data)

        response = self.make_request(
            'PATCH',
            f'workers/{employee_id}',
            data=workday_worker
        )

        if response.status_code != 200:
            raise IntegrationError(f"Failed to update worker: {response.text}")

        return {
            'id': employee_id,
            'status': 'updated',
        }

    def get_positions(self) -> List[Dict]:
        """Get positions/job requisitions from Workday."""
        response = self.make_request('GET', 'jobs')

        if response.status_code != 200:
            return []

        data = response.json()
        return [
            {
                'id': job.get('id'),
                'title': job.get('jobTitle'),
                'department': job.get('organizationName'),
                'location': job.get('location'),
                'status': job.get('status'),
            }
            for job in data.get('data', [])
        ]

    def _prepare_employee_data(self, employee_data: Dict) -> Dict:
        """Convert normalized employee data to Workday format."""
        return {
            'personalData': {
                'legalName': {
                    'firstName': employee_data.get('first_name'),
                    'lastName': employee_data.get('last_name'),
                },
                'preferredName': employee_data.get('preferred_name'),
            },
            'contactData': {
                'email': employee_data.get('work_email'),
                'phone': employee_data.get('phone'),
                'address': {
                    'line1': employee_data.get('address_line1'),
                    'city': employee_data.get('city'),
                    'region': employee_data.get('state'),
                    'postalCode': employee_data.get('postal_code'),
                    'country': employee_data.get('country'),
                },
            },
            'jobData': {
                'jobTitle': employee_data.get('job_title'),
                'department': employee_data.get('department'),
                'location': employee_data.get('location'),
                'hireDate': employee_data.get('hire_date'),
            },
        }

    def _normalize_employee(self, workday_worker: Dict) -> Dict:
        """Convert Workday worker to normalized format."""
        personal = workday_worker.get('personalData', {})
        contact = workday_worker.get('contactData', {})
        job = workday_worker.get('jobData', {})
        legal_name = personal.get('legalName', {})

        return {
            'id': workday_worker.get('id'),
            'employee_number': workday_worker.get('employeeNumber'),
            'first_name': legal_name.get('firstName'),
            'last_name': legal_name.get('lastName'),
            'preferred_name': personal.get('preferredName'),
            'email': contact.get('email'),
            'phone': contact.get('phone'),
            'job_title': job.get('jobTitle'),
            'department': job.get('department'),
            'location': job.get('location'),
            'manager_id': job.get('managerId'),
            'hire_date': job.get('hireDate'),
            'termination_date': job.get('terminationDate'),
            'status': 'Active' if workday_worker.get('active') else 'Inactive',
        }

    def handle_webhook(self, event_type: str, payload: Dict) -> Dict[str, Any]:
        """Handle Workday webhook/integration events."""
        logger.info(f"Processing Workday event: {event_type}")

        return {
            'action': event_type,
            'worker_id': payload.get('workerId'),
            'effective_date': payload.get('effectiveDate'),
        }
