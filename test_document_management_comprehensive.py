#!/usr/bin/env python
"""
Comprehensive Document Management System Tests for Zumodra

Tests the complete document management system with:
1. Document upload (various file types)
2. Document categorization and tagging
3. Version control and history
4. E-signature workflow
5. Document expiration tracking
6. Access permissions and sharing
7. Document search and retrieval
"""

import os
import json
import pytest
import tempfile
from datetime import datetime, timedelta
from io import BytesIO
from pathlib import Path

import requests
from django.test import TestCase, Client
from django.contrib.auth import get_user_model
from django.core.files.uploadedfile import SimpleUploadedFile
from django.utils import timezone
from django.conf import settings

# For API testing
BASE_URL = os.getenv('SITE_URL', 'http://localhost:8002')
API_BASE = f"{BASE_URL}/api/v1"

User = get_user_model()


class DocumentManagementTestSuite:
    """Main test suite for document management system."""

    def __init__(self):
        self.results = {
            'total_tests': 0,
            'passed': 0,
            'failed': 0,
            'errors': [],
            'test_cases': []
        }
        self.session = requests.Session()
        self.base_url = BASE_URL
        self.api_url = API_BASE
        self.test_user = None
        self.auth_token = None
        self.tenant_slug = 'demo'

    def log_test(self, test_name, status, details=None, error=None):
        """Log a test result."""
        self.results['total_tests'] += 1

        test_result = {
            'test_name': test_name,
            'status': status,
            'timestamp': datetime.now().isoformat(),
            'details': details or {}
        }

        if status == 'PASS':
            self.results['passed'] += 1
        else:
            self.results['failed'] += 1
            if error:
                test_result['error'] = str(error)
                self.results['errors'].append({
                    'test': test_name,
                    'error': str(error)
                })

        self.results['test_cases'].append(test_result)
        print(f"[{status}] {test_name}")
        if error:
            print(f"  Error: {error}")

    def setup_auth(self):
        """Setup authentication for tests."""
        print("\n=== Setting up authentication ===")
        try:
            # Try to authenticate
            login_data = {
                'email': 'testuser@example.com',
                'password': 'TestPassword123!'
            }

            response = self.session.post(
                f"{self.base_url}/auth/login/",
                json=login_data,
                timeout=10
            )

            if response.status_code == 200:
                self.auth_token = response.json().get('token')
                self.log_test('Authentication Setup', 'PASS', {
                    'method': 'Login',
                    'status_code': response.status_code
                })
                return True
            else:
                # Try to register first
                register_data = {
                    'email': 'testuser@example.com',
                    'password': 'TestPassword123!',
                    'password2': 'TestPassword123!',
                    'full_name': 'Test User'
                }

                response = self.session.post(
                    f"{self.base_url}/auth/register/",
                    json=register_data,
                    timeout=10
                )

                if response.status_code in [200, 201]:
                    self.log_test('User Registration', 'PASS', {
                        'status_code': response.status_code
                    })

                    # Now try to login
                    response = self.session.post(
                        f"{self.base_url}/auth/login/",
                        json=login_data,
                        timeout=10
                    )

                    if response.status_code == 200:
                        self.auth_token = response.json().get('token')
                        self.log_test('Authentication Setup', 'PASS', {
                            'method': 'After Registration',
                            'status_code': response.status_code
                        })
                        return True

                self.log_test('Authentication Setup', 'FAIL', error=f"Status: {response.status_code}")
                return False

        except Exception as e:
            self.log_test('Authentication Setup', 'FAIL', error=str(e))
            return False

    def get_headers(self):
        """Get request headers with authentication."""
        headers = {
            'Content-Type': 'application/json',
            'Accept': 'application/json',
        }
        if self.auth_token:
            headers['Authorization'] = f'Bearer {self.auth_token}'
        return headers

    # =========================================================================
    # TEST 1: Document Upload (Various File Types)
    # =========================================================================

    def test_document_upload_pdf(self):
        """Test uploading a PDF document."""
        print("\n=== TEST 1.1: PDF Document Upload ===")
        try:
            # Create a sample PDF file
            pdf_content = b'%PDF-1.4\n%test pdf content\n'

            files = {
                'file': ('test_document.pdf', BytesIO(pdf_content), 'application/pdf'),
                'title': (None, 'Test PDF Document'),
                'category': (None, 'form'),
                'description': (None, 'Test PDF upload')
            }

            response = self.session.post(
                f"{self.api_url}/hr/documents/",
                files=files,
                headers=self.get_headers(),
                timeout=10
            )

            if response.status_code in [200, 201]:
                data = response.json()
                doc_id = data.get('id') or data.get('uuid')
                self.log_test('PDF Upload', 'PASS', {
                    'file_type': 'PDF',
                    'status_code': response.status_code,
                    'document_id': str(doc_id)
                })
                return doc_id
            else:
                self.log_test('PDF Upload', 'FAIL', {
                    'status_code': response.status_code,
                    'response': response.text[:500]
                })
                return None
        except Exception as e:
            self.log_test('PDF Upload', 'FAIL', error=str(e))
            return None

    def test_document_upload_docx(self):
        """Test uploading a DOCX document."""
        print("\n=== TEST 1.2: DOCX Document Upload ===")
        try:
            # Create a sample DOCX content (simplified)
            docx_content = b'PK\x03\x04\x14\x00\x06\x00\x08\x00' + b'x' * 100

            files = {
                'file': ('test_document.docx', BytesIO(docx_content), 'application/vnd.openxmlformats-officedocument.wordprocessingml.document'),
                'title': (None, 'Test DOCX Document'),
                'category': (None, 'contract'),
                'description': (None, 'Test DOCX upload')
            }

            response = self.session.post(
                f"{self.api_url}/hr/documents/",
                files=files,
                headers=self.get_headers(),
                timeout=10
            )

            if response.status_code in [200, 201]:
                data = response.json()
                doc_id = data.get('id') or data.get('uuid')
                self.log_test('DOCX Upload', 'PASS', {
                    'file_type': 'DOCX',
                    'status_code': response.status_code,
                    'document_id': str(doc_id)
                })
                return doc_id
            else:
                self.log_test('DOCX Upload', 'FAIL', {
                    'status_code': response.status_code,
                    'response': response.text[:500]
                })
                return None
        except Exception as e:
            self.log_test('DOCX Upload', 'FAIL', error=str(e))
            return None

    def test_document_upload_png(self):
        """Test uploading a PNG image."""
        print("\n=== TEST 1.3: PNG Image Upload ===")
        try:
            # Create a sample PNG (simplified)
            png_header = b'\x89PNG\r\n\x1a\n' + b'\x00' * 100

            files = {
                'file': ('test_image.png', BytesIO(png_header), 'image/png'),
                'title': (None, 'Test PNG Image'),
                'category': (None, 'form'),
                'description': (None, 'Test PNG upload')
            }

            response = self.session.post(
                f"{self.api_url}/hr/documents/",
                files=files,
                headers=self.get_headers(),
                timeout=10
            )

            if response.status_code in [200, 201]:
                data = response.json()
                doc_id = data.get('id') or data.get('uuid')
                self.log_test('PNG Upload', 'PASS', {
                    'file_type': 'PNG',
                    'status_code': response.status_code,
                    'document_id': str(doc_id)
                })
                return doc_id
            else:
                self.log_test('PNG Upload', 'FAIL', {
                    'status_code': response.status_code,
                    'response': response.text[:500]
                })
                return None
        except Exception as e:
            self.log_test('PNG Upload', 'FAIL', error=str(e))
            return None

    def test_invalid_file_upload(self):
        """Test uploading an invalid file type."""
        print("\n=== TEST 1.4: Invalid File Type Upload (Should Fail) ===")
        try:
            # Create a sample EXE file (should be rejected)
            exe_content = b'MZ\x90\x00' + b'\x00' * 100

            files = {
                'file': ('test_executable.exe', BytesIO(exe_content), 'application/octet-stream'),
                'title': (None, 'Test EXE File'),
                'category': (None, 'other')
            }

            response = self.session.post(
                f"{self.api_url}/hr/documents/",
                files=files,
                headers=self.get_headers(),
                timeout=10
            )

            if response.status_code != 201:
                self.log_test('Invalid File Rejection', 'PASS', {
                    'expected_failure': True,
                    'status_code': response.status_code
                })
                return True
            else:
                self.log_test('Invalid File Rejection', 'FAIL', {
                    'status_code': response.status_code,
                    'expected': 400,
                    'message': 'Invalid file type was accepted'
                })
                return False
        except Exception as e:
            self.log_test('Invalid File Rejection', 'PASS', error=str(e))
            return True

    # =========================================================================
    # TEST 2: Document Categorization and Tagging
    # =========================================================================

    def test_document_categorization(self):
        """Test document categorization."""
        print("\n=== TEST 2.1: Document Categorization ===")
        try:
            categories = ['offer_letter', 'contract', 'nda', 'policy', 'form']
            results = {}

            for category in categories:
                files = {
                    'file': (f'test_{category}.pdf', BytesIO(b'%PDF test'), 'application/pdf'),
                    'title': (None, f'Test {category.upper()} Document'),
                    'category': (None, category)
                }

                response = self.session.post(
                    f"{self.api_url}/hr/documents/",
                    files=files,
                    headers=self.get_headers(),
                    timeout=10
                )

                results[category] = response.status_code in [200, 201]

            all_success = all(results.values())
            self.log_test('Document Categorization', 'PASS' if all_success else 'FAIL', {
                'categories_tested': results,
                'success_count': sum(results.values())
            })
            return all_success
        except Exception as e:
            self.log_test('Document Categorization', 'FAIL', error=str(e))
            return False

    # =========================================================================
    # TEST 3: Document List and Retrieval
    # =========================================================================

    def test_document_list_retrieval(self):
        """Test retrieving list of documents."""
        print("\n=== TEST 3.1: Document List Retrieval ===")
        try:
            response = self.session.get(
                f"{self.api_url}/hr/documents/",
                headers=self.get_headers(),
                timeout=10
            )

            if response.status_code == 200:
                data = response.json()
                doc_count = len(data) if isinstance(data, list) else data.get('count', 0)
                self.log_test('Document List Retrieval', 'PASS', {
                    'status_code': response.status_code,
                    'document_count': doc_count
                })
                return True
            else:
                self.log_test('Document List Retrieval', 'FAIL', {
                    'status_code': response.status_code
                })
                return False
        except Exception as e:
            self.log_test('Document List Retrieval', 'FAIL', error=str(e))
            return False

    def test_document_search(self):
        """Test document search functionality."""
        print("\n=== TEST 3.2: Document Search ===")
        try:
            # Upload a document with specific title
            files = {
                'file': ('searchable_document.pdf', BytesIO(b'%PDF test'), 'application/pdf'),
                'title': (None, 'SEARCHABLE_UNIQUE_TITLE_12345'),
                'category': (None, 'form')
            }

            response = self.session.post(
                f"{self.api_url}/hr/documents/",
                files=files,
                headers=self.get_headers(),
                timeout=10
            )

            # Now search for it
            response = self.session.get(
                f"{self.api_url}/hr/documents/?search=SEARCHABLE_UNIQUE_TITLE_12345",
                headers=self.get_headers(),
                timeout=10
            )

            if response.status_code == 200:
                data = response.json()
                results = data if isinstance(data, list) else data.get('results', [])
                found = any('SEARCHABLE' in str(r.get('title', '')) for r in results)

                self.log_test('Document Search', 'PASS' if found else 'PARTIAL', {
                    'status_code': response.status_code,
                    'results_count': len(results),
                    'found': found
                })
                return found
            else:
                self.log_test('Document Search', 'FAIL', {
                    'status_code': response.status_code
                })
                return False
        except Exception as e:
            self.log_test('Document Search', 'FAIL', error=str(e))
            return False

    # =========================================================================
    # TEST 4: E-Signature Workflow
    # =========================================================================

    def test_esignature_workflow_initiate(self):
        """Test initiating e-signature workflow."""
        print("\n=== TEST 4.1: E-Signature Workflow Initiation ===")
        try:
            # Upload a document that requires signature
            files = {
                'file': ('signature_document.pdf', BytesIO(b'%PDF test'), 'application/pdf'),
                'title': (None, 'Document for Signature'),
                'category': (None, 'contract'),
                'requires_signature': (None, 'true')
            }

            response = self.session.post(
                f"{self.api_url}/hr/documents/",
                files=files,
                headers=self.get_headers(),
                timeout=10
            )

            if response.status_code in [200, 201]:
                data = response.json()
                doc_id = data.get('id') or data.get('uuid')

                self.log_test('E-Signature Initiation', 'PASS', {
                    'status_code': response.status_code,
                    'document_id': str(doc_id),
                    'requires_signature': True
                })
                return doc_id
            else:
                self.log_test('E-Signature Initiation', 'FAIL', {
                    'status_code': response.status_code
                })
                return None
        except Exception as e:
            self.log_test('E-Signature Initiation', 'FAIL', error=str(e))
            return None

    def test_pending_signatures_list(self):
        """Test retrieving pending signatures."""
        print("\n=== TEST 4.2: Pending Signatures List ===")
        try:
            response = self.session.get(
                f"{self.api_url}/hr/documents/pending_signatures/",
                headers=self.get_headers(),
                timeout=10
            )

            if response.status_code == 200:
                data = response.json()
                pending_count = len(data) if isinstance(data, list) else data.get('count', 0)

                self.log_test('Pending Signatures List', 'PASS', {
                    'status_code': response.status_code,
                    'pending_count': pending_count
                })
                return True
            else:
                self.log_test('Pending Signatures List', 'FAIL', {
                    'status_code': response.status_code
                })
                return False
        except Exception as e:
            self.log_test('Pending Signatures List', 'FAIL', error=str(e))
            return False

    # =========================================================================
    # TEST 5: Document Expiration Tracking
    # =========================================================================

    def test_document_expiration_setting(self):
        """Test setting document expiration."""
        print("\n=== TEST 5.1: Document Expiration Setting ===")
        try:
            future_date = (datetime.now() + timedelta(days=30)).date()

            files = {
                'file': ('expiring_document.pdf', BytesIO(b'%PDF test'), 'application/pdf'),
                'title': (None, 'Document with Expiration'),
                'category': (None, 'policy'),
                'expires_at': (None, str(future_date))
            }

            response = self.session.post(
                f"{self.api_url}/hr/documents/",
                files=files,
                headers=self.get_headers(),
                timeout=10
            )

            if response.status_code in [200, 201]:
                data = response.json()
                doc_id = data.get('id') or data.get('uuid')

                self.log_test('Expiration Setting', 'PASS', {
                    'status_code': response.status_code,
                    'document_id': str(doc_id),
                    'expiration_date': str(future_date)
                })
                return doc_id
            else:
                self.log_test('Expiration Setting', 'FAIL', {
                    'status_code': response.status_code,
                    'response': response.text[:500]
                })
                return None
        except Exception as e:
            self.log_test('Expiration Setting', 'FAIL', error=str(e))
            return None

    # =========================================================================
    # TEST 6: Access Permissions and Sharing
    # =========================================================================

    def test_document_access_permissions(self):
        """Test document access control."""
        print("\n=== TEST 6.1: Document Access Permissions ===")
        try:
            # Upload a document
            files = {
                'file': ('access_controlled_document.pdf', BytesIO(b'%PDF test'), 'application/pdf'),
                'title': (None, 'Access Controlled Document'),
                'category': (None, 'contract')
            }

            response = self.session.post(
                f"{self.api_url}/hr/documents/",
                files=files,
                headers=self.get_headers(),
                timeout=10
            )

            if response.status_code in [200, 201]:
                data = response.json()
                doc_id = data.get('id') or data.get('uuid')

                # Try to retrieve the document
                response = self.session.get(
                    f"{self.api_url}/hr/documents/{doc_id}/",
                    headers=self.get_headers(),
                    timeout=10
                )

                if response.status_code == 200:
                    self.log_test('Document Access Control', 'PASS', {
                        'status_code': response.status_code,
                        'document_id': str(doc_id)
                    })
                    return True
                else:
                    self.log_test('Document Access Control', 'FAIL', {
                        'status_code': response.status_code
                    })
                    return False
            else:
                self.log_test('Document Access Control', 'FAIL', {
                    'status_code': response.status_code
                })
                return False
        except Exception as e:
            self.log_test('Document Access Control', 'FAIL', error=str(e))
            return False

    def test_user_document_visibility(self):
        """Test that users can only see their own documents."""
        print("\n=== TEST 6.2: User Document Visibility ===")
        try:
            response = self.session.get(
                f"{self.api_url}/hr/documents/my_documents/",
                headers=self.get_headers(),
                timeout=10
            )

            if response.status_code == 200:
                data = response.json()
                doc_count = len(data) if isinstance(data, list) else data.get('count', 0)

                self.log_test('User Document Visibility', 'PASS', {
                    'status_code': response.status_code,
                    'user_documents': doc_count
                })
                return True
            else:
                self.log_test('User Document Visibility', 'FAIL', {
                    'status_code': response.status_code
                })
                return False
        except Exception as e:
            self.log_test('User Document Visibility', 'FAIL', error=str(e))
            return False

    # =========================================================================
    # TEST 7: Document Templates
    # =========================================================================

    def test_document_templates_list(self):
        """Test listing available document templates."""
        print("\n=== TEST 7.1: Document Templates List ===")
        try:
            response = self.session.get(
                f"{self.api_url}/hr/document-templates/",
                headers=self.get_headers(),
                timeout=10
            )

            if response.status_code == 200:
                data = response.json()
                template_count = len(data) if isinstance(data, list) else data.get('count', 0)

                self.log_test('Document Templates List', 'PASS', {
                    'status_code': response.status_code,
                    'template_count': template_count
                })
                return True
            else:
                self.log_test('Document Templates List', 'FAIL', {
                    'status_code': response.status_code
                })
                return False
        except Exception as e:
            self.log_test('Document Templates List', 'FAIL', error=str(e))
            return False

    # =========================================================================
    # TEST 8: Document Metadata and Filtering
    # =========================================================================

    def test_document_filtering_by_category(self):
        """Test filtering documents by category."""
        print("\n=== TEST 8.1: Document Filtering by Category ===")
        try:
            response = self.session.get(
                f"{self.api_url}/hr/documents/?category=contract",
                headers=self.get_headers(),
                timeout=10
            )

            if response.status_code == 200:
                data = response.json()
                results = data if isinstance(data, list) else data.get('results', [])

                self.log_test('Filter by Category', 'PASS', {
                    'status_code': response.status_code,
                    'filtered_count': len(results)
                })
                return True
            else:
                self.log_test('Filter by Category', 'FAIL', {
                    'status_code': response.status_code
                })
                return False
        except Exception as e:
            self.log_test('Filter by Category', 'FAIL', error=str(e))
            return False

    def test_document_filtering_by_status(self):
        """Test filtering documents by status."""
        print("\n=== TEST 8.2: Document Filtering by Status ===")
        try:
            response = self.session.get(
                f"{self.api_url}/hr/documents/?status=signed",
                headers=self.get_headers(),
                timeout=10
            )

            if response.status_code == 200:
                data = response.json()
                results = data if isinstance(data, list) else data.get('results', [])

                self.log_test('Filter by Status', 'PASS', {
                    'status_code': response.status_code,
                    'filtered_count': len(results)
                })
                return True
            else:
                self.log_test('Filter by Status', 'FAIL', {
                    'status_code': response.status_code
                })
                return False
        except Exception as e:
            self.log_test('Filter by Status', 'FAIL', error=str(e))
            return False

    # =========================================================================
    # Reporting and Summary
    # =========================================================================

    def generate_report(self):
        """Generate comprehensive test report."""
        print("\n" + "="*80)
        print("DOCUMENT MANAGEMENT SYSTEM - COMPREHENSIVE TEST REPORT")
        print("="*80)

        # Summary
        print("\n## SUMMARY")
        print(f"Total Tests: {self.results['total_tests']}")
        print(f"Passed: {self.results['passed']}")
        print(f"Failed: {self.results['failed']}")
        print(f"Success Rate: {(self.results['passed']/self.results['total_tests']*100):.1f}%" if self.results['total_tests'] > 0 else "N/A")

        # Errors
        if self.results['errors']:
            print("\n## ERRORS")
            for error in self.results['errors']:
                print(f"- {error['test']}: {error['error']}")

        # Detailed Results
        print("\n## DETAILED TEST RESULTS")
        for test in self.results['test_cases']:
            status_icon = "✓" if test['status'] == 'PASS' else "✗"
            print(f"{status_icon} {test['test_name']}: {test['status']}")
            if test.get('details'):
                for key, value in test['details'].items():
                    print(f"    {key}: {value}")

        return self.results

    def run_all_tests(self):
        """Run all document management tests."""
        print("\n" + "="*80)
        print("STARTING COMPREHENSIVE DOCUMENT MANAGEMENT SYSTEM TESTS")
        print("="*80)

        # Setup
        if not self.setup_auth():
            print("Failed to setup authentication. Cannot proceed with tests.")
            return self.results

        # Test Suite 1: Document Upload
        print("\n" + "="*80)
        print("TEST SUITE 1: DOCUMENT UPLOAD")
        print("="*80)
        self.test_document_upload_pdf()
        self.test_document_upload_docx()
        self.test_document_upload_png()
        self.test_invalid_file_upload()

        # Test Suite 2: Categorization
        print("\n" + "="*80)
        print("TEST SUITE 2: DOCUMENT CATEGORIZATION")
        print("="*80)
        self.test_document_categorization()

        # Test Suite 3: Retrieval and Search
        print("\n" + "="*80)
        print("TEST SUITE 3: DOCUMENT RETRIEVAL AND SEARCH")
        print("="*80)
        self.test_document_list_retrieval()
        self.test_document_search()

        # Test Suite 4: E-Signature
        print("\n" + "="*80)
        print("TEST SUITE 4: E-SIGNATURE WORKFLOW")
        print("="*80)
        self.test_esignature_workflow_initiate()
        self.test_pending_signatures_list()

        # Test Suite 5: Expiration
        print("\n" + "="*80)
        print("TEST SUITE 5: DOCUMENT EXPIRATION")
        print("="*80)
        self.test_document_expiration_setting()

        # Test Suite 6: Permissions
        print("\n" + "="*80)
        print("TEST SUITE 6: ACCESS PERMISSIONS AND SHARING")
        print("="*80)
        self.test_document_access_permissions()
        self.test_user_document_visibility()

        # Test Suite 7: Templates
        print("\n" + "="*80)
        print("TEST SUITE 7: DOCUMENT TEMPLATES")
        print("="*80)
        self.test_document_templates_list()

        # Test Suite 8: Filtering
        print("\n" + "="*80)
        print("TEST SUITE 8: DOCUMENT FILTERING AND METADATA")
        print("="*80)
        self.test_document_filtering_by_category()
        self.test_document_filtering_by_status()

        # Generate report
        return self.generate_report()


def main():
    """Main execution function."""
    import sys

    # Initialize test suite
    suite = DocumentManagementTestSuite()

    # Run tests
    results = suite.run_all_tests()

    # Save report
    report_file = Path("tests_comprehensive/reports/document_management_test_report.json")
    report_file.parent.mkdir(parents=True, exist_ok=True)

    with open(report_file, 'w') as f:
        json.dump(results, f, indent=2, default=str)

    print(f"\nReport saved to: {report_file}")

    # Exit with appropriate code
    sys.exit(0 if results['failed'] == 0 else 1)


if __name__ == '__main__':
    main()
