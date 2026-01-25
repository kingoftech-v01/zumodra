"""
ATS Offer Management System

This module provides comprehensive offer management functionality:
- OfferTemplate: Standard offer package templates
- OfferApprovalWorkflow: Multi-level approval workflows
- Compensation calculator with market comparison
- E-signature integration hooks
- Offer letter generation
- Counter-offer handling
- Offer expiration and auto-withdrawal

All classes are tenant-aware and follow Zumodra's multi-tenant architecture.
"""

import logging
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timedelta, date
from decimal import Decimal
from enum import Enum
from typing import Any, Dict, List, Optional, Tuple

from django.conf import settings
from django.db import models, transaction
from django.db.models import Avg, F, Q, Sum
from django.template import Template, Context
from django.utils import timezone
from django.utils.translation import gettext_lazy as _
from django.core.validators import MinValueValidator

from core.db.models import TenantAwareModel, FullAuditModel
from core.db.managers import TenantAwareManager, FullAuditManager
from jobs.models import OfferTemplate, OfferApproval

logger = logging.getLogger(__name__)


# =============================================================================
# ENUMS AND CONSTANTS
# =============================================================================

class OfferStatus(str, Enum):
    """Offer status states."""
    DRAFT = 'draft'
    PENDING_APPROVAL = 'pending_approval'
    APPROVED = 'approved'
    SENT = 'sent'
    VIEWED = 'viewed'
    ACCEPTED = 'accepted'
    DECLINED = 'declined'
    COUNTERED = 'countered'
    EXPIRED = 'expired'
    WITHDRAWN = 'withdrawn'
    NEGOTIATING = 'negotiating'


class ApprovalStatus(str, Enum):
    """Approval step status."""
    PENDING = 'pending'
    APPROVED = 'approved'
    REJECTED = 'rejected'
    SKIPPED = 'skipped'


class CompensationType(str, Enum):
    """Types of compensation components."""
    BASE_SALARY = 'base_salary'
    SIGNING_BONUS = 'signing_bonus'
    ANNUAL_BONUS = 'annual_bonus'
    EQUITY = 'equity'
    RELOCATION = 'relocation'
    OTHER = 'other'


class EquityType(str, Enum):
    """Types of equity compensation."""
    STOCK_OPTIONS = 'stock_options'
    RSU = 'rsu'
    ESPP = 'espp'
    PHANTOM = 'phantom'


class ESignatureProvider(str, Enum):
    """Supported e-signature providers."""
    DOCUSIGN = 'docusign'
    HELLOSIGN = 'hellosign'
    ADOBE_SIGN = 'adobe_sign'
    PANDADOC = 'pandadoc'


# =============================================================================
# DATA CLASSES
# =============================================================================

@dataclass
class CompensationBreakdown:
    """Detailed compensation breakdown."""
    base_salary: Decimal
    currency: str = 'CAD'
    salary_period: str = 'yearly'
    signing_bonus: Decimal = Decimal('0')
    annual_bonus_target: Decimal = Decimal('0')
    annual_bonus_max: Decimal = Decimal('0')
    equity_value: Decimal = Decimal('0')
    equity_type: Optional[EquityType] = None
    equity_shares: int = 0
    equity_vesting_months: int = 48
    relocation_bonus: Decimal = Decimal('0')
    other_compensation: Dict[str, Decimal] = field(default_factory=dict)

    @property
    def total_first_year(self) -> Decimal:
        """Calculate total first-year compensation."""
        total = self.base_salary + self.signing_bonus + self.relocation_bonus
        total += self.annual_bonus_target
        # Assume 1/4 of equity vests in first year
        if self.equity_vesting_months > 0:
            first_year_equity = self.equity_value * Decimal('12') / Decimal(str(self.equity_vesting_months))
            total += first_year_equity
        for value in self.other_compensation.values():
            total += value
        return total

    @property
    def total_annual(self) -> Decimal:
        """Calculate total annual compensation (excluding one-time bonuses)."""
        annual = self.base_salary + self.annual_bonus_target
        if self.equity_vesting_months > 0:
            annual_equity = self.equity_value * Decimal('12') / Decimal(str(self.equity_vesting_months))
            annual += annual_equity
        return annual


@dataclass
class MarketComparison:
    """Market data comparison for compensation."""
    role: str
    location: str
    experience_level: str
    market_base_25th: Decimal
    market_base_50th: Decimal
    market_base_75th: Decimal
    market_base_90th: Decimal
    offer_base: Decimal
    percentile: float
    is_competitive: bool
    recommendation: str


@dataclass
class InternalEquityAnalysis:
    """Internal equity analysis results."""
    similar_role_count: int
    avg_base_salary: Decimal
    min_base_salary: Decimal
    max_base_salary: Decimal
    offer_base: Decimal
    variance_from_avg: float
    is_within_band: bool
    recommendation: str


@dataclass
class ApprovalRequest:
    """Request for offer approval."""
    offer_id: str
    approver_id: str
    approver_name: str
    level: int
    requested_at: datetime
    due_by: Optional[datetime] = None
    notes: str = ''


@dataclass
class SignatureRequest:
    """E-signature request details."""
    document_id: str
    provider: ESignatureProvider
    signer_email: str
    signer_name: str
    status: str = 'pending'
    sent_at: Optional[datetime] = None
    signed_at: Optional[datetime] = None
    signature_url: str = ''


# Note: OfferTemplate model is imported from jobs.models


# =============================================================================
# OFFER APPROVAL WORKFLOW MODEL
# =============================================================================

class OfferApprovalWorkflow(TenantAwareModel):
    """
    Multi-level approval workflow definition.

    Defines the approval chain for offers based on
    compensation thresholds or other criteria.
    """

    name = models.CharField(max_length=100)
    description = models.TextField(blank=True)
    is_active = models.BooleanField(default=True)

    # Trigger conditions
    min_base_salary = models.DecimalField(
        max_digits=12,
        decimal_places=2,
        null=True,
        blank=True,
        help_text=_('Applies to offers with base salary >= this amount')
    )
    max_base_salary = models.DecimalField(
        max_digits=12,
        decimal_places=2,
        null=True,
        blank=True,
        help_text=_('Applies to offers with base salary <= this amount')
    )
    applies_to_equity = models.BooleanField(
        default=False,
        help_text=_('Applies to offers that include equity')
    )
    applies_to_levels = models.JSONField(
        default=list,
        blank=True,
        help_text=_('Experience levels this workflow applies to')
    )

    # Workflow settings
    parallel_approval = models.BooleanField(
        default=False,
        help_text=_('Allow approvals at the same level in parallel')
    )
    auto_expire_hours = models.PositiveIntegerField(
        default=72,
        help_text=_('Auto-expire pending approvals after this many hours')
    )
    allow_delegation = models.BooleanField(default=True)

    objects = TenantAwareManager()

    class Meta:
        verbose_name = _('Offer Approval Workflow')
        verbose_name_plural = _('Offer Approval Workflows')
        ordering = ['name']

    def __str__(self):
        return self.name

    def get_approvers_for_level(self, level: int):
        """Get approvers for a specific level."""
        return self.levels.filter(level=level, is_active=True)


class OfferApprovalLevel(models.Model):
    """
    Individual level in an approval workflow.

    Tenant isolation is achieved through the parent OfferApprovalWorkflow model.
    Access tenant via self.workflow.tenant.
    """

    workflow = models.ForeignKey(
        OfferApprovalWorkflow,
        on_delete=models.CASCADE,
        related_name='levels'
    )
    level = models.PositiveIntegerField(
        help_text=_('Order of approval (1 = first)')
    )
    name = models.CharField(max_length=100)

    @property
    def tenant(self):
        """Access tenant through parent workflow."""
        return self.workflow.tenant if self.workflow else None

    def validate_tenant_access(self, request_tenant):
        """
        Validate that the requesting tenant has access to this approval level.

        Args:
            request_tenant: The tenant making the request

        Returns:
            True if access is valid, False otherwise
        """
        return self.tenant == request_tenant

    # Approvers (can be specific user or role-based)
    approver = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name='approval_levels'
    )
    approver_role = models.CharField(
        max_length=50,
        blank=True,
        help_text=_('Role-based approver (e.g., "hiring_manager")')
    )

    # Level settings
    is_active = models.BooleanField(default=True)
    is_required = models.BooleanField(
        default=True,
        help_text=_('If false, this level can be skipped')
    )
    auto_approve_under = models.DecimalField(
        max_digits=12,
        decimal_places=2,
        null=True,
        blank=True,
        help_text=_('Auto-approve if base salary is under this amount')
    )

    class Meta:
        verbose_name = _('Approval Level')
        verbose_name_plural = _('Approval Levels')
        ordering = ['workflow', 'level']
        unique_together = ['workflow', 'level']

    def __str__(self):
        return f"{self.workflow.name} - Level {self.level}: {self.name}"


# Note: OfferApproval model is imported from jobs.models


# =============================================================================
# COMPENSATION COMPONENT MODEL
# =============================================================================

class CompensationComponent(models.Model):
    """
    Individual compensation component for an offer.

    Tenant isolation is achieved through the parent Offer model.
    Access tenant via self.offer.application.tenant.
    """

    offer = models.ForeignKey(
        'jobs.Offer',
        on_delete=models.CASCADE,
        related_name='compensation_components'
    )
    component_type = models.CharField(
        max_length=20,
        choices=[(c.value, c.name.replace('_', ' ').title()) for c in CompensationType]
    )

    @property
    def tenant(self):
        """Access tenant through parent offer's application."""
        if self.offer and hasattr(self.offer, 'application') and self.offer.application:
            return self.offer.application.tenant
        return None

    def validate_tenant_access(self, request_tenant):
        """
        Validate that the requesting tenant has access to this component.

        Args:
            request_tenant: The tenant making the request

        Returns:
            True if access is valid, False otherwise
        """
        return self.tenant == request_tenant
    name = models.CharField(max_length=100)
    amount = models.DecimalField(
        max_digits=12,
        decimal_places=2,
        validators=[MinValueValidator(Decimal('0'))]
    )
    currency = models.CharField(max_length=3, default='CAD')
    frequency = models.CharField(
        max_length=20,
        choices=[
            ('one_time', _('One-time')),
            ('monthly', _('Monthly')),
            ('yearly', _('Yearly')),
        ],
        default='yearly'
    )
    is_guaranteed = models.BooleanField(default=True)
    notes = models.TextField(blank=True)

    # For equity
    equity_type = models.CharField(
        max_length=20,
        choices=[(e.value, e.name.replace('_', ' ').title()) for e in EquityType],
        blank=True
    )
    equity_shares = models.PositiveIntegerField(null=True, blank=True)
    vesting_months = models.PositiveIntegerField(null=True, blank=True)
    cliff_months = models.PositiveIntegerField(null=True, blank=True)

    class Meta:
        verbose_name = _('Compensation Component')
        verbose_name_plural = _('Compensation Components')
        ordering = ['component_type', '-amount']

    def __str__(self):
        return f"{self.name}: {self.currency} {self.amount}"


# =============================================================================
# COUNTER OFFER MODEL
# =============================================================================

class CounterOffer(TenantAwareModel):
    """
    Counter-offer from candidate during negotiation.
    """

    original_offer = models.ForeignKey(
        'jobs.Offer',
        on_delete=models.CASCADE,
        related_name='counter_offers'
    )
    counter_number = models.PositiveIntegerField(default=1)

    # Requested changes
    requested_base_salary = models.DecimalField(
        max_digits=12,
        decimal_places=2,
        null=True,
        blank=True
    )
    requested_signing_bonus = models.DecimalField(
        max_digits=12,
        decimal_places=2,
        null=True,
        blank=True
    )
    requested_equity = models.TextField(blank=True)
    requested_start_date = models.DateField(null=True, blank=True)
    other_requests = models.TextField(blank=True)
    candidate_notes = models.TextField(blank=True)

    # Response
    status = models.CharField(
        max_length=20,
        choices=[
            ('pending', _('Pending Review')),
            ('accepted', _('Accepted')),
            ('partially_accepted', _('Partially Accepted')),
            ('rejected', _('Rejected')),
            ('withdrawn', _('Withdrawn')),
        ],
        default='pending'
    )
    response_notes = models.TextField(blank=True)
    responded_at = models.DateTimeField(null=True, blank=True)
    responded_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name='counter_offer_responses'
    )

    # If counter results in new offer
    revised_offer = models.ForeignKey(
        'jobs.Offer',
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name='based_on_counter'
    )

    objects = TenantAwareManager()

    class Meta:
        verbose_name = _('Counter Offer')
        verbose_name_plural = _('Counter Offers')
        ordering = ['-created_at']

    def __str__(self):
        return f"Counter #{self.counter_number} for {self.original_offer}"


# =============================================================================
# E-SIGNATURE DOCUMENT MODEL
# =============================================================================

class ESignatureDocument(TenantAwareModel):
    """
    E-signature document tracking.
    """

    offer = models.ForeignKey(
        'jobs.Offer',
        on_delete=models.CASCADE,
        related_name='signature_documents'
    )
    provider = models.CharField(
        max_length=20,
        choices=[(p.value, p.name.replace('_', ' ').title()) for p in ESignatureProvider]
    )

    # Provider details
    external_document_id = models.CharField(max_length=255)
    external_envelope_id = models.CharField(max_length=255, blank=True)

    # Document
    document_name = models.CharField(max_length=200)
    document_url = models.URLField(blank=True)
    signed_document_url = models.URLField(blank=True)

    # Signer info
    signer_email = models.EmailField()
    signer_name = models.CharField(max_length=200)

    # Status tracking
    status = models.CharField(
        max_length=20,
        choices=[
            ('created', _('Created')),
            ('sent', _('Sent')),
            ('viewed', _('Viewed')),
            ('signed', _('Signed')),
            ('declined', _('Declined')),
            ('expired', _('Expired')),
            ('voided', _('Voided')),
        ],
        default='created'
    )
    sent_at = models.DateTimeField(null=True, blank=True)
    viewed_at = models.DateTimeField(null=True, blank=True)
    signed_at = models.DateTimeField(null=True, blank=True)
    expires_at = models.DateTimeField(null=True, blank=True)

    # Audit
    webhook_events = models.JSONField(default=list, blank=True)

    objects = TenantAwareManager()

    class Meta:
        verbose_name = _('E-Signature Document')
        verbose_name_plural = _('E-Signature Documents')
        ordering = ['-created_at']

    def __str__(self):
        return f"{self.document_name} ({self.status})"


# =============================================================================
# OFFER MANAGEMENT SERVICE
# =============================================================================

class OfferManagementService:
    """
    Comprehensive service for offer management operations.
    """

    @staticmethod
    def calculate_compensation(
        base_salary: Decimal,
        currency: str = 'CAD',
        signing_bonus: Decimal = Decimal('0'),
        annual_bonus_target_percent: Decimal = Decimal('0'),
        annual_bonus_max_percent: Decimal = Decimal('0'),
        equity_value: Decimal = Decimal('0'),
        equity_type: EquityType = None,
        equity_shares: int = 0,
        vesting_months: int = 48,
        relocation_bonus: Decimal = Decimal('0'),
        other: Dict[str, Decimal] = None
    ) -> CompensationBreakdown:
        """
        Calculate detailed compensation breakdown.

        Args:
            base_salary: Base salary amount
            currency: Currency code
            signing_bonus: One-time signing bonus
            annual_bonus_target_percent: Target bonus as % of base
            annual_bonus_max_percent: Max bonus as % of base
            equity_value: Total equity value
            equity_type: Type of equity
            equity_shares: Number of shares
            vesting_months: Vesting period in months
            relocation_bonus: Relocation assistance
            other: Other compensation components

        Returns:
            CompensationBreakdown with all details
        """
        annual_bonus_target = base_salary * annual_bonus_target_percent / Decimal('100')
        annual_bonus_max = base_salary * annual_bonus_max_percent / Decimal('100')

        return CompensationBreakdown(
            base_salary=base_salary,
            currency=currency,
            signing_bonus=signing_bonus,
            annual_bonus_target=annual_bonus_target,
            annual_bonus_max=annual_bonus_max,
            equity_value=equity_value,
            equity_type=equity_type,
            equity_shares=equity_shares,
            equity_vesting_months=vesting_months,
            relocation_bonus=relocation_bonus,
            other_compensation=other or {},
        )

    @staticmethod
    def compare_to_market(
        offer,
        market_data: Dict[str, Any]
    ) -> MarketComparison:
        """
        Compare offer compensation to market data.

        Args:
            offer: The offer to compare
            market_data: Market data with percentile values

        Returns:
            MarketComparison with analysis
        """
        offer_base = offer.base_salary

        # Market percentiles
        p25 = Decimal(str(market_data.get('base_25th', 0)))
        p50 = Decimal(str(market_data.get('base_50th', 0)))
        p75 = Decimal(str(market_data.get('base_75th', 0)))
        p90 = Decimal(str(market_data.get('base_90th', 0)))

        # Calculate percentile
        if offer_base <= p25:
            percentile = 25 * float(offer_base / p25) if p25 > 0 else 0
        elif offer_base <= p50:
            percentile = 25 + 25 * float((offer_base - p25) / (p50 - p25)) if p50 > p25 else 25
        elif offer_base <= p75:
            percentile = 50 + 25 * float((offer_base - p50) / (p75 - p50)) if p75 > p50 else 50
        elif offer_base <= p90:
            percentile = 75 + 15 * float((offer_base - p75) / (p90 - p75)) if p90 > p75 else 75
        else:
            percentile = 90 + min(10, 10 * float((offer_base - p90) / p90)) if p90 > 0 else 100

        is_competitive = percentile >= 50
        if percentile < 25:
            recommendation = "Offer is below market. Consider increasing to attract talent."
        elif percentile < 50:
            recommendation = "Offer is below median. May struggle to attract top candidates."
        elif percentile < 75:
            recommendation = "Offer is competitive and should attract good candidates."
        else:
            recommendation = "Offer is above market. Excellent for attracting top talent."

        return MarketComparison(
            role=market_data.get('role', ''),
            location=market_data.get('location', ''),
            experience_level=market_data.get('experience_level', ''),
            market_base_25th=p25,
            market_base_50th=p50,
            market_base_75th=p75,
            market_base_90th=p90,
            offer_base=offer_base,
            percentile=round(percentile, 1),
            is_competitive=is_competitive,
            recommendation=recommendation,
        )

    @staticmethod
    def analyze_internal_equity(
        tenant,
        offer,
        role: str = None,
        department: str = None
    ) -> InternalEquityAnalysis:
        """
        Analyze offer against internal equity (existing employees).

        Args:
            tenant: Tenant context
            offer: The offer to analyze
            role: Role to compare against
            department: Department to compare against

        Returns:
            InternalEquityAnalysis with results
        """
        from jobs.models import Offer

        # Get similar offers that were accepted
        similar_offers = Offer.objects.filter(
            application__tenant=tenant,
            status=OfferStatus.ACCEPTED.value,
        )

        if role:
            similar_offers = similar_offers.filter(job_title__icontains=role)
        if department:
            similar_offers = similar_offers.filter(department=department)

        count = similar_offers.count()

        if count == 0:
            return InternalEquityAnalysis(
                similar_role_count=0,
                avg_base_salary=Decimal('0'),
                min_base_salary=Decimal('0'),
                max_base_salary=Decimal('0'),
                offer_base=offer.base_salary,
                variance_from_avg=0,
                is_within_band=True,
                recommendation="No similar roles found for comparison.",
            )

        stats = similar_offers.aggregate(
            avg=Avg('base_salary'),
            min=models.Min('base_salary'),
            max=models.Max('base_salary'),
        )

        avg_salary = Decimal(str(stats['avg'] or 0))
        min_salary = Decimal(str(stats['min'] or 0))
        max_salary = Decimal(str(stats['max'] or 0))

        variance = float((offer.base_salary - avg_salary) / avg_salary * 100) if avg_salary > 0 else 0
        is_within_band = min_salary <= offer.base_salary <= max_salary

        if variance < -15:
            recommendation = "Offer is significantly below internal average. Consider increasing."
        elif variance < -5:
            recommendation = "Offer is slightly below average but within acceptable range."
        elif variance <= 5:
            recommendation = "Offer aligns well with internal equity."
        elif variance <= 15:
            recommendation = "Offer is above average. Ensure justification is documented."
        else:
            recommendation = "Offer significantly exceeds internal norms. Executive approval recommended."

        return InternalEquityAnalysis(
            similar_role_count=count,
            avg_base_salary=avg_salary,
            min_base_salary=min_salary,
            max_base_salary=max_salary,
            offer_base=offer.base_salary,
            variance_from_avg=round(variance, 2),
            is_within_band=is_within_band,
            recommendation=recommendation,
        )

    @staticmethod
    @transaction.atomic
    def create_offer_from_template(
        tenant,
        application,
        template: OfferTemplate,
        base_salary: Decimal,
        start_date: date,
        created_by,
        **overrides
    ):
        """
        Create an offer from a template.

        Args:
            tenant: Tenant context
            application: Application receiving the offer
            template: Template to use
            base_salary: Base salary amount
            start_date: Proposed start date
            created_by: User creating the offer
            **overrides: Override template defaults

        Returns:
            Created Offer instance
        """
        from jobs.models import Offer

        offer = Offer.objects.create(
            application=application,
            status=OfferStatus.DRAFT.value,
            job_title=overrides.get('job_title', application.job.title),
            department=overrides.get('department', template.description),
            start_date=start_date,
            employment_type=template.employment_type,
            base_salary=base_salary,
            salary_currency=template.default_currency,
            salary_period=template.salary_period,
            signing_bonus=overrides.get('signing_bonus'),
            annual_bonus_target=overrides.get('annual_bonus_target', template.annual_bonus_target),
            equity=overrides.get('equity', template.equity_range) if template.include_equity else '',
            benefits_summary=template.benefits_summary,
            pto_days=template.pto_days,
            terms_and_conditions=template.terms_and_conditions,
            expiration_date=timezone.now().date() + timedelta(days=template.default_expiration_days),
            created_by=created_by,
        )

        # Create compensation components
        CompensationComponent.objects.create(
            offer=offer,
            component_type=CompensationType.BASE_SALARY.value,
            name='Base Salary',
            amount=base_salary,
            currency=template.default_currency,
            frequency=template.salary_period,
        )

        if overrides.get('signing_bonus'):
            CompensationComponent.objects.create(
                offer=offer,
                component_type=CompensationType.SIGNING_BONUS.value,
                name='Signing Bonus',
                amount=overrides['signing_bonus'],
                currency=template.default_currency,
                frequency='one_time',
            )

        logger.info(f"Created offer {offer.id} from template {template.name}")

        return offer

    @staticmethod
    @transaction.atomic
    def submit_for_approval(offer, submitted_by) -> List[OfferApproval]:
        """
        Submit an offer for approval.

        Args:
            offer: The offer to submit
            submitted_by: User submitting

        Returns:
            List of created approval requests
        """
        # Find applicable workflow
        workflow = OfferApprovalWorkflow.objects.filter(
            tenant=offer.application.tenant,
            is_active=True,
        ).filter(
            Q(min_base_salary__isnull=True) | Q(min_base_salary__lte=offer.base_salary),
            Q(max_base_salary__isnull=True) | Q(max_base_salary__gte=offer.base_salary),
        ).first()

        if not workflow:
            # No workflow - auto-approve
            offer.status = OfferStatus.APPROVED.value
            offer.approved_at = timezone.now()
            offer.approved_by = submitted_by
            offer.save()
            return []

        # Create approval requests for first level
        approvals = []
        first_level = workflow.levels.filter(is_active=True).order_by('level').first()

        if first_level:
            # Check auto-approve threshold
            if first_level.auto_approve_under and offer.base_salary < first_level.auto_approve_under:
                approval = OfferApproval.objects.create(
                    tenant=offer.application.tenant,
                    offer=offer,
                    level=first_level,
                    approver=submitted_by,
                    status=ApprovalStatus.APPROVED.value,
                    responded_at=timezone.now(),
                    notes='Auto-approved: under threshold',
                )
                approvals.append(approval)
            else:
                approval = OfferApproval.objects.create(
                    tenant=offer.application.tenant,
                    offer=offer,
                    level=first_level,
                    approver=first_level.approver,
                    expires_at=timezone.now() + timedelta(hours=workflow.auto_expire_hours),
                )
                approvals.append(approval)

        offer.status = OfferStatus.PENDING_APPROVAL.value
        offer.save()

        logger.info(f"Offer {offer.id} submitted for approval")

        return approvals

    @staticmethod
    @transaction.atomic
    def process_approval(
        approval: OfferApproval,
        decision: str,
        notes: str = '',
        rejection_reason: str = '',
        user=None
    ) -> bool:
        """
        Process an approval decision.

        Args:
            approval: The approval to process
            decision: 'approved' or 'rejected'
            notes: Optional notes
            rejection_reason: Reason if rejected
            user: User making the decision (for permission checks)

        Returns:
            True if offer is now fully approved

        Raises:
            PermissionError: If user lacks permission or is not the designated approver
        """
        offer = approval.offer

        # Permission check
        if user is not None:
            # Check if user is the designated approver
            if approval.approver and approval.approver != user:
                if not (getattr(user, 'is_superuser', False) or
                        (hasattr(user, 'has_perm') and user.has_perm('jobs.approve_any_offer'))):
                    logger.warning(
                        f"User {user.id} attempted to process approval assigned to {approval.approver.id}"
                    )
                    raise PermissionError("Only the designated approver can process this approval")

            # Verify tenant access
            if hasattr(offer, 'tenant') and hasattr(user, 'tenant'):
                if offer.tenant != user.tenant:
                    raise PermissionError("User does not have access to this offer's tenant")

        if decision == 'approved':
            approval.approve(notes)

            # Check if there are more levels
            workflow = approval.level.workflow
            next_level = workflow.levels.filter(
                level__gt=approval.level.level,
                is_active=True
            ).order_by('level').first()

            if next_level:
                # Create next level approval
                OfferApproval.objects.create(
                    tenant=offer.application.tenant,
                    offer=offer,
                    level=next_level,
                    approver=next_level.approver,
                    expires_at=timezone.now() + timedelta(hours=workflow.auto_expire_hours),
                )
                return False
            else:
                # All levels approved
                offer.status = OfferStatus.APPROVED.value
                offer.approved_at = timezone.now()
                offer.approved_by = approval.approver
                offer.save()
                logger.info(f"Offer {offer.id} fully approved")
                return True
        else:
            approval.reject(rejection_reason)
            offer.status = OfferStatus.DRAFT.value  # Return to draft for revision
            offer.save()
            logger.info(f"Offer {offer.id} rejected at level {approval.level.level}")
            return False

    # Dangerous template tags that could be exploited for template injection
    DANGEROUS_TEMPLATE_TAGS = [
        '{% load',      # Loading arbitrary template tags
        '{% import',    # Importing modules
        '{% include',   # Including other templates
        '{% extends',   # Extending templates
        '{% ssi',       # Server-side includes
        '{% debug',     # Debug info exposure
        '{% csrf_token',  # CSRF manipulation
        '{# comment',   # Could be used to hide malicious code
        '{{ request',   # Access to request object
        '{{ settings',  # Access to settings
        '{{ user',      # Access to user object
        '__class__',    # Python introspection
        '__mro__',      # Method resolution order
        '__subclasses__',  # Class hierarchy access
        '__globals__',  # Global variables access
        '__builtins__', # Builtin functions access
        '__import__',   # Import statement
    ]

    @staticmethod
    def _sanitize_template(template_content: str) -> str:
        """
        Sanitize template content to prevent template injection attacks.

        Args:
            template_content: Raw template string

        Returns:
            Sanitized template string

        Raises:
            ValueError: If template contains dangerous tags
        """
        if not template_content:
            return template_content

        template_lower = template_content.lower()

        for dangerous_tag in OfferManagementService.DANGEROUS_TEMPLATE_TAGS:
            if dangerous_tag.lower() in template_lower:
                logger.warning(
                    f"Dangerous template tag detected: {dangerous_tag}"
                )
                raise ValueError(
                    f"Template contains forbidden tag: {dangerous_tag}. "
                    "Only safe variable interpolation and basic control structures are allowed."
                )

        return template_content

    @staticmethod
    def _get_safe_template_engine():
        """
        Get a safe template engine configuration.

        Returns:
            Django template Engine with restricted settings
        """
        from django.template import Engine

        # Create a restricted template engine with no builtins except safe ones
        safe_engine = Engine(
            debug=False,
            autoescape=True,  # Always escape HTML
            libraries={},      # No custom template libraries
            builtins=[
                'django.template.defaultfilters',  # Safe filters only
            ],
        )
        return safe_engine

    @staticmethod
    def generate_offer_letter(offer, template_content: str = None) -> str:
        """
        Generate offer letter content from template.

        Args:
            offer: The offer to generate letter for
            template_content: Optional custom template

        Returns:
            Rendered offer letter HTML

        Raises:
            ValueError: If template contains dangerous/forbidden tags
        """
        from django.utils.html import escape

        # Default template if none provided
        if not template_content:
            template_content = """
            <h1>Offer of Employment</h1>

            <p>Dear {{ candidate_name }},</p>

            <p>We are pleased to offer you the position of <strong>{{ job_title }}</strong>
            at {{ company_name }}.</p>

            <h2>Compensation</h2>
            <ul>
                <li>Base Salary: {{ currency }} {{ base_salary|floatformat:2 }} {{ salary_period }}</li>
                {% if signing_bonus %}<li>Signing Bonus: {{ currency }} {{ signing_bonus|floatformat:2 }}</li>{% endif %}
                {% if annual_bonus %}<li>Annual Bonus Target: {{ annual_bonus }}</li>{% endif %}
                {% if equity %}<li>Equity: {{ equity }}</li>{% endif %}
            </ul>

            <h2>Benefits</h2>
            <p>{{ benefits_summary }}</p>

            <h2>Start Date</h2>
            <p>Your anticipated start date is <strong>{{ start_date }}</strong>.</p>

            <h2>Terms</h2>
            <p>{{ terms_and_conditions }}</p>

            <p>This offer expires on {{ expiration_date }}.</p>

            <p>We look forward to welcoming you to the team!</p>

            <p>Sincerely,<br>
            {{ sender_name }}<br>
            {{ sender_title }}</p>
            """
        else:
            # Sanitize user-provided template content
            template_content = OfferManagementService._sanitize_template(template_content)

        # Build context with escaped values for safety
        context = Context({
            'candidate_name': escape(offer.application.candidate.full_name),
            'job_title': escape(offer.job_title),
            'company_name': escape(offer.application.tenant.name if hasattr(offer.application, 'tenant') else 'Company'),
            'currency': escape(offer.salary_currency),
            'base_salary': offer.base_salary,
            'salary_period': escape(offer.salary_period),
            'signing_bonus': offer.signing_bonus,
            'annual_bonus': escape(str(offer.annual_bonus_target)) if offer.annual_bonus_target else '',
            'equity': escape(offer.equity) if offer.equity else '',
            'benefits_summary': escape(offer.benefits_summary) if offer.benefits_summary else '',
            'start_date': offer.start_date,
            'terms_and_conditions': escape(offer.terms_and_conditions) if offer.terms_and_conditions else '',
            'expiration_date': offer.expiration_date,
            'sender_name': escape(offer.created_by.get_full_name() if offer.created_by else 'Hiring Team'),
            'sender_title': 'Hiring Manager',
        }, autoescape=True)

        # Use safe template engine
        safe_engine = OfferManagementService._get_safe_template_engine()
        template = safe_engine.from_string(template_content)
        return template.render(context)

    @staticmethod
    @transaction.atomic
    def handle_counter_offer(
        offer,
        counter_data: Dict[str, Any],
        candidate_notes: str = ''
    ) -> CounterOffer:
        """
        Record a counter-offer from candidate.

        Args:
            offer: The original offer
            counter_data: Counter-offer details
            candidate_notes: Notes from candidate

        Returns:
            Created CounterOffer instance
        """
        # Get counter number
        existing_count = offer.counter_offers.count()

        counter = CounterOffer.objects.create(
            tenant=offer.application.tenant,
            original_offer=offer,
            counter_number=existing_count + 1,
            requested_base_salary=counter_data.get('base_salary'),
            requested_signing_bonus=counter_data.get('signing_bonus'),
            requested_equity=counter_data.get('equity', ''),
            requested_start_date=counter_data.get('start_date'),
            other_requests=counter_data.get('other', ''),
            candidate_notes=candidate_notes,
        )

        offer.status = OfferStatus.NEGOTIATING.value
        offer.save()

        logger.info(f"Counter-offer #{counter.counter_number} received for offer {offer.id}")

        return counter

    @staticmethod
    @transaction.atomic
    def create_revised_offer(
        original_offer,
        counter_offer: CounterOffer,
        accepted_changes: Dict[str, Any],
        created_by
    ):
        """
        Create a revised offer based on counter-offer negotiation.

        Args:
            original_offer: The original offer
            counter_offer: The counter-offer being responded to
            accepted_changes: Changes that were accepted
            created_by: User creating revised offer

        Returns:
            New revised Offer instance
        """
        from jobs.models import Offer

        # Copy original offer with accepted changes
        revised = Offer.objects.create(
            application=original_offer.application,
            status=OfferStatus.DRAFT.value,
            job_title=original_offer.job_title,
            department=original_offer.department,
            reports_to=original_offer.reports_to,
            start_date=accepted_changes.get('start_date', original_offer.start_date),
            employment_type=original_offer.employment_type,
            base_salary=accepted_changes.get('base_salary', original_offer.base_salary),
            salary_currency=original_offer.salary_currency,
            salary_period=original_offer.salary_period,
            signing_bonus=accepted_changes.get('signing_bonus', original_offer.signing_bonus),
            annual_bonus_target=original_offer.annual_bonus_target,
            equity=accepted_changes.get('equity', original_offer.equity),
            benefits_summary=original_offer.benefits_summary,
            pto_days=original_offer.pto_days,
            terms_and_conditions=original_offer.terms_and_conditions,
            expiration_date=timezone.now().date() + timedelta(days=7),
            created_by=created_by,
        )

        # Link counter-offer to revised offer
        counter_offer.revised_offer = revised
        counter_offer.status = 'accepted' if accepted_changes else 'partially_accepted'
        counter_offer.responded_at = timezone.now()
        counter_offer.responded_by = created_by
        counter_offer.save()

        # Mark original offer as superseded
        original_offer.status = OfferStatus.WITHDRAWN.value
        original_offer.save()

        logger.info(f"Created revised offer {revised.id} from counter-offer {counter_offer.id}")

        return revised

    @staticmethod
    @transaction.atomic
    def send_offer(offer, send_method: str = 'email') -> bool:
        """
        Send offer to candidate.

        Args:
            offer: The offer to send
            send_method: Method to send ('email', 'portal', 'esign')

        Returns:
            True if sent successfully
        """
        if offer.status != OfferStatus.APPROVED.value:
            logger.warning(f"Cannot send unapproved offer {offer.id}")
            return False

        offer.status = OfferStatus.SENT.value
        offer.sent_at = timezone.now()
        offer.save()

        # In production, send actual notification
        logger.info(f"Offer {offer.id} sent to candidate via {send_method}")

        return True

    @staticmethod
    @transaction.atomic
    def expire_pending_offers(tenant) -> int:
        """
        Expire offers that have passed their expiration date.

        Args:
            tenant: Tenant context

        Returns:
            Count of expired offers
        """
        from jobs.models import Offer

        expired = Offer.objects.filter(
            application__tenant=tenant,
            status__in=[OfferStatus.SENT.value, OfferStatus.VIEWED.value],
            expiration_date__lt=timezone.now().date()
        )

        count = expired.count()
        expired.update(status=OfferStatus.EXPIRED.value)

        if count > 0:
            logger.info(f"Expired {count} offers for tenant {tenant.id}")

        return count


# =============================================================================
# E-SIGNATURE SERVICE
# =============================================================================

class ESignatureService:
    """
    Service for e-signature integration.
    """

    @staticmethod
    def create_signature_request(
        offer,
        provider: ESignatureProvider,
        document_content: str,
        document_name: str = 'Offer Letter'
    ) -> ESignatureDocument:
        """
        Create an e-signature request.

        Args:
            offer: The offer being signed
            provider: E-signature provider
            document_content: HTML/PDF content
            document_name: Name for the document

        Returns:
            ESignatureDocument record
        """
        # In production, this would call the provider's API
        external_id = f"{provider.value}_{uuid.uuid4().hex[:12]}"

        doc = ESignatureDocument.objects.create(
            tenant=offer.application.tenant,
            offer=offer,
            provider=provider.value,
            external_document_id=external_id,
            document_name=document_name,
            signer_email=offer.application.candidate.email,
            signer_name=offer.application.candidate.full_name,
            status='created',
            expires_at=timezone.now() + timedelta(days=14),
        )

        logger.info(f"Created e-signature request {doc.id} for offer {offer.id}")

        return doc

    @staticmethod
    def send_for_signature(doc: ESignatureDocument) -> bool:
        """
        Send document for e-signature.

        Args:
            doc: The document to send

        Returns:
            True if sent successfully
        """
        # In production, call provider API to send
        doc.status = 'sent'
        doc.sent_at = timezone.now()
        doc.save()

        logger.info(f"Sent document {doc.id} for signature")

        return True

    # Webhook signature secrets (should be loaded from settings in production)
    WEBHOOK_SECRETS = {
        ESignatureProvider.DOCUSIGN: 'docusign_webhook_secret',
        ESignatureProvider.HELLOSIGN: 'hellosign_webhook_secret',
        ESignatureProvider.ADOBE_SIGN: 'adobe_sign_webhook_secret',
        ESignatureProvider.PANDADOC: 'pandadoc_webhook_secret',
    }

    @staticmethod
    def _verify_webhook_signature(
        provider: ESignatureProvider,
        payload: bytes,
        signature: str,
        timestamp: str = None
    ) -> bool:
        """
        Verify HMAC signature of incoming webhook.

        Args:
            provider: E-signature provider
            payload: Raw request body bytes
            signature: Signature header value from request
            timestamp: Optional timestamp header for replay protection

        Returns:
            True if signature is valid, False otherwise
        """
        import hmac
        import hashlib
        import time

        # Get secret for this provider from settings
        secret_key = getattr(
            settings,
            f'{provider.value.upper()}_WEBHOOK_SECRET',
            ESignatureService.WEBHOOK_SECRETS.get(provider)
        )

        if not secret_key:
            logger.error(f"No webhook secret configured for provider: {provider.value}")
            return False

        # Check timestamp if provided (replay protection)
        if timestamp:
            try:
                webhook_time = int(timestamp)
                current_time = int(time.time())
                # Reject webhooks older than 5 minutes
                if abs(current_time - webhook_time) > 300:
                    logger.warning(
                        f"Webhook timestamp too old: {webhook_time}, current: {current_time}"
                    )
                    return False
            except (ValueError, TypeError):
                logger.warning(f"Invalid webhook timestamp: {timestamp}")

        # Compute expected signature based on provider
        if provider == ESignatureProvider.DOCUSIGN:
            # DocuSign uses HMAC-SHA256 with base64 encoding
            import base64
            expected_signature = base64.b64encode(
                hmac.new(
                    secret_key.encode('utf-8'),
                    payload,
                    hashlib.sha256
                ).digest()
            ).decode('utf-8')
        elif provider == ESignatureProvider.HELLOSIGN:
            # HelloSign uses HMAC-SHA256 hex
            expected_signature = hmac.new(
                secret_key.encode('utf-8'),
                payload,
                hashlib.sha256
            ).hexdigest()
        else:
            # Default to HMAC-SHA256 hex
            expected_signature = hmac.new(
                secret_key.encode('utf-8'),
                payload,
                hashlib.sha256
            ).hexdigest()

        # Constant-time comparison to prevent timing attacks
        is_valid = hmac.compare_digest(expected_signature, signature)

        if not is_valid:
            logger.warning(
                f"Invalid webhook signature from {provider.value}. "
                f"Expected: {expected_signature[:20]}..., Got: {signature[:20]}..."
            )

        return is_valid

    @staticmethod
    def handle_webhook(
        provider: ESignatureProvider,
        event_type: str,
        document_id: str,
        event_data: Dict[str, Any],
        raw_payload: bytes = None,
        signature: str = None,
        timestamp: str = None
    ) -> bool:
        """
        Handle webhook callback from e-signature provider.

        Args:
            provider: The provider sending the webhook
            event_type: Type of event (signed, viewed, declined, etc.)
            document_id: External document ID
            event_data: Full event data
            raw_payload: Raw request body for signature verification
            signature: Signature header from the webhook request
            timestamp: Optional timestamp header for replay protection

        Returns:
            True if handled successfully

        Raises:
            ValueError: If signature verification fails
        """
        # Verify webhook signature if provided
        if signature and raw_payload:
            if not ESignatureService._verify_webhook_signature(
                provider, raw_payload, signature, timestamp
            ):
                logger.error(
                    f"Webhook signature verification failed for {provider.value} document {document_id}"
                )
                raise ValueError("Invalid webhook signature")
        elif signature or raw_payload:
            # Partial verification data provided - log warning but continue
            logger.warning(
                f"Incomplete webhook verification data for {provider.value}. "
                "Both raw_payload and signature are required for verification."
            )

        try:
            doc = ESignatureDocument.objects.get(
                provider=provider.value,
                external_document_id=document_id
            )

            # Log event
            doc.webhook_events.append({
                'type': event_type,
                'timestamp': timezone.now().isoformat(),
                'data': event_data,
            })

            # Update status based on event
            if event_type == 'viewed':
                doc.status = 'viewed'
                doc.viewed_at = timezone.now()
                # Update offer status
                doc.offer.status = OfferStatus.VIEWED.value
                doc.offer.save()

            elif event_type == 'signed':
                doc.status = 'signed'
                doc.signed_at = timezone.now()
                doc.signed_document_url = event_data.get('signed_url', '')
                # Mark offer as accepted
                doc.offer.accept()

            elif event_type == 'declined':
                doc.status = 'declined'
                doc.offer.status = OfferStatus.DECLINED.value
                doc.offer.decline_reason = event_data.get('reason', 'Declined via e-signature')
                doc.offer.responded_at = timezone.now()
                doc.offer.save()

            doc.save()

            logger.info(f"Processed {event_type} webhook for document {doc.id}")
            return True

        except ESignatureDocument.DoesNotExist:
            logger.error(f"Document not found for webhook: {document_id}")
            return False
