"""
ATS Advanced Features Tests - Comprehensive tests for Cycle 3 enhancements

This module provides tests for:
- Pipeline management (templates, SLA tracking, analytics)
- Interview scheduling (availability, panel coordination, reminders)
- Offer management (templates, approvals, counter-offers, e-signature)
- Advanced reporting (funnel, DEI, cost, time-to-fill, source quality)

Tests are marked with appropriate pytest markers for categorization.
"""

import pytest
from datetime import datetime, timedelta, date, time
from decimal import Decimal
from unittest.mock import patch, MagicMock
from zoneinfo import ZoneInfo

from django.utils import timezone
from django.db import transaction

from ats.pipelines import (
    PipelineTemplateType,
    SLAStatus,
    StageTemplate,
    SLAMetrics,
    StageAnalytics,
    PipelineAnalytics,
    PipelineComparison,
    PipelineTemplate,
    StageSLAConfig,
    SLAEscalation,
    PipelineTemplateService,
    SLATrackingService,
    PipelineAnalyticsService,
)
from ats.scheduling import (
    CalendarProvider,
    MeetingProvider,
    SlotStatus,
    ReminderType,
    TimeSlot,
    AvailabilitySlot,
    CommonAvailability,
    MeetingDetails,
    SchedulingResult,
    InterviewSlot,
    InterviewerAvailability,
    AvailabilityException,
    InterviewReminder,
    GoogleCalendarAdapter,
    OutlookCalendarAdapter,
    MeetingLinkGenerator,
    InterviewSchedulingService,
)
from ats.offers import (
    OfferStatus,
    ApprovalStatus,
    CompensationType,
    EquityType,
    ESignatureProvider,
    CompensationBreakdown,
    MarketComparison,
    InternalEquityAnalysis,
    OfferTemplate,
    OfferApprovalWorkflow,
    OfferApprovalLevel,
    OfferApproval,
    CompensationComponent,
    CounterOffer,
    ESignatureDocument,
    OfferManagementService,
    ESignatureService,
)
from ats.advanced_reports import (
    ReportPeriod,
    GroupBy,
    FunnelStage,
    RecruitingFunnelData,
    DEIMetrics,
    DEIReport,
    CostComponent,
    CostPerHireData,
    TimeToFillMetrics,
    TimeToFillReport,
    SourceMetrics,
    SourceQualityReport,
    RecruiterMetrics,
    RecruiterPerformanceReport,
    HiringManagerMetrics,
    HiringManagerScorecard,
    ReportService,
    RecruitingFunnelReportService,
    DEIReportService,
    CostPerHireReportService,
    TimeToFillReportService,
    SourceQualityReportService,
    RecruiterPerformanceReportService,
    HiringManagerScorecardService,
)


# ============================================================================
# PIPELINE MANAGEMENT TESTS
# ============================================================================

@pytest.mark.pipelines
class TestPipelineTemplates:
    """Tests for pipeline template functionality."""

    def test_pipeline_template_type_enum(self):
        """Test PipelineTemplateType enum values."""
        assert PipelineTemplateType.TECHNICAL.value == 'technical'
        assert PipelineTemplateType.EXECUTIVE.value == 'executive'
        assert PipelineTemplateType.INTERN.value == 'intern'
        assert PipelineTemplateType.CONTRACTOR.value == 'contractor'

    def test_sla_status_enum(self):
        """Test SLAStatus enum values."""
        assert SLAStatus.ON_TRACK.value == 'on_track'
        assert SLAStatus.WARNING.value == 'warning'
        assert SLAStatus.CRITICAL.value == 'critical'
        assert SLAStatus.BREACHED.value == 'breached'

    def test_stage_template_dataclass(self):
        """Test StageTemplate dataclass."""
        stage = StageTemplate(
            name='Phone Screen',
            stage_type='screening',
            description='Initial phone screening',
            order=1,
            target_days=3,
        )

        assert stage.name == 'Phone Screen'
        assert stage.stage_type == 'screening'
        assert stage.target_days == 3
        assert stage.warning_threshold_days == 2  # default

    def test_sla_metrics_dataclass(self):
        """Test SLAMetrics dataclass."""
        metrics = SLAMetrics(
            status=SLAStatus.WARNING,
            days_in_stage=3,
            target_days=5,
            warning_threshold=3,
            critical_threshold=7,
            time_remaining=timedelta(days=2),
            is_breached=False,
        )

        assert metrics.status == SLAStatus.WARNING
        assert metrics.days_in_stage == 3
        assert not metrics.is_breached

    def test_get_template_config(self):
        """Test getting template configurations."""
        config = PipelineTemplateService.get_template_config(
            PipelineTemplateType.TECHNICAL
        )

        assert config['name'] == 'Technical Hiring'
        assert 'stages' in config
        assert len(config['stages']) > 0
        assert config['stages'][0]['stage_type'] == 'new'

    def test_get_template_config_executive(self):
        """Test executive template configuration."""
        config = PipelineTemplateService.get_template_config(
            PipelineTemplateType.EXECUTIVE
        )

        assert config['name'] == 'Executive Search'
        assert config['average_time_to_hire_days'] == 60
        # Executive pipeline should have more stages
        assert len(config['stages']) >= 8

    def test_get_template_config_intern(self):
        """Test intern template configuration."""
        config = PipelineTemplateService.get_template_config(
            PipelineTemplateType.INTERN
        )

        assert config['name'] == 'Intern/Entry-Level'
        assert config['average_time_to_hire_days'] == 14
        # Intern pipeline should be shorter
        assert len(config['stages']) <= 7

    def test_get_recommended_template(self):
        """Test template recommendation based on job type."""
        assert PipelineTemplateService.get_recommended_template(
            'Software Engineer'
        ) == PipelineTemplateType.TECHNICAL

        assert PipelineTemplateService.get_recommended_template(
            'Summer Intern'
        ) == PipelineTemplateType.INTERN

        assert PipelineTemplateService.get_recommended_template(
            'VP of Engineering'
        ) == PipelineTemplateType.EXECUTIVE

        assert PipelineTemplateService.get_recommended_template(
            'Freelance Designer'
        ) == PipelineTemplateType.CONTRACTOR


@pytest.mark.pipelines
@pytest.mark.django_db
class TestPipelineTemplateModel:
    """Tests for PipelineTemplate model."""

    def test_create_pipeline_template(self, tenant_factory):
        """Test creating a pipeline template."""
        tenant = tenant_factory()

        template = PipelineTemplate.objects.create(
            tenant=tenant,
            name='Custom Engineering',
            template_type=PipelineTemplateType.TECHNICAL.value,
            description='Custom pipeline for engineering roles',
            stages_config=[
                {'name': 'Applied', 'stage_type': 'new', 'target_days': 2},
                {'name': 'Review', 'stage_type': 'screening', 'target_days': 3},
            ],
            average_time_to_hire_days=21,
        )

        assert template.name == 'Custom Engineering'
        assert template.template_type == 'technical'

        # Test get_stages method
        stages = template.get_stages()
        assert len(stages) == 2
        assert stages[0].name == 'Applied'
        assert stages[0].target_days == 2


@pytest.mark.pipelines
class TestSLATracking:
    """Tests for SLA tracking functionality."""

    def test_sla_config_get_status_on_track(self):
        """Test SLA status calculation - on track."""
        config = MagicMock()
        config.target_days = 5
        config.warning_threshold_days = 3
        config.critical_threshold_days = 7

        config.get_sla_status = StageSLAConfig.get_sla_status.__get__(config)

        assert config.get_sla_status(1) == SLAStatus.ON_TRACK
        assert config.get_sla_status(3) == SLAStatus.ON_TRACK

    def test_sla_config_get_status_warning(self):
        """Test SLA status calculation - warning."""
        config = MagicMock()
        config.target_days = 5
        config.warning_threshold_days = 3
        config.critical_threshold_days = 7

        config.get_sla_status = StageSLAConfig.get_sla_status.__get__(config)

        assert config.get_sla_status(4) == SLAStatus.WARNING
        assert config.get_sla_status(5) == SLAStatus.WARNING

    def test_sla_config_get_status_critical(self):
        """Test SLA status calculation - critical."""
        config = MagicMock()
        config.target_days = 5
        config.warning_threshold_days = 3
        config.critical_threshold_days = 7

        config.get_sla_status = StageSLAConfig.get_sla_status.__get__(config)

        assert config.get_sla_status(6) == SLAStatus.CRITICAL
        assert config.get_sla_status(7) == SLAStatus.CRITICAL

    def test_sla_config_get_status_breached(self):
        """Test SLA status calculation - breached."""
        config = MagicMock()
        config.target_days = 5
        config.warning_threshold_days = 3
        config.critical_threshold_days = 7

        config.get_sla_status = StageSLAConfig.get_sla_status.__get__(config)

        assert config.get_sla_status(8) == SLAStatus.BREACHED
        assert config.get_sla_status(14) == SLAStatus.BREACHED


@pytest.mark.pipelines
class TestPipelineAnalytics:
    """Tests for pipeline analytics dataclasses."""

    def test_stage_analytics_dataclass(self):
        """Test StageAnalytics dataclass."""
        analytics = StageAnalytics(
            stage_id='abc123',
            stage_name='Phone Screen',
            stage_type='screening',
            application_count=25,
            average_time_days=3.5,
            median_time_days=3,
            conversion_rate=75.0,
            drop_off_rate=25.0,
            sla_compliance_rate=90.0,
            bottleneck_score=1.5,
        )

        assert analytics.stage_name == 'Phone Screen'
        assert analytics.conversion_rate == 75.0
        assert analytics.bottleneck_score == 1.5

    def test_pipeline_analytics_dataclass(self):
        """Test PipelineAnalytics dataclass."""
        analytics = PipelineAnalytics(
            pipeline_id='pipe123',
            pipeline_name='Engineering Pipeline',
            total_applications=100,
            active_applications=30,
            hired_count=10,
            rejected_count=50,
            withdrawn_count=10,
            average_time_to_hire_days=28.5,
            overall_conversion_rate=10.0,
            stage_analytics=[],
            bottleneck_stages=['Technical Assessment'],
            sla_compliance_rate=85.0,
        )

        assert analytics.total_applications == 100
        assert analytics.hired_count == 10
        assert 'Technical Assessment' in analytics.bottleneck_stages

    def test_pipeline_comparison_dataclass(self):
        """Test PipelineComparison dataclass."""
        comparison = PipelineComparison(
            pipeline_a_id='a123',
            pipeline_a_name='Pipeline A',
            pipeline_b_id='b456',
            pipeline_b_name='Pipeline B',
            metrics_comparison={
                'conversion_rate': {'pipeline_a': 12.0, 'pipeline_b': 10.0},
            },
            winner='a',
            confidence_level=0.85,
            recommendations=['Pipeline A has better conversion rate'],
        )

        assert comparison.winner == 'a'
        assert comparison.confidence_level == 0.85


# ============================================================================
# SCHEDULING TESTS
# ============================================================================

@pytest.mark.scheduling
class TestSchedulingEnums:
    """Tests for scheduling enums."""

    def test_calendar_provider_enum(self):
        """Test CalendarProvider enum values."""
        assert CalendarProvider.GOOGLE.value == 'google'
        assert CalendarProvider.OUTLOOK.value == 'outlook'

    def test_meeting_provider_enum(self):
        """Test MeetingProvider enum values."""
        assert MeetingProvider.ZOOM.value == 'zoom'
        assert MeetingProvider.TEAMS.value == 'teams'
        assert MeetingProvider.GOOGLE_MEET.value == 'google_meet'
        assert MeetingProvider.JITSI.value == 'jitsi'

    def test_slot_status_enum(self):
        """Test SlotStatus enum values."""
        assert SlotStatus.AVAILABLE.value == 'available'
        assert SlotStatus.BOOKED.value == 'booked'
        assert SlotStatus.BLOCKED.value == 'blocked'


@pytest.mark.scheduling
class TestTimeSlot:
    """Tests for TimeSlot dataclass."""

    def test_time_slot_creation(self):
        """Test TimeSlot creation."""
        start = datetime(2025, 1, 15, 10, 0, tzinfo=ZoneInfo('UTC'))
        end = datetime(2025, 1, 15, 11, 0, tzinfo=ZoneInfo('UTC'))

        slot = TimeSlot(start=start, end=end, timezone='UTC')

        assert slot.duration_minutes == 60

    def test_time_slot_overlaps(self):
        """Test TimeSlot overlap detection."""
        slot1 = TimeSlot(
            start=datetime(2025, 1, 15, 10, 0, tzinfo=ZoneInfo('UTC')),
            end=datetime(2025, 1, 15, 11, 0, tzinfo=ZoneInfo('UTC')),
        )
        slot2 = TimeSlot(
            start=datetime(2025, 1, 15, 10, 30, tzinfo=ZoneInfo('UTC')),
            end=datetime(2025, 1, 15, 11, 30, tzinfo=ZoneInfo('UTC')),
        )
        slot3 = TimeSlot(
            start=datetime(2025, 1, 15, 11, 0, tzinfo=ZoneInfo('UTC')),
            end=datetime(2025, 1, 15, 12, 0, tzinfo=ZoneInfo('UTC')),
        )

        assert slot1.overlaps(slot2) is True
        assert slot1.overlaps(slot3) is False

    def test_time_slot_timezone_conversion(self):
        """Test timezone conversion."""
        slot = TimeSlot(
            start=datetime(2025, 1, 15, 10, 0, tzinfo=ZoneInfo('UTC')),
            end=datetime(2025, 1, 15, 11, 0, tzinfo=ZoneInfo('UTC')),
            timezone='UTC'
        )

        converted = slot.to_timezone('America/Toronto')
        assert converted.timezone == 'America/Toronto'


@pytest.mark.scheduling
class TestMeetingLinkGenerator:
    """Tests for meeting link generation."""

    def test_generate_zoom_meeting(self):
        """Test Zoom meeting link generation."""
        details = MeetingLinkGenerator.generate_zoom_meeting(
            topic='Interview',
            start_time=datetime.now(),
            duration_minutes=60,
        )

        assert details.provider == MeetingProvider.ZOOM
        assert 'zoom.us' in details.meeting_url
        assert details.meeting_id != ''
        assert details.password != ''

    def test_generate_teams_meeting(self):
        """Test Teams meeting link generation."""
        details = MeetingLinkGenerator.generate_teams_meeting(
            subject='Interview',
            start_time=datetime.now(),
            end_time=datetime.now() + timedelta(hours=1),
        )

        assert details.provider == MeetingProvider.TEAMS
        assert 'teams.microsoft.com' in details.meeting_url

    def test_generate_google_meet(self):
        """Test Google Meet link generation."""
        details = MeetingLinkGenerator.generate_google_meet(
            title='Interview'
        )

        assert details.provider == MeetingProvider.GOOGLE_MEET
        assert 'meet.google.com' in details.meeting_url

    def test_generate_jitsi_meeting(self):
        """Test Jitsi meeting link generation."""
        details = MeetingLinkGenerator.generate_jitsi_meeting()

        assert details.provider == MeetingProvider.JITSI
        assert 'meet.jit.si' in details.meeting_url

    def test_generate_meeting_dispatch(self):
        """Test generate_meeting dispatch to correct provider."""
        details = MeetingLinkGenerator.generate_meeting(
            provider=MeetingProvider.ZOOM,
            topic='Test Interview',
            start_time=datetime.now(),
            end_time=datetime.now() + timedelta(hours=1),
        )

        assert details.provider == MeetingProvider.ZOOM


@pytest.mark.scheduling
class TestCalendarAdapters:
    """Tests for calendar integration adapters."""

    def test_google_calendar_authenticate(self):
        """Test Google Calendar authentication."""
        adapter = GoogleCalendarAdapter(credentials={})
        result = adapter.authenticate()
        assert result is True

    def test_google_calendar_create_event(self):
        """Test Google Calendar event creation."""
        adapter = GoogleCalendarAdapter(credentials={})
        event_id = adapter.create_event(
            title='Interview',
            start=datetime.now(),
            end=datetime.now() + timedelta(hours=1),
            attendees=['candidate@example.com'],
        )

        assert event_id is not None
        assert event_id.startswith('gcal_')

    def test_outlook_calendar_authenticate(self):
        """Test Outlook Calendar authentication."""
        adapter = OutlookCalendarAdapter(credentials={})
        result = adapter.authenticate()
        assert result is True

    def test_outlook_calendar_create_event(self):
        """Test Outlook Calendar event creation."""
        adapter = OutlookCalendarAdapter(credentials={})
        event_id = adapter.create_event(
            title='Interview',
            start=datetime.now(),
            end=datetime.now() + timedelta(hours=1),
            attendees=['candidate@example.com'],
        )

        assert event_id is not None
        assert event_id.startswith('outlook_')


@pytest.mark.scheduling
class TestSchedulingDataClasses:
    """Tests for scheduling data classes."""

    def test_availability_slot(self):
        """Test AvailabilitySlot dataclass."""
        slot = AvailabilitySlot(
            interviewer_id='user123',
            interviewer_name='John Doe',
            slot=TimeSlot(
                start=datetime.now(),
                end=datetime.now() + timedelta(hours=1),
            ),
            status=SlotStatus.AVAILABLE,
        )

        assert slot.interviewer_name == 'John Doe'
        assert slot.status == SlotStatus.AVAILABLE

    def test_common_availability(self):
        """Test CommonAvailability dataclass."""
        common = CommonAvailability(
            slot=TimeSlot(
                start=datetime.now(),
                end=datetime.now() + timedelta(hours=1),
            ),
            available_interviewers=['user1', 'user2', 'user3'],
            total_interviewers=4,
            coverage_percentage=75.0,
        )

        assert len(common.available_interviewers) == 3
        assert common.coverage_percentage == 75.0

    def test_scheduling_result_success(self):
        """Test SchedulingResult for successful scheduling."""
        result = SchedulingResult(
            success=True,
            interview_id='int123',
            message='Interview scheduled successfully',
        )

        assert result.success is True
        assert result.interview_id == 'int123'
        assert len(result.conflicts) == 0

    def test_scheduling_result_failure(self):
        """Test SchedulingResult for failed scheduling."""
        result = SchedulingResult(
            success=False,
            message='Scheduling conflicts detected',
            conflicts=['John Doe has a conflicting interview'],
        )

        assert result.success is False
        assert len(result.conflicts) == 1


# ============================================================================
# OFFER MANAGEMENT TESTS
# ============================================================================

@pytest.mark.offers
class TestOfferEnums:
    """Tests for offer-related enums."""

    def test_offer_status_enum(self):
        """Test OfferStatus enum values."""
        assert OfferStatus.DRAFT.value == 'draft'
        assert OfferStatus.PENDING_APPROVAL.value == 'pending_approval'
        assert OfferStatus.SENT.value == 'sent'
        assert OfferStatus.ACCEPTED.value == 'accepted'
        assert OfferStatus.COUNTERED.value == 'countered'

    def test_approval_status_enum(self):
        """Test ApprovalStatus enum values."""
        assert ApprovalStatus.PENDING.value == 'pending'
        assert ApprovalStatus.APPROVED.value == 'approved'
        assert ApprovalStatus.REJECTED.value == 'rejected'

    def test_compensation_type_enum(self):
        """Test CompensationType enum values."""
        assert CompensationType.BASE_SALARY.value == 'base_salary'
        assert CompensationType.SIGNING_BONUS.value == 'signing_bonus'
        assert CompensationType.EQUITY.value == 'equity'

    def test_equity_type_enum(self):
        """Test EquityType enum values."""
        assert EquityType.STOCK_OPTIONS.value == 'stock_options'
        assert EquityType.RSU.value == 'rsu'


@pytest.mark.offers
class TestCompensationBreakdown:
    """Tests for CompensationBreakdown dataclass."""

    def test_compensation_breakdown_creation(self):
        """Test creating a compensation breakdown."""
        comp = CompensationBreakdown(
            base_salary=Decimal('100000'),
            currency='CAD',
            signing_bonus=Decimal('10000'),
            annual_bonus_target=Decimal('15000'),
            equity_value=Decimal('50000'),
            equity_vesting_months=48,
        )

        assert comp.base_salary == Decimal('100000')
        assert comp.signing_bonus == Decimal('10000')

    def test_total_first_year_calculation(self):
        """Test first year total calculation."""
        comp = CompensationBreakdown(
            base_salary=Decimal('100000'),
            signing_bonus=Decimal('10000'),
            annual_bonus_target=Decimal('15000'),
            relocation_bonus=Decimal('5000'),
            equity_value=Decimal('48000'),
            equity_vesting_months=48,
        )

        # First year: 100000 + 10000 + 15000 + 5000 + (48000 * 12/48) = 142000
        expected_first_year = Decimal('142000')
        assert comp.total_first_year == expected_first_year

    def test_total_annual_calculation(self):
        """Test annual total calculation."""
        comp = CompensationBreakdown(
            base_salary=Decimal('100000'),
            annual_bonus_target=Decimal('15000'),
            equity_value=Decimal('48000'),
            equity_vesting_months=48,
        )

        # Annual: 100000 + 15000 + (48000 * 12/48) = 127000
        expected_annual = Decimal('127000')
        assert comp.total_annual == expected_annual


@pytest.mark.offers
class TestOfferManagementService:
    """Tests for OfferManagementService."""

    def test_calculate_compensation(self):
        """Test compensation calculation."""
        breakdown = OfferManagementService.calculate_compensation(
            base_salary=Decimal('120000'),
            currency='CAD',
            signing_bonus=Decimal('15000'),
            annual_bonus_target_percent=Decimal('15'),
            equity_value=Decimal('60000'),
            vesting_months=48,
        )

        assert breakdown.base_salary == Decimal('120000')
        assert breakdown.signing_bonus == Decimal('15000')
        assert breakdown.annual_bonus_target == Decimal('18000')  # 15% of 120000

    def test_compare_to_market_competitive(self):
        """Test market comparison for competitive offer."""
        offer = MagicMock()
        offer.base_salary = Decimal('95000')

        market_data = {
            'role': 'Software Engineer',
            'location': 'Toronto',
            'experience_level': 'Mid',
            'base_25th': 70000,
            'base_50th': 90000,
            'base_75th': 110000,
            'base_90th': 130000,
        }

        comparison = OfferManagementService.compare_to_market(offer, market_data)

        assert comparison.offer_base == Decimal('95000')
        assert comparison.percentile > 50
        assert comparison.is_competitive is True

    def test_compare_to_market_below_median(self):
        """Test market comparison for below-median offer."""
        offer = MagicMock()
        offer.base_salary = Decimal('75000')

        market_data = {
            'role': 'Software Engineer',
            'base_25th': 70000,
            'base_50th': 90000,
            'base_75th': 110000,
            'base_90th': 130000,
        }

        comparison = OfferManagementService.compare_to_market(offer, market_data)

        assert comparison.percentile < 50
        assert comparison.is_competitive is False
        assert 'below' in comparison.recommendation.lower()

    def test_generate_offer_letter(self):
        """Test offer letter generation."""
        offer = MagicMock()
        offer.application.candidate.full_name = 'John Doe'
        offer.job_title = 'Software Engineer'
        offer.base_salary = Decimal('100000')
        offer.salary_currency = 'CAD'
        offer.salary_period = 'yearly'
        offer.signing_bonus = Decimal('10000')
        offer.annual_bonus_target = '15%'
        offer.equity = '1000 RSUs'
        offer.benefits_summary = 'Full health benefits'
        offer.start_date = date(2025, 2, 1)
        offer.terms_and_conditions = 'Standard terms apply'
        offer.expiration_date = date(2025, 1, 20)
        offer.created_by = MagicMock()
        offer.created_by.get_full_name.return_value = 'HR Manager'
        offer.application.tenant = MagicMock()
        offer.application.tenant.name = 'Test Company'

        letter = OfferManagementService.generate_offer_letter(offer)

        assert 'John Doe' in letter
        assert 'Software Engineer' in letter
        assert '100000' in letter


@pytest.mark.offers
class TestMarketComparison:
    """Tests for MarketComparison dataclass."""

    def test_market_comparison_creation(self):
        """Test MarketComparison dataclass creation."""
        comparison = MarketComparison(
            role='Software Engineer',
            location='Toronto',
            experience_level='Senior',
            market_base_25th=Decimal('80000'),
            market_base_50th=Decimal('100000'),
            market_base_75th=Decimal('120000'),
            market_base_90th=Decimal('140000'),
            offer_base=Decimal('110000'),
            percentile=62.5,
            is_competitive=True,
            recommendation='Offer is competitive',
        )

        assert comparison.role == 'Software Engineer'
        assert comparison.percentile == 62.5
        assert comparison.is_competitive is True


@pytest.mark.offers
class TestInternalEquityAnalysis:
    """Tests for InternalEquityAnalysis dataclass."""

    def test_internal_equity_creation(self):
        """Test InternalEquityAnalysis creation."""
        analysis = InternalEquityAnalysis(
            similar_role_count=15,
            avg_base_salary=Decimal('95000'),
            min_base_salary=Decimal('80000'),
            max_base_salary=Decimal('110000'),
            offer_base=Decimal('98000'),
            variance_from_avg=3.16,
            is_within_band=True,
            recommendation='Offer aligns well with internal equity',
        )

        assert analysis.similar_role_count == 15
        assert analysis.is_within_band is True


# ============================================================================
# ADVANCED REPORTS TESTS
# ============================================================================

@pytest.mark.reports
class TestReportEnums:
    """Tests for report-related enums."""

    def test_report_period_enum(self):
        """Test ReportPeriod enum values."""
        assert ReportPeriod.LAST_7_DAYS.value == 'last_7_days'
        assert ReportPeriod.LAST_30_DAYS.value == 'last_30_days'
        assert ReportPeriod.YEAR_TO_DATE.value == 'year_to_date'

    def test_group_by_enum(self):
        """Test GroupBy enum values."""
        assert GroupBy.DAY.value == 'day'
        assert GroupBy.DEPARTMENT.value == 'department'
        assert GroupBy.SOURCE.value == 'source'


@pytest.mark.reports
class TestReportService:
    """Tests for ReportService base class."""

    def test_get_date_range_last_7_days(self):
        """Test date range for last 7 days."""
        start, end = ReportService.get_date_range(ReportPeriod.LAST_7_DAYS)

        assert (end - start).days == 7
        assert end == timezone.now().date()

    def test_get_date_range_last_30_days(self):
        """Test date range for last 30 days."""
        start, end = ReportService.get_date_range(ReportPeriod.LAST_30_DAYS)

        assert (end - start).days == 30

    def test_get_date_range_year_to_date(self):
        """Test date range for year to date."""
        start, end = ReportService.get_date_range(ReportPeriod.YEAR_TO_DATE)

        today = timezone.now().date()
        assert start == date(today.year, 1, 1)
        assert end == today

    def test_get_date_range_custom(self):
        """Test custom date range."""
        custom_from = date(2024, 6, 1)
        custom_to = date(2024, 6, 30)

        start, end = ReportService.get_date_range(
            ReportPeriod.CUSTOM,
            custom_from=custom_from,
            custom_to=custom_to
        )

        assert start == custom_from
        assert end == custom_to

    def test_calculate_percentage(self):
        """Test percentage calculation."""
        assert ReportService.calculate_percentage(25, 100) == 25.0
        assert ReportService.calculate_percentage(1, 3) == 33.33
        assert ReportService.calculate_percentage(0, 100) == 0.0
        assert ReportService.calculate_percentage(50, 0) == 0.0


@pytest.mark.reports
class TestFunnelReportDataClasses:
    """Tests for funnel report data classes."""

    def test_funnel_stage_creation(self):
        """Test FunnelStage dataclass."""
        stage = FunnelStage(
            stage_name='Phone Screen',
            stage_type='screening',
            entered_count=100,
            exited_count=75,
            current_count=25,
            conversion_rate=75.0,
            drop_off_rate=25.0,
            average_time_days=3.5,
            median_time_days=3,
        )

        assert stage.stage_name == 'Phone Screen'
        assert stage.conversion_rate == 75.0

    def test_recruiting_funnel_data_creation(self):
        """Test RecruitingFunnelData dataclass."""
        funnel = RecruitingFunnelData(
            report_period='last_30_days',
            date_from=date(2024, 12, 1),
            date_to=date(2024, 12, 31),
            total_applications=500,
            total_hires=25,
            overall_conversion_rate=5.0,
            stages=[],
            bottleneck_stages=['Technical Assessment'],
            improvement_opportunities=['Reduce time in screening'],
        )

        assert funnel.total_applications == 500
        assert funnel.overall_conversion_rate == 5.0


@pytest.mark.reports
class TestDEIReportDataClasses:
    """Tests for DEI report data classes."""

    def test_dei_metrics_creation(self):
        """Test DEIMetrics dataclass."""
        metrics = DEIMetrics(
            category='Female',
            applicant_count=150,
            applicant_percentage=45.0,
            interview_count=50,
            interview_rate=33.3,
            hire_count=10,
            hire_rate=6.7,
            avg_time_to_decision_days=14.5,
        )

        assert metrics.category == 'Female'
        assert metrics.applicant_percentage == 45.0

    def test_dei_report_creation(self):
        """Test DEIReport dataclass."""
        report = DEIReport(
            report_period='last_90_days',
            date_from=date(2024, 10, 1),
            date_to=date(2024, 12, 31),
            total_applications=1000,
            total_interviews=300,
            total_hires=50,
            gender_metrics=[],
            ethnicity_metrics=[],
            veteran_metrics=[],
            disability_metrics=[],
            age_group_metrics=[],
            recommendations=['Continue monitoring DEI metrics'],
        )

        assert report.total_applications == 1000
        assert report.total_hires == 50


@pytest.mark.reports
class TestCostReportDataClasses:
    """Tests for cost report data classes."""

    def test_cost_component_creation(self):
        """Test CostComponent dataclass."""
        component = CostComponent(
            category='sourcing',
            subcategory='job_boards',
            amount=Decimal('5000'),
            currency='CAD',
            is_estimated=False,
        )

        assert component.category == 'sourcing'
        assert component.amount == Decimal('5000')

    def test_cost_per_hire_data_creation(self):
        """Test CostPerHireData dataclass."""
        data = CostPerHireData(
            report_period='last_90_days',
            date_from=date(2024, 10, 1),
            date_to=date(2024, 12, 31),
            total_hires=25,
            total_cost=Decimal('112500'),
            cost_per_hire=Decimal('4500'),
            currency='CAD',
            cost_breakdown=[],
            by_department={'Engineering': Decimal('50000')},
            by_source={'LinkedIn': Decimal('30000')},
            by_job_type={'Full-time': Decimal('100000')},
            trend_data=[],
            benchmark_comparison={},
        )

        assert data.cost_per_hire == Decimal('4500')
        assert data.total_hires == 25


@pytest.mark.reports
class TestTimeToFillDataClasses:
    """Tests for time to fill report data classes."""

    def test_time_to_fill_metrics_creation(self):
        """Test TimeToFillMetrics dataclass."""
        metrics = TimeToFillMetrics(
            category='Engineering',
            total_positions=20,
            filled_positions=15,
            fill_rate=75.0,
            avg_days_to_fill=32.5,
            median_days_to_fill=28,
            min_days_to_fill=14,
            max_days_to_fill=60,
            stddev_days=12.3,
        )

        assert metrics.category == 'Engineering'
        assert metrics.avg_days_to_fill == 32.5

    def test_time_to_fill_report_creation(self):
        """Test TimeToFillReport dataclass."""
        report = TimeToFillReport(
            report_period='last_90_days',
            date_from=date(2024, 10, 1),
            date_to=date(2024, 12, 31),
            overall_avg_days=35.0,
            overall_median_days=30,
            by_department=[],
            by_role=[],
            by_experience_level=[],
            by_job_type=[],
            trend_over_time=[],
            slowest_positions=[],
            fastest_positions=[],
        )

        assert report.overall_avg_days == 35.0


@pytest.mark.reports
class TestSourceQualityDataClasses:
    """Tests for source quality report data classes."""

    def test_source_metrics_creation(self):
        """Test SourceMetrics dataclass."""
        metrics = SourceMetrics(
            source_name='LinkedIn',
            total_applications=200,
            applications_percentage=40.0,
            interview_count=60,
            interview_rate=30.0,
            hire_count=12,
            hire_rate=6.0,
            avg_time_to_hire_days=35.0,
            avg_quality_score=4.2,
            cost_per_application=Decimal('25'),
            cost_per_hire=Decimal('417'),
            roi_score=14.4,
        )

        assert metrics.source_name == 'LinkedIn'
        assert metrics.hire_rate == 6.0

    def test_source_quality_report_creation(self):
        """Test SourceQualityReport dataclass."""
        report = SourceQualityReport(
            report_period='last_90_days',
            date_from=date(2024, 10, 1),
            date_to=date(2024, 12, 31),
            total_applications=500,
            total_hires=30,
            sources=[],
            top_sources=['LinkedIn', 'Referrals'],
            underperforming_sources=['Indeed'],
            recommendations=['Increase LinkedIn budget'],
        )

        assert report.total_applications == 500
        assert 'LinkedIn' in report.top_sources


@pytest.mark.reports
class TestRecruiterPerformanceDataClasses:
    """Tests for recruiter performance report data classes."""

    def test_recruiter_metrics_creation(self):
        """Test RecruiterMetrics dataclass."""
        metrics = RecruiterMetrics(
            recruiter_id='rec123',
            recruiter_name='Jane Smith',
            active_requisitions=8,
            applications_processed=150,
            interviews_scheduled=45,
            offers_extended=12,
            hires_made=10,
            avg_time_to_fill_days=28.0,
            candidate_satisfaction_score=4.5,
            hiring_manager_satisfaction=4.3,
            response_time_hours=18.0,
            quality_of_hire_score=4.1,
        )

        assert metrics.recruiter_name == 'Jane Smith'
        assert metrics.hires_made == 10

    def test_recruiter_performance_report_creation(self):
        """Test RecruiterPerformanceReport dataclass."""
        report = RecruiterPerformanceReport(
            report_period='last_90_days',
            date_from=date(2024, 10, 1),
            date_to=date(2024, 12, 31),
            recruiters=[],
            team_avg_time_to_fill=32.0,
            team_avg_hires=8.5,
            top_performers=['Jane Smith'],
            coaching_opportunities=[],
        )

        assert report.team_avg_time_to_fill == 32.0


@pytest.mark.reports
class TestHiringManagerDataClasses:
    """Tests for hiring manager scorecard data classes."""

    def test_hiring_manager_metrics_creation(self):
        """Test HiringManagerMetrics dataclass."""
        metrics = HiringManagerMetrics(
            manager_id='mgr123',
            manager_name='Bob Johnson',
            department='Engineering',
            open_positions=3,
            filled_positions=5,
            fill_rate=62.5,
            avg_time_to_fill_days=35.0,
            avg_interviews_per_hire=4.5,
            interview_to_offer_ratio=0.35,
            offer_acceptance_rate=85.0,
            new_hire_retention_90_days=90.0,
            avg_feedback_turnaround_hours=36.0,
            candidate_experience_score=4.2,
        )

        assert metrics.manager_name == 'Bob Johnson'
        assert metrics.offer_acceptance_rate == 85.0

    def test_hiring_manager_scorecard_creation(self):
        """Test HiringManagerScorecard dataclass."""
        scorecard = HiringManagerScorecard(
            report_period='last_90_days',
            date_from=date(2024, 10, 1),
            date_to=date(2024, 12, 31),
            managers=[],
            department_rankings={'Engineering': 1, 'Sales': 2},
            best_practices=['Quick feedback turnaround'],
            improvement_areas=[],
        )

        assert scorecard.department_rankings['Engineering'] == 1


# ============================================================================
# INTEGRATION TESTS
# ============================================================================

@pytest.mark.integration
@pytest.mark.django_db
class TestAdvancedFeaturesIntegration:
    """Integration tests for advanced features."""

    def test_pipeline_to_scheduling_flow(
        self,
        tenant_factory,
        pipeline_factory,
        pipeline_stage_factory,
        job_posting_factory,
        candidate_factory,
        application_factory,
        user_factory
    ):
        """Test flow from pipeline stage to interview scheduling."""
        # Setup
        tenant = tenant_factory()
        pipeline = pipeline_factory(tenant=tenant)
        interview_stage = pipeline_stage_factory(
            pipeline=pipeline,
            name='Technical Interview',
            stage_type='interview',
            order=2,
            is_active=True
        )

        job = job_posting_factory(
            tenant=tenant,
            pipeline=pipeline,
            status='open'
        )
        candidate = candidate_factory(tenant=tenant)
        application = application_factory(
            tenant=tenant,
            job=job,
            candidate=candidate,
            current_stage=interview_stage,
            status='interviewing'
        )

        # Verify application is in interview stage
        assert application.current_stage.stage_type == 'interview'

        # Meeting link would be generated for interview
        meeting = MeetingLinkGenerator.generate_meeting(
            provider=MeetingProvider.ZOOM,
            topic=f"Interview with {candidate.full_name}",
            start_time=datetime.now() + timedelta(days=1),
            end_time=datetime.now() + timedelta(days=1, hours=1),
        )

        assert meeting.provider == MeetingProvider.ZOOM
        assert meeting.meeting_url is not None

    def test_full_offer_workflow_dataclasses(self):
        """Test full offer workflow using dataclasses."""
        # Create compensation breakdown
        comp = OfferManagementService.calculate_compensation(
            base_salary=Decimal('110000'),
            signing_bonus=Decimal('10000'),
            annual_bonus_target_percent=Decimal('15'),
            equity_value=Decimal('50000'),
            vesting_months=48,
        )

        assert comp.base_salary == Decimal('110000')
        assert comp.total_first_year > comp.base_salary

        # Mock market comparison
        mock_offer = MagicMock()
        mock_offer.base_salary = Decimal('110000')

        market_data = {
            'role': 'Software Engineer',
            'location': 'Toronto',
            'base_25th': 80000,
            'base_50th': 100000,
            'base_75th': 120000,
            'base_90th': 140000,
        }

        comparison = OfferManagementService.compare_to_market(
            mock_offer, market_data
        )

        # 110k should be between 50th and 75th percentile
        assert comparison.percentile > 50
        assert comparison.percentile < 75
        assert comparison.is_competitive is True
