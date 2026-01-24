"""
ATS Workflows - State Machine Definitions for HR Processes

This module implements comprehensive state machines for:
- ApplicationWorkflow: Manages application lifecycle from submission to hire/rejection
- InterviewWorkflow: Handles interview scheduling through completion and feedback
- OfferWorkflow: Controls offer lifecycle from draft to acceptance/decline
- HiringWorkflow: Orchestrates complete hiring flow from application to onboarding

Each workflow follows HR best practices including:
- Clear state definitions and valid transitions
- Audit trail for all state changes
- Validation rules for state transitions
- Integration with notification system
- Support for parallel interview tracks
"""

from enum import Enum
from dataclasses import dataclass, field
from typing import List, Dict, Optional, Callable, Any, Set
from datetime import datetime, timedelta
from django.utils import timezone
from django.db import transaction


# ==================== BASE WORKFLOW CLASSES ====================

class WorkflowState:
    """Base class for workflow states with metadata."""

    def __init__(
        self,
        name: str,
        display_name: str,
        description: str = "",
        is_terminal: bool = False,
        is_initial: bool = False,
        requires_action: bool = False,
        max_duration_days: Optional[int] = None,
        auto_transition_to: Optional[str] = None,
        color: str = "#6B7280"
    ):
        self.name = name
        self.display_name = display_name
        self.description = description
        self.is_terminal = is_terminal
        self.is_initial = is_initial
        self.requires_action = requires_action
        self.max_duration_days = max_duration_days
        self.auto_transition_to = auto_transition_to
        self.color = color

    def __repr__(self):
        return f"<WorkflowState: {self.name}>"

    def __eq__(self, other):
        if isinstance(other, WorkflowState):
            return self.name == other.name
        if isinstance(other, str):
            return self.name == other
        return False

    def __hash__(self):
        return hash(self.name)


@dataclass
class WorkflowTransition:
    """Defines a valid transition between workflow states."""

    from_state: str
    to_state: str
    name: str
    display_name: str
    description: str = ""
    requires_permission: Optional[str] = None
    requires_reason: bool = False
    triggers_notification: bool = True
    validators: List[Callable] = field(default_factory=list)
    on_transition: Optional[Callable] = None

    def validate(self, context: Dict[str, Any]) -> tuple[bool, Optional[str]]:
        """Run all validators for this transition."""
        for validator in self.validators:
            is_valid, error = validator(context)
            if not is_valid:
                return False, error
        return True, None


class WorkflowEngine:
    """
    Generic workflow engine for state machine management.

    Provides:
    - State registration and management
    - Transition validation
    - Audit logging
    - Hook system for custom logic
    """

    def __init__(self, name: str):
        self.name = name
        self.states: Dict[str, WorkflowState] = {}
        self.transitions: Dict[str, List[WorkflowTransition]] = {}
        self.hooks: Dict[str, List[Callable]] = {
            'pre_transition': [],
            'post_transition': [],
            'on_enter_state': [],
            'on_exit_state': [],
        }

    def add_state(self, state: WorkflowState) -> None:
        """Register a new state in the workflow."""
        self.states[state.name] = state
        if state.name not in self.transitions:
            self.transitions[state.name] = []

    def add_transition(self, transition: WorkflowTransition) -> None:
        """Register a valid transition between states."""
        if transition.from_state not in self.transitions:
            self.transitions[transition.from_state] = []
        self.transitions[transition.from_state].append(transition)

    def get_state(self, state_name: str) -> Optional[WorkflowState]:
        """Get a state by name."""
        return self.states.get(state_name)

    def get_initial_state(self) -> Optional[WorkflowState]:
        """Get the initial state of the workflow."""
        for state in self.states.values():
            if state.is_initial:
                return state
        return None

    def get_terminal_states(self) -> List[WorkflowState]:
        """Get all terminal states."""
        return [s for s in self.states.values() if s.is_terminal]

    def get_available_transitions(self, current_state: str) -> List[WorkflowTransition]:
        """Get all valid transitions from the current state."""
        return self.transitions.get(current_state, [])

    def can_transition(
        self,
        from_state: str,
        to_state: str,
        context: Optional[Dict[str, Any]] = None
    ) -> tuple[bool, Optional[str]]:
        """
        Check if a transition is valid.

        Validates:
        - Transition exists from current state to target state
        - All custom validators pass
        - Required reason is provided if transition requires it
        - Required permission is held by user (if specified)
        """
        context = context or {}

        transitions = self.get_available_transitions(from_state)
        for transition in transitions:
            if transition.to_state == to_state:
                # Check if transition requires a reason
                if transition.requires_reason:
                    reason = context.get('reason', '').strip()
                    if not reason:
                        return False, f"Transition '{transition.display_name}' requires a reason"

                # Check if transition requires permission
                if transition.requires_permission:
                    user = context.get('user')
                    if user is None:
                        return False, f"Transition '{transition.display_name}' requires authentication"
                    if not user.has_perm(transition.requires_permission):
                        return False, f"User lacks permission '{transition.requires_permission}' for this transition"

                # Run custom validators
                return transition.validate(context)

        return False, f"No valid transition from {from_state} to {to_state}"

    def execute_transition(
        self,
        entity: Any,
        from_state: str,
        to_state: str,
        context: Optional[Dict[str, Any]] = None,
        user: Any = None
    ) -> tuple[bool, Optional[str]]:
        """
        Execute a state transition.

        Args:
            entity: The object being transitioned
            from_state: Current state name
            to_state: Target state name
            context: Additional context for validation
            user: User performing the transition

        Returns:
            Tuple of (success, error_message)
        """
        context = context or {}
        context['user'] = user
        context['entity'] = entity
        context['timestamp'] = timezone.now()

        # Validate transition
        can_do, error = self.can_transition(from_state, to_state, context)
        if not can_do:
            return False, error

        # Find the transition
        transition = None
        for t in self.get_available_transitions(from_state):
            if t.to_state == to_state:
                transition = t
                break

        if not transition:
            return False, "Transition not found"

        # Execute hooks
        for hook in self.hooks['pre_transition']:
            hook(entity, from_state, to_state, context)

        for hook in self.hooks['on_exit_state']:
            hook(entity, from_state, context)

        # Execute transition callback if defined
        if transition.on_transition:
            transition.on_transition(entity, context)

        for hook in self.hooks['on_enter_state']:
            hook(entity, to_state, context)

        for hook in self.hooks['post_transition']:
            hook(entity, from_state, to_state, context)

        return True, None

    def add_hook(self, hook_type: str, callback: Callable) -> None:
        """Add a hook to the workflow."""
        if hook_type in self.hooks:
            self.hooks[hook_type].append(callback)

    def get_workflow_diagram(self) -> Dict[str, Any]:
        """Generate a workflow diagram representation."""
        nodes = []
        edges = []

        for state in self.states.values():
            nodes.append({
                'id': state.name,
                'label': state.display_name,
                'color': state.color,
                'is_initial': state.is_initial,
                'is_terminal': state.is_terminal
            })

        for from_state, transitions in self.transitions.items():
            for t in transitions:
                edges.append({
                    'from': from_state,
                    'to': t.to_state,
                    'label': t.display_name
                })

        return {'nodes': nodes, 'edges': edges}


# ==================== APPLICATION WORKFLOW ====================

class ApplicationStates(Enum):
    """Application workflow states following HR best practices."""

    # Initial states
    NEW = "new"

    # Screening phase
    SCREENING = "screening"
    SCREENED_PASS = "screened_pass"
    SCREENED_FAIL = "screened_fail"

    # Review phase
    IN_REVIEW = "in_review"
    SHORTLISTED = "shortlisted"

    # Interview phase
    INTERVIEW_SCHEDULED = "interview_scheduled"
    INTERVIEWING = "interviewing"
    INTERVIEW_COMPLETED = "interview_completed"

    # Decision phase
    UNDER_CONSIDERATION = "under_consideration"
    OFFER_PENDING = "offer_pending"
    OFFER_EXTENDED = "offer_extended"

    # Pre-rejection (Adverse Action) - Required for FCRA/EEOC compliance
    PRE_ADVERSE_ACTION = "pre_adverse_action"

    # Terminal states
    HIRED = "hired"
    REJECTED = "rejected"
    WITHDRAWN = "withdrawn"
    ON_HOLD = "on_hold"


def create_application_workflow() -> WorkflowEngine:
    """
    Create the application workflow state machine.

    Flow:
    NEW -> SCREENING -> IN_REVIEW -> SHORTLISTED -> INTERVIEWING ->
    UNDER_CONSIDERATION -> OFFER_PENDING -> OFFER_EXTENDED -> HIRED

    With rejection/withdrawal possible from most states.
    """
    workflow = WorkflowEngine("ApplicationWorkflow")

    # Define states
    states = [
        WorkflowState(
            name="new",
            display_name="New Application",
            description="Application just received, pending initial review",
            is_initial=True,
            requires_action=True,
            max_duration_days=3,
            color="#10B981"
        ),
        WorkflowState(
            name="screening",
            display_name="Screening",
            description="Initial screening in progress (resume review, basic qualifications)",
            requires_action=True,
            max_duration_days=5,
            color="#3B82F6"
        ),
        WorkflowState(
            name="screened_pass",
            display_name="Screening Passed",
            description="Candidate passed initial screening",
            color="#10B981"
        ),
        WorkflowState(
            name="screened_fail",
            display_name="Screening Failed",
            description="Candidate did not pass screening criteria",
            is_terminal=True,
            color="#EF4444"
        ),
        WorkflowState(
            name="in_review",
            display_name="In Review",
            description="Detailed review by hiring team",
            requires_action=True,
            max_duration_days=7,
            color="#8B5CF6"
        ),
        WorkflowState(
            name="shortlisted",
            display_name="Shortlisted",
            description="Candidate shortlisted for interviews",
            color="#F59E0B"
        ),
        WorkflowState(
            name="interview_scheduled",
            display_name="Interview Scheduled",
            description="Interview(s) have been scheduled",
            color="#06B6D4"
        ),
        WorkflowState(
            name="interviewing",
            display_name="Interviewing",
            description="Interview process in progress",
            color="#8B5CF6"
        ),
        WorkflowState(
            name="interview_completed",
            display_name="Interviews Completed",
            description="All interviews completed, pending decision",
            requires_action=True,
            max_duration_days=5,
            color="#10B981"
        ),
        WorkflowState(
            name="under_consideration",
            display_name="Under Consideration",
            description="Final evaluation by hiring team",
            requires_action=True,
            max_duration_days=7,
            color="#F59E0B"
        ),
        WorkflowState(
            name="offer_pending",
            display_name="Offer Pending",
            description="Offer being prepared/approved",
            requires_action=True,
            max_duration_days=5,
            color="#EC4899"
        ),
        WorkflowState(
            name="offer_extended",
            display_name="Offer Extended",
            description="Offer sent to candidate, awaiting response",
            requires_action=True,
            max_duration_days=14,
            color="#8B5CF6"
        ),
        WorkflowState(
            name="hired",
            display_name="Hired",
            description="Candidate accepted offer and is hired",
            is_terminal=True,
            color="#10B981"
        ),
        WorkflowState(
            name="rejected",
            display_name="Rejected",
            description="Application rejected",
            is_terminal=True,
            color="#EF4444"
        ),
        WorkflowState(
            name="withdrawn",
            display_name="Withdrawn",
            description="Candidate withdrew application",
            is_terminal=True,
            color="#6B7280"
        ),
        WorkflowState(
            name="on_hold",
            display_name="On Hold",
            description="Application temporarily on hold (previous state stored in metadata)",
            color="#F59E0B"
        ),
        WorkflowState(
            name="pre_adverse_action",
            display_name="Pre-Adverse Action",
            description="Pending rejection - waiting period for adverse action notice (FCRA/EEOC compliance)",
            requires_action=True,
            max_duration_days=7,  # Configurable waiting period per jurisdiction
            color="#DC2626"
        ),
    ]

    for state in states:
        workflow.add_state(state)

    # Define transitions
    transitions = [
        # From NEW
        WorkflowTransition(
            from_state="new",
            to_state="screening",
            name="start_screening",
            display_name="Start Screening",
            description="Begin initial screening process"
        ),
        WorkflowTransition(
            from_state="new",
            to_state="rejected",
            name="reject_new",
            display_name="Reject",
            requires_reason=True,
            description="Reject application without screening"
        ),
        WorkflowTransition(
            from_state="new",
            to_state="on_hold",
            name="hold_new",
            display_name="Put on Hold"
        ),

        # From SCREENING
        WorkflowTransition(
            from_state="screening",
            to_state="screened_pass",
            name="pass_screening",
            display_name="Pass Screening",
            description="Candidate meets basic qualifications"
        ),
        WorkflowTransition(
            from_state="screening",
            to_state="screened_fail",
            name="fail_screening",
            display_name="Fail Screening",
            requires_reason=True,
            description="Candidate does not meet basic qualifications"
        ),
        WorkflowTransition(
            from_state="screening",
            to_state="on_hold",
            name="hold_screening",
            display_name="Put on Hold"
        ),

        # From SCREENED_PASS
        WorkflowTransition(
            from_state="screened_pass",
            to_state="in_review",
            name="start_review",
            display_name="Start Review",
            description="Begin detailed review by hiring team"
        ),

        # From IN_REVIEW
        WorkflowTransition(
            from_state="in_review",
            to_state="shortlisted",
            name="shortlist",
            display_name="Shortlist",
            description="Add to shortlist for interviews"
        ),
        WorkflowTransition(
            from_state="in_review",
            to_state="rejected",
            name="reject_review",
            display_name="Reject",
            requires_reason=True
        ),
        WorkflowTransition(
            from_state="in_review",
            to_state="on_hold",
            name="hold_review",
            display_name="Put on Hold"
        ),

        # From SHORTLISTED
        WorkflowTransition(
            from_state="shortlisted",
            to_state="interview_scheduled",
            name="schedule_interview",
            display_name="Schedule Interview",
            description="Schedule first interview"
        ),
        WorkflowTransition(
            from_state="shortlisted",
            to_state="rejected",
            name="reject_shortlist",
            display_name="Reject",
            requires_reason=True
        ),

        # From INTERVIEW_SCHEDULED
        WorkflowTransition(
            from_state="interview_scheduled",
            to_state="interviewing",
            name="start_interview",
            display_name="Start Interview",
            description="Interview process begins"
        ),
        WorkflowTransition(
            from_state="interview_scheduled",
            to_state="withdrawn",
            name="candidate_withdraw_scheduled",
            display_name="Candidate Withdrew"
        ),

        # From INTERVIEWING
        WorkflowTransition(
            from_state="interviewing",
            to_state="interview_completed",
            name="complete_interviews",
            display_name="Complete Interviews",
            description="All scheduled interviews completed"
        ),
        WorkflowTransition(
            from_state="interviewing",
            to_state="interview_scheduled",
            name="schedule_additional",
            display_name="Schedule Additional Interview",
            description="Schedule another interview round"
        ),
        WorkflowTransition(
            from_state="interviewing",
            to_state="rejected",
            name="reject_interview",
            display_name="Reject After Interview",
            requires_reason=True
        ),
        WorkflowTransition(
            from_state="interviewing",
            to_state="withdrawn",
            name="candidate_withdraw_interview",
            display_name="Candidate Withdrew"
        ),

        # From INTERVIEW_COMPLETED
        WorkflowTransition(
            from_state="interview_completed",
            to_state="under_consideration",
            name="consider",
            display_name="Under Consideration",
            description="Move to final evaluation"
        ),
        WorkflowTransition(
            from_state="interview_completed",
            to_state="rejected",
            name="reject_post_interview",
            display_name="Reject",
            requires_reason=True
        ),
        WorkflowTransition(
            from_state="interview_completed",
            to_state="interview_scheduled",
            name="schedule_final_round",
            display_name="Schedule Final Round",
            description="Schedule additional interview round"
        ),

        # From UNDER_CONSIDERATION
        WorkflowTransition(
            from_state="under_consideration",
            to_state="offer_pending",
            name="prepare_offer",
            display_name="Prepare Offer",
            description="Begin offer preparation"
        ),
        WorkflowTransition(
            from_state="under_consideration",
            to_state="rejected",
            name="reject_final",
            display_name="Reject",
            requires_reason=True
        ),

        # From OFFER_PENDING
        WorkflowTransition(
            from_state="offer_pending",
            to_state="offer_extended",
            name="extend_offer",
            display_name="Extend Offer",
            description="Send offer to candidate"
        ),
        WorkflowTransition(
            from_state="offer_pending",
            to_state="rejected",
            name="reject_offer_stage",
            display_name="Reject",
            requires_reason=True
        ),

        # From OFFER_EXTENDED
        WorkflowTransition(
            from_state="offer_extended",
            to_state="hired",
            name="accept_offer",
            display_name="Offer Accepted",
            description="Candidate accepted the offer"
        ),
        WorkflowTransition(
            from_state="offer_extended",
            to_state="rejected",
            name="decline_offer",
            display_name="Offer Declined",
            requires_reason=True,
            description="Candidate declined the offer"
        ),
        WorkflowTransition(
            from_state="offer_extended",
            to_state="offer_pending",
            name="renegotiate_offer",
            display_name="Renegotiate",
            description="Modify offer terms"
        ),
        WorkflowTransition(
            from_state="offer_extended",
            to_state="withdrawn",
            name="candidate_withdraw_offer",
            display_name="Candidate Withdrew"
        ),

        # From ON_HOLD - with option to restore previous state
        WorkflowTransition(
            from_state="on_hold",
            to_state="new",
            name="reactivate_new",
            display_name="Reactivate to New",
            description="Resume application review from New state"
        ),
        WorkflowTransition(
            from_state="on_hold",
            to_state="screening",
            name="reactivate_screening",
            display_name="Reactivate to Screening",
            description="Resume application from Screening state"
        ),
        WorkflowTransition(
            from_state="on_hold",
            to_state="in_review",
            name="reactivate_review",
            display_name="Reactivate to Review",
            description="Resume application from In Review state"
        ),
        WorkflowTransition(
            from_state="on_hold",
            to_state="shortlisted",
            name="reactivate_shortlisted",
            display_name="Reactivate to Shortlisted",
            description="Resume application from Shortlisted state"
        ),
        WorkflowTransition(
            from_state="on_hold",
            to_state="interviewing",
            name="reactivate_interviewing",
            display_name="Reactivate to Interviewing",
            description="Resume application from Interviewing state"
        ),
        WorkflowTransition(
            from_state="on_hold",
            to_state="pre_adverse_action",
            name="initiate_adverse_action_from_hold",
            display_name="Initiate Adverse Action",
            requires_reason=True,
            description="Start pre-adverse action period before rejection"
        ),
        WorkflowTransition(
            from_state="on_hold",
            to_state="rejected",
            name="reject_hold",
            display_name="Reject (Skip Adverse Action)",
            requires_reason=True,
            description="Direct rejection - use only if adverse action not required"
        ),

        # Pre-Adverse Action transitions (FCRA/EEOC compliance)
        WorkflowTransition(
            from_state="pre_adverse_action",
            to_state="rejected",
            name="complete_adverse_action",
            display_name="Complete Rejection",
            requires_reason=True,
            description="Finalize rejection after waiting period"
        ),
        WorkflowTransition(
            from_state="pre_adverse_action",
            to_state="in_review",
            name="cancel_adverse_action",
            display_name="Cancel Adverse Action",
            description="Cancel pending rejection and return to review"
        ),
        WorkflowTransition(
            from_state="pre_adverse_action",
            to_state="on_hold",
            name="hold_adverse_action",
            display_name="Put on Hold",
            description="Pause adverse action process"
        ),

        # Add pre_adverse_action transitions from other rejection points
        WorkflowTransition(
            from_state="in_review",
            to_state="pre_adverse_action",
            name="initiate_adverse_action_review",
            display_name="Initiate Adverse Action",
            requires_reason=True,
            description="Start pre-adverse action period before rejection"
        ),
        WorkflowTransition(
            from_state="interview_completed",
            to_state="pre_adverse_action",
            name="initiate_adverse_action_interview",
            display_name="Initiate Adverse Action",
            requires_reason=True,
            description="Start pre-adverse action period before rejection"
        ),
        WorkflowTransition(
            from_state="under_consideration",
            to_state="pre_adverse_action",
            name="initiate_adverse_action_consideration",
            display_name="Initiate Adverse Action",
            requires_reason=True,
            description="Start pre-adverse action period before rejection"
        ),
    ]

    for transition in transitions:
        workflow.add_transition(transition)

    return workflow


# ==================== INTERVIEW WORKFLOW ====================

class InterviewStates(Enum):
    """Interview workflow states."""

    PENDING_SCHEDULE = "pending_schedule"
    SCHEDULED = "scheduled"
    CONFIRMED = "confirmed"
    IN_PROGRESS = "in_progress"
    COMPLETED = "completed"
    FEEDBACK_PENDING = "feedback_pending"
    FEEDBACK_COMPLETE = "feedback_complete"
    CANCELLED = "cancelled"
    NO_SHOW = "no_show"
    RESCHEDULED = "rescheduled"


def create_interview_workflow() -> WorkflowEngine:
    """
    Create the interview workflow state machine.

    Flow:
    PENDING_SCHEDULE -> SCHEDULED -> CONFIRMED -> IN_PROGRESS ->
    COMPLETED -> FEEDBACK_PENDING -> FEEDBACK_COMPLETE

    With cancellation/no-show/reschedule branches.
    """
    workflow = WorkflowEngine("InterviewWorkflow")

    states = [
        WorkflowState(
            name="pending_schedule",
            display_name="Pending Schedule",
            description="Interview needs to be scheduled",
            is_initial=True,
            requires_action=True,
            max_duration_days=3,
            color="#F59E0B"
        ),
        WorkflowState(
            name="scheduled",
            display_name="Scheduled",
            description="Interview scheduled, pending confirmation",
            requires_action=True,
            color="#3B82F6"
        ),
        WorkflowState(
            name="confirmed",
            display_name="Confirmed",
            description="Interview confirmed by all parties",
            color="#10B981"
        ),
        WorkflowState(
            name="in_progress",
            display_name="In Progress",
            description="Interview currently happening",
            color="#8B5CF6"
        ),
        WorkflowState(
            name="completed",
            display_name="Completed",
            description="Interview completed, pending feedback",
            color="#10B981"
        ),
        WorkflowState(
            name="feedback_pending",
            display_name="Feedback Pending",
            description="Awaiting interviewer feedback",
            requires_action=True,
            max_duration_days=2,
            color="#F59E0B"
        ),
        WorkflowState(
            name="feedback_complete",
            display_name="Feedback Complete",
            description="All feedback submitted",
            is_terminal=True,
            color="#10B981"
        ),
        WorkflowState(
            name="cancelled",
            display_name="Cancelled",
            description="Interview was cancelled",
            is_terminal=True,
            color="#EF4444"
        ),
        WorkflowState(
            name="no_show",
            display_name="No Show",
            description="Candidate did not attend",
            is_terminal=True,
            color="#EF4444"
        ),
        WorkflowState(
            name="rescheduled",
            display_name="Rescheduled",
            description="Interview has been rescheduled",
            color="#6B7280"
        ),
    ]

    for state in states:
        workflow.add_state(state)

    transitions = [
        # From PENDING_SCHEDULE
        WorkflowTransition(
            from_state="pending_schedule",
            to_state="scheduled",
            name="schedule",
            display_name="Schedule Interview",
            description="Set interview date and time"
        ),
        WorkflowTransition(
            from_state="pending_schedule",
            to_state="cancelled",
            name="cancel_before_schedule",
            display_name="Cancel",
            requires_reason=True
        ),

        # From SCHEDULED
        WorkflowTransition(
            from_state="scheduled",
            to_state="confirmed",
            name="confirm",
            display_name="Confirm",
            description="All parties confirmed attendance"
        ),
        WorkflowTransition(
            from_state="scheduled",
            to_state="rescheduled",
            name="reschedule_from_scheduled",
            display_name="Reschedule",
            requires_reason=True
        ),
        WorkflowTransition(
            from_state="scheduled",
            to_state="cancelled",
            name="cancel_scheduled",
            display_name="Cancel",
            requires_reason=True
        ),

        # From CONFIRMED
        WorkflowTransition(
            from_state="confirmed",
            to_state="in_progress",
            name="start",
            display_name="Start Interview"
        ),
        WorkflowTransition(
            from_state="confirmed",
            to_state="no_show",
            name="mark_no_show",
            display_name="Mark No Show"
        ),
        WorkflowTransition(
            from_state="confirmed",
            to_state="rescheduled",
            name="reschedule_from_confirmed",
            display_name="Reschedule",
            requires_reason=True
        ),
        WorkflowTransition(
            from_state="confirmed",
            to_state="cancelled",
            name="cancel_confirmed",
            display_name="Cancel",
            requires_reason=True
        ),

        # From IN_PROGRESS
        WorkflowTransition(
            from_state="in_progress",
            to_state="completed",
            name="complete",
            display_name="Complete Interview"
        ),

        # From COMPLETED
        WorkflowTransition(
            from_state="completed",
            to_state="feedback_pending",
            name="request_feedback",
            display_name="Request Feedback"
        ),
        WorkflowTransition(
            from_state="completed",
            to_state="feedback_complete",
            name="skip_feedback",
            display_name="Skip Feedback",
            description="Mark complete without feedback"
        ),

        # From FEEDBACK_PENDING
        WorkflowTransition(
            from_state="feedback_pending",
            to_state="feedback_complete",
            name="submit_feedback",
            display_name="Submit Feedback"
        ),

        # From RESCHEDULED
        WorkflowTransition(
            from_state="rescheduled",
            to_state="scheduled",
            name="reschedule_complete",
            display_name="Set New Time"
        ),
        WorkflowTransition(
            from_state="rescheduled",
            to_state="cancelled",
            name="cancel_rescheduled",
            display_name="Cancel"
        ),
    ]

    for transition in transitions:
        workflow.add_transition(transition)

    return workflow


# ==================== OFFER WORKFLOW ====================

class OfferStates(Enum):
    """Offer workflow states."""

    DRAFT = "draft"
    PENDING_APPROVAL = "pending_approval"
    APPROVED = "approved"
    SENT = "sent"
    UNDER_REVIEW = "under_review"
    NEGOTIATING = "negotiating"
    ACCEPTED = "accepted"
    DECLINED = "declined"
    EXPIRED = "expired"
    WITHDRAWN = "withdrawn"


def create_offer_workflow() -> WorkflowEngine:
    """
    Create the offer workflow state machine.

    Flow:
    DRAFT -> PENDING_APPROVAL -> APPROVED -> SENT ->
    UNDER_REVIEW -> ACCEPTED/DECLINED/NEGOTIATING

    With expiration and withdrawal branches.
    """
    workflow = WorkflowEngine("OfferWorkflow")

    states = [
        WorkflowState(
            name="draft",
            display_name="Draft",
            description="Offer being drafted",
            is_initial=True,
            color="#6B7280"
        ),
        WorkflowState(
            name="pending_approval",
            display_name="Pending Approval",
            description="Awaiting management/HR approval",
            requires_action=True,
            max_duration_days=3,
            color="#F59E0B"
        ),
        WorkflowState(
            name="approved",
            display_name="Approved",
            description="Offer approved and ready to send",
            color="#10B981"
        ),
        WorkflowState(
            name="sent",
            display_name="Sent",
            description="Offer sent to candidate",
            requires_action=True,
            max_duration_days=7,
            color="#3B82F6"
        ),
        WorkflowState(
            name="under_review",
            display_name="Under Review",
            description="Candidate reviewing offer",
            max_duration_days=14,
            color="#8B5CF6"
        ),
        WorkflowState(
            name="negotiating",
            display_name="Negotiating",
            description="Terms under negotiation",
            max_duration_days=7,
            color="#F59E0B"
        ),
        WorkflowState(
            name="accepted",
            display_name="Accepted",
            description="Candidate accepted the offer",
            is_terminal=True,
            color="#10B981"
        ),
        WorkflowState(
            name="declined",
            display_name="Declined",
            description="Candidate declined the offer",
            is_terminal=True,
            color="#EF4444"
        ),
        WorkflowState(
            name="expired",
            display_name="Expired",
            description="Offer expired without response",
            is_terminal=True,
            color="#6B7280"
        ),
        WorkflowState(
            name="withdrawn",
            display_name="Withdrawn",
            description="Offer withdrawn by employer",
            is_terminal=True,
            color="#EF4444"
        ),
    ]

    for state in states:
        workflow.add_state(state)

    transitions = [
        # From DRAFT
        WorkflowTransition(
            from_state="draft",
            to_state="pending_approval",
            name="submit_for_approval",
            display_name="Submit for Approval"
        ),
        WorkflowTransition(
            from_state="draft",
            to_state="approved",
            name="auto_approve",
            display_name="Auto-Approve",
            description="For pre-approved salary bands"
        ),

        # From PENDING_APPROVAL
        WorkflowTransition(
            from_state="pending_approval",
            to_state="approved",
            name="approve",
            display_name="Approve",
            requires_permission="can_approve_offers"
        ),
        WorkflowTransition(
            from_state="pending_approval",
            to_state="draft",
            name="request_changes",
            display_name="Request Changes",
            requires_reason=True
        ),
        WorkflowTransition(
            from_state="pending_approval",
            to_state="withdrawn",
            name="withdraw_pending",
            display_name="Withdraw"
        ),

        # From APPROVED
        WorkflowTransition(
            from_state="approved",
            to_state="sent",
            name="send",
            display_name="Send to Candidate"
        ),
        WorkflowTransition(
            from_state="approved",
            to_state="draft",
            name="edit_approved",
            display_name="Edit Offer"
        ),
        WorkflowTransition(
            from_state="approved",
            to_state="withdrawn",
            name="withdraw_approved",
            display_name="Withdraw"
        ),

        # From SENT
        WorkflowTransition(
            from_state="sent",
            to_state="under_review",
            name="candidate_reviewing",
            display_name="Candidate Reviewing"
        ),
        WorkflowTransition(
            from_state="sent",
            to_state="accepted",
            name="accept_immediate",
            display_name="Accept"
        ),
        WorkflowTransition(
            from_state="sent",
            to_state="declined",
            name="decline_immediate",
            display_name="Decline"
        ),
        WorkflowTransition(
            from_state="sent",
            to_state="withdrawn",
            name="withdraw_sent",
            display_name="Withdraw"
        ),
        WorkflowTransition(
            from_state="sent",
            to_state="expired",
            name="expire_sent",
            display_name="Expire"
        ),

        # From UNDER_REVIEW
        WorkflowTransition(
            from_state="under_review",
            to_state="accepted",
            name="accept",
            display_name="Accept"
        ),
        WorkflowTransition(
            from_state="under_review",
            to_state="declined",
            name="decline",
            display_name="Decline",
            requires_reason=True
        ),
        WorkflowTransition(
            from_state="under_review",
            to_state="negotiating",
            name="negotiate",
            display_name="Negotiate"
        ),
        WorkflowTransition(
            from_state="under_review",
            to_state="expired",
            name="expire_review",
            display_name="Expire"
        ),
        WorkflowTransition(
            from_state="under_review",
            to_state="withdrawn",
            name="withdraw_review",
            display_name="Withdraw"
        ),

        # From NEGOTIATING
        WorkflowTransition(
            from_state="negotiating",
            to_state="draft",
            name="revise_offer",
            display_name="Revise Offer"
        ),
        WorkflowTransition(
            from_state="negotiating",
            to_state="accepted",
            name="accept_negotiated",
            display_name="Accept Terms"
        ),
        WorkflowTransition(
            from_state="negotiating",
            to_state="declined",
            name="decline_negotiation",
            display_name="Decline"
        ),
        WorkflowTransition(
            from_state="negotiating",
            to_state="withdrawn",
            name="withdraw_negotiation",
            display_name="Withdraw"
        ),
    ]

    for transition in transitions:
        workflow.add_transition(transition)

    return workflow


# ==================== HIRING WORKFLOW ====================

class HiringStages(Enum):
    """Complete hiring workflow stages."""

    # Sourcing
    SOURCING = "sourcing"
    TALENT_POOL = "talent_pool"

    # Application
    APPLICATION_RECEIVED = "application_received"
    INITIAL_SCREENING = "initial_screening"

    # Assessment
    SKILLS_ASSESSMENT = "skills_assessment"
    PHONE_SCREEN = "phone_screen"

    # Interview
    TECHNICAL_INTERVIEW = "technical_interview"
    HIRING_MANAGER_INTERVIEW = "hiring_manager_interview"
    PANEL_INTERVIEW = "panel_interview"
    EXECUTIVE_INTERVIEW = "executive_interview"

    # Background
    REFERENCE_CHECK = "reference_check"
    BACKGROUND_CHECK = "background_check"

    # Offer
    OFFER_PREPARATION = "offer_preparation"
    OFFER_EXTENDED = "offer_extended"
    OFFER_ACCEPTED = "offer_accepted"

    # Onboarding
    PRE_BOARDING = "pre_boarding"
    ONBOARDING = "onboarding"

    # Terminal
    HIRED = "hired"
    NOT_SELECTED = "not_selected"
    WITHDRAWN = "withdrawn"


def create_hiring_workflow() -> WorkflowEngine:
    """
    Create comprehensive hiring workflow from sourcing to onboarding.

    This workflow represents the complete candidate journey and integrates
    with the application, interview, and offer workflows.
    """
    workflow = WorkflowEngine("HiringWorkflow")

    states = [
        # Sourcing
        WorkflowState(
            name="sourcing",
            display_name="Sourcing",
            description="Actively sourcing candidates",
            is_initial=True,
            color="#6B7280"
        ),
        WorkflowState(
            name="talent_pool",
            display_name="Talent Pool",
            description="Candidate in talent pool for future roles",
            color="#8B5CF6"
        ),

        # Application
        WorkflowState(
            name="application_received",
            display_name="Application Received",
            description="Application submitted and received",
            requires_action=True,
            max_duration_days=3,
            color="#10B981"
        ),
        WorkflowState(
            name="initial_screening",
            display_name="Initial Screening",
            description="Resume and qualifications review",
            requires_action=True,
            max_duration_days=5,
            color="#3B82F6"
        ),

        # Assessment
        WorkflowState(
            name="skills_assessment",
            display_name="Skills Assessment",
            description="Technical or skills assessment",
            max_duration_days=7,
            color="#F59E0B"
        ),
        WorkflowState(
            name="phone_screen",
            display_name="Phone Screen",
            description="Initial phone screening call",
            max_duration_days=5,
            color="#06B6D4"
        ),

        # Interview
        WorkflowState(
            name="technical_interview",
            display_name="Technical Interview",
            description="Technical skills evaluation",
            max_duration_days=10,
            color="#8B5CF6"
        ),
        WorkflowState(
            name="hiring_manager_interview",
            display_name="Hiring Manager Interview",
            description="Interview with hiring manager",
            max_duration_days=7,
            color="#EC4899"
        ),
        WorkflowState(
            name="panel_interview",
            display_name="Panel Interview",
            description="Interview with team panel",
            max_duration_days=7,
            color="#14B8A6"
        ),
        WorkflowState(
            name="executive_interview",
            display_name="Executive Interview",
            description="Final interview with executive(s)",
            max_duration_days=7,
            color="#F97316"
        ),

        # Background
        WorkflowState(
            name="reference_check",
            display_name="Reference Check",
            description="Checking candidate references",
            requires_action=True,
            max_duration_days=7,
            color="#84CC16"
        ),
        WorkflowState(
            name="background_check",
            display_name="Background Check",
            description="Background verification in progress",
            max_duration_days=14,
            color="#A855F7"
        ),

        # Offer
        WorkflowState(
            name="offer_preparation",
            display_name="Offer Preparation",
            description="Preparing job offer",
            requires_action=True,
            max_duration_days=5,
            color="#F59E0B"
        ),
        WorkflowState(
            name="offer_extended",
            display_name="Offer Extended",
            description="Offer sent to candidate",
            requires_action=True,
            max_duration_days=14,
            color="#3B82F6"
        ),
        WorkflowState(
            name="offer_accepted",
            display_name="Offer Accepted",
            description="Candidate accepted offer",
            color="#10B981"
        ),

        # Onboarding
        WorkflowState(
            name="pre_boarding",
            display_name="Pre-boarding",
            description="Pre-employment preparation",
            max_duration_days=30,
            color="#06B6D4"
        ),
        WorkflowState(
            name="onboarding",
            display_name="Onboarding",
            description="Employee onboarding in progress",
            max_duration_days=90,
            color="#8B5CF6"
        ),

        # Terminal
        WorkflowState(
            name="hired",
            display_name="Hired",
            description="Successfully hired and onboarded",
            is_terminal=True,
            color="#10B981"
        ),
        WorkflowState(
            name="not_selected",
            display_name="Not Selected",
            description="Candidate not selected for position",
            is_terminal=True,
            color="#EF4444"
        ),
        WorkflowState(
            name="withdrawn",
            display_name="Withdrawn",
            description="Candidate withdrew from process",
            is_terminal=True,
            color="#6B7280"
        ),
    ]

    for state in states:
        workflow.add_state(state)

    # Define comprehensive transitions
    transitions = [
        # Sourcing to Application
        WorkflowTransition("sourcing", "application_received", "apply", "Submit Application"),
        WorkflowTransition("sourcing", "talent_pool", "add_to_pool", "Add to Talent Pool"),
        WorkflowTransition("talent_pool", "application_received", "apply_from_pool", "Apply from Pool"),

        # Application flow
        WorkflowTransition("application_received", "initial_screening", "screen", "Start Screening"),
        WorkflowTransition("application_received", "not_selected", "reject_immediate", "Reject"),
        WorkflowTransition("initial_screening", "phone_screen", "schedule_phone", "Schedule Phone Screen"),
        WorkflowTransition("initial_screening", "skills_assessment", "send_assessment", "Send Assessment"),
        WorkflowTransition("initial_screening", "not_selected", "reject_screening", "Reject"),

        # Assessment flow
        WorkflowTransition("skills_assessment", "phone_screen", "pass_assessment", "Pass Assessment"),
        WorkflowTransition("skills_assessment", "not_selected", "fail_assessment", "Fail Assessment"),
        WorkflowTransition("phone_screen", "technical_interview", "advance_technical", "Schedule Technical"),
        WorkflowTransition("phone_screen", "hiring_manager_interview", "advance_hm", "Schedule HM Interview"),
        WorkflowTransition("phone_screen", "not_selected", "reject_phone", "Reject"),

        # Interview flow
        WorkflowTransition("technical_interview", "hiring_manager_interview", "pass_technical", "Pass Technical"),
        WorkflowTransition("technical_interview", "not_selected", "fail_technical", "Fail Technical"),
        WorkflowTransition("hiring_manager_interview", "panel_interview", "schedule_panel", "Schedule Panel"),
        WorkflowTransition("hiring_manager_interview", "reference_check", "skip_to_reference", "Proceed to References"),
        WorkflowTransition("hiring_manager_interview", "not_selected", "reject_hm", "Reject"),
        WorkflowTransition("panel_interview", "executive_interview", "schedule_exec", "Schedule Executive"),
        WorkflowTransition("panel_interview", "reference_check", "proceed_reference", "Proceed to References"),
        WorkflowTransition("panel_interview", "not_selected", "reject_panel", "Reject"),
        WorkflowTransition("executive_interview", "reference_check", "approve_exec", "Approve"),
        WorkflowTransition("executive_interview", "not_selected", "reject_exec", "Reject"),

        # Background flow
        WorkflowTransition("reference_check", "background_check", "start_background", "Start Background Check"),
        WorkflowTransition("reference_check", "offer_preparation", "skip_background", "Skip to Offer"),
        WorkflowTransition("reference_check", "not_selected", "fail_reference", "Poor References"),
        WorkflowTransition("background_check", "offer_preparation", "pass_background", "Pass Background"),
        WorkflowTransition("background_check", "not_selected", "fail_background", "Fail Background"),

        # Offer flow
        WorkflowTransition("offer_preparation", "offer_extended", "send_offer", "Send Offer"),
        WorkflowTransition("offer_extended", "offer_accepted", "accept", "Accept Offer"),
        WorkflowTransition("offer_extended", "not_selected", "decline", "Decline Offer"),
        WorkflowTransition("offer_extended", "offer_preparation", "renegotiate", "Renegotiate"),

        # Onboarding flow
        WorkflowTransition("offer_accepted", "pre_boarding", "start_preboarding", "Start Pre-boarding"),
        WorkflowTransition("pre_boarding", "onboarding", "start_onboarding", "Start Onboarding"),
        WorkflowTransition("onboarding", "hired", "complete_onboarding", "Complete Onboarding"),

        # Withdrawal from any active state
        WorkflowTransition("application_received", "withdrawn", "withdraw_app", "Withdraw"),
        WorkflowTransition("initial_screening", "withdrawn", "withdraw_screen", "Withdraw"),
        WorkflowTransition("skills_assessment", "withdrawn", "withdraw_assess", "Withdraw"),
        WorkflowTransition("phone_screen", "withdrawn", "withdraw_phone", "Withdraw"),
        WorkflowTransition("technical_interview", "withdrawn", "withdraw_tech", "Withdraw"),
        WorkflowTransition("hiring_manager_interview", "withdrawn", "withdraw_hm", "Withdraw"),
        WorkflowTransition("panel_interview", "withdrawn", "withdraw_panel", "Withdraw"),
        WorkflowTransition("executive_interview", "withdrawn", "withdraw_exec", "Withdraw"),
        WorkflowTransition("reference_check", "withdrawn", "withdraw_ref", "Withdraw"),
        WorkflowTransition("background_check", "withdrawn", "withdraw_bg", "Withdraw"),
        WorkflowTransition("offer_preparation", "withdrawn", "withdraw_offer", "Withdraw"),
        WorkflowTransition("offer_extended", "withdrawn", "withdraw_extended", "Withdraw"),
    ]

    for t in transitions:
        if isinstance(t, tuple):
            workflow.add_transition(WorkflowTransition(*t))
        else:
            workflow.add_transition(t)

    return workflow


# ==================== WORKFLOW INSTANCES ====================

# Pre-configured workflow instances
APPLICATION_WORKFLOW = create_application_workflow()
INTERVIEW_WORKFLOW = create_interview_workflow()
OFFER_WORKFLOW = create_offer_workflow()
HIRING_WORKFLOW = create_hiring_workflow()


# ==================== WORKFLOW SERVICE ====================

class WorkflowService:
    """
    Service class for managing workflow operations.

    Provides high-level operations for:
    - Transitioning entities between states
    - Validating workflows
    - Generating workflow analytics
    - On-hold state context preservation and restoration
    - Adverse action compliance tracking
    """

    # Default waiting periods for adverse action by jurisdiction (in days)
    ADVERSE_ACTION_WAITING_PERIODS = {
        'US': 5,      # FCRA pre-adverse action notice period
        'US-CA': 7,   # California additional requirements
        'EU': 7,      # GDPR consideration period
        'UK': 7,      # UK GDPR
        'DEFAULT': 5
    }

    def __init__(self):
        self.workflows = {
            'application': APPLICATION_WORKFLOW,
            'interview': INTERVIEW_WORKFLOW,
            'offer': OFFER_WORKFLOW,
            'hiring': HIRING_WORKFLOW,
        }

    def get_workflow(self, workflow_name: str) -> Optional[WorkflowEngine]:
        """Get a workflow by name."""
        return self.workflows.get(workflow_name)

    def get_adverse_action_waiting_period(self, jurisdiction: str = 'DEFAULT') -> int:
        """Get the required waiting period for adverse action by jurisdiction."""
        return self.ADVERSE_ACTION_WAITING_PERIODS.get(
            jurisdiction,
            self.ADVERSE_ACTION_WAITING_PERIODS['DEFAULT']
        )

    def transition_application(
        self,
        application,
        to_state: str,
        user=None,
        reason: str = "",
        metadata: Dict[str, Any] = None
    ) -> tuple[bool, Optional[str]]:
        """
        Transition an application to a new state.

        Args:
            application: Application model instance
            to_state: Target state name
            user: User performing the transition
            reason: Reason for the transition
            metadata: Additional metadata

        Returns:
            Tuple of (success, error_message)

        Special handling:
        - ON_HOLD: Stores previous_state in metadata for later restoration
        - PRE_ADVERSE_ACTION: Records adverse_action_initiated_at timestamp
        - Reactivation from ON_HOLD: Can restore to previous_state if specified
        """
        workflow = self.workflows['application']
        current_state = application.status
        metadata = metadata or {}

        # Handle on-hold state: preserve previous state for later restoration
        if to_state == 'on_hold' and current_state != 'on_hold':
            metadata['previous_state'] = current_state
            metadata['on_hold_at'] = timezone.now().isoformat()

        # Handle pre-adverse action state: record initiation timestamp
        if to_state == 'pre_adverse_action':
            jurisdiction = metadata.get('jurisdiction', 'DEFAULT')
            waiting_period = self.get_adverse_action_waiting_period(jurisdiction)
            metadata['adverse_action_initiated_at'] = timezone.now().isoformat()
            metadata['adverse_action_waiting_period_days'] = waiting_period
            metadata['adverse_action_earliest_completion'] = (
                timezone.now() + timedelta(days=waiting_period)
            ).isoformat()

        # Handle reactivation from on-hold: optionally restore to previous state
        if current_state == 'on_hold' and to_state != 'rejected':
            # Check if we should restore to previous state
            previous_state = self._get_previous_state_from_application(application)
            if previous_state and metadata.get('restore_previous_state', False):
                # Validate the previous state is a valid target
                if previous_state in [s.name for s in workflow.states.values()]:
                    to_state = previous_state
                    metadata['restored_from_on_hold'] = True

        context = {
            'reason': reason,
            'metadata': metadata
        }

        success, error = workflow.execute_transition(
            entity=application,
            from_state=current_state,
            to_state=to_state,
            context=context,
            user=user
        )

        if success:
            # Update the application
            application.status = to_state

            # Store metadata on application if it has a metadata field
            if hasattr(application, 'workflow_metadata'):
                existing_metadata = application.workflow_metadata or {}
                existing_metadata.update(metadata)
                application.workflow_metadata = existing_metadata

            application.save(update_fields=['status', 'updated_at'] + (
                ['workflow_metadata'] if hasattr(application, 'workflow_metadata') else []
            ))

            # Log activity
            from .models import ApplicationActivity
            ApplicationActivity.objects.create(
                application=application,
                activity_type=ApplicationActivity.ActivityType.STATUS_CHANGE,
                performed_by=user,
                old_value=current_state,
                new_value=to_state,
                notes=reason,
                metadata=metadata
            )

        return success, error

    def _get_previous_state_from_application(self, application) -> Optional[str]:
        """
        Get the previous state before on-hold from application metadata.

        Searches:
        1. application.workflow_metadata['previous_state']
        2. Most recent activity log showing transition to on_hold
        """
        # Try workflow_metadata first
        if hasattr(application, 'workflow_metadata'):
            metadata = application.workflow_metadata or {}
            if 'previous_state' in metadata:
                return metadata['previous_state']

        # Fall back to activity log
        from .models import ApplicationActivity
        try:
            last_hold_activity = ApplicationActivity.objects.filter(
                application=application,
                new_value='on_hold',
                activity_type=ApplicationActivity.ActivityType.STATUS_CHANGE
            ).order_by('-created_at').first()

            if last_hold_activity:
                return last_hold_activity.old_value
        except Exception:
            pass

        return None

    def reactivate_from_hold(
        self,
        application,
        user=None,
        reason: str = "",
        restore_previous: bool = True,
        target_state: str = None
    ) -> tuple[bool, Optional[str]]:
        """
        Reactivate an application from on-hold state.

        Args:
            application: Application model instance
            user: User performing the transition
            reason: Reason for reactivation
            restore_previous: If True, restore to the state before on-hold
            target_state: Optional explicit target state (overrides restore_previous)

        Returns:
            Tuple of (success, error_message)
        """
        if application.status != 'on_hold':
            return False, "Application is not currently on hold"

        metadata = {'restore_previous_state': restore_previous}

        if target_state:
            return self.transition_application(
                application=application,
                to_state=target_state,
                user=user,
                reason=reason,
                metadata=metadata
            )

        if restore_previous:
            previous_state = self._get_previous_state_from_application(application)
            if previous_state:
                return self.transition_application(
                    application=application,
                    to_state=previous_state,
                    user=user,
                    reason=reason,
                    metadata=metadata
                )
            else:
                return False, "Cannot restore previous state: no previous state recorded"

        # Default to 'new' if no specific target
        return self.transition_application(
            application=application,
            to_state='new',
            user=user,
            reason=reason,
            metadata=metadata
        )

    def initiate_adverse_action(
        self,
        application,
        user=None,
        reason: str = "",
        jurisdiction: str = 'DEFAULT',
        metadata: Dict[str, Any] = None
    ) -> tuple[bool, Optional[str]]:
        """
        Initiate adverse action (pre-rejection) process for compliance.

        This is required by FCRA, EEOC, and similar regulations before
        rejecting candidates based on background checks or other factors.

        Args:
            application: Application model instance
            user: User performing the action
            reason: Reason for adverse action
            jurisdiction: Jurisdiction code for waiting period determination
            metadata: Additional metadata

        Returns:
            Tuple of (success, error_message)
        """
        metadata = metadata or {}
        metadata['jurisdiction'] = jurisdiction
        metadata['adverse_action_reason'] = reason

        return self.transition_application(
            application=application,
            to_state='pre_adverse_action',
            user=user,
            reason=reason,
            metadata=metadata
        )

    def complete_adverse_action(
        self,
        application,
        user=None,
        final_reason: str = "",
        metadata: Dict[str, Any] = None
    ) -> tuple[bool, Optional[str]]:
        """
        Complete adverse action and finalize rejection.

        Validates that the required waiting period has elapsed.

        Args:
            application: Application model instance
            user: User performing the action
            final_reason: Final rejection reason
            metadata: Additional metadata

        Returns:
            Tuple of (success, error_message)
        """
        if application.status != 'pre_adverse_action':
            return False, "Application is not in pre-adverse action state"

        # Check waiting period
        workflow_metadata = getattr(application, 'workflow_metadata', {}) or {}
        earliest_completion = workflow_metadata.get('adverse_action_earliest_completion')

        if earliest_completion:
            from datetime import datetime
            earliest_dt = datetime.fromisoformat(earliest_completion.replace('Z', '+00:00'))
            if timezone.now() < earliest_dt:
                remaining = (earliest_dt - timezone.now()).days
                return False, f"Waiting period not complete. {remaining} day(s) remaining."

        metadata = metadata or {}
        metadata['adverse_action_completed_at'] = timezone.now().isoformat()

        return self.transition_application(
            application=application,
            to_state='rejected',
            user=user,
            reason=final_reason,
            metadata=metadata
        )

    def get_available_actions(
        self,
        workflow_name: str,
        current_state: str
    ) -> List[Dict[str, Any]]:
        """
        Get available actions for the current state.

        Returns list of actions with metadata.
        """
        workflow = self.workflows.get(workflow_name)
        if not workflow:
            return []

        transitions = workflow.get_available_transitions(current_state)
        return [
            {
                'name': t.name,
                'display_name': t.display_name,
                'description': t.description,
                'to_state': t.to_state,
                'requires_reason': t.requires_reason,
                'requires_permission': t.requires_permission,
            }
            for t in transitions
        ]

    def get_workflow_metrics(self, workflow_name: str) -> Dict[str, Any]:
        """
        Get metrics for a workflow.

        Returns state counts, average times, bottlenecks.
        """
        workflow = self.workflows.get(workflow_name)
        if not workflow:
            return {}

        return {
            'workflow_name': workflow.name,
            'total_states': len(workflow.states),
            'terminal_states': len(workflow.get_terminal_states()),
            'states_requiring_action': sum(
                1 for s in workflow.states.values() if s.requires_action
            ),
            'diagram': workflow.get_workflow_diagram()
        }


# Create singleton service instance
workflow_service = WorkflowService()
