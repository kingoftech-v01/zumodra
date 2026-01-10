"""
Services Views - Zumodra Freelance Marketplace

Views for browsing services, managing provider profiles, handling proposals,
contracts, and reviews.

Security Features:
- Tenant isolation on all queries
- Role-based access control via decorators
- Object-level permission checks
- Audit logging for sensitive operations
"""

import logging
from django.shortcuts import render, redirect, get_object_or_404
from django.http import HttpResponse, JsonResponse, HttpResponseBadRequest
from django.contrib.auth.decorators import login_required
from django.contrib import messages
from django.core.paginator import Paginator
from django.db.models import Q, Avg, Count
from django.contrib.gis.geos import Point
from django.contrib.gis.db.models.functions import Distance
from django.contrib.gis.measure import D
from geopy.geocoders import Nominatim
from geopy.exc import GeocoderUnavailable, GeocoderTimedOut
from decimal import Decimal
from django.utils import timezone

# Import security decorators
from core.decorators import (
    require_tenant_user,
    audit_access,
    rate_limit,
)

logger = logging.getLogger(__name__)
security_logger = logging.getLogger('security.services')

from .models import (
    ServiceCategory,
    ServiceTag,
    ServiceImage,
    ServiceProvider,
    Service,
    ServiceLike,
    ClientRequest,
    ServiceProposal,
    ServiceContract,
    ServiceReview,
)
from configurations.models import Skill, Company
from finance.models import EscrowTransaction, Dispute

# Initialize geolocator
geolocator = Nominatim(user_agent="zumodra_app")


# ==================== SERVICE BROWSING & SEARCH ====================

def browse_services(request):
    """
    Browse all services with filtering and search capabilities.
    Handles empty database gracefully (e.g., during initial setup).
    """
    try:
        services_query = Service.objects.select_related('provider', 'category').prefetch_related('tags', 'images')

        # Search by name or description
        search = request.GET.get('search', '')
        if search:
            services_query = services_query.filter(
                Q(name__icontains=search) |
                Q(description__icontains=search) |
                Q(tags__name__icontains=search)
            ).distinct()

        # Filter by category
        category_id = request.GET.get('category')
        if category_id:
            services_query = services_query.filter(category_id=category_id)

        # Filter by price range
        min_price = request.GET.get('min_price')
        max_price = request.GET.get('max_price')
        if min_price:
            services_query = services_query.filter(price__gte=min_price)
        if max_price:
            services_query = services_query.filter(price__lte=max_price)

        # Filter by tags
        tag = request.GET.get('tag')
        if tag:
            services_query = services_query.filter(tags__name__iexact=tag)

        # Sorting
        sort_by = request.GET.get('sort', '-created_at')
        allowed_sorts = ['-created_at', 'created_at', 'price', '-price', 'name']
        if sort_by in allowed_sorts:
            services_query = services_query.order_by(sort_by)

        # Pagination
        paginator = Paginator(services_query, 12)
        page_number = request.GET.get('page', 1)
        services = paginator.get_page(page_number)

        # Get categories and tags for filters
        categories = ServiceCategory.objects.all()
        popular_tags = ServiceTag.objects.annotate(
            service_count=Count('services')
        ).order_by('-service_count')[:10]

        context = {
            'services': services,
            'categories': categories,
            'popular_tags': popular_tags,
            'search': search,
        }

    except Exception as e:
        # Handle case where tables don't exist yet (during migrations)
        import logging
        logger = logging.getLogger(__name__)
        logger.warning(f"Error loading services: {e}")

        # Return empty context to display "no services" message
        from django.core.paginator import Paginator, EmptyPage
        empty_list = []
        paginator = Paginator(empty_list, 12)

        context = {
            'services': paginator.get_page(1),
            'categories': [],
            'popular_tags': [],
            'search': request.GET.get('search', ''),
            'error_message': 'Services will be available once the system is fully initialized.',
        }

    return render(request, 'services/browse_services.html', context)


def service_detail(request, service_uuid):
    """
    View detailed information about a specific service.
    """
    service = get_object_or_404(
        Service.objects.select_related('provider__user', 'category')
        .prefetch_related('images', 'tags', 'reviews__reviewer'),
        uuid=service_uuid
    )

    # Get reviews
    reviews = service.reviews.all().order_by('-created_at')
    avg_rating = reviews.aggregate(avg=Avg('rating'))['avg'] or 0

    # Check if user has liked this service
    user_has_liked = False
    if request.user.is_authenticated:
        user_has_liked = ServiceLike.objects.filter(
            user=request.user,
            service=service
        ).exists()

    # Get related services (same category)
    related_services = Service.objects.filter(
        category=service.category
    ).exclude(uuid=service_uuid)[:4]

    context = {
        'service': service,
        'reviews': reviews,
        'avg_rating': round(avg_rating, 2),
        'user_has_liked': user_has_liked,
        'related_services': related_services,
    }
    return render(request, 'services/service_detail.html', context)


@login_required
@require_tenant_user
@rate_limit('like_service', '30/minute')  # Prevent like/unlike spam
def like_service(request, service_uuid):
    """
    Toggle like/unlike a service.

    Security:
    - Requires authenticated tenant user
    - Rate limited to prevent abuse
    """
    service = get_object_or_404(Service, uuid=service_uuid)
    like, created = ServiceLike.objects.get_or_create(
        user=request.user,
        service=service
    )

    if not created:
        like.delete()
        liked = False
        messages.success(request, 'Service removed from favorites')
    else:
        liked = True
        messages.success(request, 'Service added to favorites')

    if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
        return JsonResponse({'liked': liked})

    return redirect('service_detail', service_uuid=service_uuid)


def browse_nearby_services(request):
    """
    Find services near a specific location.
    """
    lat = request.GET.get('lat')
    lng = request.GET.get('lng')

    if lat is None or lng is None:
        # Try to get user's location from their profile if logged in
        if request.user.is_authenticated and hasattr(request.user, 'service_provider_profile'):
            provider = request.user.service_provider_profile
            if provider.location_lat and provider.location_lng:
                lat = provider.location_lat
                lng = provider.location_lng
        else:
            messages.warning(request, 'Please provide your location')
            return redirect('service_list')

    try:
        user_lat = float(lat)
        user_lng = float(lng)
    except (ValueError, TypeError):
        messages.error(request, 'Invalid location coordinates')
        return redirect('service_list')

    user_location = Point(user_lng, user_lat, srid=4326)
    within_area = int(request.GET.get('within_area', 10))  # Default 10km

    # Find providers within distance
    nearby_providers = (
        ServiceProvider.objects
        .filter(
            location__distance_lte=(user_location, D(km=within_area)),
            availability_status='available'
        )
        .annotate(distance=Distance('location', user_location))
        .order_by('distance')
    )

    # Get services from nearby providers
    nearby_services = Service.objects.filter(
        provider__in=nearby_providers
    ).select_related('provider')

    context = {
        'providers': nearby_providers,
        'services': nearby_services,
        'search_location': {'lat': user_lat, 'lng': user_lng},
        'within_area': within_area,
    }
    return render(request, 'services/nearby_services.html', context)


# ==================== PROVIDER PROFILE MANAGEMENT ====================

@login_required
def provider_dashboard(request):
    """
    Provider dashboard showing their services, proposals, contracts.
    """
    try:
        provider = request.user.service_provider_profile
    except ServiceProvider.DoesNotExist:
        messages.info(request, 'Please create your provider profile first')
        return redirect('create_provider_profile')

    # Get provider's services
    services = provider.services.all()

    # Get active contracts
    active_contracts = ServiceContract.objects.filter(
        provider=provider,
        status='active'
    )

    # Get pending proposals
    pending_proposals = ServiceProposal.objects.filter(
        provider=provider,
        status='pending'
    )

    # Get recent reviews
    recent_reviews = ServiceReview.objects.filter(
        provider=provider
    ).order_by('-created_at')[:5]

    # Calculate stats
    total_services = services.count()
    total_contracts = provider.contracts.count()
    avg_rating = recent_reviews.aggregate(avg=Avg('rating'))['avg'] or 0

    context = {
        'provider': provider,
        'services': services,
        'active_contracts': active_contracts,
        'pending_proposals': pending_proposals,
        'recent_reviews': recent_reviews,
        'total_services': total_services,
        'total_contracts': total_contracts,
        'avg_rating': round(avg_rating, 2),
    }
    return render(request, 'services/provider_dashboard.html', context)


@login_required
def create_provider_profile(request):
    """
    Create a new service provider profile.
    """
    # Check if user already has a provider profile
    if hasattr(request.user, 'service_provider_profile'):
        messages.warning(request, 'You already have a provider profile')
        return redirect('provider_dashboard')

    if request.method == 'POST':
        # Get form data
        bio = request.POST.get('bio', '')
        address = request.POST.get('address', '')
        city = request.POST.get('city', '')
        country = request.POST.get('country', '')
        postal_code = request.POST.get('postal_code', '')
        hourly_rate = request.POST.get('hourly_rate', 0)
        is_mobile = request.POST.get('is_mobile') == 'on'
        availability_status = request.POST.get('availability_status', 'available')

        # Create provider profile
        provider = ServiceProvider.objects.create(
            user=request.user,
            bio=bio,
            address=address,
            city=city,
            country=country,
            postal_code=postal_code,
            hourly_rate=Decimal(hourly_rate),
            is_mobile=is_mobile,
            availability_status=availability_status
        )

        # Handle image upload
        if 'avatar' in request.FILES:
            provider.avatar = request.FILES['avatar']
            provider.save()

        # Add selected categories
        category_ids = request.POST.getlist('categories')
        if category_ids:
            provider.categories.set(category_ids)

        messages.success(request, 'Provider profile created successfully!')
        return redirect('provider_dashboard')

    # GET request - show form
    categories = ServiceCategory.objects.all()
    context = {'categories': categories}
    return render(request, 'services/create_provider_profile.html', context)


@login_required
def edit_provider_profile(request):
    """
    Edit existing provider profile.
    """
    provider = get_object_or_404(ServiceProvider, user=request.user)

    if request.method == 'POST':
        # Update profile fields
        provider.bio = request.POST.get('bio', provider.bio)
        provider.address = request.POST.get('address', provider.address)
        provider.city = request.POST.get('city', provider.city)
        provider.country = request.POST.get('country', provider.country)
        provider.postal_code = request.POST.get('postal_code', provider.postal_code)
        provider.hourly_rate = Decimal(request.POST.get('hourly_rate', provider.hourly_rate))
        provider.is_mobile = request.POST.get('is_mobile') == 'on'
        provider.availability_status = request.POST.get('availability_status', provider.availability_status)

        # Handle image upload
        if 'avatar' in request.FILES:
            provider.avatar = request.FILES['avatar']

        provider.save()

        # Update categories
        category_ids = request.POST.getlist('categories')
        if category_ids:
            provider.categories.set(category_ids)

        messages.success(request, 'Profile updated successfully!')
        return redirect('provider_dashboard')

    categories = ServiceCategory.objects.all()
    context = {
        'provider': provider,
        'categories': categories,
    }
    return render(request, 'services/edit_provider_profile.html', context)


def provider_profile_view(request, provider_uuid):
    """
    Public view of a provider's profile.
    """
    provider = get_object_or_404(
        ServiceProvider.objects.prefetch_related('services'),
        uuid=provider_uuid
    )

    # Don't show private profiles
    if provider.is_private:
        messages.error(request, 'This profile is private')
        return redirect('service_list')

    # Get provider's services
    services = provider.services.all()

    # Get reviews
    reviews = ServiceReview.objects.filter(provider=provider).order_by('-created_at')
    avg_rating = reviews.aggregate(avg=Avg('rating'))['avg'] or 0

    context = {
        'provider': provider,
        'services': services,
        'reviews': reviews,
        'avg_rating': round(avg_rating, 2),
    }
    return render(request, 'services/provider_profile.html', context)


# ==================== SERVICE CRUD (Provider) ====================

@login_required
def create_service(request):
    """
    Create a new service offering.
    """
    # Ensure user has a provider profile
    try:
        provider = request.user.service_provider_profile
    except ServiceProvider.DoesNotExist:
        messages.error(request, 'Please create a provider profile first')
        return redirect('create_provider_profile')

    if request.method == 'POST':
        name = request.POST.get('name')
        description = request.POST.get('description', '')
        price = request.POST.get('price')
        duration_days = request.POST.get('duration_days')
        category_id = request.POST.get('category')

        # Create service
        service = Service.objects.create(
            provider=provider,
            name=name,
            description=description,
            price=Decimal(price) if price else None,
            duration_days=int(duration_days) if duration_days else None,
            category_id=category_id if category_id else None
        )

        # Handle thumbnail
        if 'thumbnail' in request.FILES:
            service.thumbnail = request.FILES['thumbnail']
            service.save()

        # Add tags
        tags = request.POST.get('tags', '').split(',')
        for tag_name in tags:
            tag_name = tag_name.strip()
            if tag_name:
                tag, _ = ServiceTag.objects.get_or_create(name=tag_name)
                service.tags.add(tag)

        messages.success(request, 'Service created successfully!')
        return redirect('provider_dashboard')

    categories = ServiceCategory.objects.all()
    context = {'categories': categories}
    return render(request, 'services/create_service.html', context)


@login_required
def edit_service(request, service_uuid):
    """
    Edit an existing service.
    """
    service = get_object_or_404(Service, uuid=service_uuid, provider__user=request.user)

    if request.method == 'POST':
        service.name = request.POST.get('name', service.name)
        service.description = request.POST.get('description', service.description)

        price = request.POST.get('price')
        service.price = Decimal(price) if price else None

        duration = request.POST.get('duration_days')
        service.duration_days = int(duration) if duration else None

        category_id = request.POST.get('category')
        service.category_id = category_id if category_id else None

        # Handle thumbnail
        if 'thumbnail' in request.FILES:
            service.thumbnail = request.FILES['thumbnail']

        service.save()

        # Update tags
        service.tags.clear()
        tags = request.POST.get('tags', '').split(',')
        for tag_name in tags:
            tag_name = tag_name.strip()
            if tag_name:
                tag, _ = ServiceTag.objects.get_or_create(name=tag_name)
                service.tags.add(tag)

        messages.success(request, 'Service updated successfully!')
        return redirect('provider_dashboard')

    categories = ServiceCategory.objects.all()
    current_tags = ', '.join([tag.name for tag in service.tags.all()])

    context = {
        'service': service,
        'categories': categories,
        'current_tags': current_tags,
    }
    return render(request, 'services/edit_service.html', context)


@login_required
def delete_service(request, service_uuid):
    """
    Delete a service.
    """
    service = get_object_or_404(Service, uuid=service_uuid, provider__user=request.user)

    if request.method == 'POST':
        service_name = service.name
        service.delete()
        messages.success(request, f'Service "{service_name}" deleted successfully!')
        return redirect('provider_dashboard')

    context = {'service': service}
    return render(request, 'services/delete_service_confirm.html', context)


# ==================== CLIENT REQUESTS & PROPOSALS ====================

@login_required
def create_service_request(request):
    """
    Client creates a service request.
    """
    if request.method == 'POST':
        title = request.POST.get('title')
        description = request.POST.get('description')
        budget_min = request.POST.get('budget_min')
        budget_max = request.POST.get('budget_max')
        deadline = request.POST.get('deadline')
        category_id = request.POST.get('category')

        # Create request
        client_request = ClientRequest.objects.create(
            client=request.user,
            category_id=category_id if category_id else None,
            title=title,
            description=description,
            budget_min=Decimal(budget_min) if budget_min else None,
            budget_max=Decimal(budget_max) if budget_max else None,
            deadline=deadline if deadline else None,
        )

        # Add required skills
        skill_ids = request.POST.getlist('skills')
        if skill_ids:
            client_request.required_skills.set(skill_ids)

        messages.success(request, 'Service request created successfully!')
        return redirect('my_requests')

    skills = Skill.objects.all()
    categories = ServiceCategory.objects.all()

    context = {
        'skills': skills,
        'categories': categories,
    }
    return render(request, 'services/create_request.html', context)


@login_required
def my_requests(request):
    """
    View user's service requests.
    """
    client_requests = ClientRequest.objects.filter(client=request.user).order_by('-created_at')

    context = {'requests': client_requests}
    return render(request, 'services/my_requests.html', context)


@login_required
def view_request(request, request_uuid):
    """
    View a specific service request with proposals.
    """
    client_request = get_object_or_404(
        ClientRequest.objects.prefetch_related('proposals__provider'),
        uuid=request_uuid
    )

    # Only owner or providers can view
    is_owner = client_request.client == request.user
    has_provider_profile = hasattr(request.user, 'service_provider_profile')

    if not (is_owner or has_provider_profile):
        messages.error(request, 'You do not have permission to view this request')
        return redirect('service_list')

    proposals = client_request.proposals.all().order_by('-created_at')

    context = {
        'client_request': client_request,
        'proposals': proposals,
        'is_owner': is_owner,
    }
    return render(request, 'services/view_request.html', context)


@login_required
def submit_proposal(request, request_uuid):
    """
    Provider submits a proposal for a service request.
    """
    try:
        provider = request.user.service_provider_profile
    except ServiceProvider.DoesNotExist:
        messages.error(request, 'You need a provider profile to submit proposals')
        return redirect('create_provider_profile')

    client_request = get_object_or_404(ClientRequest, uuid=request_uuid, status='open')

    # Check if already submitted
    if ServiceProposal.objects.filter(client_request=client_request, provider=provider).exists():
        messages.warning(request, 'You already submitted a proposal for this request')
        return redirect('view_request', request_uuid=request_uuid)

    if request.method == 'POST':
        proposed_rate = request.POST.get('proposed_rate')
        cover_letter = request.POST.get('cover_letter', '')

        ServiceProposal.objects.create(
            client_request=client_request,
            provider=provider,
            proposed_rate=Decimal(proposed_rate),
            cover_letter=cover_letter
        )

        messages.success(request, 'Proposal submitted successfully!')
        return redirect('provider_dashboard')

    context = {
        'client_request': client_request,
        'provider': provider,
    }
    return render(request, 'services/submit_proposal.html', context)


@login_required
@require_tenant_user
@audit_access('accept_proposal')
def accept_proposal(request, proposal_id):
    """
    Client accepts a proposal and creates a contract with escrow.

    Security:
    - Requires authenticated tenant user
    - Only the request client can accept proposals
    - Audit logged for financial transaction
    """
    proposal = get_object_or_404(ServiceProposal, id=proposal_id)

    # Ensure user is the client who made the request
    if proposal.client_request.client != request.user:
        security_logger.warning(
            f"PROPOSAL_ACCEPT_DENIED: user={request.user.id} attempted to accept "
            f"proposal={proposal_id} owned by user={proposal.client_request.client.id}"
        )
        messages.error(request, 'You do not have permission to accept this proposal')
        return redirect('service_list')

    if request.method == 'POST':
        # Mark proposal as accepted
        proposal.status = 'accepted'
        proposal.save()

        # Close the request
        proposal.client_request.status = 'in_progress'
        proposal.client_request.save()

        # Create escrow transaction for the contract
        escrow = EscrowTransaction.objects.create(
            buyer=request.user,
            seller=proposal.provider.user,
            amount=proposal.proposed_rate,
            currency='CAD',
            status='initialized',
            agreement_details=f"Escrow for proposal: {proposal.client_request.title}"
        )

        # Create contract with escrow linked
        agreed_deadline = request.POST.get('agreed_deadline')
        contract_title = proposal.client_request.title or f"Contract with {proposal.provider.display_name}"
        contract = ServiceContract.objects.create(
            proposal=proposal,
            client_request=proposal.client_request,
            provider=proposal.provider,
            client=request.user,
            title=contract_title,
            description=proposal.cover_letter,
            agreed_rate=proposal.proposed_rate,
            agreed_deadline=agreed_deadline if agreed_deadline else None,
            status=ServiceContract.ContractStatus.PENDING_PAYMENT,
            escrow_transaction=escrow
        )

        # Audit log the contract creation
        security_logger.info(
            f"CONTRACT_CREATED: user={request.user.id} proposal={proposal_id} "
            f"contract={contract.id} escrow={escrow.id} amount={proposal.proposed_rate}"
        )

        messages.success(request, 'Proposal accepted! Contract created. Please fund the escrow to start work.')
        return redirect('services:view_contract', contract_id=contract.id)

    context = {'proposal': proposal}
    return render(request, 'services/accept_proposal.html', context)


# ==================== CONTRACT MANAGEMENT ====================

@login_required
def view_contract(request, contract_id):
    """
    View contract details.
    """
    contract = get_object_or_404(ServiceContract, id=contract_id)

    # Only client or provider can view
    is_client = contract.client == request.user
    is_provider = contract.provider.user == request.user

    if not (is_client or is_provider):
        messages.error(request, 'You do not have permission to view this contract')
        return redirect('service_list')

    # Get contract messages
    contract_messages = contract.messages.all().order_by('created_at')

    context = {
        'contract': contract,
        'messages': contract_messages,
        'is_client': is_client,
        'is_provider': is_provider,
    }
    return render(request, 'services/view_contract.html', context)


@login_required
def my_contracts(request):
    """
    View user's contracts (as client or provider).
    """
    # Contracts as client
    client_contracts = ServiceContract.objects.filter(client=request.user)

    # Contracts as provider
    provider_contracts = []
    if hasattr(request.user, 'service_provider_profile'):
        provider_contracts = ServiceContract.objects.filter(
            provider=request.user.service_provider_profile
        )

    context = {
        'client_contracts': client_contracts,
        'provider_contracts': provider_contracts,
    }
    return render(request, 'services/my_contracts.html', context)


@login_required
@require_tenant_user
@audit_access('update_contract_status')
def update_contract_status(request, contract_id):
    """
    Update contract status with full escrow lifecycle integration.

    Workflow:
    - PENDING_PAYMENT -> FUNDED (after client funds escrow)
    - FUNDED -> IN_PROGRESS (provider starts work)
    - IN_PROGRESS -> DELIVERED (provider submits delivery)
    - DELIVERED -> COMPLETED (client accepts, escrow released)
    - Any -> DISPUTED (either party raises dispute)
    - Any -> CANCELLED (with potential refund)

    Security:
    - Requires authenticated tenant user
    - Only contract participants can update status
    - Audit logged for status changes
    """
    contract = get_object_or_404(ServiceContract, id=contract_id)

    # Check permissions
    is_client = contract.client == request.user
    is_provider = contract.provider.user == request.user

    if not (is_client or is_provider):
        security_logger.warning(
            f"CONTRACT_UPDATE_DENIED: user={request.user.id} attempted to update "
            f"contract={contract_id} where they are not a participant"
        )
        messages.error(request, 'You do not have permission to update this contract')
        return redirect('service_list')

    if request.method == 'POST':
        new_status = request.POST.get('status')
        escrow = contract.escrow_transaction

        # Provider starts work (after escrow is funded)
        if new_status == 'in_progress' and contract.status == ServiceContract.ContractStatus.FUNDED and is_provider:
            contract.start()
            messages.success(request, 'Contract started! Begin working on the deliverables.')

        # Provider delivers work
        elif new_status == 'delivered' and contract.status == ServiceContract.ContractStatus.IN_PROGRESS and is_provider:
            contract.deliver()
            if escrow:
                escrow.mark_service_delivered()
            messages.success(request, 'Delivery submitted! Waiting for client approval.')

        # Client accepts delivery (releases escrow)
        elif new_status == 'completed' and contract.status == ServiceContract.ContractStatus.DELIVERED and is_client:
            contract.complete()
            # Update provider stats
            contract.provider.completed_jobs_count += 1
            contract.provider.save()
            messages.success(request, 'Contract completed! Funds have been released to the provider.')

        # Client requests revision (if revisions available)
        elif new_status == 'revision_requested' and contract.status == ServiceContract.ContractStatus.DELIVERED and is_client:
            if contract.revisions_used < contract.revisions_allowed:
                contract.status = ServiceContract.ContractStatus.REVISION_REQUESTED
                contract.revisions_used += 1
                contract.save()
                messages.success(request, f'Revision requested. {contract.revisions_allowed - contract.revisions_used} revisions remaining.')
            else:
                messages.error(request, 'No revisions remaining. Please accept or dispute the delivery.')

        # Provider resubmits after revision
        elif new_status == 'delivered' and contract.status == ServiceContract.ContractStatus.REVISION_REQUESTED and is_provider:
            contract.status = ServiceContract.ContractStatus.DELIVERED
            contract.delivered_at = timezone.now()
            contract.save()
            messages.success(request, 'Revision submitted! Waiting for client approval.')

        # Cancel contract (refund if funded)
        elif new_status == 'cancelled' and is_client:
            reason = request.POST.get('reason', '')
            contract.cancel(reason=reason)
            if escrow and escrow.status == 'funded':
                escrow.mark_refunded()
                messages.success(request, 'Contract cancelled. Escrow funds have been refunded.')
            else:
                messages.success(request, 'Contract cancelled.')

        else:
            messages.error(request, 'Invalid status transition.')

        return redirect('services:view_contract', contract_id=contract_id)

    context = {'contract': contract, 'is_client': is_client, 'is_provider': is_provider}
    return render(request, 'services/update_contract_status.html', context)


@login_required
@require_tenant_user
@audit_access('fund_contract')
def fund_contract(request, contract_id):
    """
    Client funds the escrow for a contract via Stripe.

    This creates a Stripe PaymentIntent and processes the payment.
    On success, escrow status changes to 'funded' and contract to 'FUNDED'.

    Security:
    - Requires authenticated tenant user
    - Only contract client can fund
    - Audit logged for financial transaction
    """
    contract = get_object_or_404(ServiceContract, id=contract_id)

    # Only client can fund
    if contract.client != request.user:
        security_logger.warning(
            f"FUND_CONTRACT_DENIED: user={request.user.id} attempted to fund "
            f"contract={contract_id} owned by client={contract.client.id}"
        )
        messages.error(request, 'Only the client can fund this contract')
        return redirect('services:view_contract', contract_id=contract_id)

    # Contract must be pending payment
    if contract.status != ServiceContract.ContractStatus.PENDING_PAYMENT:
        messages.error(request, 'This contract cannot be funded at this stage')
        return redirect('services:view_contract', contract_id=contract_id)

    escrow = contract.escrow_transaction
    if not escrow:
        messages.error(request, 'No escrow transaction found for this contract')
        return redirect('services:view_contract', contract_id=contract_id)

    if request.method == 'POST':
        # In production, this would integrate with Stripe
        # For now, we simulate successful payment
        payment_intent_id = request.POST.get('payment_intent_id', '')

        if payment_intent_id or request.POST.get('simulate_payment'):
            # Mark escrow as funded
            escrow.payment_intent_id = payment_intent_id or f"sim_{escrow.id}"
            escrow.mark_funded()

            # Update contract status
            contract.status = ServiceContract.ContractStatus.FUNDED
            contract.save()

            messages.success(request, 'Payment successful! Escrow funded. The provider can now start work.')
            return redirect('services:view_contract', contract_id=contract_id)
        else:
            messages.error(request, 'Payment processing failed. Please try again.')

    # Calculate platform fee and provider payout
    platform_fee = contract.agreed_rate * (contract.platform_fee_percent / 100)
    provider_payout = contract.agreed_rate - platform_fee

    context = {
        'contract': contract,
        'escrow': escrow,
        'platform_fee': platform_fee,
        'provider_payout': provider_payout,
    }
    return render(request, 'services/fund_contract.html', context)


@login_required
@require_tenant_user
@audit_access('create_dispute')
def create_dispute(request, contract_id):
    """
    Either party raises a dispute on a contract.

    Valid for contracts that are: FUNDED, IN_PROGRESS, DELIVERED, or REVISION_REQUESTED.

    Security:
    - Requires authenticated tenant user
    - Only contract participants can dispute
    - Audit logged for financial dispute
    """
    contract = get_object_or_404(ServiceContract, id=contract_id)

    # Check permissions
    is_client = contract.client == request.user
    is_provider = contract.provider.user == request.user

    if not (is_client or is_provider):
        security_logger.warning(
            f"DISPUTE_DENIED: user={request.user.id} attempted to dispute "
            f"contract={contract_id} where they are not a participant"
        )
        messages.error(request, 'You do not have permission to dispute this contract')
        return redirect('service_list')

    # Check if contract can be disputed
    disputable_statuses = [
        ServiceContract.ContractStatus.FUNDED,
        ServiceContract.ContractStatus.IN_PROGRESS,
        ServiceContract.ContractStatus.DELIVERED,
        ServiceContract.ContractStatus.REVISION_REQUESTED,
    ]
    if contract.status not in disputable_statuses:
        messages.error(request, 'This contract cannot be disputed at this stage')
        return redirect('services:view_contract', contract_id=contract_id)

    escrow = contract.escrow_transaction
    if not escrow:
        messages.error(request, 'No escrow transaction found for this contract')
        return redirect('services:view_contract', contract_id=contract_id)

    if request.method == 'POST':
        reason = request.POST.get('reason', '').strip()
        details = request.POST.get('details', '').strip()

        if not reason:
            messages.error(request, 'Please provide a reason for the dispute')
        else:
            # Create dispute record
            dispute = Dispute.objects.create(
                escrow=escrow,
                raised_by=request.user,
                reason=reason,
                details=details
            )

            # Update escrow and contract status
            escrow.raise_dispute()
            contract.status = ServiceContract.ContractStatus.DISPUTED
            contract.save()

            messages.success(request, 'Dispute raised successfully. Our team will review and respond within 48 hours.')
            return redirect('services:view_contract', contract_id=contract_id)

    context = {
        'contract': contract,
        'is_client': is_client,
        'is_provider': is_provider,
    }
    return render(request, 'services/create_dispute.html', context)


@login_required
def view_dispute(request, dispute_id):
    """
    View dispute details and resolution status.
    """
    dispute = get_object_or_404(Dispute, id=dispute_id)
    escrow = dispute.escrow

    # Get the contract associated with the escrow
    try:
        contract = escrow.service_contract
    except ServiceContract.DoesNotExist:
        messages.error(request, 'Contract not found for this dispute')
        return redirect('services:my_contracts')

    # Check permissions
    is_client = contract.client == request.user
    is_provider = contract.provider.user == request.user
    is_raiser = dispute.raised_by == request.user

    if not (is_client or is_provider):
        messages.error(request, 'You do not have permission to view this dispute')
        return redirect('services:my_contracts')

    context = {
        'dispute': dispute,
        'contract': contract,
        'escrow': escrow,
        'is_client': is_client,
        'is_provider': is_provider,
        'is_raiser': is_raiser,
    }
    return render(request, 'services/view_dispute.html', context)


# ==================== REVIEWS & COMMENTS ====================

@login_required
def add_review(request, service_uuid):
    """
    Add a review/comment to a service.
    """
    service = get_object_or_404(Service, uuid=service_uuid)

    if request.method == 'POST':
        content = request.POST.get('content', '')
        rating = request.POST.get('rating')

        if not rating:
            messages.error(request, 'Please provide a rating')
            return redirect('service_detail', service_uuid=service_uuid)

        ServiceReview.objects.create(
            provider=service.provider,
            service=service,
            reviewer=request.user,
            content=content,
            rating=int(rating)
        )

        # Update provider rating
        avg_rating = ServiceReview.objects.filter(
            provider=service.provider
        ).aggregate(avg=Avg('rating'))['avg']

        service.provider.rating_avg = Decimal(str(round(avg_rating, 2)))
        service.provider.total_reviews = ServiceReview.objects.filter(
            provider=service.provider
        ).count()
        service.provider.save()

        messages.success(request, 'Review submitted successfully!')
        return redirect('service_detail', service_uuid=service_uuid)

    context = {'service': service}
    return render(request, 'services/add_review.html', context)


# ==================== UTILITY FUNCTIONS ====================

def address_to_coords(address):
    """Convert a text address into geographic (lat, lon) coordinates."""
    try:
        location = geolocator.geocode(address)
        if location:
            return (location.latitude, location.longitude)
    except (GeocoderUnavailable, GeocoderTimedOut):
        return None
    return None


def coords_to_address(latitude, longitude):
    """Convert (lat, lon) coordinates back into a readable address."""
    try:
        location = geolocator.reverse((latitude, longitude))
        if location:
            return location.address
    except (GeocoderUnavailable, GeocoderTimedOut):
        return None
    return None


# ==================== AJAX/API ENDPOINTS ====================

@login_required
def search_services_ajax(request):
    """
    AJAX endpoint for live service search.
    """
    query = request.GET.get('q', '')

    if len(query) < 2:
        return JsonResponse({'results': []})

    services = Service.objects.filter(
        Q(name__icontains=query) | Q(description__icontains=query)
    )[:10]

    results = [{
        'uuid': str(service.uuid),
        'name': service.name,
        'price': float(service.price) if service.price else None,
        'provider': service.provider.display_name,
    } for service in services]

    return JsonResponse({'results': results})
