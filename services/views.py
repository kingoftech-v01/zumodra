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
from .models import *
from configurations.models import Skill, Company
from django.utils import timezone

# Initialize geolocator
geolocator = Nominatim(user_agent="zumodra_app")


# ==================== SERVICE BROWSING & SEARCH ====================

def browse_services(request):
    """
    Browse all services with filtering and search capabilities.
    """
    services_query = DService.objects.select_related('provider', 'DServiceCategory').prefetch_related('tags', 'images')

    # Search by name or description
    search = request.GET.get('search', '')
    if search:
        services_query = services_query.filter(
            Q(name__icontains=search) |
            Q(description__icontains=search) |
            Q(tags__tag__icontains=search)
        ).distinct()

    # Filter by category
    category_id = request.GET.get('category')
    if category_id:
        services_query = services_query.filter(DServiceCategory_id=category_id)

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
        services_query = services_query.filter(tags__tag__iexact=tag)

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
    categories = DServiceCategory.objects.all()
    popular_tags = DServicesTag.objects.annotate(
        service_count=Count('DServices_with_tag')
    ).order_by('-service_count')[:10]

    context = {
        'services': services,
        'categories': categories,
        'popular_tags': popular_tags,
        'search': search,
    }
    return render(request, 'services/browse_services.html', context)


def service_detail(request, service_uuid):
    """
    View detailed information about a specific service.
    """
    service = get_object_or_404(
        DService.objects.select_related('provider__user', 'DServiceCategory')
        .prefetch_related('images', 'tags', 'comments_DService__reviewer'),
        uuid=service_uuid
    )

    # Get reviews/comments
    comments = service.comments_DService.filter(parent__isnull=True).order_by('-created_at')
    avg_rating = comments.aggregate(avg=Avg('rating'))['avg'] or 0

    # Check if user has liked this service
    user_has_liked = False
    if request.user.is_authenticated:
        user_has_liked = DServiceLike.objects.filter(
            user=request.user,
            DService=service
        ).exists()

    # Get related services (same category)
    related_services = DService.objects.filter(
        DServiceCategory=service.DServiceCategory
    ).exclude(uuid=service_uuid)[:4]

    context = {
        'service': service,
        'comments': comments,
        'avg_rating': round(avg_rating, 2),
        'user_has_liked': user_has_liked,
        'related_services': related_services,
    }
    return render(request, 'services/service_detail.html', context)


@login_required
def like_service(request, service_uuid):
    """
    Toggle like/unlike a service.
    """
    service = get_object_or_404(DService, uuid=service_uuid)
    like, created = DServiceLike.objects.get_or_create(
        user=request.user,
        DService=service
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
        if request.user.is_authenticated and hasattr(request.user, 'DService_provider_profile'):
            provider = request.user.DService_provider_profile
            if provider.location_lat and provider.location_lng:
                lat = provider.location_lat
                lng = provider.location_lng
        else:
            messages.warning(request, 'Please provide your location')
            return redirect('browse_services')

    try:
        user_lat = float(lat)
        user_lng = float(lng)
    except (ValueError, TypeError):
        messages.error(request, 'Invalid location coordinates')
        return redirect('browse_services')

    user_location = Point(user_lng, user_lat, srid=4326)
    within_area = int(request.GET.get('within_area', 10))  # Default 10km

    # Find providers within distance
    nearby_providers = (
        DServiceProviderProfile.objects
        .filter(
            location__distance_lte=(user_location, D(km=within_area)),
            availability_status='available'
        )
        .annotate(distance=Distance('location', user_location))
        .order_by('distance')
    )

    # Get services from nearby providers
    nearby_services = DService.objects.filter(
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
        provider = request.user.DService_provider_profile
    except DServiceProviderProfile.DoesNotExist:
        messages.info(request, 'Please create your provider profile first')
        return redirect('create_provider_profile')

    # Get provider's services
    services = provider.DServices_offered_by_provider.all()

    # Get active contracts
    active_contracts = DServiceContract.objects.filter(
        provider=provider,
        status='active'
    )

    # Get pending proposals
    pending_proposals = DServiceProposal.objects.filter(
        provider=provider,
        is_accepted=False
    )

    # Get recent comments
    recent_comments = DServiceComment.objects.filter(
        provider=provider
    ).order_by('-created_at')[:5]

    # Calculate stats
    total_services = services.count()
    total_contracts = provider.config_provider_contracts.count()
    avg_rating = recent_comments.aggregate(avg=Avg('rating'))['avg'] or 0

    context = {
        'provider': provider,
        'services': services,
        'active_contracts': active_contracts,
        'pending_proposals': pending_proposals,
        'recent_comments': recent_comments,
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
    if hasattr(request.user, 'DService_provider_profile'):
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
        provider = DServiceProviderProfile.objects.create(
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
        if 'image' in request.FILES:
            provider.image = request.FILES['image']
            provider.save()

        # Add selected categories
        category_ids = request.POST.getlist('categories')
        if category_ids:
            provider.categories.set(category_ids)

        messages.success(request, 'Provider profile created successfully!')
        return redirect('provider_dashboard')

    # GET request - show form
    categories = DServiceCategory.objects.all()
    context = {'categories': categories}
    return render(request, 'services/create_provider_profile.html', context)


@login_required
def edit_provider_profile(request):
    """
    Edit existing provider profile.
    """
    provider = get_object_or_404(DServiceProviderProfile, user=request.user)

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
        if 'image' in request.FILES:
            provider.image = request.FILES['image']

        provider.save()

        # Update categories
        category_ids = request.POST.getlist('categories')
        if category_ids:
            provider.categories.set(category_ids)

        messages.success(request, 'Profile updated successfully!')
        return redirect('provider_dashboard')

    categories = DServiceCategory.objects.all()
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
        DServiceProviderProfile.objects.prefetch_related('DServices_offered_by_provider'),
        uuid=provider_uuid
    )

    # Don't show private profiles
    if provider.is_private:
        messages.error(request, 'This profile is private')
        return redirect('browse_services')

    # Get provider's services
    services = provider.DServices_offered_by_provider.all()

    # Get reviews
    reviews = DServiceComment.objects.filter(provider=provider).order_by('-created_at')
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
        provider = request.user.DService_provider_profile
    except DServiceProviderProfile.DoesNotExist:
        messages.error(request, 'Please create a provider profile first')
        return redirect('create_provider_profile')

    if request.method == 'POST':
        name = request.POST.get('name')
        description = request.POST.get('description', '')
        price = request.POST.get('price')
        duration_minutes = request.POST.get('duration_minutes')
        category_id = request.POST.get('category')

        # Create service
        service = DService.objects.create(
            provider=provider,
            name=name,
            description=description,
            price=int(price) if price else None,
            duration_minutes=int(duration_minutes) if duration_minutes else None,
            DServiceCategory_id=category_id if category_id else None
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
                tag, _ = DServicesTag.objects.get_or_create(tag=tag_name)
                service.tags.add(tag)

        messages.success(request, 'Service created successfully!')
        return redirect('provider_dashboard')

    categories = DServiceCategory.objects.all()
    context = {'categories': categories}
    return render(request, 'services/create_service.html', context)


@login_required
def edit_service(request, service_uuid):
    """
    Edit an existing service.
    """
    service = get_object_or_404(DService, uuid=service_uuid, provider__user=request.user)

    if request.method == 'POST':
        service.name = request.POST.get('name', service.name)
        service.description = request.POST.get('description', service.description)

        price = request.POST.get('price')
        service.price = int(price) if price else None

        duration = request.POST.get('duration_minutes')
        service.duration_minutes = int(duration) if duration else None

        category_id = request.POST.get('category')
        service.DServiceCategory_id = category_id if category_id else None

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
                tag, _ = DServicesTag.objects.get_or_create(tag=tag_name)
                service.tags.add(tag)

        messages.success(request, 'Service updated successfully!')
        return redirect('provider_dashboard')

    categories = DServiceCategory.objects.all()
    current_tags = ', '.join([tag.tag for tag in service.tags.all()])

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
    service = get_object_or_404(DService, uuid=service_uuid, provider__user=request.user)

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
        company_id = request.POST.get('company')

        # Create request
        service_request = DServiceRequest.objects.create(
            client=request.user,
            company_id=company_id if company_id else None,
            title=title,
            description=description,
            budget_min=Decimal(budget_min) if budget_min else None,
            budget_max=Decimal(budget_max) if budget_max else None,
            deadline=deadline if deadline else None,
        )

        # Add required skills
        skill_ids = request.POST.getlist('skills')
        if skill_ids:
            service_request.required_skills.set(skill_ids)

        messages.success(request, 'Service request created successfully!')
        return redirect('my_requests')

    skills = Skill.objects.all()
    companies = Company.objects.filter(Q(owner=request.user) | Q(members=request.user))

    context = {
        'skills': skills,
        'companies': companies,
    }
    return render(request, 'services/create_request.html', context)


@login_required
def my_requests(request):
    """
    View user's service requests.
    """
    requests = DServiceRequest.objects.filter(client=request.user).order_by('-created_at')

    context = {'requests': requests}
    return render(request, 'services/my_requests.html', context)


@login_required
def view_request(request, request_uuid):
    """
    View a specific service request with proposals.
    """
    service_request = get_object_or_404(
        DServiceRequest.objects.prefetch_related('proposals__provider'),
        uuid=request_uuid
    )

    # Only owner or providers can view
    is_owner = service_request.client == request.user
    has_provider_profile = hasattr(request.user, 'DService_provider_profile')

    if not (is_owner or has_provider_profile):
        messages.error(request, 'You do not have permission to view this request')
        return redirect('browse_services')

    proposals = service_request.proposals.all().order_by('-submitted_at')

    context = {
        'request': service_request,
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
        provider = request.user.DService_provider_profile
    except DServiceProviderProfile.DoesNotExist:
        messages.error(request, 'You need a provider profile to submit proposals')
        return redirect('create_provider_profile')

    service_request = get_object_or_404(DServiceRequest, uuid=request_uuid, is_open=True)

    # Check if already submitted
    if DServiceProposal.objects.filter(request=service_request, provider=provider).exists():
        messages.warning(request, 'You already submitted a proposal for this request')
        return redirect('view_request', request_uuid=request_uuid)

    if request.method == 'POST':
        proposed_rate = request.POST.get('proposed_rate')
        message = request.POST.get('message', '')

        DServiceProposal.objects.create(
            request=service_request,
            provider=provider,
            proposed_rate=Decimal(proposed_rate),
            message=message
        )

        messages.success(request, 'Proposal submitted successfully!')
        return redirect('provider_dashboard')

    context = {
        'request': service_request,
        'provider': provider,
    }
    return render(request, 'services/submit_proposal.html', context)


@login_required
def accept_proposal(request, proposal_id):
    """
    Client accepts a proposal and creates a contract.
    """
    proposal = get_object_or_404(DServiceProposal, id=proposal_id)

    # Ensure user is the client who made the request
    if proposal.request.client != request.user:
        messages.error(request, 'You do not have permission to accept this proposal')
        return redirect('browse_services')

    if request.method == 'POST':
        # Mark proposal as accepted
        proposal.is_accepted = True
        proposal.save()

        # Close the request
        proposal.request.is_open = False
        proposal.request.save()

        # Create contract
        agreed_deadline = request.POST.get('agreed_deadline')
        contract = DServiceContract.objects.create(
            request=proposal.request,
            provider=proposal.provider,
            client=request.user,
            agreed_rate=proposal.proposed_rate,
            agreed_deadline=agreed_deadline if agreed_deadline else None,
            status='pending'
        )

        messages.success(request, 'Proposal accepted! Contract created.')
        return redirect('view_contract', contract_id=contract.id)

    context = {'proposal': proposal}
    return render(request, 'services/accept_proposal.html', context)


# ==================== CONTRACT MANAGEMENT ====================

@login_required
def view_contract(request, contract_id):
    """
    View contract details.
    """
    contract = get_object_or_404(DServiceContract, id=contract_id)

    # Only client or provider can view
    is_client = contract.client == request.user
    is_provider = contract.provider.user == request.user

    if not (is_client or is_provider):
        messages.error(request, 'You do not have permission to view this contract')
        return redirect('browse_services')

    # Get contract messages
    contract_messages = contract.messages.all().order_by('sent_at')

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
    client_contracts = DServiceContract.objects.filter(client=request.user)

    # Contracts as provider
    provider_contracts = []
    if hasattr(request.user, 'DService_provider_profile'):
        provider_contracts = DServiceContract.objects.filter(
            provider=request.user.DService_provider_profile
        )

    context = {
        'client_contracts': client_contracts,
        'provider_contracts': provider_contracts,
    }
    return render(request, 'services/my_contracts.html', context)


@login_required
def update_contract_status(request, contract_id):
    """
    Update contract status (start, complete, cancel).
    """
    contract = get_object_or_404(DServiceContract, id=contract_id)

    # Check permissions
    is_client = contract.client == request.user
    is_provider = contract.provider.user == request.user

    if not (is_client or is_provider):
        messages.error(request, 'You do not have permission to update this contract')
        return redirect('browse_services')

    if request.method == 'POST':
        new_status = request.POST.get('status')

        if new_status == 'active' and contract.status == 'pending':
            contract.status = 'active'
            contract.started_at = timezone.now()
            messages.success(request, 'Contract activated')

        elif new_status == 'completed' and contract.status == 'active' and is_provider:
            contract.status = 'completed'
            contract.completed_at = timezone.now()
            # Update provider stats
            contract.provider.completed_jobs_count += 1
            contract.provider.save()
            messages.success(request, 'Contract marked as completed')

        elif new_status == 'cancelled' and is_client:
            contract.status = 'cancelled'
            messages.success(request, 'Contract cancelled')

        contract.save()
        return redirect('view_contract', contract_id=contract_id)

    context = {'contract': contract}
    return render(request, 'services/update_contract_status.html', context)


# ==================== REVIEWS & COMMENTS ====================

@login_required
def add_review(request, service_uuid):
    """
    Add a review/comment to a service.
    """
    service = get_object_or_404(DService, uuid=service_uuid)

    if request.method == 'POST':
        content = request.POST.get('content', '')
        rating = request.POST.get('rating')

        if not rating:
            messages.error(request, 'Please provide a rating')
            return redirect('service_detail', service_uuid=service_uuid)

        DServiceComment.objects.create(
            provider=service.provider,
            DService=service,
            reviewer=request.user,
            content=content,
            rating=int(rating)
        )

        # Update provider rating
        avg_rating = DServiceComment.objects.filter(
            provider=service.provider
        ).aggregate(avg=Avg('rating'))['avg']

        service.provider.rating_avg = Decimal(str(round(avg_rating, 2)))
        service.provider.total_reviews = DServiceComment.objects.filter(
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

    services = DService.objects.filter(
        Q(name__icontains=query) | Q(description__icontains=query)
    )[:10]

    results = [{
        'uuid': str(service.uuid),
        'name': service.name,
        'price': service.price,
        'provider': service.provider.get_full_name(),
    } for service in services]

    return JsonResponse({'results': results})
