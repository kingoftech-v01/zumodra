from django.shortcuts import render
from django.contrib.auth.decorators import login_required
from django.db.models import Count, Sum, Avg, Q
from django.db.models.functions import TruncDate, TruncMonth
from django.utils import timezone
from datetime import timedelta
from .models import PageView, UserAction, SearchQuery, DashboardMetric
from services.models import DService, DServiceContract, DServiceProviderProfile
from custom_account_u.models import User


@login_required
def analytics_dashboard(request):
    """
    Main analytics dashboard with key metrics
    """
    # Date ranges
    today = timezone.now().date()
    last_7_days = today - timedelta(days=7)
    last_30_days = today - timedelta(days=30)

    # User metrics
    total_users = User.objects.count()
    active_users_7d = User.objects.filter(last_login__gte=last_7_days).count()
    new_users_7d = User.objects.filter(date_joined__gte=last_7_days).count()

    # Service metrics
    total_services = DService.objects.count()
    new_services_7d = DService.objects.filter(created_at__gte=last_7_days).count()

    # Contract metrics
    total_contracts = DServiceContract.objects.count()
    active_contracts = DServiceContract.objects.filter(status='active').count()
    completed_contracts = DServiceContract.objects.filter(status='completed').count()
    completed_contracts_7d = DServiceContract.objects.filter(
        status='completed',
        completed_at__gte=last_7_days
    ).count()

    # Provider metrics
    total_providers = DServiceProviderProfile.objects.count()
    verified_providers = DServiceProviderProfile.objects.filter(is_verified=True).count()
    avg_provider_rating = DServiceProviderProfile.objects.aggregate(
        avg=Avg('rating_avg')
    )['avg'] or 0

    # Page views (last 7 days)
    page_views_7d = PageView.objects.filter(timestamp__gte=last_7_days).count()

    # Most popular services (by views/likes)
    popular_services = DService.objects.annotate(
        likes_count=Count('config_liked_DServices')
    ).order_by('-likes_count')[:5]

    # Recent user actions
    recent_actions = UserAction.objects.select_related('user')[:20]

    # Search trends
    popular_searches = SearchQuery.objects.filter(
        timestamp__gte=last_7_days
    ).values('query').annotate(
        count=Count('id')
    ).order_by('-count')[:10]

    # Daily metrics for charts (last 30 days)
    daily_users = User.objects.filter(
        date_joined__gte=last_30_days
    ).annotate(
        date=TruncDate('date_joined')
    ).values('date').annotate(
        count=Count('id')
    ).order_by('date')

    daily_contracts = DServiceContract.objects.filter(
        created_at__gte=last_30_days
    ).annotate(
        date=TruncDate('created_at')
    ).values('date').annotate(
        count=Count('id')
    ).order_by('date')

    context = {
        # User metrics
        'total_users': total_users,
        'active_users_7d': active_users_7d,
        'new_users_7d': new_users_7d,

        # Service metrics
        'total_services': total_services,
        'new_services_7d': new_services_7d,
        'popular_services': popular_services,

        # Contract metrics
        'total_contracts': total_contracts,
        'active_contracts': active_contracts,
        'completed_contracts': completed_contracts,
        'completed_contracts_7d': completed_contracts_7d,

        # Provider metrics
        'total_providers': total_providers,
        'verified_providers': verified_providers,
        'avg_provider_rating': round(avg_provider_rating, 2),

        # Activity metrics
        'page_views_7d': page_views_7d,
        'recent_actions': recent_actions,
        'popular_searches': popular_searches,

        # Chart data
        'daily_users': list(daily_users),
        'daily_contracts': list(daily_contracts),
    }

    return render(request, 'analytics/dashboard.html', context)


@login_required
def provider_analytics(request):
    """
    Analytics dashboard for service providers
    """
    try:
        provider = request.user.DService_provider_profile
    except DServiceProviderProfile.DoesNotExist:
        return render(request, 'analytics/no_provider_profile.html')

    # Date ranges
    today = timezone.now().date()
    last_30_days = today - timedelta(days=30)

    # Provider stats
    total_services = provider.DServices_offered_by_provider.count()
    total_contracts = provider.config_provider_contracts.count()
    active_contracts = provider.config_provider_contracts.filter(status='active').count()
    completed_contracts = provider.config_provider_contracts.filter(status='completed').count()

    # Revenue (if using finance app)
    # total_revenue = provider.config_provider_contracts.filter(
    #     status='completed'
    # ).aggregate(total=Sum('agreed_rate'))['total'] or 0

    # Most viewed services
    service_views = UserAction.objects.filter(
        action_type='service_view',
        content_type__model='dservice'
    ).values('object_id').annotate(
        views=Count('id')
    ).order_by('-views')[:5]

    # Service IDs
    service_ids = [sv['object_id'] for sv in service_views]
    services = DService.objects.filter(id__in=service_ids, provider=provider)

    # Recent reviews
    from services.models import DServiceComment
    recent_reviews = DServiceComment.objects.filter(
        provider=provider
    ).order_by('-created_at')[:5]

    # Monthly contract trend
    monthly_contracts = DServiceContract.objects.filter(
        provider=provider,
        created_at__gte=last_30_days
    ).annotate(
        month=TruncMonth('created_at')
    ).values('month').annotate(
        count=Count('id')
    ).order_by('month')

    context = {
        'provider': provider,
        'total_services': total_services,
        'total_contracts': total_contracts,
        'active_contracts': active_contracts,
        'completed_contracts': completed_contracts,
        # 'total_revenue': total_revenue,
        'top_services': services,
        'recent_reviews': recent_reviews,
        'monthly_contracts': list(monthly_contracts),
    }

    return render(request, 'analytics/provider_analytics.html', context)


@login_required
def client_analytics(request):
    """
    Analytics dashboard for clients
    """
    # Date ranges
    today = timezone.now().date()
    last_30_days = today - timedelta(days=30)

    # Client stats
    total_requests = DServiceRequest.objects.filter(client=request.user).count()
    open_requests = DServiceRequest.objects.filter(client=request.user, is_open=True).count()
    total_contracts = DServiceContract.objects.filter(client=request.user).count()
    active_contracts = DServiceContract.objects.filter(client=request.user, status='active').count()
    completed_contracts = DServiceContract.objects.filter(client=request.user, status='completed').count()

    # Spending (if using finance app)
    # total_spent = DServiceContract.objects.filter(
    #     client=request.user,
    #     status='completed'
    #).aggregate(total=Sum('agreed_rate'))['total'] or 0

    # Favorite services
    from services.models import DServiceLike
    favorite_services = DService.objects.filter(
        config_liked_DServices__user=request.user
    )[:5]

    # Recent searches
    recent_searches = SearchQuery.objects.filter(
        user=request.user
    ).order_by('-timestamp')[:10]

    context = {
        'total_requests': total_requests,
        'open_requests': open_requests,
        'total_contracts': total_contracts,
        'active_contracts': active_contracts,
        'completed_contracts': completed_contracts,
        # 'total_spent': total_spent,
        'favorite_services': favorite_services,
        'recent_searches': recent_searches,
    }

    return render(request, 'analytics/client_analytics.html', context)
