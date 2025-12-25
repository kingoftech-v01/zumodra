# Dashboard Implementation Examples

This document provides complete, ready-to-use code examples for implementing dynamic dashboards with QuerySets in the Zumodra application.

## Table of Contents

1. [Quick Start](#quick-start)
2. [Public User Dashboard](#public-user-dashboard)
3. [Company Employee Dashboard](#company-employee-dashboard)
4. [Dashboard Router](#dashboard-router)
5. [Template Context Examples](#template-context-examples)
6. [Testing Your Implementation](#testing-your-implementation)

---

## Quick Start

### Step 1: Update dashboard/views.py

Replace the empty `dashboard_view()` function with the smart router and the two dashboard implementations below.

### Step 2: Add Required Imports

Add these imports at the top of `dashboard/views.py`:

```python
from django.shortcuts import render, redirect
from django.contrib.auth.decorators import login_required
from django.db.models import Count, Avg, Sum, Q
from django.utils import timezone
from datetime import timedelta

# Import models from your apps
from DServices.models import (
    DService, DServiceRequest, DServiceProposal,
    DServiceContract, DServiceProviderProfile
)
from appointments.models import Appointment
from notifications.models import Notification
from payments.models import Payment
from companies.models import Company
from newsletter.models import Subscriber, Campaign, EmailTemplate
```

---

## Public User Dashboard

Complete implementation for users who are NOT part of a company (job seekers, service clients, general public).

```python
@login_required
def public_dashboard_view(request):
    """
    Dashboard for public users (non-company members).
    Shows service requests, contracts, appointments, and provider stats if applicable.
    """
    user = request.user

    # Calculate date ranges for analytics
    today = timezone.now()
    last_7_days = today - timedelta(days=7)
    last_30_days = today - timedelta(days=30)

    # ============================================
    # Service Requests (as a client)
    # ============================================
    my_requests = DServiceRequest.objects.filter(client=user)
    open_requests_count = my_requests.filter(is_open=True).count()
    closed_requests_count = my_requests.filter(is_open=False).count()
    recent_requests = my_requests.order_by('-created_at')[:5]

    # Requests with pending proposals
    requests_with_proposals = my_requests.annotate(
        proposal_count=Count('DServiceProposal')
    ).filter(proposal_count__gt=0).order_by('-created_at')[:5]

    # ============================================
    # Contracts (as a client)
    # ============================================
    my_contracts = DServiceContract.objects.filter(client=user)
    active_contracts_count = my_contracts.filter(status='active').count()
    completed_contracts_count = my_contracts.filter(status='completed').count()
    pending_contracts_count = my_contracts.filter(status='pending').count()
    recent_contracts = my_contracts.order_by('-created_at')[:5]

    # ============================================
    # Provider Statistics (if user is a provider)
    # ============================================
    provider_stats = None
    provider_services = []
    provider_proposals = []
    provider_contracts = []

    if hasattr(user, 'DService_provider_profile'):
        provider = user.DService_provider_profile

        # Provider services
        provider_services = provider.DServices_offered_by_provider.all()
        total_services = provider_services.count()
        active_services = provider_services.filter(is_active=True).count()

        # Provider proposals
        provider_proposals = DServiceProposal.objects.filter(
            provider=provider
        ).order_by('-created_at')[:5]

        pending_proposals = DServiceProposal.objects.filter(
            provider=provider,
            is_accepted=False
        ).count()

        # Provider contracts
        provider_contracts = DServiceContract.objects.filter(
            provider=provider
        ).order_by('-created_at')[:5]

        # Calculate earnings
        total_earnings = DServiceContract.objects.filter(
            provider=provider,
            status='completed'
        ).aggregate(total=Sum('agreed_rate'))['total'] or 0

        provider_stats = {
            'total_services': total_services,
            'active_services': active_services,
            'rating': provider.rating_avg or 0,
            'total_reviews': provider.rating_count or 0,
            'completed_jobs': provider.completed_jobs_count or 0,
            'pending_proposals': pending_proposals,
            'total_earnings': total_earnings,
        }

    # ============================================
    # Appointments
    # ============================================
    upcoming_appointments = Appointment.objects.filter(
        user=user,
        start_time__gte=today
    ).order_by('start_time')[:5]

    past_appointments = Appointment.objects.filter(
        user=user,
        start_time__lt=today
    ).order_by('-start_time')[:5]

    # ============================================
    # Notifications
    # ============================================
    unread_notifications = Notification.objects.filter(
        recipient=user,
        is_read=False
    ).order_by('-created_at')[:10]

    unread_count = unread_notifications.count()

    # ============================================
    # Payments
    # ============================================
    recent_payments = Payment.objects.filter(
        user=user
    ).order_by('-created_at')[:5]

    total_spent = Payment.objects.filter(
        user=user,
        status='completed'
    ).aggregate(total=Sum('amount'))['total'] or 0

    # ============================================
    # Activity Summary (Last 7 days)
    # ============================================
    activity_summary = {
        'new_requests': my_requests.filter(created_at__gte=last_7_days).count(),
        'new_proposals': DServiceProposal.objects.filter(
            request__client=user,
            created_at__gte=last_7_days
        ).count(),
        'new_contracts': my_contracts.filter(created_at__gte=last_7_days).count(),
        'new_appointments': Appointment.objects.filter(
            user=user,
            created_at__gte=last_7_days
        ).count(),
    }

    # ============================================
    # Context for Template
    # ============================================
    context = {
        'user_type': 'public',
        'dashboard_title': 'My Dashboard',

        # Service Requests
        'my_requests': recent_requests,
        'open_requests_count': open_requests_count,
        'closed_requests_count': closed_requests_count,
        'requests_with_proposals': requests_with_proposals,

        # Contracts
        'my_contracts': recent_contracts,
        'active_contracts_count': active_contracts_count,
        'completed_contracts_count': completed_contracts_count,
        'pending_contracts_count': pending_contracts_count,

        # Provider Info (if applicable)
        'is_provider': provider_stats is not None,
        'provider_stats': provider_stats,
        'provider_services': provider_services[:5],
        'provider_proposals': provider_proposals,
        'provider_contracts': provider_contracts,

        # Appointments
        'upcoming_appointments': upcoming_appointments,
        'past_appointments': past_appointments,

        # Notifications
        'recent_notifications': unread_notifications,
        'unread_notifications_count': unread_count,

        # Payments
        'recent_payments': recent_payments,
        'total_spent': total_spent,

        # Activity
        'activity_summary': activity_summary,
    }

    return render(request, 'dashboard/public_dashboard.html', context)
```

---

## Company Employee Dashboard

Complete implementation for users who ARE part of a company/tenant (company employees, HR managers, etc.).

```python
@login_required
def company_dashboard_view(request):
    """
    Dashboard for company employees (tenant members).
    Shows company-wide stats, employee management, campaigns, and company services.
    """
    user = request.user

    # Check if user belongs to a company
    try:
        company = user.company
    except AttributeError:
        # User is not associated with a company
        return redirect('public_dashboard')

    # Calculate date ranges
    today = timezone.now()
    last_7_days = today - timedelta(days=7)
    last_30_days = today - timedelta(days=30)

    # ============================================
    # Company Overview
    # ============================================
    total_employees = company.employees.count()
    active_employees = company.employees.filter(is_active=True).count()

    # ============================================
    # Company Services
    # ============================================
    company_services = DService.objects.filter(
        provider__user__company=company
    )

    total_services = company_services.count()
    active_services = company_services.filter(is_active=True).count()

    # Service performance
    service_stats = company_services.annotate(
        request_count=Count('DServiceRequest'),
        contract_count=Count('DServiceContract')
    ).order_by('-request_count')[:10]

    # ============================================
    # Service Requests (company-wide)
    # ============================================
    company_requests = DServiceRequest.objects.filter(
        DService__provider__user__company=company
    )

    open_requests = company_requests.filter(is_open=True).count()
    total_requests = company_requests.count()
    recent_requests = company_requests.order_by('-created_at')[:10]

    # ============================================
    # Contracts (company-wide)
    # ============================================
    company_contracts = DServiceContract.objects.filter(
        provider__user__company=company
    )

    active_contracts = company_contracts.filter(status='active').count()
    completed_contracts = company_contracts.filter(status='completed').count()
    pending_contracts = company_contracts.filter(status='pending').count()

    # Revenue calculation
    total_revenue = company_contracts.filter(
        status='completed'
    ).aggregate(total=Sum('agreed_rate'))['total'] or 0

    revenue_last_30_days = company_contracts.filter(
        status='completed',
        updated_at__gte=last_30_days
    ).aggregate(total=Sum('agreed_rate'))['total'] or 0

    # ============================================
    # Providers Performance
    # ============================================
    company_providers = DServiceProviderProfile.objects.filter(
        user__company=company
    )

    top_providers = company_providers.annotate(
        contract_count=Count('DServiceContract')
    ).order_by('-rating_avg', '-contract_count')[:5]

    avg_company_rating = company_providers.aggregate(
        avg=Avg('rating_avg')
    )['avg'] or 0

    # ============================================
    # Newsletter/Marketing Campaigns
    # ============================================
    company_campaigns = Campaign.objects.filter(
        created_by__company=company
    ).order_by('-created_at')[:5]

    active_campaigns = Campaign.objects.filter(
        created_by__company=company,
        status='active'
    ).count()

    total_subscribers = Subscriber.objects.filter(
        is_active=True
    ).count()  # Adjust filter if subscribers are company-specific

    # ============================================
    # Appointments (company-wide)
    # ============================================
    company_appointments = Appointment.objects.filter(
        user__company=company
    )

    upcoming_appointments = company_appointments.filter(
        start_time__gte=today
    ).order_by('start_time')[:10]

    appointments_today = company_appointments.filter(
        start_time__date=today.date()
    ).count()

    # ============================================
    # Recent Activity (Last 7 days)
    # ============================================
    activity_summary = {
        'new_employees': company.employees.filter(
            date_joined__gte=last_7_days
        ).count(),
        'new_services': company_services.filter(
            created_at__gte=last_7_days
        ).count(),
        'new_requests': company_requests.filter(
            created_at__gte=last_7_days
        ).count(),
        'new_contracts': company_contracts.filter(
            created_at__gte=last_7_days
        ).count(),
        'completed_contracts': company_contracts.filter(
            status='completed',
            updated_at__gte=last_7_days
        ).count(),
    }

    # ============================================
    # Notifications (for current user)
    # ============================================
    unread_notifications = Notification.objects.filter(
        recipient=user,
        is_read=False
    ).order_by('-created_at')[:10]

    # ============================================
    # Team Members
    # ============================================
    team_members = company.employees.filter(is_active=True)[:10]

    # ============================================
    # Context for Template
    # ============================================
    context = {
        'user_type': 'company',
        'dashboard_title': f'{company.name} Dashboard',
        'company': company,

        # Company Overview
        'total_employees': total_employees,
        'active_employees': active_employees,

        # Services
        'total_services': total_services,
        'active_services': active_services,
        'service_stats': service_stats,

        # Requests
        'open_requests': open_requests,
        'total_requests': total_requests,
        'recent_requests': recent_requests,

        # Contracts
        'active_contracts': active_contracts,
        'completed_contracts': completed_contracts,
        'pending_contracts': pending_contracts,

        # Revenue
        'total_revenue': total_revenue,
        'revenue_last_30_days': revenue_last_30_days,

        # Providers
        'top_providers': top_providers,
        'avg_company_rating': avg_company_rating,

        # Campaigns
        'company_campaigns': company_campaigns,
        'active_campaigns': active_campaigns,
        'total_subscribers': total_subscribers,

        # Appointments
        'upcoming_appointments': upcoming_appointments,
        'appointments_today': appointments_today,

        # Activity
        'activity_summary': activity_summary,

        # Notifications
        'recent_notifications': unread_notifications,
        'unread_notifications_count': unread_notifications.count(),

        # Team
        'team_members': team_members,
    }

    return render(request, 'dashboard/company_dashboard.html', context)
```

---

## Dashboard Router

Smart router that automatically directs users to the appropriate dashboard.

```python
@login_required
def dashboard_view(request):
    """
    Main dashboard view - routes users to appropriate dashboard based on their type.

    - Company employees -> company_dashboard_view()
    - Public users -> public_dashboard_view()
    """
    user = request.user

    # Check if user belongs to a company/tenant
    if hasattr(user, 'company') and user.company is not None:
        return company_dashboard_view(request)
    else:
        return public_dashboard_view(request)
```

---

## Template Context Examples

### Public Dashboard Template (dashboard/public_dashboard.html)

Example of how to use the context in your template:

```django
{% extends "base.html" %}
{% load static %}

{% block title %}{{ dashboard_title }}{% endblock %}

{% block content %}
<div class="dashboard-container">
    <h1>Welcome, {{ user.get_full_name|default:user.username }}</h1>

    <!-- Activity Summary -->
    <div class="dashboard-stats">
        <div class="stat-card">
            <h3>{{ open_requests_count }}</h3>
            <p>Open Requests</p>
        </div>
        <div class="stat-card">
            <h3>{{ active_contracts_count }}</h3>
            <p>Active Contracts</p>
        </div>
        <div class="stat-card">
            <h3>{{ unread_notifications_count }}</h3>
            <p>New Notifications</p>
        </div>
        <div class="stat-card">
            <h3>${{ total_spent|floatformat:2 }}</h3>
            <p>Total Spent</p>
        </div>
    </div>

    <!-- Provider Stats (if applicable) -->
    {% if is_provider %}
    <div class="provider-section">
        <h2>Provider Dashboard</h2>
        <div class="provider-stats">
            <p>Rating: {{ provider_stats.rating|floatformat:1 }} ⭐ ({{ provider_stats.total_reviews }} reviews)</p>
            <p>Completed Jobs: {{ provider_stats.completed_jobs }}</p>
            <p>Total Earnings: ${{ provider_stats.total_earnings|floatformat:2 }}</p>
            <p>Pending Proposals: {{ provider_stats.pending_proposals }}</p>
        </div>

        <h3>My Services</h3>
        <ul>
            {% for service in provider_services %}
            <li>
                <a href="{% url 'DService_detail' service.uuid %}">{{ service.name }}</a>
                - ${{ service.price }}
                {% if service.is_active %}<span class="badge active">Active</span>{% endif %}
            </li>
            {% endfor %}
        </ul>
    </div>
    {% endif %}

    <!-- Recent Requests -->
    <div class="requests-section">
        <h2>My Service Requests</h2>
        {% if my_requests %}
        <ul>
            {% for request in my_requests %}
            <li>
                <a href="{% url 'DService_request_detail' request.uuid %}">{{ request.DService.name }}</a>
                - {{ request.created_at|date:"M d, Y" }}
                <span class="badge {% if request.is_open %}open{% else %}closed{% endif %}">
                    {% if request.is_open %}Open{% else %}Closed{% endif %}
                </span>
            </li>
            {% endfor %}
        </ul>
        {% else %}
        <p>No service requests yet.</p>
        {% endif %}
    </div>

    <!-- Upcoming Appointments -->
    <div class="appointments-section">
        <h2>Upcoming Appointments</h2>
        {% if upcoming_appointments %}
        <ul>
            {% for appointment in upcoming_appointments %}
            <li>
                {{ appointment.title }} - {{ appointment.start_time|date:"M d, Y g:i A" }}
            </li>
            {% endfor %}
        </ul>
        {% else %}
        <p>No upcoming appointments.</p>
        {% endif %}
    </div>

    <!-- Recent Activity -->
    <div class="activity-section">
        <h2>Recent Activity (Last 7 Days)</h2>
        <ul>
            <li>{{ activity_summary.new_requests }} new request(s)</li>
            <li>{{ activity_summary.new_proposals }} new proposal(s)</li>
            <li>{{ activity_summary.new_contracts }} new contract(s)</li>
            <li>{{ activity_summary.new_appointments }} new appointment(s)</li>
        </ul>
    </div>
</div>
{% endblock %}
```

### Company Dashboard Template (dashboard/company_dashboard.html)

```django
{% extends "base.html" %}
{% load static %}

{% block title %}{{ dashboard_title }}{% endblock %}

{% block content %}
<div class="company-dashboard-container">
    <h1>{{ company.name }} - Company Dashboard</h1>

    <!-- Company Stats -->
    <div class="dashboard-stats">
        <div class="stat-card">
            <h3>{{ active_employees }}</h3>
            <p>Active Employees</p>
        </div>
        <div class="stat-card">
            <h3>{{ total_services }}</h3>
            <p>Total Services</p>
        </div>
        <div class="stat-card">
            <h3>{{ active_contracts }}</h3>
            <p>Active Contracts</p>
        </div>
        <div class="stat-card">
            <h3>${{ total_revenue|floatformat:2 }}</h3>
            <p>Total Revenue</p>
        </div>
        <div class="stat-card">
            <h3>{{ avg_company_rating|floatformat:1 }} ⭐</h3>
            <p>Avg Rating</p>
        </div>
    </div>

    <!-- Top Providers -->
    <div class="top-providers-section">
        <h2>Top Providers</h2>
        <table>
            <thead>
                <tr>
                    <th>Provider</th>
                    <th>Rating</th>
                    <th>Completed Jobs</th>
                </tr>
            </thead>
            <tbody>
                {% for provider in top_providers %}
                <tr>
                    <td>{{ provider.user.get_full_name }}</td>
                    <td>{{ provider.rating_avg|floatformat:1 }} ⭐</td>
                    <td>{{ provider.completed_jobs_count }}</td>
                </tr>
                {% endfor %}
            </tbody>
        </table>
    </div>

    <!-- Recent Requests -->
    <div class="requests-section">
        <h2>Recent Service Requests ({{ open_requests }} open)</h2>
        <ul>
            {% for request in recent_requests %}
            <li>
                {{ request.DService.name }} - {{ request.created_at|date:"M d, Y" }}
                <span class="badge {% if request.is_open %}open{% else %}closed{% endif %}">
                    {% if request.is_open %}Open{% else %}Closed{% endif %}
                </span>
            </li>
            {% endfor %}
        </ul>
    </div>

    <!-- Marketing Campaigns -->
    <div class="campaigns-section">
        <h2>Marketing Campaigns ({{ active_campaigns }} active)</h2>
        {% if company_campaigns %}
        <ul>
            {% for campaign in company_campaigns %}
            <li>
                {{ campaign.name }} - {{ campaign.status }}
                <small>({{ campaign.created_at|date:"M d, Y" }})</small>
            </li>
            {% endfor %}
        </ul>
        {% else %}
        <p>No campaigns yet.</p>
        {% endif %}
    </div>

    <!-- Team Members -->
    <div class="team-section">
        <h2>Team Members</h2>
        <ul>
            {% for member in team_members %}
            <li>{{ member.get_full_name|default:member.username }} - {{ member.email }}</li>
            {% endfor %}
        </ul>
    </div>
</div>
{% endblock %}
```

---

## Testing Your Implementation

### 1. Test Public Dashboard

```python
# In Django shell
python manage.py shell

from django.contrib.auth import get_user_model
User = get_user_model()

# Get a public user (not associated with company)
user = User.objects.filter(company__isnull=True).first()

# Check what data they would see
from DServices.models import DServiceRequest
requests = DServiceRequest.objects.filter(client=user)
print(f"User has {requests.count()} requests")
```

### 2. Test Company Dashboard

```python
# In Django shell
from companies.models import Company

# Get a company user
company = Company.objects.first()
user = company.employees.first()

# Check company-wide data
from DServices.models import DServiceContract
contracts = DServiceContract.objects.filter(provider__user__company=company)
print(f"Company has {contracts.count()} contracts")
```

### 3. Test Dashboard Router

```bash
# Start development server
python manage.py runserver

# Visit http://localhost:8000/dashboard/
# Should automatically route to correct dashboard based on user type
```

### 4. Verify Data Loading

Add this to your view temporarily for debugging:

```python
# Add at the end of public_dashboard_view() before return
print(f"DEBUG: User {user.username}")
print(f"DEBUG: Open requests: {open_requests_count}")
print(f"DEBUG: Active contracts: {active_contracts_count}")
print(f"DEBUG: Is provider: {provider_stats is not None}")
```

---

## Next Steps

1. **Copy the code** from this document into `dashboard/views.py`
2. **Update your URL configuration** if needed:
   ```python
   # dashboard/urls.py
   from django.urls import path
   from . import views

   urlpatterns = [
       path('', views.dashboard_view, name='dashboard'),
       path('public/', views.public_dashboard_view, name='public_dashboard'),
       path('company/', views.company_dashboard_view, name='company_dashboard'),
   ]
   ```
3. **Create/update templates** in `dashboard/templates/dashboard/`
4. **Test with real data** using the testing examples above
5. **Add charts/graphs** using libraries like Chart.js or plotly
6. **Implement caching** for expensive queries if needed

---

## Performance Optimization Tips

### 1. Use select_related() and prefetch_related()

```python
# Instead of:
my_requests = DServiceRequest.objects.filter(client=user)

# Use:
my_requests = DServiceRequest.objects.filter(client=user).select_related('DService', 'DServiceCategory')
```

### 2. Cache Expensive Queries

```python
from django.core.cache import cache

def company_dashboard_view(request):
    cache_key = f'company_stats_{company.id}'
    stats = cache.get(cache_key)

    if not stats:
        stats = calculate_expensive_stats(company)
        cache.set(cache_key, stats, 300)  # Cache for 5 minutes
```

### 3. Use Database Indexes

Add to your models:

```python
class DServiceRequest(models.Model):
    # ...
    class Meta:
        indexes = [
            models.Index(fields=['client', 'is_open']),
            models.Index(fields=['created_at']),
        ]
```

---

**Document created**: 2025-12-25
**For**: Zumodra Dashboard Implementation
**Status**: Ready for implementation
