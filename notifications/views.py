from django.shortcuts import render, redirect, get_object_or_404
from django.contrib.auth.decorators import login_required
from django.http import JsonResponse
from django.core.paginator import Paginator
from .models import Notification, NotificationPreference


@login_required
def notification_list(request):
    """List all notifications for the current user"""
    notifications = Notification.objects.filter(recipient=request.user)

    # Filter by read/unread
    filter_type = request.GET.get('filter', 'all')
    if filter_type == 'unread':
        notifications = notifications.filter(is_read=False)
    elif filter_type == 'read':
        notifications = notifications.filter(is_read=True)

    # Pagination
    paginator = Paginator(notifications, 20)
    page_number = request.GET.get('page', 1)
    page_obj = paginator.get_page(page_number)

    # Count unread
    unread_count = Notification.objects.filter(
        recipient=request.user,
        is_read=False
    ).count()

    context = {
        'notifications': page_obj,
        'unread_count': unread_count,
        'filter_type': filter_type,
    }
    return render(request, 'notifications/notification_list.html', context)


@login_required
def notification_mark_read(request, notification_id):
    """Mark a notification as read"""
    notification = get_object_or_404(
        Notification,
        id=notification_id,
        recipient=request.user
    )
    notification.mark_as_read()

    # If AJAX request, return JSON
    if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
        return JsonResponse({'success': True, 'is_read': True})

    # Otherwise redirect to action URL or back to notifications
    if notification.action_url:
        return redirect(notification.action_url)
    return redirect('notifications:notification_list')


@login_required
def notification_mark_all_read(request):
    """Mark all notifications as read"""
    if request.method == 'POST':
        Notification.objects.filter(
            recipient=request.user,
            is_read=False
        ).update(is_read=True)

        if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
            return JsonResponse({'success': True})

    return redirect('notifications:notification_list')


@login_required
def notification_delete(request, notification_id):
    """Delete a notification"""
    notification = get_object_or_404(
        Notification,
        id=notification_id,
        recipient=request.user
    )

    if request.method == 'POST':
        notification.delete()

        if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
            return JsonResponse({'success': True})

        return redirect('notifications:notification_list')

    context = {'notification': notification}
    return render(request, 'notifications/notification_delete.html', context)


@login_required
def notification_preferences(request):
    """Manage notification preferences"""
    preferences, created = NotificationPreference.objects.get_or_create(
        user=request.user
    )

    if request.method == 'POST':
        # Update preferences
        preferences.email_on_proposal = request.POST.get('email_on_proposal') == 'on'
        preferences.email_on_contract = request.POST.get('email_on_contract') == 'on'
        preferences.email_on_payment = request.POST.get('email_on_payment') == 'on'
        preferences.email_on_review = request.POST.get('email_on_review') == 'on'
        preferences.email_on_message = request.POST.get('email_on_message') == 'on'

        preferences.app_on_proposal = request.POST.get('app_on_proposal') == 'on'
        preferences.app_on_contract = request.POST.get('app_on_contract') == 'on'
        preferences.app_on_payment = request.POST.get('app_on_payment') == 'on'
        preferences.app_on_review = request.POST.get('app_on_review') == 'on'
        preferences.app_on_message = request.POST.get('app_on_message') == 'on'

        preferences.daily_digest = request.POST.get('daily_digest') == 'on'
        preferences.weekly_digest = request.POST.get('weekly_digest') == 'on'

        preferences.save()

        return redirect('notifications:notification_preferences')

    context = {'preferences': preferences}
    return render(request, 'notifications/notification_preferences.html', context)


@login_required
def notification_count_api(request):
    """API endpoint to get unread notification count"""
    count = Notification.objects.filter(
        recipient=request.user,
        is_read=False
    ).count()

    return JsonResponse({'unread_count': count})
