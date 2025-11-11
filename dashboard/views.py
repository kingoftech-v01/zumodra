from django.shortcuts import render

# Create your views here.

def dashboard_view(request):
    return render(request, 'dashboard.html')

def my_bookmarks_view(request):
    return render(request, 'my-bookmarks.html')
